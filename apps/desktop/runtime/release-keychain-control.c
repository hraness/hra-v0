#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct __SecCodeSignerRemote *SecCodeSignerRemoteRef;
typedef CFDataRef (^SecCodeRemoteLegacySignHandler)(
  CFDataRef,
  SecCSDigestAlgorithm
);
typedef CFDataRef (^SecCodeRemoteModernSignHandler)(
  CFDataRef,
  SecCSDigestAlgorithm,
  SecKeyAlgorithm
);
typedef OSStatus (*SecCodeSignerRemoteCreateFunction)(
  CFDictionaryRef,
  CFArrayRef,
  SecCSFlags,
  SecCodeSignerRemoteRef *,
  CFErrorRef *
);
typedef OSStatus (*SecCodeSignerRemoteAddSignatureLegacyFunction)(
  SecCodeSignerRemoteRef,
  SecStaticCodeRef,
  SecCSFlags,
  SecCodeRemoteLegacySignHandler,
  CFErrorRef *
);
typedef OSStatus (*SecCodeSignerRemoteAddSignatureModernFunction)(
  SecCodeSignerRemoteRef,
  SecStaticCodeRef,
  SecCSFlags,
  SecCodeRemoteModernSignHandler,
  CFErrorRef *
);
typedef OSStatus (*SecTrustedApplicationCopyRequirementFunction)(
  SecTrustedApplicationRef,
  SecRequirementRef *
);
typedef OSStatus (*SecTrustedApplicationValidateWithPathFunction)(
  SecTrustedApplicationRef,
  const char *
);

typedef struct {
  uint8_t *bytes;
  size_t length;
  size_t capacity;
} SecretBytes;

static volatile sig_atomic_t received_signal = 0;

static const int managed_signals[] = {
  SIGHUP,
  SIGINT,
  SIGQUIT,
  SIGTERM,
  SIGALRM,
};

static void release_cf(CFTypeRef value) {
  if (value != NULL) CFRelease(value);
}

static void clear_secret(SecretBytes *secret) {
  if (secret->bytes != NULL) {
    volatile uint8_t *cursor = secret->bytes;
    for (size_t index = 0; index < secret->capacity; index += 1) {
      cursor[index] = 0;
    }
    free(secret->bytes);
  }
  secret->bytes = NULL;
  secret->length = 0;
  secret->capacity = 0;
}

static void catch_signal(int signal_number) {
  if (received_signal == 0) received_signal = signal_number;
}

static bool install_signal_handlers(struct sigaction *prior) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = catch_signal;
  if (sigemptyset(&action.sa_mask) != 0) return false;
  for (size_t index = 0;
       index < sizeof(managed_signals) / sizeof(managed_signals[0]);
       index += 1) {
    if (sigaction(managed_signals[index], &action, &prior[index]) != 0) {
      for (size_t rollback = 0; rollback < index; rollback += 1) {
        (void)sigaction(managed_signals[rollback], &prior[rollback], NULL);
      }
      return false;
    }
  }
  return true;
}

static void restore_signal_handlers(const struct sigaction *prior) {
  for (size_t index = 0;
       index < sizeof(managed_signals) / sizeof(managed_signals[0]);
       index += 1) {
    (void)sigaction(managed_signals[index], &prior[index], NULL);
  }
}

static bool path_shape_is_safe(const char *path) {
  if (path == NULL || path[0] != '/' || path[1] == '\0') return false;
  size_t length = strnlen(path, PATH_MAX);
  if (length == 0 || length >= PATH_MAX) return false;
  if (strchr(path, '\n') != NULL || strchr(path, '\r') != NULL) return false;
  if (strstr(path, "//") != NULL || strstr(path, "/./") != NULL) return false;
  if (strstr(path, "/../") != NULL) return false;
  if (length >= 2 && strcmp(path + length - 2, "/.") == 0) return false;
  if (length >= 3 && strcmp(path + length - 3, "/..") == 0) return false;
  return true;
}

static bool path_is_canonical(const char *path) {
  if (!path_shape_is_safe(path)) return false;
  char resolved[PATH_MAX];
  return realpath(path, resolved) != NULL && strcmp(path, resolved) == 0;
}

static bool owner_private_parent(const char *path) {
  char parent[PATH_MAX];
  size_t length = strlen(path);
  if (length >= sizeof(parent)) return false;
  memcpy(parent, path, length + 1);
  char *separator = strrchr(parent, '/');
  if (separator == NULL || separator == parent) return false;
  *separator = '\0';

  struct stat status;
  return lstat(parent, &status) == 0
    && S_ISDIR(status.st_mode)
    && status.st_uid == geteuid()
    && (status.st_mode & (S_IRWXG | S_IRWXO)) == 0;
}

static bool owner_protected_target_parent(const char *path) {
  char parent[PATH_MAX];
  size_t length = strlen(path);
  if (length >= sizeof(parent)) return false;
  memcpy(parent, path, length + 1);
  char *separator = strrchr(parent, '/');
  if (separator == NULL || separator == parent) return false;
  *separator = '\0';
  struct stat status;
  return lstat(parent, &status) == 0
    && S_ISDIR(status.st_mode)
    && !S_ISLNK(status.st_mode)
    && status.st_uid == geteuid()
    && (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool owner_private_regular_file(const char *path, struct stat *result) {
  if (!path_is_canonical(path) || !owner_private_parent(path)) return false;
  int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  struct stat status;
  bool ok = fstat(descriptor, &status) == 0
    && S_ISREG(status.st_mode)
    && status.st_uid == geteuid()
    && status.st_nlink == 1
    && (status.st_mode & (S_IRWXG | S_IRWXO)) == 0;
  if (close(descriptor) != 0) ok = false;
  if (ok && result != NULL) *result = status;
  return ok;
}

static bool owner_controlled_target(const char *path) {
  if (!path_is_canonical(path) || !owner_protected_target_parent(path)) {
    return false;
  }
  struct stat status;
  bool ok = lstat(path, &status) == 0
    && !S_ISLNK(status.st_mode)
    && (S_ISREG(status.st_mode) || S_ISDIR(status.st_mode))
    && status.st_uid == geteuid();
  char current[PATH_MAX];
  if (!ok || strlen(path) >= sizeof(current)) return false;
  memcpy(current, path, strlen(path) + 1);
  while (true) {
    char *separator = strrchr(current, '/');
    if (separator == NULL) return false;
    if (separator == current) {
      current[1] = '\0';
    } else {
      *separator = '\0';
    }
    struct stat ancestor;
    if (lstat(current, &ancestor) != 0
        || !S_ISDIR(ancestor.st_mode)
        || S_ISLNK(ancestor.st_mode)) {
      return false;
    }
    bool writable = (ancestor.st_mode & (S_IWGRP | S_IWOTH)) != 0;
    if (writable) {
      return ancestor.st_uid == 0 && (ancestor.st_mode & S_ISVTX) != 0;
    }
    if (ancestor.st_uid != geteuid() && ancestor.st_uid != 0) return false;
    if (strcmp(current, "/") == 0) return true;
  }
}

static bool copy_main_executable_path(
  const char *target_path,
  const struct stat *target_status,
  char result[PATH_MAX]
) {
  if (S_ISREG(target_status->st_mode)) {
    size_t length = strlen(target_path);
    if (length >= PATH_MAX) return false;
    memcpy(result, target_path, length + 1);
    return owner_controlled_target(result);
  }
  if (!S_ISDIR(target_status->st_mode)) return false;
  CFURLRef bundle_url = CFURLCreateFromFileSystemRepresentation(
    kCFAllocatorDefault,
    (const UInt8 *)target_path,
    (CFIndex)strlen(target_path),
    true
  );
  CFBundleRef bundle = bundle_url == NULL
    ? NULL
    : CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFURLRef executable_url = bundle == NULL
    ? NULL
    : CFBundleCopyExecutableURL(bundle);
  bool ok = executable_url != NULL
    && CFURLGetFileSystemRepresentation(
      executable_url,
      true,
      (UInt8 *)result,
      PATH_MAX
    );
  size_t target_length = strlen(target_path);
  ok = ok
    && strncmp(result, target_path, target_length) == 0
    && result[target_length] == '/'
    && owner_controlled_target(result);
  release_cf(executable_url);
  release_cf(bundle);
  release_cf(bundle_url);
  return ok;
}

static bool signer_staging_path_absent(const char *executable_path) {
  char staging[PATH_MAX];
  int length = snprintf(staging, sizeof(staging), "%s.cstemp", executable_path);
  if (length <= 0 || (size_t)length >= sizeof(staging)) return false;
  struct stat status;
  errno = 0;
  return lstat(staging, &status) != 0 && errno == ENOENT;
}

static bool read_password_file(const char *path, SecretBytes *result) {
  if (!path_is_canonical(path) || !owner_private_parent(path)) return false;
  int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;

  struct stat status;
  bool ok = fstat(descriptor, &status) == 0
    && S_ISREG(status.st_mode)
    && status.st_uid == geteuid()
    && status.st_nlink == 1
    && (status.st_mode & (S_IRWXG | S_IRWXO)) == 0
    && status.st_size >= 32
    && status.st_size <= 512;
  if (!ok) {
    (void)close(descriptor);
    return false;
  }

  size_t capacity = (size_t)status.st_size;
  uint8_t *bytes = calloc(capacity, 1);
  if (bytes == NULL) {
    (void)close(descriptor);
    return false;
  }
  size_t offset = 0;
  while (offset < capacity) {
    ssize_t count = read(descriptor, bytes + offset, capacity - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      ok = false;
      break;
    }
    offset += (size_t)count;
  }
  if (close(descriptor) != 0) ok = false;

  size_t length = offset;
  while (length > 0 && (bytes[length - 1] == '\n' || bytes[length - 1] == '\r')) {
    length -= 1;
  }
  if (length < 32 || length > 512) ok = false;
  for (size_t index = 0; ok && index < length; index += 1) {
    if (bytes[index] == 0 || bytes[index] == '\n' || bytes[index] == '\r') {
      ok = false;
    }
  }
  if (!ok) {
    SecretBytes temporary = {bytes, length, capacity};
    clear_secret(&temporary);
    return false;
  }
  result->bytes = bytes;
  result->length = length;
  result->capacity = capacity;
  return true;
}

static bool open_validated_keychain(const char *path, SecKeychainRef *keychain) {
  struct stat before;
  if (!owner_private_regular_file(path, &before)) return false;
  if (SecKeychainOpen(path, keychain) != errSecSuccess || *keychain == NULL) {
    return false;
  }
  struct stat after;
  if (lstat(path, &after) != 0
      || !S_ISREG(after.st_mode)
      || after.st_uid != before.st_uid
      || after.st_dev != before.st_dev
      || after.st_ino != before.st_ino
      || after.st_nlink != 1
      || (after.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    CFRelease(*keychain);
    *keychain = NULL;
    return false;
  }
  return true;
}

static bool keychain_is_locked(SecKeychainRef keychain) {
  SecKeychainStatus status = 0;
  return SecKeychainGetStatus(keychain, &status) == errSecSuccess
    && (status & kSecUnlockStateStatus) == 0;
}

static bool keychain_is_unlocked(SecKeychainRef keychain) {
  SecKeychainStatus status = 0;
  return SecKeychainGetStatus(keychain, &status) == errSecSuccess
    && (status & kSecUnlockStateStatus) != 0;
}

static bool lowercase_sha1(const char *value) {
  if (value == NULL || strlen(value) != CC_SHA1_DIGEST_LENGTH * 2) return false;
  for (size_t index = 0; index < CC_SHA1_DIGEST_LENGTH * 2; index += 1) {
    char byte = value[index];
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
      return false;
    }
  }
  return true;
}

static bool certificate_sha1(SecCertificateRef certificate, char output[41]) {
  CFDataRef data = SecCertificateCopyData(certificate);
  if (data == NULL || CFDataGetLength(data) <= 0 || CFDataGetLength(data) > UINT32_MAX) {
    release_cf(data);
    return false;
  }
  unsigned char digest[CC_SHA1_DIGEST_LENGTH];
  CC_SHA1(
    CFDataGetBytePtr(data),
    (CC_LONG)CFDataGetLength(data),
    digest
  );
  release_cf(data);
  for (size_t index = 0; index < sizeof(digest); index += 1) {
    (void)snprintf(output + index * 2, 3, "%02x", digest[index]);
  }
  output[40] = '\0';
  return true;
}

static bool exact_certificates(
  SecKeychainRef keychain,
  const char *leaf_sha1,
  const char *root_sha1,
  SecCertificateRef *leaf_result,
  SecCertificateRef *root_result
) {
  if (leaf_result != NULL) *leaf_result = NULL;
  if (root_result != NULL) *root_result = NULL;
  const void *keychain_values[] = {keychain};
  CFArrayRef keychains = CFArrayCreate(
    kCFAllocatorDefault,
    keychain_values,
    1,
    &kCFTypeArrayCallBacks
  );
  const void *keys[] = {
    kSecClass,
    kSecMatchSearchList,
    kSecMatchLimit,
    kSecReturnRef,
  };
  const void *values[] = {
    kSecClassCertificate,
    keychains,
    kSecMatchLimitAll,
    kCFBooleanTrue,
  };
  CFDictionaryRef query = keychains == NULL ? NULL : CFDictionaryCreate(
    kCFAllocatorDefault,
    keys,
    values,
    4,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
  CFTypeRef result = NULL;
  bool ok = query != NULL
    && SecItemCopyMatching(query, &result) == errSecSuccess
    && result != NULL
    && CFGetTypeID(result) == CFArrayGetTypeID();
  bool saw_leaf = false;
  bool saw_root = false;
  if (ok) {
    CFArrayRef certificates = (CFArrayRef)result;
    ok = CFArrayGetCount(certificates) == 2;
    for (CFIndex index = 0; ok && index < 2; index += 1) {
      SecCertificateRef certificate =
        (SecCertificateRef)CFArrayGetValueAtIndex(certificates, index);
      char digest[41];
      ok = certificate != NULL && certificate_sha1(certificate, digest);
      if (ok && strcmp(digest, leaf_sha1) == 0 && !saw_leaf) {
        saw_leaf = true;
        if (leaf_result != NULL) {
          CFRetain(certificate);
          *leaf_result = certificate;
        }
      } else if (ok && strcmp(digest, root_sha1) == 0 && !saw_root) {
        saw_root = true;
        if (root_result != NULL) {
          CFRetain(certificate);
          *root_result = certificate;
        }
      } else {
        ok = false;
      }
    }
  }
  release_cf(result);
  release_cf(query);
  release_cf(keychains);
  ok = ok && saw_leaf && saw_root;
  if (!ok) {
    if (leaf_result != NULL) {
      release_cf(*leaf_result);
      *leaf_result = NULL;
    }
    if (root_result != NULL) {
      release_cf(*root_result);
      *root_result = NULL;
    }
  }
  return ok;
}

static bool exact_signer_acl(SecKeyRef private_key, const char *signer_path) {
  SecAccessRef access = NULL;
  CFArrayRef acl_list = NULL;
  CFArrayRef broad_acl_list = NULL;
  CFArrayRef applications = NULL;
  SecTrustedApplicationRef expected_application = NULL;
  SecRequirementRef expected_requirement = NULL;
  SecRequirementRef actual_requirement = NULL;
  CFDataRef expected_requirement_data = NULL;
  CFDataRef actual_requirement_data = NULL;
  bool ok = SecKeychainItemCopyAccess((SecKeychainItemRef)private_key, &access)
      == errSecSuccess
    && access != NULL
    && SecAccessCopySelectedACLList(
      access,
      CSSM_ACL_AUTHORIZATION_ANY,
      &broad_acl_list
    ) == errSecSuccess
    && broad_acl_list == NULL
    && SecAccessCopySelectedACLList(
      access,
      CSSM_ACL_AUTHORIZATION_SIGN,
      &acl_list
    ) == errSecSuccess
    && acl_list != NULL
    && CFArrayGetCount(acl_list) == 1;
  if (ok) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, 0);
    CFStringRef description = NULL;
    SecKeychainPromptSelector prompt = 0;
    ok = SecACLCopyContents(acl, &applications, &description, &prompt)
        == errSecSuccess
      && applications != NULL
      && CFArrayGetCount(applications) == 1
      && prompt == 0;
    release_cf(description);
  }
  if (ok) {
    SecTrustedApplicationRef actual_application =
      (SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, 0);
    SecTrustedApplicationCopyRequirementFunction copy_requirement =
      (SecTrustedApplicationCopyRequirementFunction)dlsym(
        RTLD_DEFAULT,
        "SecTrustedApplicationCopyRequirement"
      );
    SecTrustedApplicationValidateWithPathFunction validate_path =
      (SecTrustedApplicationValidateWithPathFunction)dlsym(
        RTLD_DEFAULT,
        "SecTrustedApplicationValidateWithPath"
      );
    ok = SecTrustedApplicationCreateFromPath(signer_path, &expected_application)
        == errSecSuccess
      && expected_application != NULL
      && copy_requirement != NULL
      && validate_path != NULL
      && copy_requirement(expected_application, &expected_requirement)
        == errSecSuccess
      && copy_requirement(actual_application, &actual_requirement)
        == errSecSuccess
      && expected_requirement != NULL
      && actual_requirement != NULL
      && SecRequirementCopyData(
        expected_requirement,
        0,
        &expected_requirement_data
      ) == errSecSuccess
      && SecRequirementCopyData(
        actual_requirement,
        0,
        &actual_requirement_data
      ) == errSecSuccess
      && expected_requirement_data != NULL
      && actual_requirement_data != NULL
      && CFEqual(expected_requirement_data, actual_requirement_data)
      && validate_path(actual_application, signer_path) == errSecSuccess;
  }
  release_cf(actual_requirement_data);
  release_cf(expected_requirement_data);
  release_cf(actual_requirement);
  release_cf(expected_requirement);
  release_cf(expected_application);
  release_cf(applications);
  release_cf(broad_acl_list);
  release_cf(acl_list);
  release_cf(access);
  return ok;
}

static bool exact_private_key(
  SecKeychainRef keychain,
  const char *signer_path,
  SecKeyRef *key_result
) {
  if (key_result != NULL) *key_result = NULL;
  const void *keychain_values[] = {keychain};
  CFArrayRef keychains = CFArrayCreate(
    kCFAllocatorDefault,
    keychain_values,
    1,
    &kCFTypeArrayCallBacks
  );
  const void *keys[] = {
    kSecClass,
    kSecAttrKeyClass,
    kSecMatchSearchList,
    kSecMatchLimit,
    kSecReturnRef,
  };
  const void *values[] = {
    kSecClassKey,
    kSecAttrKeyClassPrivate,
    keychains,
    kSecMatchLimitAll,
    kCFBooleanTrue,
  };
  CFDictionaryRef query = keychains == NULL ? NULL : CFDictionaryCreate(
    kCFAllocatorDefault,
    keys,
    values,
    5,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
  CFTypeRef result = NULL;
  bool ok = query != NULL
    && SecItemCopyMatching(query, &result) == errSecSuccess
    && result != NULL
    && CFGetTypeID(result) == CFArrayGetTypeID()
    && CFArrayGetCount((CFArrayRef)result) == 1;
  CFDictionaryRef attributes = NULL;
  SecKeyRef private_key = NULL;
  if (ok) {
    private_key = (SecKeyRef)CFArrayGetValueAtIndex((CFArrayRef)result, 0);
    ok = private_key != NULL && CFGetTypeID(private_key) == SecKeyGetTypeID();
  }
  if (ok) {
    attributes = SecKeyCopyAttributes(private_key);
    ok = attributes != NULL
      && CFDictionaryGetValue(attributes, kSecAttrKeyClass)
        == kSecAttrKeyClassPrivate
      && CFDictionaryGetValue(attributes, kSecAttrCanSign) == kCFBooleanTrue
      && CFDictionaryGetValue(attributes, kSecAttrIsExtractable)
        == kCFBooleanFalse
      && exact_signer_acl(private_key, signer_path);
  }
  if (ok && key_result != NULL) {
    CFRetain(private_key);
    *key_result = private_key;
  }
  release_cf(attributes);
  release_cf(result);
  release_cf(query);
  release_cf(keychains);
  if (!ok && key_result != NULL) {
    release_cf(*key_result);
    *key_result = NULL;
  }
  return ok;
}

static bool keychain_absent_from_search_list(SecKeychainRef isolated) {
  CFArrayRef search_list = NULL;
  bool ok = SecKeychainCopySearchList(&search_list) == errSecSuccess
    && search_list != NULL
    && CFArrayGetCount(search_list) <= 32;
  for (CFIndex index = 0;
       ok && index < CFArrayGetCount(search_list);
       index += 1) {
    CFTypeRef value = CFArrayGetValueAtIndex(search_list, index);
    ok = value != NULL
      && CFGetTypeID(value) == SecKeychainGetTypeID()
      && !CFEqual(value, isolated);
    for (CFIndex prior = 0; ok && prior < index; prior += 1) {
      if (CFEqual(value, CFArrayGetValueAtIndex(search_list, prior))) ok = false;
    }
  }
  release_cf(search_list);
  return ok;
}

static bool identifier_is_safe(const char *identifier) {
  if (identifier == NULL) return false;
  size_t length = strnlen(identifier, 129);
  if (length == 0 || length > 128) return false;
  for (size_t index = 0; index < length; index += 1) {
    char value = identifier[index];
    if (!((value >= 'A' && value <= 'Z')
          || (value >= 'a' && value <= 'z')
          || (value >= '0' && value <= '9')
          || value == '.'
          || value == '-')) {
      return false;
    }
  }
  return true;
}

static CFStringRef signing_requirement(
  const char *identifier,
  const char *leaf_sha1,
  const char *root_sha1
) {
  char value[512];
  int length = snprintf(
    value,
    sizeof(value),
    "designated => identifier \"%s\" and certificate root = H\"%s\" and certificate leaf = H\"%s\"",
    identifier,
    root_sha1,
    leaf_sha1
  );
  if (length <= 0 || (size_t)length >= sizeof(value)) return NULL;
  return CFStringCreateWithCString(
    kCFAllocatorDefault,
    value,
    kCFStringEncodingUTF8
  );
}

static bool find_exact_identity(
  SecKeychainRef keychain,
  const char *leaf_sha1,
  SecIdentityRef *result
) {
  SecIdentitySearchRef search = NULL;
  SecIdentityRef identity = NULL;
  SecIdentityRef duplicate = NULL;
  SecCertificateRef certificate = NULL;
  char digest[41];
  bool ok = SecIdentitySearchCreate(keychain, CSSM_KEYUSE_SIGN, &search)
      == errSecSuccess
    && search != NULL
    && SecIdentitySearchCopyNext(search, &identity) == errSecSuccess
    && identity != NULL
    && SecIdentitySearchCopyNext(search, &duplicate) == errSecItemNotFound
    && SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess
    && certificate != NULL
    && certificate_sha1(certificate, digest)
    && strcmp(digest, leaf_sha1) == 0;
  if (ok) {
    *result = identity;
    identity = NULL;
  }
  release_cf(certificate);
  release_cf(duplicate);
  release_cf(identity);
  release_cf(search);
  return ok;
}

static CFStringRef signer_parameter_key(const char *name) {
  const CFStringRef *symbol = (const CFStringRef *)dlsym(RTLD_DEFAULT, name);
  return symbol == NULL ? NULL : *symbol;
}

static CFDataRef create_remote_signature(
  SecKeyRef identity_key,
  CFDataRef cms_digest,
  SecCSDigestAlgorithm digest_algorithm,
  SecKeyAlgorithm signature_algorithm,
  bool verify_signature_algorithm,
  unsigned *callback_count,
  bool *callback_ok
) {
  *callback_count += 1;
  if (*callback_count != 1
      || cms_digest == NULL
      || CFDataGetLength(cms_digest) != CC_SHA256_DIGEST_LENGTH
      || digest_algorithm != kSecCodeSignatureHashSHA256
      || signature_algorithm == NULL
      || (verify_signature_algorithm
        && !CFEqual(
          signature_algorithm,
          kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
        ))) {
    *callback_ok = false;
    return NULL;
  }
  CFErrorRef signature_error = NULL;
  CFDataRef signature = SecKeyCreateSignature(
    identity_key,
    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
    cms_digest,
    &signature_error
  );
  if (signature_error != NULL) {
    *callback_ok = false;
    CFRelease(signature_error);
  }
  if (signature == NULL) *callback_ok = false;
  return signature;
}

static bool remote_sign(
  const char *signer_path,
  SecKeychainRef keychain,
  const char *leaf_sha1,
  const char *root_sha1,
  const char *identifier,
  const char *target_path
) {
  struct stat target_before;
  if (!lowercase_sha1(leaf_sha1)
      || !lowercase_sha1(root_sha1)
      || strcmp(leaf_sha1, root_sha1) == 0
      || !identifier_is_safe(identifier)
      || !owner_controlled_target(target_path)
      || lstat(target_path, &target_before) != 0
      || received_signal != 0) {
    return false;
  }
  char main_executable[PATH_MAX];
  if (!copy_main_executable_path(
        target_path,
        &target_before,
        main_executable
      )
      || !signer_staging_path_absent(main_executable)) {
    return false;
  }

  SecCertificateRef leaf = NULL;
  SecCertificateRef root = NULL;
  SecKeyRef exact_key = NULL;
  SecIdentityRef identity = NULL;
  SecCertificateRef identity_certificate = NULL;
  SecKeyRef identity_key = NULL;
  CFArrayRef chain = NULL;
  CFStringRef identifier_value = NULL;
  CFStringRef requirement = NULL;
  CFNumberRef digest = NULL;
  CFNumberRef flags = NULL;
  CFNumberRef page_size = NULL;
  CFMutableDictionaryRef parameters = NULL;
  CFURLRef target_url = NULL;
  SecStaticCodeRef code = NULL;
  SecCodeSignerRemoteRef signer = NULL;
  CFErrorRef create_error = NULL;
  CFErrorRef add_error = NULL;

  bool ok = keychain_is_unlocked(keychain)
    && exact_certificates(
      keychain,
      leaf_sha1,
      root_sha1,
      &leaf,
      &root
    )
    && exact_private_key(keychain, signer_path, &exact_key)
    && find_exact_identity(keychain, leaf_sha1, &identity)
    && SecIdentityCopyCertificate(identity, &identity_certificate)
      == errSecSuccess
    && identity_certificate != NULL
    && SecIdentityCopyPrivateKey(identity, &identity_key) == errSecSuccess
    && identity_key != NULL
    && CFEqual(identity_certificate, leaf)
    && CFEqual(identity_key, exact_key);

  CFStringRef identifier_key = signer_parameter_key("kSecCodeSignerIdentifier");
  CFStringRef digest_key = signer_parameter_key("kSecCodeSignerDigestAlgorithm");
  CFStringRef flags_key = signer_parameter_key("kSecCodeSignerFlags");
  CFStringRef page_size_key = signer_parameter_key("kSecCodeSignerPageSize");
  CFStringRef signing_time_key = signer_parameter_key("kSecCodeSignerSigningTime");
  CFStringRef timestamp_key = signer_parameter_key("kSecCodeSignerRequireTimestamp");
  CFStringRef requirements_key = signer_parameter_key("kSecCodeSignerRequirements");
  SecCodeSignerRemoteCreateFunction remote_create =
    (SecCodeSignerRemoteCreateFunction)dlsym(
      RTLD_DEFAULT,
      "SecCodeSignerRemoteCreate"
    );
  void *remote_add = dlsym(RTLD_DEFAULT, "SecCodeSignerRemoteAddSignature");
  ok = ok
    && identifier_key != NULL
    && digest_key != NULL
    && flags_key != NULL
    && page_size_key != NULL
    && signing_time_key != NULL
    && timestamp_key != NULL
    && requirements_key != NULL
    && remote_create != NULL
    && remote_add != NULL;

  if (ok) {
    const void *certificate_values[] = {leaf, root};
    chain = CFArrayCreate(
      kCFAllocatorDefault,
      certificate_values,
      2,
      &kCFTypeArrayCallBacks
    );
    identifier_value = CFStringCreateWithCString(
      kCFAllocatorDefault,
      identifier,
      kCFStringEncodingUTF8
    );
    requirement = signing_requirement(identifier, leaf_sha1, root_sha1);
    int32_t digest_value = kSecCodeSignatureHashSHA256;
    int32_t flags_value = kSecCodeSignatureRuntime;
    int64_t page_size_value = 16384;
    digest = CFNumberCreate(
      kCFAllocatorDefault,
      kCFNumberSInt32Type,
      &digest_value
    );
    flags = CFNumberCreate(
      kCFAllocatorDefault,
      kCFNumberSInt32Type,
      &flags_value
    );
    page_size = CFNumberCreate(
      kCFAllocatorDefault,
      kCFNumberSInt64Type,
      &page_size_value
    );
    parameters = CFDictionaryCreateMutable(
      kCFAllocatorDefault,
      7,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks
    );
    ok = chain != NULL
      && CFArrayGetCount(chain) == 2
      && identifier_value != NULL
      && requirement != NULL
      && digest != NULL
      && flags != NULL
      && page_size != NULL
      && parameters != NULL;
  }

  if (ok) {
    CFDictionaryAddValue(parameters, identifier_key, identifier_value);
    CFDictionaryAddValue(parameters, digest_key, digest);
    CFDictionaryAddValue(parameters, flags_key, flags);
    CFDictionaryAddValue(parameters, page_size_key, page_size);
    CFDictionaryAddValue(parameters, signing_time_key, kCFNull);
    CFDictionaryAddValue(parameters, timestamp_key, kCFBooleanFalse);
    CFDictionaryAddValue(parameters, requirements_key, requirement);

    struct stat target_immediate;
    ok = lstat(target_path, &target_immediate) == 0
      && target_immediate.st_dev == target_before.st_dev
      && target_immediate.st_ino == target_before.st_ino
      && target_immediate.st_mode == target_before.st_mode
      && target_immediate.st_uid == target_before.st_uid
      && target_immediate.st_gid == target_before.st_gid
      && target_immediate.st_nlink == target_before.st_nlink
      && received_signal == 0;
    if (ok) {
      target_url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault,
        (const UInt8 *)target_path,
        (CFIndex)strlen(target_path),
        S_ISDIR(target_immediate.st_mode)
      );
      ok = target_url != NULL
        && SecStaticCodeCreateWithPath(target_url, 0, &code) == errSecSuccess
        && code != NULL;
    }
  }

  __block unsigned callback_count = 0;
  __block bool callback_ok = true;
  if (ok) {
    ok = remote_create(
      parameters,
      chain,
      0,
      &signer,
      &create_error
    ) == errSecSuccess
      && signer != NULL
      && create_error == NULL;
  }
  if (ok) {
    ok = owner_controlled_target(main_executable)
      && signer_staging_path_absent(main_executable)
      && received_signal == 0;
  }
  if (ok) {
    OSStatus add_status = errSecUnimplemented;
    if (__builtin_available(macOS 27.0, *)) {
      callback_ok = false;
    } else if (__builtin_available(macOS 26.0, *)) {
      SecCodeSignerRemoteAddSignatureModernFunction modern_add =
        (SecCodeSignerRemoteAddSignatureModernFunction)remote_add;
      add_status = modern_add(
        signer,
        code,
        0,
        ^CFDataRef(
          CFDataRef cms_digest,
          SecCSDigestAlgorithm digest_algorithm,
          SecKeyAlgorithm signature_algorithm
        ) {
          return create_remote_signature(
            identity_key,
            cms_digest,
            digest_algorithm,
            signature_algorithm,
            true,
            &callback_count,
            &callback_ok
          );
        },
        &add_error
      );
    } else {
      SecCodeSignerRemoteAddSignatureLegacyFunction legacy_add =
        (SecCodeSignerRemoteAddSignatureLegacyFunction)remote_add;
      add_status = legacy_add(
        signer,
        code,
        0,
        ^CFDataRef(
          CFDataRef cms_digest,
          SecCSDigestAlgorithm digest_algorithm
        ) {
          return create_remote_signature(
            identity_key,
            cms_digest,
            digest_algorithm,
            kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
            false,
            &callback_count,
            &callback_ok
          );
        },
        &add_error
      );
    }
    ok = add_status == errSecSuccess
      && add_error == NULL
      && callback_ok
      && callback_count == 1
      && owner_controlled_target(target_path)
      && owner_controlled_target(main_executable)
      && signer_staging_path_absent(main_executable)
      && received_signal == 0;
  }

  SecKeyRef key_after = NULL;
  if (ok) {
    ok = exact_certificates(
      keychain,
      leaf_sha1,
      root_sha1,
      NULL,
      NULL
    )
      && exact_private_key(keychain, signer_path, &key_after)
      && CFEqual(key_after, identity_key);
  }

  release_cf(key_after);
  release_cf(add_error);
  release_cf(create_error);
  release_cf(signer);
  release_cf(code);
  release_cf(target_url);
  release_cf(parameters);
  release_cf(page_size);
  release_cf(flags);
  release_cf(digest);
  release_cf(requirement);
  release_cf(identifier_value);
  release_cf(chain);
  release_cf(identity_key);
  release_cf(identity_certificate);
  release_cf(identity);
  release_cf(exact_key);
  release_cf(root);
  release_cf(leaf);
  return ok;
}

static bool parent_sign(
  const char *signer_path,
  const char *keychain_path,
  const char *passphrase_path,
  const char *leaf_sha1,
  const char *root_sha1,
  const char *identifier,
  const char *target_path,
  int *signal_result
) {
  if (!owner_private_regular_file(signer_path, NULL)
      || !lowercase_sha1(leaf_sha1)
      || !lowercase_sha1(root_sha1)
      || strcmp(leaf_sha1, root_sha1) == 0
      || !identifier_is_safe(identifier)
      || !owner_controlled_target(target_path)
      || strcmp(keychain_path, passphrase_path) == 0
      || strcmp(keychain_path, signer_path) == 0
      || strcmp(passphrase_path, signer_path) == 0) {
    return false;
  }
  struct sigaction prior[
    sizeof(managed_signals) / sizeof(managed_signals[0])
  ];
  if (!install_signal_handlers(prior)) return false;
  (void)alarm(20);

  SecKeychainRef keychain = NULL;
  SecretBytes password = {0};
  bool initially_locked = false;
  bool ok = SecKeychainSetUserInteractionAllowed(false) == errSecSuccess
    && open_validated_keychain(keychain_path, &keychain);
  if (ok) {
    initially_locked = keychain_is_locked(keychain);
    ok = initially_locked
      && keychain_absent_from_search_list(keychain)
      && read_password_file(passphrase_path, &password)
      && received_signal == 0;
  }
  if (ok) {
    ok = password.length <= UINT32_MAX
      && SecKeychainUnlock(
        keychain,
        (UInt32)password.length,
        password.bytes,
        true
      ) == errSecSuccess
      && keychain_is_unlocked(keychain)
      && keychain_absent_from_search_list(keychain)
      && received_signal == 0;
  }
  clear_secret(&password);
  if (ok) {
    ok = remote_sign(
      signer_path,
      keychain,
      leaf_sha1,
      root_sha1,
      identifier,
      target_path
    );
  }

  bool lock_ok = keychain == NULL
    || (SecKeychainLock(keychain) == errSecSuccess && keychain_is_locked(keychain));
  bool search_ok = keychain == NULL
    || keychain_absent_from_search_list(keychain);
  clear_secret(&password);
  release_cf(keychain);

  sigset_t blocked;
  sigset_t prior_mask;
  (void)sigemptyset(&blocked);
  for (size_t index = 0;
       index < sizeof(managed_signals) / sizeof(managed_signals[0]);
       index += 1) {
    (void)sigaddset(&blocked, managed_signals[index]);
  }
  bool mask_ok = sigprocmask(SIG_BLOCK, &blocked, &prior_mask) == 0;
  (void)alarm(0);
  int caught = (int)received_signal;
  received_signal = 0;
  restore_signal_handlers(prior);
  if (mask_ok) (void)sigprocmask(SIG_SETMASK, &prior_mask, NULL);
  *signal_result = caught;
  return ok
    && initially_locked
    && lock_ok
    && search_ok
    && mask_ok
    && caught == 0;
}

static bool lock_keychain(const char *keychain_path) {
  SecKeychainRef keychain = NULL;
  bool ok = open_validated_keychain(keychain_path, &keychain)
    && SecKeychainLock(keychain) == errSecSuccess
    && keychain_is_locked(keychain)
    && keychain_absent_from_search_list(keychain);
  release_cf(keychain);
  return ok;
}

int main(int argc, char **argv) {
  bool ok = false;
  int caught_signal = 0;
  if (argc == 3 && strcmp(argv[1], "lock") == 0) {
    ok = lock_keychain(argv[2]);
  } else if (argc == 8 && strcmp(argv[1], "sign") == 0) {
    ok = parent_sign(
      argv[0],
      argv[2],
      argv[3],
      argv[4],
      argv[5],
      argv[6],
      argv[7],
      &caught_signal
    );
  } else {
    fputs("HRA release signer failed.\n", stderr);
    return 64;
  }
  if (caught_signal != 0 && caught_signal != SIGALRM) {
    (void)raise(caught_signal);
  }
  if (!ok) {
    fputs("HRA release signer failed.\n", stderr);
    return 1;
  }
  return 0;
}
