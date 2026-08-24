#import "macos_gateway_attestation.h"
#import "macos_release_validation_status.h"
#import "macos_renderer_authority.h"
#import "macos_self_managed_code_identity.h"

#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <Security/CMSDecoder.h>
#import <Security/Security.h>
#import <errno.h>
#import <fcntl.h>
#import <libproc.h>
#import <limits.h>
#import <os/lock.h>
#import <pthread.h>
#import <signal.h>
#import <spawn.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/proc.h>
#import <sys/wait.h>
#import <unistd.h>

extern const uint8_t HRAExpectedGatewayFileSHA256[32];
extern const uint8_t HRAReleaseLeafCertificateSHA1[20];
extern const uint8_t HRAReleaseLeafCertificateSHA256[32];
extern const uint8_t HRAReleaseRootCertificateSHA1[20];
extern const uint8_t HRAReleaseRootCertificateSHA256[32];
extern const char HRAReleaseLeafCertificateSHA1Hex[41];
extern const char HRAReleaseRootCertificateSHA1Hex[41];

static NSString *const HRAGatewayIdentifier = @"oprte-gateway";
static NSString *const HRAGatewayJITEntitlement =
    @"com.apple.security.cs.allow-unsigned-executable-memory";

static os_unfair_lock HRAGatewayGenerationLock = OS_UNFAIR_LOCK_INIT;
static pid_t HRAAttestedGatewayPID = -1;
static uint64_t HRAAttestedGatewayStartSeconds = 0;
static uint64_t HRAAttestedGatewayStartMicroseconds = 0;

typedef struct {
  dev_t device;
  ino_t inode;
  mode_t mode;
  nlink_t links;
  uid_t owner;
  gid_t group;
  off_t size;
  struct timespec modified;
  struct timespec changed;
} HRAFileIdentity;

static int HRAAuthenticatedGatewayDescriptor = -1;
static HRAFileIdentity HRAAuthenticatedGatewayFileIdentity;
static uint8_t HRAAuthenticatedGatewayCDHash[HRA_MACOS_CDHASH_LENGTH];
static pid_t HRAAuthenticatedGatewayPID = -1;
static pid_t HRAAuthenticatedGatewayParentPID = -1;
static uint64_t HRAAuthenticatedGatewayStartSeconds = 0;
static uint64_t HRAAuthenticatedGatewayStartMicroseconds = 0;

bool hra_macos_child_process_policy_is_exact(void) {
  struct sigaction childExit;
  memset(&childExit, 0, sizeof(childExit));
  sigset_t currentMask;
  return sigaction(SIGCHLD, NULL, &childExit) == 0 &&
      childExit.sa_handler == SIG_DFL &&
      (childExit.sa_flags & SA_NOCLDWAIT) == 0 &&
      pthread_sigmask(SIG_SETMASK, NULL, &currentMask) == 0 &&
      sigismember(&currentMask, SIGCHLD) == 0;
}

bool hra_macos_establish_child_process_policy(void) {
  struct sigaction childExit;
  memset(&childExit, 0, sizeof(childExit));
  childExit.sa_handler = SIG_DFL;
  sigset_t childSignal;
  return sigemptyset(&childExit.sa_mask) == 0 &&
      sigaction(SIGCHLD, &childExit, NULL) == 0 &&
      sigemptyset(&childSignal) == 0 &&
      sigaddset(&childSignal, SIGCHLD) == 0 &&
      pthread_sigmask(SIG_UNBLOCK, &childSignal, NULL) == 0 &&
      hra_macos_child_process_policy_is_exact();
}

static bool HRAFileIdentityFromStat(
    const struct stat *metadata,
    HRAFileIdentity *outIdentity) {
  if (metadata == NULL || outIdentity == NULL ||
      !S_ISREG(metadata->st_mode) || metadata->st_nlink != 1 ||
      metadata->st_uid != geteuid() || metadata->st_size <= 0) {
    return false;
  }
  *outIdentity = (HRAFileIdentity){
    .device = metadata->st_dev,
    .inode = metadata->st_ino,
    .mode = metadata->st_mode,
    .links = metadata->st_nlink,
    .owner = metadata->st_uid,
    .group = metadata->st_gid,
    .size = metadata->st_size,
    .modified = metadata->st_mtimespec,
    .changed = metadata->st_ctimespec,
  };
  return true;
}

static bool HRAFileIdentityMatches(
    const HRAFileIdentity *expected,
    const struct stat *actual) {
  HRAFileIdentity value;
  memset(&value, 0, sizeof(value));
  return expected != NULL && HRAFileIdentityFromStat(actual, &value) &&
      expected->device == value.device && expected->inode == value.inode &&
      expected->mode == value.mode && expected->links == value.links &&
      expected->owner == value.owner && expected->group == value.group &&
      expected->size == value.size &&
      expected->modified.tv_sec == value.modified.tv_sec &&
      expected->modified.tv_nsec == value.modified.tv_nsec &&
      expected->changed.tv_sec == value.changed.tv_sec &&
      expected->changed.tv_nsec == value.changed.tv_nsec;
}

static bool HRAPathIsCanonical(NSString *path) {
  if (path == nil || ![path hasPrefix:@"/"]) return false;
  char resolved[PATH_MAX];
  memset(resolved, 0, sizeof(resolved));
  const char *representation = path.fileSystemRepresentation;
  return representation != NULL && realpath(representation, resolved) != NULL &&
      strcmp(representation, resolved) == 0;
}

static bool HRADescriptorNamesPath(int descriptor, NSString *path) {
  char descriptorPath[PATH_MAX];
  memset(descriptorPath, 0, sizeof(descriptorPath));
  return descriptor >= 0 && path != nil &&
      fcntl(descriptor, F_GETPATH, descriptorPath) == 0 &&
      strcmp(descriptorPath, path.fileSystemRepresentation) == 0;
}

static bool HRAHashExactDescriptor(
    int descriptor,
    const HRAFileIdentity *identity,
    const uint8_t expectedDigest[CC_SHA256_DIGEST_LENGTH]) {
  if (descriptor < 0 || identity == NULL || identity->size <= 0 ||
      expectedDigest == NULL) return false;
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  memset(digest, 0, sizeof(digest));
  bool valid = true;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  CC_SHA256_CTX context;
  memset(&context, 0, sizeof(context));
  valid = CC_SHA256_Init(&context) == 1;
  uint8_t buffer[64 * 1024];
  memset(buffer, 0, sizeof(buffer));
  uint64_t offset = 0;
  while (valid && offset < (uint64_t)identity->size) {
    size_t request = sizeof(buffer);
    if ((uint64_t)request > (uint64_t)identity->size - offset) {
      request = (size_t)((uint64_t)identity->size - offset);
    }
    ssize_t received = pread(descriptor, buffer, request, (off_t)offset);
    valid = received == (ssize_t)request &&
        CC_SHA256_Update(&context, buffer, (CC_LONG)request) == 1;
    if (valid) offset += request;
  }
  valid = valid && offset == (uint64_t)identity->size &&
      CC_SHA256_Final(digest, &context) == 1 &&
      memcmp(digest, expectedDigest, sizeof(digest)) == 0;
  memset(buffer, 0, sizeof(buffer));
  memset(&context, 0, sizeof(context));
#pragma clang diagnostic pop
  memset(digest, 0, sizeof(digest));
  return valid;
}

static NSDictionary *_Nullable HRASigningInformation(SecCodeRef code) {
  CFDictionaryRef raw = NULL;
  if (code == NULL || SecCodeCopySigningInformation(
          code, kSecCSSigningInformation, &raw) != errSecSuccess || raw == NULL) {
    return nil;
  }
  return CFBridgingRelease(raw);
}

static NSData *_Nullable HRACDHash(NSDictionary *information) {
  id value = information[(__bridge NSString *)kSecCodeInfoUnique];
  return [value isKindOfClass:[NSData class]] &&
          [value length] == HRA_MACOS_CDHASH_LENGTH
      ? value
      : nil;
}

static bool HRAGatewaySignaturePostureIsExact(NSDictionary *information) {
  id identifier = information[(__bridge NSString *)kSecCodeInfoIdentifier];
  id team = information[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
  id flags = information[(__bridge NSString *)kSecCodeInfoFlags];
  id certificates = information[(__bridge NSString *)kSecCodeInfoCertificates];
  id entitlements =
      information[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
  if (![identifier isEqual:HRAGatewayIdentifier] || team != nil ||
      ![flags isKindOfClass:[NSNumber class]] ||
      [(NSNumber *)flags unsignedIntValue] !=
          (kSecCodeSignatureAdhoc | kSecCodeSignatureRuntime) ||
      (certificates != nil &&
       (![certificates isKindOfClass:[NSArray class]] ||
        [(NSArray *)certificates count] != 0)) ||
      ![entitlements isKindOfClass:[NSDictionary class]]) {
    return false;
  }
  NSDictionary *dictionary = entitlements;
  return dictionary.count == 1 &&
      [dictionary[HRAGatewayJITEntitlement] isEqual:@YES] &&
      HRACDHash(information) != nil;
}

static bool HRACodePathIsExact(SecCodeRef code, NSString *expected) {
  CFURLRef raw = NULL;
  if (SecCodeCopyPath(code, kSecCSDefaultFlags, &raw) != errSecSuccess ||
      raw == NULL) return false;
  NSURL *url = CFBridgingRelease(raw);
  return [url.path isEqualToString:expected];
}

static bool HRAMainExecutablePathIsExact(
    NSDictionary *information,
    NSString *expected) {
  if (information == nil || expected == nil) return false;
  id raw = information[(__bridge NSString *)kSecCodeInfoMainExecutable];
  return raw != nil &&
      CFGetTypeID((__bridge CFTypeRef)raw) == CFURLGetTypeID() &&
      [[(NSURL *)raw path] isEqualToString:expected];
}

static bool HRAReleaseCertificateMatches(
    SecCertificateRef certificate,
    const uint8_t expectedSHA1[CC_SHA1_DIGEST_LENGTH],
    const uint8_t expectedSHA256[CC_SHA256_DIGEST_LENGTH]) {
  if (certificate == NULL) return false;
  CFDataRef raw = SecCertificateCopyData(certificate);
  if (raw == NULL) return false;
  const uint8_t *bytes = CFDataGetBytePtr(raw);
  CFIndex length = CFDataGetLength(raw);
  uint8_t sha1[CC_SHA1_DIGEST_LENGTH];
  uint8_t sha256[CC_SHA256_DIGEST_LENGTH];
  memset(sha1, 0, sizeof(sha1));
  memset(sha256, 0, sizeof(sha256));
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  bool exact = bytes != NULL && length > 0 && (uint64_t)length <= UINT32_MAX &&
      CC_SHA1(bytes, (CC_LONG)length, sha1) != NULL &&
      CC_SHA256(bytes, (CC_LONG)length, sha256) != NULL &&
      memcmp(sha1, expectedSHA1, sizeof(sha1)) == 0 &&
      memcmp(sha256, expectedSHA256, sizeof(sha256)) == 0;
#pragma clang diagnostic pop
  memset(sha1, 0, sizeof(sha1));
  memset(sha256, 0, sizeof(sha256));
  CFRelease(raw);
  return exact;
}

static bool HRAReleaseCertificateArrayIsExact(NSArray *certificates) {
  if (certificates == nil || certificates.count != 2) return false;
  id leaf = certificates[0];
  id root = certificates[1];
  return CFGetTypeID((__bridge CFTypeRef)leaf) == SecCertificateGetTypeID() &&
      CFGetTypeID((__bridge CFTypeRef)root) == SecCertificateGetTypeID() &&
      HRAReleaseCertificateMatches(
          (__bridge SecCertificateRef)leaf,
          HRAReleaseLeafCertificateSHA1,
          HRAReleaseLeafCertificateSHA256) &&
      HRAReleaseCertificateMatches(
          (__bridge SecCertificateRef)root,
          HRAReleaseRootCertificateSHA1,
          HRAReleaseRootCertificateSHA256);
}

static bool HRAReleaseEmbeddedCertificateSetIsExact(NSArray *certificates) {
  if (certificates == nil || certificates.count != 2) return false;
  bool foundLeaf = false;
  bool foundRoot = false;
  for (id value in certificates) {
    if (CFGetTypeID((__bridge CFTypeRef)value) !=
        SecCertificateGetTypeID()) return false;
    SecCertificateRef certificate = (__bridge SecCertificateRef)value;
    bool leaf = HRAReleaseCertificateMatches(
        certificate,
        HRAReleaseLeafCertificateSHA1,
        HRAReleaseLeafCertificateSHA256);
    bool root = HRAReleaseCertificateMatches(
        certificate,
        HRAReleaseRootCertificateSHA1,
        HRAReleaseRootCertificateSHA256);
    if (!hra_macos_release_record_certificate_role(
            leaf, root, &foundLeaf, &foundRoot)) return false;
  }
  return foundLeaf && foundRoot;
}

static bool HRAEmbeddedReleaseCertificateChainIsExact(NSData *cms) {
  if (cms == nil || cms.length == 0) return false;
  CMSDecoderRef decoder = NULL;
  SecCertificateRef signer = NULL;
  CFArrayRef rawCertificates = NULL;
  size_t signerCount = 0;
  bool exact = CMSDecoderCreate(&decoder) == errSecSuccess && decoder != NULL &&
      CMSDecoderUpdateMessage(decoder, cms.bytes, cms.length) ==
          errSecSuccess &&
      CMSDecoderFinalizeMessage(decoder) == errSecSuccess &&
      CMSDecoderGetNumSigners(decoder, &signerCount) == errSecSuccess &&
      signerCount == 1 &&
      CMSDecoderCopySignerCert(decoder, 0, &signer) == errSecSuccess &&
      signer != NULL &&
      HRAReleaseCertificateMatches(
          signer,
          HRAReleaseLeafCertificateSHA1,
          HRAReleaseLeafCertificateSHA256) &&
      CMSDecoderCopyAllCerts(decoder, &rawCertificates) == errSecSuccess &&
      rawCertificates != NULL &&
      HRAReleaseEmbeddedCertificateSetIsExact(
          (__bridge NSArray *)rawCertificates);
  if (rawCertificates != NULL) CFRelease(rawCertificates);
  if (signer != NULL) CFRelease(signer);
  if (decoder != NULL) CFRelease(decoder);
  return exact;
}

static bool HRAReleaseCertificateChainIsExact(
    NSDictionary *information,
    bool allowEmbeddedChainAfterPinnedTrustFailure) {
  id raw = information[(__bridge NSString *)kSecCodeInfoCertificates];
  bool securityCertificateChainIsExact =
      [raw isKindOfClass:[NSArray class]] &&
      HRAReleaseCertificateArrayIsExact(raw);
  id cms = information[(__bridge NSString *)kSecCodeInfoCMS];
  return securityCertificateChainIsExact ||
      (hra_macos_release_should_validate_embedded_certificate_set(
           securityCertificateChainIsExact,
           allowEmbeddedChainAfterPinnedTrustFailure) &&
       [cms isKindOfClass:[NSData class]] &&
       HRAEmbeddedReleaseCertificateChainIsExact(cms));
}

static NSString *HRAReleaseDesignatedRequirement(NSString *identifier) {
  return [NSString stringWithFormat:
      @"identifier \"%@\" and certificate root = H\"%s\" and "
       "certificate leaf = H\"%s\"",
      identifier,
      HRAReleaseRootCertificateSHA1Hex,
      HRAReleaseLeafCertificateSHA1Hex];
}

static SecRequirementRef _Nullable HRACopyReleaseRequirement(
    NSString *identifier) {
  SecRequirementRef requirement = NULL;
  NSString *text = HRAReleaseDesignatedRequirement(identifier);
  return SecRequirementCreateWithString(
             (__bridge CFStringRef)text,
             kSecCSDefaultFlags,
             &requirement) == errSecSuccess
      ? requirement
      : NULL;
}

static bool HRAReleaseDesignatedRequirementIsExact(
    SecCodeRef code,
    NSString *identifier) {
  if (code == NULL) return false;
  SecRequirementRef expected = HRACopyReleaseRequirement(identifier);
  SecRequirementRef actual = NULL;
  CFDataRef expectedData = NULL;
  CFDataRef actualData = NULL;
  bool exact = expected != NULL &&
      SecCodeCopyDesignatedRequirement(
          code, kSecCSDefaultFlags, &actual) == errSecSuccess &&
      actual != NULL &&
      SecRequirementCopyData(
          expected, kSecCSDefaultFlags, &expectedData) == errSecSuccess &&
      expectedData != NULL &&
      SecRequirementCopyData(
          actual, kSecCSDefaultFlags, &actualData) == errSecSuccess &&
      actualData != NULL && CFEqual(expectedData, actualData);
  if (actualData != NULL) CFRelease(actualData);
  if (expectedData != NULL) CFRelease(expectedData);
  if (actual != NULL) CFRelease(actual);
  if (expected != NULL) CFRelease(expected);
  return exact;
}

static bool HRAReleaseSignaturePostureIsExact(
    NSDictionary *information,
    NSString *identifier,
    bool allowEmbeddedChainAfterPinnedTrustFailure) {
  id team = information[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
  id flags = information[(__bridge NSString *)kSecCodeInfoFlags];
  id entitlements =
      information[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
  return [information[(__bridge NSString *)kSecCodeInfoIdentifier]
              isEqualToString:identifier] &&
      team == nil && [flags isKindOfClass:[NSNumber class]] &&
      [(NSNumber *)flags unsignedIntValue] == kSecCodeSignatureRuntime &&
      (entitlements == nil ||
       ([entitlements isKindOfClass:[NSDictionary class]] &&
        [(NSDictionary *)entitlements count] == 0)) &&
      HRAReleaseCertificateChainIsExact(
          information, allowEmbeddedChainAfterPinnedTrustFailure) &&
      HRACDHash(information) != nil;
}

static void HRAFillReleasePins(
    HRAMacOSSelfManagedCodeExpectation *expectation) {
  memcpy(expectation->leaf_certificate_sha1,
         HRAReleaseLeafCertificateSHA1,
         HRA_MACOS_SHA1_LENGTH);
  memcpy(expectation->leaf_certificate_sha256,
         HRAReleaseLeafCertificateSHA256,
         HRA_MACOS_SHA256_LENGTH);
  memcpy(expectation->root_certificate_sha1,
         HRAReleaseRootCertificateSHA1,
         HRA_MACOS_SHA1_LENGTH);
  memcpy(expectation->root_certificate_sha256,
         HRAReleaseRootCertificateSHA256,
         HRA_MACOS_SHA256_LENGTH);
}

static bool HRAExternalSlotIsExact(
    NSString *path,
    uint32_t slot,
    HRAMacOSExternalCodeSpecialSlot *outSlot) {
  if (path == nil || outSlot == NULL || !HRAPathIsCanonical(path)) return false;
  struct stat metadata;
  memset(&metadata, 0, sizeof(metadata));
  const char *bytes = path.fileSystemRepresentation;
  if (bytes == NULL || lstat(bytes, &metadata) != 0 ||
      !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1 ||
      metadata.st_uid != geteuid() || (metadata.st_mode & 07777) != 0644) {
    return false;
  }
  *outSlot = (HRAMacOSExternalCodeSpecialSlot){
    .slot = slot,
    .canonical_path = bytes,
    .canonical_path_length = strlen(bytes),
    .expected_uid = (uint32_t)metadata.st_uid,
    .expected_permissions = (uint32_t)metadata.st_mode & 07777u,
  };
  return true;
}

static bool HRAReleaseExecutableIdentityIsExact(
    NSString *path,
    NSString *identifier,
    bool bindOuterSlots,
    uint8_t outCDHash[HRA_MACOS_CDHASH_LENGTH]) {
  if (path == nil || identifier == nil || outCDHash == NULL ||
      !HRAPathIsCanonical(path)) return false;
  memset(outCDHash, 0, HRA_MACOS_CDHASH_LENGTH);
  const char *canonicalPath = path.fileSystemRepresentation;
  const char *identifierBytes = identifier.UTF8String;
  struct stat metadata;
  memset(&metadata, 0, sizeof(metadata));
  if (canonicalPath == NULL || identifierBytes == NULL ||
      lstat(canonicalPath, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_nlink != 1 || metadata.st_uid != geteuid() ||
      (metadata.st_mode & 07777) != 0755) return false;

  HRAMacOSExternalCodeSpecialSlot externalSlots[2];
  memset(externalSlots, 0, sizeof(externalSlots));
  HRAMacOSCodeResourcesFileExpectation resource;
  memset(&resource, 0, sizeof(resource));
  NSString *infoPath = nil;
  NSString *resourcesPath = nil;
  NSString *securityPath = path;
  if (bindOuterSlots) {
    static NSString *const suffix = @"/Contents/MacOS/hra";
    if (![identifier isEqualToString:@"kitchen.hraness"] ||
        ![path hasSuffix:suffix] || path.length <= suffix.length) return false;
    NSString *outer = [path substringToIndex:path.length - suffix.length];
    // Security.framework models a signed bundle's main executable as the
    // enclosing bundle code object. The independent descriptor proof below
    // remains pinned to Contents/MacOS/hra; Security's path proof must bind
    // the corresponding exact outer object instead.
    securityPath = outer;
    infoPath = [outer stringByAppendingString:@"/Contents/Info.plist"];
    resourcesPath = [outer stringByAppendingString:
        @"/Contents/_CodeSignature/CodeResources"];
    if (!HRAExternalSlotIsExact(infoPath, 1, &externalSlots[0]) ||
        !HRAExternalSlotIsExact(resourcesPath, 3, &externalSlots[1])) {
      return false;
    }
    static const char resourcePath[] =
        "Resources/runtime/bin/oprte-gateway";
    resource.relative_path = resourcePath;
    resource.relative_path_length = sizeof(resourcePath) - 1;
    memcpy(resource.sha256,
           HRAExpectedGatewayFileSHA256,
           sizeof(resource.sha256));
  }

  HRAMacOSSelfManagedCodeExpectation expectation;
  memset(&expectation, 0, sizeof(expectation));
  expectation.canonical_path = canonicalPath;
  expectation.canonical_path_length = strlen(canonicalPath);
  expectation.identifier = identifierBytes;
  expectation.identifier_length = strlen(identifierBytes);
  expectation.expected_uid = (uint32_t)metadata.st_uid;
  expectation.expected_permissions = (uint32_t)metadata.st_mode & 07777u;
  expectation.expected_code_directory_flags = HRA_MACOS_CODE_DIRECTORY_RUNTIME;
  expectation.expected_hash_type = HRA_MACOS_CODE_DIRECTORY_HASH_SHA256;
  expectation.expected_page_size_shift = 14;
  expectation.external_special_slots = bindOuterSlots ? externalSlots : NULL;
  expectation.external_special_slot_count = bindOuterSlots ? 2 : 0;
  expectation.code_resources_files = bindOuterSlots ? &resource : NULL;
  expectation.code_resources_file_count = bindOuterSlots ? 1 : 0;
  HRAFillReleasePins(&expectation);

  HRAMacOSSelfManagedCodeIdentity identity;
  memset(&identity, 0, sizeof(identity));
  bool pinnedSelfManagedIdentityIsExact =
      hra_macos_verify_self_managed_code_identity(&expectation, &identity);
  if (!pinnedSelfManagedIdentityIsExact) return false;
  SecStaticCodeRef code = NULL;
  SecRequirementRef requirement = HRACopyReleaseRequirement(identifier);
  if (requirement == NULL || SecStaticCodeCreateWithPath(
          (__bridge CFURLRef)[NSURL fileURLWithPath:securityPath],
          kSecCSDefaultFlags,
          &code) != errSecSuccess || code == NULL) {
    if (requirement != NULL) CFRelease(requirement);
    memset(&identity, 0, sizeof(identity));
    return false;
  }
  OSStatus status = SecStaticCodeCheckValidity(
      code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement);
  bool validationStatusIsAdmissible =
      hra_macos_release_validation_status_is_admissible(
          pinnedSelfManagedIdentityIsExact, status);
  NSDictionary *information = validationStatusIsAdmissible
      ? HRASigningInformation((SecCodeRef)code)
      : nil;
  NSData *securityHash = information == nil ? nil : HRACDHash(information);
  bool exact = information != nil &&
      HRAReleaseSignaturePostureIsExact(
          information,
          identifier,
          status == CSSMERR_TP_NOT_TRUSTED) &&
      HRAReleaseDesignatedRequirementIsExact((SecCodeRef)code, identifier) &&
      HRACodePathIsExact((SecCodeRef)code, securityPath) &&
      HRAMainExecutablePathIsExact(information, path) &&
      securityHash.length == HRA_MACOS_CDHASH_LENGTH &&
      memcmp(securityHash.bytes,
             identity.cdhash,
             HRA_MACOS_CDHASH_LENGTH) == 0 &&
      hra_macos_reverify_self_managed_code_identity(&expectation, &identity);
  CFRelease(code);
  CFRelease(requirement);
  if (exact) memcpy(outCDHash, identity.cdhash, HRA_MACOS_CDHASH_LENGTH);
  memset(&identity, 0, sizeof(identity));
  return exact;
}

static bool HRAInspectStaticGateway(
    NSString *path,
    int descriptor,
    const HRAFileIdentity *fileIdentity,
    HRAMacOSSelfManagedCodeIdentity *outIdentity) {
  if (path == nil || descriptor < 0 || fileIdentity == NULL ||
      outIdentity == NULL) return false;
  memset(outIdentity, 0, sizeof(*outIdentity));
  const char *canonicalPath = path.fileSystemRepresentation;
  const char *identifier = HRAGatewayIdentifier.UTF8String;
  if (canonicalPath == NULL || identifier == NULL) return false;
  HRAMacOSSelfManagedCodeExpectation expectation;
  memset(&expectation, 0, sizeof(expectation));
  expectation.canonical_path = canonicalPath;
  expectation.canonical_path_length = strlen(canonicalPath);
  expectation.identifier = identifier;
  expectation.identifier_length = strlen(identifier);
  expectation.expected_uid = (uint32_t)fileIdentity->owner;
  expectation.expected_permissions = (uint32_t)fileIdentity->mode & 07777u;
  expectation.expected_code_directory_flags =
      HRA_MACOS_CODE_DIRECTORY_ADHOC | HRA_MACOS_CODE_DIRECTORY_RUNTIME;
  expectation.expected_hash_type = HRA_MACOS_CODE_DIRECTORY_HASH_SHA256;
  expectation.expected_page_size_shift = 14;
  HRAMacOSSelfManagedCodeIdentity descriptorIdentity;
  memset(&descriptorIdentity, 0, sizeof(descriptorIdentity));
  if (!hra_macos_verify_adhoc_code_identity_at_descriptor(
          &expectation, descriptor, &descriptorIdentity)) return false;
  SecStaticCodeRef code = NULL;
  if (SecStaticCodeCreateWithPath(
          (__bridge CFURLRef)[NSURL fileURLWithPath:path],
          kSecCSDefaultFlags,
          &code) != errSecSuccess || code == NULL) return false;
  OSStatus status = SecStaticCodeCheckValidity(
      code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, NULL);
  NSDictionary *information = status == errSecSuccess
      ? HRASigningInformation((SecCodeRef)code)
      : nil;
  bool valid = information != nil &&
      HRAGatewaySignaturePostureIsExact(information) &&
      HRACodePathIsExact((SecCodeRef)code, path) &&
      [HRACDHash(information) isEqualToData:[NSData
          dataWithBytes:descriptorIdentity.cdhash
                 length:HRA_MACOS_CDHASH_LENGTH]];
  CFRelease(code);
  if (valid) *outIdentity = descriptorIdentity;
  memset(&descriptorIdentity, 0, sizeof(descriptorIdentity));
  return valid;
}

static bool HRADynamicGatewayIsExact(
    NSString *path,
    pid_t processIdentifier,
    const uint8_t expectedCDHash[HRA_MACOS_CDHASH_LENGTH]) {
  NSDictionary *attributes = @{
    (__bridge NSString *)kSecGuestAttributePid: @(processIdentifier),
    (__bridge NSString *)kSecGuestAttributeHash: [NSData
        dataWithBytes:expectedCDHash length:HRA_MACOS_CDHASH_LENGTH],
  };
  SecCodeRef code = NULL;
  if (SecCodeCopyGuestWithAttributes(
          NULL,
          (__bridge CFDictionaryRef)attributes,
          kSecCSDefaultFlags,
          &code) != errSecSuccess || code == NULL) return false;
  OSStatus status = SecCodeCheckValidity(code, kSecCSStrictValidate, NULL);
  NSDictionary *information = status == errSecSuccess
      ? HRASigningInformation(code)
      : nil;
  bool valid = information != nil &&
      HRAGatewaySignaturePostureIsExact(information) &&
      [HRACDHash(information) isEqualToData:[NSData
          dataWithBytes:expectedCDHash length:HRA_MACOS_CDHASH_LENGTH]] &&
      HRACodePathIsExact(code, path);
  CFRelease(code);
  return valid;
}

static bool HRAReadProcessGeneration(
    pid_t processIdentifier,
    pid_t expectedParent,
    bool requireStopped,
    uint64_t *outSeconds,
    uint64_t *outMicroseconds) {
  struct proc_bsdinfo information;
  memset(&information, 0, sizeof(information));
  int bytes = proc_pidinfo(
      processIdentifier,
      PROC_PIDTBSDINFO,
      0,
      &information,
      (int)sizeof(information));
  if (bytes != (int)sizeof(information) ||
      information.pbi_pid != (uint32_t)processIdentifier ||
      information.pbi_ppid != (uint32_t)expectedParent ||
      (requireStopped && information.pbi_status != SSTOP)) {
    return false;
  }
  *outSeconds = information.pbi_start_tvsec;
  *outMicroseconds = information.pbi_start_tvusec;
  return true;
}

static bool HRAProcessPathIsExact(pid_t processIdentifier, NSString *path) {
  char actual[PROC_PIDPATHINFO_MAXSIZE];
  memset(actual, 0, sizeof(actual));
  int length = proc_pidpath(processIdentifier, actual, sizeof(actual));
  const char *expected = path.fileSystemRepresentation;
  return length > 0 && expected != NULL && strcmp(actual, expected) == 0;
}

static bool HRARendererAuthorityForGatewayIsExact(NSString *gatewayPath) {
  static NSString *const suffix =
      @"/Contents/Resources/runtime/bin/oprte-gateway";
  if (gatewayPath == nil || ![gatewayPath hasSuffix:suffix] ||
      gatewayPath.length <= suffix.length) return false;
  NSString *outerRoot = [gatewayPath
      substringToIndex:gatewayPath.length - suffix.length];
  if (![outerRoot.pathExtension isEqualToString:@"app"]) return false;
  NSString *rendererRoot = [outerRoot stringByAppendingString:
      @"/Contents/Resources/frontend/dist"];
  const char *path = rendererRoot.fileSystemRepresentation;
  return path != NULL && HRAPathIsCanonical(rendererRoot) &&
      hra_macos_renderer_authority_is_exact(path, strlen(path));
}

static bool HRAGatewayGenerationIsExact(
    NSString *path,
    pid_t processIdentifier,
    pid_t expectedParent,
    uint64_t expectedSeconds,
    uint64_t expectedMicroseconds,
    bool requireStopped) {
  if (processIdentifier <= 1 || expectedParent <= 1 ||
      !HRAPathIsCanonical(path) ||
      !HRARendererAuthorityForGatewayIsExact(path)) return false;
  struct stat pathBefore;
  memset(&pathBefore, 0, sizeof(pathBefore));
  if (lstat(path.fileSystemRepresentation, &pathBefore) != 0) return false;
  HRAFileIdentity identity;
  memset(&identity, 0, sizeof(identity));
  if (!HRAFileIdentityFromStat(&pathBefore, &identity) ||
      (identity.mode & 0111) == 0) return false;
  int descriptor = open(
      path.fileSystemRepresentation,
      O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) return false;
  bool valid = false;
  uint8_t authenticatedCDHash[HRA_MACOS_CDHASH_LENGTH];
  memset(authenticatedCDHash, 0, sizeof(authenticatedCDHash));
  do {
    struct stat opened;
    memset(&opened, 0, sizeof(opened));
    if (fstat(descriptor, &opened) != 0 ||
        !HRAFileIdentityMatches(&identity, &opened) ||
        !HRADescriptorNamesPath(descriptor, path) ||
        !HRAHashExactDescriptor(
            descriptor,
            &identity,
            HRAExpectedGatewayFileSHA256)) break;
    HRAMacOSSelfManagedCodeIdentity codeIdentity;
    memset(&codeIdentity, 0, sizeof(codeIdentity));
    if (!HRAInspectStaticGateway(
            path, descriptor, &identity, &codeIdentity)) break;
    uint64_t seconds = 0;
    uint64_t microseconds = 0;
    if (!HRAReadProcessGeneration(
            processIdentifier,
            expectedParent,
            requireStopped,
            &seconds,
            &microseconds) ||
        (expectedSeconds != 0 && seconds != expectedSeconds) ||
        (expectedMicroseconds != 0 && microseconds != expectedMicroseconds) ||
        !HRAProcessPathIsExact(processIdentifier, path) ||
        !HRADynamicGatewayIsExact(
            path, processIdentifier, codeIdentity.cdhash)) break;
    struct stat descriptorAfter;
    struct stat pathAfter;
    memset(&descriptorAfter, 0, sizeof(descriptorAfter));
    memset(&pathAfter, 0, sizeof(pathAfter));
    uint64_t secondsAfter = 0;
    uint64_t microsecondsAfter = 0;
    valid = fstat(descriptor, &descriptorAfter) == 0 &&
        lstat(path.fileSystemRepresentation, &pathAfter) == 0 &&
        HRAFileIdentityMatches(&identity, &descriptorAfter) &&
        HRAFileIdentityMatches(&identity, &pathAfter) &&
        HRADescriptorNamesPath(descriptor, path) &&
        HRAReadProcessGeneration(
            processIdentifier,
            expectedParent,
            requireStopped,
            &secondsAfter,
            &microsecondsAfter) &&
        secondsAfter == seconds && microsecondsAfter == microseconds &&
        HRAProcessPathIsExact(processIdentifier, path) &&
        HRADynamicGatewayIsExact(
            path, processIdentifier, codeIdentity.cdhash);
    if (valid) {
      const char *canonicalPath = path.fileSystemRepresentation;
      const char *identifier = HRAGatewayIdentifier.UTF8String;
      HRAMacOSSelfManagedCodeExpectation expectation;
      memset(&expectation, 0, sizeof(expectation));
      expectation.canonical_path = canonicalPath;
      expectation.canonical_path_length = canonicalPath == NULL
          ? 0
          : strlen(canonicalPath);
      expectation.identifier = identifier;
      expectation.identifier_length = identifier == NULL
          ? 0
          : strlen(identifier);
      expectation.expected_uid = (uint32_t)identity.owner;
      expectation.expected_permissions = (uint32_t)identity.mode & 07777u;
      expectation.expected_code_directory_flags =
          HRA_MACOS_CODE_DIRECTORY_ADHOC | HRA_MACOS_CODE_DIRECTORY_RUNTIME;
      expectation.expected_hash_type = HRA_MACOS_CODE_DIRECTORY_HASH_SHA256;
      expectation.expected_page_size_shift = 14;
      valid = hra_macos_reverify_adhoc_code_identity_at_descriptor(
          &expectation, descriptor, &codeIdentity);
    }
    if (valid) memcpy(
        authenticatedCDHash,
        codeIdentity.cdhash,
        sizeof(authenticatedCDHash));
    memset(&codeIdentity, 0, sizeof(codeIdentity));
  } while (false);
  if (valid) {
    os_unfair_lock_lock(&HRAGatewayGenerationLock);
    if (HRAAuthenticatedGatewayDescriptor >= 0)
      close(HRAAuthenticatedGatewayDescriptor);
    HRAAuthenticatedGatewayDescriptor = descriptor;
    descriptor = -1;
    HRAAuthenticatedGatewayFileIdentity = identity;
    memcpy(HRAAuthenticatedGatewayCDHash,
           authenticatedCDHash,
           sizeof(HRAAuthenticatedGatewayCDHash));
    HRAAuthenticatedGatewayPID = processIdentifier;
    HRAAuthenticatedGatewayParentPID = expectedParent;
    HRAAuthenticatedGatewayStartSeconds = expectedSeconds;
    HRAAuthenticatedGatewayStartMicroseconds = expectedMicroseconds;
    os_unfair_lock_unlock(&HRAGatewayGenerationLock);
  }
  if (descriptor >= 0) close(descriptor);
  memset(authenticatedCDHash, 0, sizeof(authenticatedCDHash));
  return valid;
}

static bool HRASpawnAttestedGateway(
    const char *path,
    size_t path_length,
    char *const environment[],
    HRAMacOSAttestedGateway *out_gateway,
    bool createProcessGroup) {
  @autoreleasepool {
    if (path == NULL || path_length == 0 || path_length > 4096 ||
        memchr(path, '\0', path_length) != NULL || environment == NULL ||
        out_gateway == NULL ||
        !hra_macos_child_process_policy_is_exact()) return false;
    memset(out_gateway, 0, sizeof(*out_gateway));
    out_gateway->process_identifier = -1;
    out_gateway->standard_input = -1;
    out_gateway->standard_output = -1;
    NSString *gatewayPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    const char *gatewayCString = gatewayPath.fileSystemRepresentation;
    if (!HRAPathIsCanonical(gatewayPath) || gatewayCString == NULL ||
        strlen(gatewayCString) != path_length ||
        memcmp(gatewayCString, path, path_length) != 0) return false;

    int inputPipe[2] = {-1, -1};
    int outputPipe[2] = {-1, -1};
    if (pipe(inputPipe) != 0 || pipe(outputPipe) != 0) {
      if (inputPipe[0] >= 0) close(inputPipe[0]);
      if (inputPipe[1] >= 0) close(inputPipe[1]);
      if (outputPipe[0] >= 0) close(outputPipe[0]);
      if (outputPipe[1] >= 0) close(outputPipe[1]);
      return false;
    }
    posix_spawnattr_t attributes = NULL;
    posix_spawn_file_actions_t actions = NULL;
    bool initializedAttributes = posix_spawnattr_init(&attributes) == 0;
    bool initializedActions = initializedAttributes &&
        posix_spawn_file_actions_init(&actions) == 0;
    sigset_t childSignalMask;
    sigset_t childSignalDefaults;
    bool signalSetsConfigured = sigemptyset(&childSignalMask) == 0 &&
        sigemptyset(&childSignalDefaults) == 0 &&
        sigaddset(&childSignalDefaults, SIGTERM) == 0 &&
        sigaddset(&childSignalDefaults, SIGINT) == 0 &&
        sigaddset(&childSignalDefaults, SIGHUP) == 0 &&
        sigaddset(&childSignalDefaults, SIGQUIT) == 0 &&
        sigaddset(&childSignalDefaults, SIGPIPE) == 0 &&
        sigaddset(&childSignalDefaults, SIGCHLD) == 0;
    short flags = POSIX_SPAWN_START_SUSPENDED |
        POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK |
        POSIX_SPAWN_SETSIGDEF |
        (createProcessGroup ? POSIX_SPAWN_SETPGROUP : 0);
    bool configured = initializedActions && signalSetsConfigured &&
        posix_spawnattr_setflags(&attributes, flags) == 0 &&
        posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0 &&
        posix_spawnattr_setsigdefault(
            &attributes, &childSignalDefaults) == 0 &&
        (!createProcessGroup ||
         posix_spawnattr_setpgroup(&attributes, 0) == 0) &&
        posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO) == 0 &&
        posix_spawn_file_actions_addopen(
            &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawn_file_actions_addclose(&actions, inputPipe[1]) == 0 &&
        posix_spawn_file_actions_addclose(&actions, outputPipe[0]) == 0;
    char *argv[] = {(char *)gatewayCString, NULL};
    pid_t processIdentifier = -1;
    int spawnStatus = configured
        ? posix_spawn(
            &processIdentifier,
            gatewayCString,
            &actions,
            &attributes,
            argv,
            environment)
        : EINVAL;
    if (initializedActions) posix_spawn_file_actions_destroy(&actions);
    if (initializedAttributes) posix_spawnattr_destroy(&attributes);
    close(inputPipe[0]);
    close(outputPipe[1]);
    if (spawnStatus != 0 || processIdentifier <= 1) {
      close(inputPipe[1]);
      close(outputPipe[0]);
      return false;
    }

    uint64_t seconds = 0;
    uint64_t microseconds = 0;
    pid_t expectedProcessGroup = createProcessGroup
        ? processIdentifier
        : getpgrp();
    bool valid = expectedProcessGroup > 1 &&
        getpgid(processIdentifier) == expectedProcessGroup &&
        HRAReadProcessGeneration(
        processIdentifier,
        getpid(),
        true,
        &seconds,
        &microseconds) &&
        HRAGatewayGenerationIsExact(
            gatewayPath,
            processIdentifier,
            getpid(),
            seconds,
            microseconds,
            true);
    if (valid) {
      os_unfair_lock_lock(&HRAGatewayGenerationLock);
      valid = HRAAttestedGatewayPID == -1;
      if (valid) {
        HRAAttestedGatewayPID = processIdentifier;
        HRAAttestedGatewayStartSeconds = seconds;
        HRAAttestedGatewayStartMicroseconds = microseconds;
      }
      os_unfair_lock_unlock(&HRAGatewayGenerationLock);
    }
    if (valid) valid = kill(processIdentifier, SIGCONT) == 0;
    if (!valid) {
      hra_macos_clear_attested_gateway_generation(
          processIdentifier, seconds, microseconds);
      (void)kill(processIdentifier, SIGKILL);
      int ignored = 0;
      while (waitpid(processIdentifier, &ignored, 0) < 0 && errno == EINTR) {}
      close(inputPipe[1]);
      close(outputPipe[0]);
      return false;
    }
    out_gateway->process_identifier = processIdentifier;
    out_gateway->standard_input = inputPipe[1];
    out_gateway->standard_output = outputPipe[0];
    out_gateway->start_seconds = seconds;
    out_gateway->start_microseconds = microseconds;
    return true;
  }
}

bool hra_macos_spawn_attested_gateway(
    const char *path,
    size_t path_length,
    char *const environment[],
    HRAMacOSAttestedGateway *out_gateway) {
  return HRASpawnAttestedGateway(
      path, path_length, environment, out_gateway, true);
}

bool hra_macos_spawn_attested_gateway_for_custody_probe(
    const char *path,
    size_t path_length,
    char *const environment[],
    HRAMacOSAttestedGateway *out_gateway) {
  // The dedicated native supervisor creates the probe host as a process-group
  // leader before this path is reachable. Refuse to create an unsupervised
  // topology even though the gateway's code identity would still be exact.
  if (getpgrp() != getpid()) return false;
  return HRASpawnAttestedGateway(
      path, path_length, environment, out_gateway, false);
}

bool hra_macos_gateway_generation_is_exact(
    const char *path,
    size_t path_length,
    pid_t process_identifier,
    pid_t expected_parent,
    uint64_t start_seconds,
    uint64_t start_microseconds) {
  @autoreleasepool {
    if (path == NULL || path_length == 0 || path_length > 4096 ||
        memchr(path, '\0', path_length) != NULL ||
        start_seconds == 0) return false;
    NSString *gatewayPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    return HRAGatewayGenerationIsExact(
        gatewayPath,
        process_identifier,
        expected_parent,
        start_seconds,
        start_microseconds,
        false);
  }
}

bool hra_macos_gateway_generation_remains_exact(
    const char *path,
    size_t path_length,
    pid_t process_identifier,
    pid_t expected_parent,
    uint64_t start_seconds,
    uint64_t start_microseconds) {
  @autoreleasepool {
    if (path == NULL || path_length == 0 || path_length > 4096 ||
        memchr(path, '\0', path_length) != NULL) return false;
    NSString *gatewayPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    const char *canonical = gatewayPath.fileSystemRepresentation;
    if (canonical == NULL || strlen(canonical) != path_length ||
        memcmp(canonical, path, path_length) != 0) return false;
    os_unfair_lock_lock(&HRAGatewayGenerationLock);
    bool exact = HRAAuthenticatedGatewayDescriptor >= 0 &&
        HRAAuthenticatedGatewayPID == process_identifier &&
        HRAAuthenticatedGatewayParentPID == expected_parent &&
        HRAAuthenticatedGatewayStartSeconds == start_seconds &&
        HRAAuthenticatedGatewayStartMicroseconds == start_microseconds;
    struct stat descriptorMetadata;
    struct stat pathMetadata;
    memset(&descriptorMetadata, 0, sizeof(descriptorMetadata));
    memset(&pathMetadata, 0, sizeof(pathMetadata));
    uint64_t seconds = 0;
    uint64_t microseconds = 0;
    exact = exact &&
        fstat(HRAAuthenticatedGatewayDescriptor, &descriptorMetadata) == 0 &&
        lstat(canonical, &pathMetadata) == 0 &&
        HRAFileIdentityMatches(
            &HRAAuthenticatedGatewayFileIdentity, &descriptorMetadata) &&
        HRAFileIdentityMatches(
            &HRAAuthenticatedGatewayFileIdentity, &pathMetadata) &&
        HRADescriptorNamesPath(
            HRAAuthenticatedGatewayDescriptor, gatewayPath) &&
        HRAReadProcessGeneration(
            process_identifier,
            expected_parent,
            false,
            &seconds,
            &microseconds) &&
        seconds == start_seconds && microseconds == start_microseconds &&
        HRAProcessPathIsExact(process_identifier, gatewayPath) &&
        HRADynamicGatewayIsExact(
            gatewayPath,
            process_identifier,
            HRAAuthenticatedGatewayCDHash);
    os_unfair_lock_unlock(&HRAGatewayGenerationLock);
    return exact;
  }
}

bool hra_macos_copy_attested_gateway_generation(
    const char *path,
    size_t path_length,
    pid_t *out_process_identifier,
    uint64_t *out_start_seconds,
    uint64_t *out_start_microseconds) {
  if (out_process_identifier == NULL || out_start_seconds == NULL ||
      out_start_microseconds == NULL) return false;
  os_unfair_lock_lock(&HRAGatewayGenerationLock);
  pid_t processIdentifier = HRAAttestedGatewayPID;
  uint64_t seconds = HRAAttestedGatewayStartSeconds;
  uint64_t microseconds = HRAAttestedGatewayStartMicroseconds;
  os_unfair_lock_unlock(&HRAGatewayGenerationLock);
  if (!hra_macos_gateway_generation_is_exact(
          path,
          path_length,
          processIdentifier,
          getpid(),
          seconds,
          microseconds)) return false;
  *out_process_identifier = processIdentifier;
  *out_start_seconds = seconds;
  *out_start_microseconds = microseconds;
  return true;
}

void hra_macos_clear_attested_gateway_generation(
    pid_t process_identifier,
    uint64_t start_seconds,
    uint64_t start_microseconds) {
  os_unfair_lock_lock(&HRAGatewayGenerationLock);
  if (HRAAttestedGatewayPID == process_identifier &&
      HRAAttestedGatewayStartSeconds == start_seconds &&
      HRAAttestedGatewayStartMicroseconds == start_microseconds) {
    HRAAttestedGatewayPID = -1;
    HRAAttestedGatewayStartSeconds = 0;
    HRAAttestedGatewayStartMicroseconds = 0;
  }
  if (HRAAuthenticatedGatewayPID == process_identifier &&
      HRAAuthenticatedGatewayStartSeconds == start_seconds &&
      HRAAuthenticatedGatewayStartMicroseconds == start_microseconds) {
    if (HRAAuthenticatedGatewayDescriptor >= 0)
      close(HRAAuthenticatedGatewayDescriptor);
    HRAAuthenticatedGatewayDescriptor = -1;
    memset(&HRAAuthenticatedGatewayFileIdentity,
           0,
           sizeof(HRAAuthenticatedGatewayFileIdentity));
    memset(HRAAuthenticatedGatewayCDHash,
           0,
           sizeof(HRAAuthenticatedGatewayCDHash));
    HRAAuthenticatedGatewayPID = -1;
    HRAAuthenticatedGatewayParentPID = -1;
    HRAAuthenticatedGatewayStartSeconds = 0;
    HRAAuthenticatedGatewayStartMicroseconds = 0;
  }
  os_unfair_lock_unlock(&HRAGatewayGenerationLock);
}

bool hra_macos_parent_payload_identity_is_exact(
    const char *path,
    size_t path_length,
    uint8_t out_cdhash[HRA_MACOS_CDHASH_LENGTH]) {
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
  @autoreleasepool {
    if (path == NULL || path_length == 0 || path_length >= PATH_MAX ||
        memchr(path, '\0', path_length) != NULL || out_cdhash == NULL)
      return false;
    NSString *parentPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    const char *canonicalPath = parentPath.fileSystemRepresentation;
    return canonicalPath != NULL && strlen(canonicalPath) == path_length &&
        memcmp(canonicalPath, path, path_length) == 0 &&
        HRAReleaseExecutableIdentityIsExact(
            parentPath, @"kitchen.hraness", true, out_cdhash);
  }
#else
  (void)path;
  (void)path_length;
  if (out_cdhash != NULL) memset(out_cdhash, 0, HRA_MACOS_CDHASH_LENGTH);
  return false;
#endif
}

bool hra_macos_release_helper_identity_is_exact(
    const char *path,
    size_t path_length,
    uint8_t out_cdhash[HRA_MACOS_CDHASH_LENGTH]) {
  @autoreleasepool {
    if (path == NULL || path_length == 0 || path_length >= PATH_MAX ||
        memchr(path, '\0', path_length) != NULL || out_cdhash == NULL)
      return false;
    NSString *helperPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    const char *canonicalPath = helperPath.fileSystemRepresentation;
    return canonicalPath != NULL && strlen(canonicalPath) == path_length &&
        memcmp(canonicalPath, path, path_length) == 0 &&
        HRAReleaseExecutableIdentityIsExact(
            helperPath,
            @"oprte-keychain-custodian",
            false,
            out_cdhash);
  }
}

bool hra_macos_release_outer_bundle_is_exact(
    const char *path,
    size_t path_length) {
  @autoreleasepool {
    if (path == NULL || path_length == 0 || path_length >= PATH_MAX ||
        memchr(path, '\0', path_length) != NULL) return false;
    NSString *outerPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    const char *canonical = outerPath.fileSystemRepresentation;
    if (canonical == NULL || strlen(canonical) != path_length ||
        memcmp(canonical, path, path_length) != 0 ||
        !HRAPathIsCanonical(outerPath) ||
        ![outerPath.pathExtension.lowercaseString isEqualToString:@"app"])
      return false;
    SecRequirementRef requirement = HRACopyReleaseRequirement(@"kitchen.hraness");
    SecStaticCodeRef code = NULL;
    if (requirement == NULL || SecStaticCodeCreateWithPath(
            (__bridge CFURLRef)[NSURL fileURLWithPath:outerPath],
            kSecCSDefaultFlags,
            &code) != errSecSuccess || code == NULL) {
      if (requirement != NULL) CFRelease(requirement);
      return false;
    }
    OSStatus status = SecStaticCodeCheckValidity(
        code,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures |
            kSecCSCheckNestedCode,
        requirement);
    NSDictionary *information = status == errSecSuccess
        ? HRASigningInformation((SecCodeRef)code)
        : nil;
    bool exact = information != nil &&
        HRAReleaseSignaturePostureIsExact(
            information, @"kitchen.hraness", false) &&
        HRAReleaseDesignatedRequirementIsExact(
            (SecCodeRef)code, @"kitchen.hraness") &&
        HRACodePathIsExact((SecCodeRef)code, outerPath);
    CFRelease(code);
    CFRelease(requirement);
    return exact;
  }
}
