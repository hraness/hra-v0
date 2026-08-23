#import "macos_renderer_authority.h"

#import <CommonCrypto/CommonDigest.h>
#import <dirent.h>
#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

enum {
  HRARendererDirectory = 1,
  HRARendererFile = 2,
  HRAMaximumRendererEntries = 4096,
};

static const uint8_t HRARendererAuthorityDomain[] =
    "hra-renderer-authority-v1\0";

typedef struct {
  int descriptor;
  struct stat metadata;
} HRAHeldRendererEntry;

static bool HRAConstantTimeEqual(
    const uint8_t *left,
    const uint8_t *right,
    size_t length) {
  if (left == NULL || right == NULL) return false;
  uint8_t difference = 0;
  for (size_t index = 0; index < length; index += 1)
    difference |= left[index] ^ right[index];
  return difference == 0;
}

static bool HRAStatMatches(
    const struct stat *left,
    const struct stat *right) {
  return left != NULL && right != NULL &&
      left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
      left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
      left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
      left->st_size == right->st_size && left->st_flags == right->st_flags &&
      left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
      left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
      left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
      left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec &&
      left->st_birthtimespec.tv_sec == right->st_birthtimespec.tv_sec &&
      left->st_birthtimespec.tv_nsec == right->st_birthtimespec.tv_nsec;
}

static bool HRARelativePathIsCanonical(const char *path, size_t length) {
  if (path == NULL || length == 0 || length >= PATH_MAX || path[0] == '/' ||
      memchr(path, '\0', length) != NULL || path[length] != '\0') return false;
  size_t component = 0;
  for (size_t index = 0; index <= length; index += 1) {
    if (index != length && path[index] != '/') continue;
    size_t componentLength = index - component;
    if (componentLength == 0 || componentLength > NAME_MAX ||
        (componentLength == 1 && path[component] == '.') ||
        (componentLength == 2 && path[component] == '.' &&
         path[component + 1] == '.')) return false;
    component = index + 1;
  }
  return true;
}

static bool HRAExpectedEntriesAreCanonical(void) {
  if (HRAExpectedRendererAuthorityEntryCount == 0 ||
      HRAExpectedRendererAuthorityEntryCount > HRAMaximumRendererEntries)
    return false;
  for (size_t index = 0;
       index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) {
    const HRAMacOSRendererAuthorityEntry *entry =
        &HRAExpectedRendererAuthorityEntries[index];
    if (!HRARelativePathIsCanonical(
            entry->relative_path, entry->relative_path_length) ||
        (entry->type != HRARendererDirectory &&
         entry->type != HRARendererFile) ||
        entry->permissions !=
            (entry->type == HRARendererDirectory ? 0755u : 0644u) ||
        (entry->type == HRARendererDirectory && entry->byte_length != 0) ||
        (index > 0 && strcmp(
            HRAExpectedRendererAuthorityEntries[index - 1].relative_path,
            entry->relative_path) >= 0)) return false;
  }
  return true;
}

static void HRAWriteBig32(uint8_t bytes[4], uint32_t value) {
  bytes[0] = (uint8_t)(value >> 24);
  bytes[1] = (uint8_t)(value >> 16);
  bytes[2] = (uint8_t)(value >> 8);
  bytes[3] = (uint8_t)value;
}

static void HRAWriteBig64(uint8_t bytes[8], uint64_t value) {
  for (size_t index = 0; index < 8; index += 1)
    bytes[index] = (uint8_t)(value >> (56 - index * 8));
}

static bool HRAExpectedAuthorityRootIsExact(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  CC_SHA256_CTX context;
  memset(&context, 0, sizeof(context));
  bool valid = HRAExpectedEntriesAreCanonical() &&
      CC_SHA256_Init(&context) == 1 &&
      CC_SHA256_Update(
          &context,
          HRARendererAuthorityDomain,
          (CC_LONG)(sizeof(HRARendererAuthorityDomain) - 1)) == 1;
  for (size_t index = 0;
       valid && index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) {
    const HRAMacOSRendererAuthorityEntry *entry =
        &HRAExpectedRendererAuthorityEntries[index];
    uint8_t kind = entry->type == HRARendererDirectory ? 'd' : 'f';
    uint8_t header[12];
    HRAWriteBig32(header, (uint32_t)entry->relative_path_length);
    HRAWriteBig64(header + 4, entry->byte_length);
    valid = CC_SHA256_Update(&context, &kind, 1) == 1 &&
        CC_SHA256_Update(&context, header, sizeof(header)) == 1 &&
        CC_SHA256_Update(
            &context,
            entry->relative_path,
            (CC_LONG)entry->relative_path_length) == 1 &&
        (entry->type == HRARendererDirectory ||
         CC_SHA256_Update(&context, entry->sha256, 32) == 1);
  }
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  memset(digest, 0, sizeof(digest));
  valid = valid && CC_SHA256_Final(digest, &context) == 1 &&
      HRAConstantTimeEqual(
          digest, HRAExpectedRendererAuthorityRootSHA256, sizeof(digest));
  memset(digest, 0, sizeof(digest));
  memset(&context, 0, sizeof(context));
#pragma clang diagnostic pop
  return valid;
}

static int HRAOpenRelativeNoFollow(
    int rootDescriptor,
    const HRAMacOSRendererAuthorityEntry *entry) {
  if (rootDescriptor < 0 || entry == NULL) return -1;
  int current = dup(rootDescriptor);
  if (current < 0) return -1;
  size_t cursor = 0;
  while (cursor < entry->relative_path_length) {
    size_t end = cursor;
    while (end < entry->relative_path_length &&
           entry->relative_path[end] != '/') end += 1;
    size_t length = end - cursor;
    char component[NAME_MAX + 1];
    memset(component, 0, sizeof(component));
    memcpy(component, entry->relative_path + cursor, length);
    bool last = end == entry->relative_path_length;
    int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
    if (!last || entry->type == HRARendererDirectory) flags |= O_DIRECTORY;
    int next = openat(current, component, flags);
    close(current);
    if (next < 0) return -1;
    current = next;
    cursor = end + 1;
  }
  return current;
}

static bool HRAHashFile(
    int descriptor,
    uint64_t length,
    const uint8_t expected[32]) {
  if (descriptor < 0 || length > INT64_MAX || expected == NULL) return false;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  CC_SHA256_CTX context;
  memset(&context, 0, sizeof(context));
  uint8_t buffer[64 * 1024];
  memset(buffer, 0, sizeof(buffer));
  bool valid = CC_SHA256_Init(&context) == 1;
  uint64_t offset = 0;
  while (valid && offset < length) {
    size_t request = length - offset < sizeof(buffer)
        ? (size_t)(length - offset)
        : sizeof(buffer);
    ssize_t received = pread(descriptor, buffer, request, (off_t)offset);
    if (received < 0 && errno == EINTR) continue;
    valid = received == (ssize_t)request &&
        CC_SHA256_Update(&context, buffer, (CC_LONG)request) == 1;
    if (valid) offset += request;
  }
  uint8_t extra = 0;
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  memset(digest, 0, sizeof(digest));
  valid = valid && pread(descriptor, &extra, 1, (off_t)length) == 0 &&
      CC_SHA256_Final(digest, &context) == 1 &&
      HRAConstantTimeEqual(digest, expected, sizeof(digest));
  memset(buffer, 0, sizeof(buffer));
  memset(digest, 0, sizeof(digest));
  memset(&context, 0, sizeof(context));
#pragma clang diagnostic pop
  return valid;
}

static ssize_t HRAExpectedIndex(const char *path, size_t length) {
  for (size_t index = 0;
       index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) {
    const HRAMacOSRendererAuthorityEntry *entry =
        &HRAExpectedRendererAuthorityEntries[index];
    if (entry->relative_path_length == length &&
        memcmp(entry->relative_path, path, length) == 0)
      return (ssize_t)index;
  }
  return -1;
}

static bool HRAEnumerateDirectory(
    int descriptor,
    const char *prefix,
    size_t prefixLength) {
  // dup(2) shares the directory offset with the held authority descriptor.
  // Every scan needs an independent open-file description so repeated
  // before/after enumeration cannot inherit EOF from an earlier pass.
  int independent = openat(
      descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (independent < 0) return false;
  DIR *directory = fdopendir(independent);
  if (directory == NULL) {
    close(independent);
    return false;
  }
  size_t actualCount = 0;
  bool valid = true;
  errno = 0;
  while (valid) {
    struct dirent *child = readdir(directory);
    if (child == NULL) {
      valid = errno == 0;
      break;
    }
    if (strcmp(child->d_name, ".") == 0 || strcmp(child->d_name, "..") == 0)
      continue;
    size_t nameLength = strlen(child->d_name);
    if (nameLength == 0 || nameLength > NAME_MAX ||
        prefixLength + (prefixLength == 0 ? 0 : 1) + nameLength >= PATH_MAX) {
      valid = false;
      break;
    }
    char relativePath[PATH_MAX];
    memset(relativePath, 0, sizeof(relativePath));
    if (prefixLength > 0) {
      memcpy(relativePath, prefix, prefixLength);
      relativePath[prefixLength] = '/';
    }
    size_t offset = prefixLength + (prefixLength == 0 ? 0 : 1);
    memcpy(relativePath + offset, child->d_name, nameLength);
    if (HRAExpectedIndex(relativePath, offset + nameLength) < 0) valid = false;
    actualCount += 1;
  }
  closedir(directory);
  if (!valid) return false;
  size_t expectedCount = 0;
  for (size_t index = 0;
       index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) {
    const char *path = HRAExpectedRendererAuthorityEntries[index].relative_path;
    size_t length = HRAExpectedRendererAuthorityEntries[index].relative_path_length;
    const char *slash = NULL;
    for (size_t cursor = length; cursor > 0; cursor -= 1) {
      if (path[cursor - 1] == '/') {
        slash = path + cursor - 1;
        break;
      }
    }
    size_t parentLength = slash == NULL ? 0 : (size_t)(slash - path);
    if (parentLength == prefixLength &&
        (prefixLength == 0 || memcmp(path, prefix, prefixLength) == 0))
      expectedCount += 1;
  }
  return actualCount == expectedCount;
}

bool hra_macos_renderer_authority_is_exact(
    const char *root_path,
    size_t root_path_length) {
  if (root_path == NULL || root_path_length == 0 ||
      root_path_length >= PATH_MAX || root_path[0] != '/' ||
      memchr(root_path, '\0', root_path_length) != NULL ||
      root_path[root_path_length] != '\0' ||
      !HRAExpectedAuthorityRootIsExact()) return false;
  char resolved[PATH_MAX];
  memset(resolved, 0, sizeof(resolved));
  if (realpath(root_path, resolved) == NULL || strcmp(root_path, resolved) != 0)
    return false;
  struct stat rootBefore;
  memset(&rootBefore, 0, sizeof(rootBefore));
  if (lstat(root_path, &rootBefore) != 0 ||
      !S_ISDIR(rootBefore.st_mode) || rootBefore.st_uid != geteuid() ||
      (rootBefore.st_mode & 07777u) != 0755u) return false;
  int rootDescriptor = open(
      root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (rootDescriptor < 0) return false;
  HRAHeldRendererEntry *held = calloc(
      HRAExpectedRendererAuthorityEntryCount, sizeof(*held));
  if (held == NULL) {
    close(rootDescriptor);
    return false;
  }
  for (size_t index = 0;
       index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) held[index].descriptor = -1;
  bool valid = HRAEnumerateDirectory(rootDescriptor, "", 0);
  uint64_t totalBytes = 0;
  for (size_t index = 0;
       valid && index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) {
    const HRAMacOSRendererAuthorityEntry *expected =
        &HRAExpectedRendererAuthorityEntries[index];
    HRAHeldRendererEntry *actual = &held[index];
    actual->descriptor = HRAOpenRelativeNoFollow(rootDescriptor, expected);
    valid = actual->descriptor >= 0 &&
        fstat(actual->descriptor, &actual->metadata) == 0 &&
        actual->metadata.st_uid == geteuid() &&
        ((uint32_t)actual->metadata.st_mode & 07777u) == expected->permissions;
    if (!valid) break;
    if (expected->type == HRARendererDirectory) {
      valid = S_ISDIR(actual->metadata.st_mode) &&
          HRAEnumerateDirectory(
              actual->descriptor,
              expected->relative_path,
              expected->relative_path_length);
    } else {
      valid = S_ISREG(actual->metadata.st_mode) &&
          actual->metadata.st_nlink == 1 && actual->metadata.st_size >= 0 &&
          (uint64_t)actual->metadata.st_size == expected->byte_length &&
          totalBytes <= UINT64_C(128) * 1024 * 1024 - expected->byte_length &&
          HRAHashFile(
              actual->descriptor, expected->byte_length, expected->sha256);
      totalBytes += valid ? expected->byte_length : 0;
    }
  }
  for (size_t index = 0;
       valid && index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) {
    const HRAMacOSRendererAuthorityEntry *expected =
        &HRAExpectedRendererAuthorityEntries[index];
    HRAHeldRendererEntry *actual = &held[index];
    struct stat after;
    memset(&after, 0, sizeof(after));
    char descriptorPath[PATH_MAX];
    char expectedPath[PATH_MAX];
    memset(descriptorPath, 0, sizeof(descriptorPath));
    memset(expectedPath, 0, sizeof(expectedPath));
    size_t expectedLength = root_path_length + 1 + expected->relative_path_length;
    valid = expectedLength < PATH_MAX &&
        fstat(actual->descriptor, &after) == 0 &&
        HRAStatMatches(&actual->metadata, &after) &&
        fcntl(actual->descriptor, F_GETPATH, descriptorPath) == 0;
    if (valid) {
      memcpy(expectedPath, root_path, root_path_length);
      expectedPath[root_path_length] = '/';
      memcpy(expectedPath + root_path_length + 1,
             expected->relative_path,
             expected->relative_path_length);
      valid = strcmp(descriptorPath, expectedPath) == 0;
    }
  }
  struct stat rootDescriptorAfter;
  struct stat rootPathAfter;
  memset(&rootDescriptorAfter, 0, sizeof(rootDescriptorAfter));
  memset(&rootPathAfter, 0, sizeof(rootPathAfter));
  valid = valid && fstat(rootDescriptor, &rootDescriptorAfter) == 0 &&
      lstat(root_path, &rootPathAfter) == 0 &&
      HRAStatMatches(&rootBefore, &rootDescriptorAfter) &&
      HRAStatMatches(&rootBefore, &rootPathAfter) &&
      HRAEnumerateDirectory(rootDescriptor, "", 0);
  for (size_t index = 0;
       index < HRAExpectedRendererAuthorityEntryCount;
       index += 1) {
    if (held[index].descriptor >= 0) close(held[index].descriptor);
  }
  memset(held, 0,
         HRAExpectedRendererAuthorityEntryCount * sizeof(*held));
  free(held);
  close(rootDescriptor);
  return valid;
}

bool native_sdk_appkit_asset_bytes_are_authorized(
    const char *root_path,
    size_t root_path_length,
    const char *relative_path,
    size_t relative_path_length,
    const uint8_t *bytes,
    size_t byte_length) {
  if (!HRARelativePathIsCanonical(relative_path, relative_path_length) ||
      bytes == NULL ||
      !hra_macos_renderer_authority_is_exact(root_path, root_path_length))
    return false;
  ssize_t index = HRAExpectedIndex(relative_path, relative_path_length);
  if (index < 0) return false;
  const HRAMacOSRendererAuthorityEntry *entry =
      &HRAExpectedRendererAuthorityEntries[(size_t)index];
  if (entry->type != HRARendererFile || entry->byte_length != byte_length ||
      byte_length > UINT32_MAX) return false;
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  memset(digest, 0, sizeof(digest));
  bool valid = CC_SHA256(bytes, (CC_LONG)byte_length, digest) != NULL &&
      HRAConstantTimeEqual(digest, entry->sha256, sizeof(digest));
  memset(digest, 0, sizeof(digest));
  return valid;
}
