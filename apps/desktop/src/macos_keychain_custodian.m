#import "macos_keychain_custodian.h"
#import "macos_gateway_attestation.h"
#import "macos_keychain_access_control.h"
#import "macos_custody_probe_parent_gate.h"
#import "macos_renderer_authority.h"
#import "macos_self_managed_code_identity.h"

#import <bsm/libbsm.h>
#import <CommonCrypto/CommonDigest.h>
#import <crt_externs.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <libproc.h>
#import <mach/mach.h>
#import <mach/task_info.h>
#import <os/lock.h>
#import <poll.h>
#import <pwd.h>
#import <signal.h>
#import <spawn.h>
#import <stdatomic.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/proc.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <time.h>
#import <unistd.h>


static NSString *const HRAHarnessKeychainService =
    @"com.0thernet.oprte.context-heap.v2";
static NSString *const HRAHarnessKeychainAccount =
    @"installation-master";
static NSString *const HRAHarnessReconciliationAccount =
    @"legacy-reconciliation";
static NSString *const HRALegacyGatewayCDHashHex =
    @"9f39a6414ae834959ec63b39237a0ee426fd978a";
static NSString *const HRAKeychainCustodianIdentifier =
    @"oprte-keychain-custodian";
static NSString *const HRALegacyGatewayIdentifier =
    @"kitchen.hraness.gateway";
static NSString *const HRALegacyGatewayRequirement =
    @"identifier \"kitchen.hraness.gateway\" and certificate root = H\"3b08b5c6d4209824787da73fd5108d66954a16e9\" and certificate leaf = H\"8e70be5be2b1804a473f4ef1d337930bdbd17dc0\"";
static NSString *const HRALegacyGatewayRelativePath =
    @"runtime/legacy/preview-0.1.4-5/oprte-gateway";
static const off_t HRALegacyGatewayByteLength = 69161536;
static const uint8_t HRALegacyGatewaySHA256[] = {
  0x51, 0x8c, 0xca, 0x92, 0x54, 0x18, 0x0f, 0x23,
  0xb3, 0xe8, 0xf5, 0x24, 0xa4, 0x55, 0x11, 0x79,
  0xee, 0x1f, 0xd5, 0x6d, 0x43, 0x3a, 0xb0, 0xcb,
  0x93, 0xb3, 0x93, 0x76, 0x0b, 0x63, 0x80, 0xcf,
};
static const uint8_t HRALegacyGatewayCDHash[] = {
  0x9f, 0x39, 0xa6, 0x41, 0x4a, 0xe8, 0x34, 0x95, 0x9e, 0xc6,
  0x3b, 0x39, 0x23, 0x7a, 0x0e, 0xe4, 0x26, 0xfd, 0x97, 0x8a,
};
static const uint8_t HRAPreviewLeafCertificateSHA1[] = {
  0x8e, 0x70, 0xbe, 0x5b, 0xe2, 0xb1, 0x80, 0x4a, 0x47, 0x3f,
  0x4e, 0xf1, 0xd3, 0x37, 0x93, 0x0b, 0xdb, 0xd1, 0x7d, 0xc0,
};
static const uint8_t HRAPreviewLeafCertificateSHA256[] = {
  0x6e, 0xc2, 0xc6, 0x3a, 0x7d, 0x3b, 0xf2, 0x8e,
  0x54, 0xc9, 0xc3, 0x84, 0x86, 0xdc, 0x37, 0xb8,
  0xf7, 0xc9, 0x4a, 0xbf, 0xc6, 0xfb, 0xc0, 0x7e,
  0xd5, 0x17, 0x46, 0x79, 0x2a, 0x5a, 0xe7, 0x93,
};
static const uint8_t HRAPreviewRootCertificateSHA1[] = {
  0x3b, 0x08, 0xb5, 0xc6, 0xd4, 0x20, 0x98, 0x24, 0x78, 0x7d,
  0xa7, 0x3f, 0xd5, 0x10, 0x8d, 0x66, 0x95, 0x4a, 0x16, 0xe9,
};
static const uint8_t HRAPreviewRootCertificateSHA256[] = {
  0xfa, 0x59, 0x3d, 0x3d, 0x8c, 0x22, 0x43, 0x41,
  0x2f, 0x89, 0x64, 0xed, 0x7a, 0x24, 0xf4, 0x55,
  0xe3, 0xab, 0x87, 0xb7, 0xc5, 0x06, 0x86, 0x2c,
  0xe8, 0x1a, 0x59, 0xc1, 0x9c, 0xb5, 0xec, 0xb9,
};
static const char *HRALegacyHarnessReadScript =
    "const descriptor={service:'com.0thernet.oprte.context-heap.v1',"
    "name:'installation-master'};"
    "const value=await Bun.secrets.get(descriptor);"
    "await Bun.write(Bun.stdout,JSON.stringify(value===null?"
    "{version:1,state:'absent'}:{version:1,state:'present',value}));";
static const char *HRALegacyHarnessDeleteScript =
    "const descriptor={service:'com.0thernet.oprte.context-heap.v1',"
    "name:'installation-master'};"
    "const deleted=await Bun.secrets.delete(descriptor);"
    "const after=await Bun.secrets.get(descriptor);"
    "if(after!==null)process.exit(1);"
    "await Bun.write(Bun.stdout,JSON.stringify({version:1,deleted}));";
static const size_t HRACustodianMaximumRequestBytes = 512;
static const size_t HRACustodianMaximumResponseBytes = 512;
static const uint32_t HRACustodianReapTimeoutMilliseconds = 1000;
static const uint32_t HRALegacyGroupQuiescenceTimeoutMilliseconds = 1000;
// Once Native stops treating a PID/PGID as signalable, cancellation must never
// use that number again. An ambiguous retirement therefore poisons the custody
// lane until the Native host itself restarts.
static const int HRAProcessRetiring = -3;
static const int HRACustodianRetirementUnproven = -2;
static const int HRALegacyRetirementUnproven = -2;
static _Atomic(int) HRACurrentCustodianProcess = -1;
static _Atomic(int) HRACurrentLegacyGatewayProcess = -1;
static os_unfair_lock HRACustodianProcessLock = OS_UNFAIR_LOCK_INIT;
static os_unfair_lock HRALegacyGatewayProcessLock = OS_UNFAIR_LOCK_INIT;
static uint64_t HRACustodianGeneration = 0;
static uint64_t HRALegacyGatewayGeneration = 0;
static bool HRACustodianGenerationPrepared = false;
static bool HRALegacyGatewayGenerationPrepared = false;
static bool HRACustodianGenerationCancelled = true;
static bool HRALegacyGatewayGenerationCancelled = true;
static bool HRACustodianUntrackedRetirementUnproven = false;
static bool HRALegacyUntrackedRetirementUnproven = false;
static pid_t HRAAuthorizedParentProcess = -1;
static audit_token_t HRAAuthorizedParentAuditToken;
static bool HRAAuthorizedParentAuditTokenPresent = false;

typedef enum {
  HRAChildLeaseAmbiguous = 0,
  HRAChildLeaseRetained = 1,
  HRAChildLeaseLost = 2,
} HRAChildLeaseObservation;
static pid_t HRAAuthorizedGatewayProcess = -1;
static uint64_t HRAAuthorizedGatewayStartSeconds = 0;
static uint64_t HRAAuthorizedGatewayStartMicroseconds = 0;
static int HRAAuthorizedParentDescriptor = -1;
static struct stat HRAAuthorizedParentMetadata;
static int HRAAuthorizedHelperDescriptor = -1;
static struct stat HRAAuthorizedHelperMetadata;
static int HRAAuthorizedOuterDescriptor = -1;
static struct stat HRAAuthorizedOuterMetadata;
static int HRAAuthorizedInfoDescriptor = -1;
static struct stat HRAAuthorizedInfoMetadata;
static int HRAAuthorizedCodeResourcesDescriptor = -1;
static struct stat HRAAuthorizedCodeResourcesMetadata;
static int HRAAuthorizedRendererDescriptor = -1;
static struct stat HRAAuthorizedRendererMetadata;
static uint8_t HRAAuthorizedParentCDHash[HRA_MACOS_CDHASH_LENGTH];
static NSString *_Nullable HRAAuthorizedOuterPath = nil;
static NSString *_Nullable HRAAuthorizedHelperPath = nil;
static NSString *_Nullable HRAAuthorizedParentPath = nil;
static NSString *_Nullable HRAAuthorizedGatewayPath = nil;
static NSString *_Nullable HRAAuthorizedInfoPath = nil;
static NSString *_Nullable HRAAuthorizedCodeResourcesPath = nil;
static NSString *_Nullable HRAAuthorizedRendererPath = nil;
static int HRAAuthorizedLoginKeychainDescriptor = -1;
static struct stat HRAAuthorizedLoginKeychainMetadata;
static NSString *_Nullable HRAAuthorizedLoginKeychainPath = nil;
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
extern const char HRAExpectedGatewayFileSHA256Hex[65];
#endif
extern const uint8_t HRAReleaseLeafCertificateSHA1[20];
extern const uint8_t HRAReleaseLeafCertificateSHA256[32];
extern const uint8_t HRAReleaseRootCertificateSHA1[20];
extern const uint8_t HRAReleaseRootCertificateSHA256[32];


typedef NS_ENUM(NSUInteger, HRAKeychainReadState) {
  HRAKeychainReadFailure = 0,
  HRAKeychainReadAbsent = 1,
  HRAKeychainReadPresent = 2,
};

static void HRASecureZero(void *bytes, size_t length) {
  volatile uint8_t *cursor = (volatile uint8_t *)bytes;
  while (length > 0) {
    *cursor = 0;
    cursor += 1;
    length -= 1;
  }
  atomic_signal_fence(memory_order_seq_cst);
}

static bool HRAJSONIntegerIsExactlyOne(id _Nullable value) {
  if (value == nil ||
      CFGetTypeID((__bridge CFTypeRef)value) != CFNumberGetTypeID() ||
      CFNumberIsFloatType((__bridge CFNumberRef)value)) {
    return false;
  }
  int64_t integer = 0;
  return CFNumberGetValue(
             (__bridge CFNumberRef)value,
             kCFNumberSInt64Type,
             &integer) &&
      integer == 1;
}

static NSDictionary *_Nullable HRACopySigningInformationForCode(
    SecCodeRef code) {
  CFDictionaryRef information = NULL;
  if (SecCodeCopySigningInformation(
          code, kSecCSSigningInformation, &information) != errSecSuccess ||
      information == NULL) {
    return nil;
  }
  return CFBridgingRelease(information);
}

static NSArray<NSData *> *_Nullable HRACertificateChain(
    NSDictionary *information) {
  id raw = information[(__bridge NSString *)kSecCodeInfoCertificates];
  if (raw == nil) return @[];
  if (![raw isKindOfClass:[NSArray class]]) return nil;
  NSMutableArray<NSData *> *chain = [NSMutableArray array];
  for (id value in (NSArray *)raw) {
    if (CFGetTypeID((__bridge CFTypeRef)value) != SecCertificateGetTypeID()) {
      return nil;
    }
    CFDataRef data = SecCertificateCopyData((__bridge SecCertificateRef)value);
    if (data == NULL) return nil;
    [chain addObject:CFBridgingRelease(data)];
  }
  return chain;
}

static bool HRAOuterBundleIsSealed(void);

static bool HRAAuditTokenNamesExactParent(
    const audit_token_t *token,
    pid_t parentProcess) {
  return token != NULL && parentProcess > 1 && getppid() == parentProcess &&
      audit_token_to_pid(*token) == parentProcess &&
      audit_token_to_pidversion(*token) > 0;
}

static NSData *_Nullable HRAExactCodeDirectoryHash(
    NSDictionary *information) {
  id value = information[(__bridge NSString *)kSecCodeInfoUnique];
  return [value isKindOfClass:[NSData class]] &&
          [value length] == HRA_MACOS_CDHASH_LENGTH
      ? value
      : nil;
}

static bool HRAAdHocSignaturePostureIsExact(
    NSDictionary *information,
    NSString *identifier,
    bool emptyEntitlements) {
  id team = information[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
  id flags = information[(__bridge NSString *)kSecCodeInfoFlags];
  id certificates =
      information[(__bridge NSString *)kSecCodeInfoCertificates];
  id entitlements =
      information[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
  return [information[(__bridge NSString *)kSecCodeInfoIdentifier]
              isEqualToString:identifier] &&
      team == nil && [flags isKindOfClass:[NSNumber class]] &&
      [(NSNumber *)flags unsignedIntValue] ==
          (kSecCodeSignatureAdhoc | kSecCodeSignatureRuntime) &&
      (certificates == nil ||
       ([certificates isKindOfClass:[NSArray class]] &&
        [(NSArray *)certificates count] == 0)) &&
      [entitlements isKindOfClass:[NSDictionary class]] &&
      (!emptyEntitlements || [(NSDictionary *)entitlements count] == 0) &&
      HRAExactCodeDirectoryHash(information) != nil;
}

static NSString *_Nullable HRAProcessPath(pid_t processIdentifier) {
  char path[PROC_PIDPATHINFO_MAXSIZE];
  memset(path, 0, sizeof(path));
  int length = proc_pidpath(processIdentifier, path, sizeof(path));
  if (length <= 0 || (size_t)length >= sizeof(path) ||
      path[length] != '\0') return nil;
  return [[NSFileManager defaultManager]
      stringWithFileSystemRepresentation:path length:(NSUInteger)length];
}

static bool HRAReleaseBundlePathsAreExact(
    pid_t parentProcess,
    NSString **outOuterPath,
    NSString **outHelperPath,
    NSString **outParentPath,
    NSString **outGatewayPath) {
  NSString *helperPath = HRAProcessPath(getpid());
  NSString *parentPath = HRAProcessPath(parentProcess);
  static NSString *const helperSuffix =
      @"/Contents/Resources/runtime/bin/oprte-keychain-custodian";
  if (helperPath == nil || parentPath == nil ||
      ![helperPath hasSuffix:helperSuffix] ||
      helperPath.length <= helperSuffix.length) return false;
  NSString *outerPath = [helperPath
      substringToIndex:helperPath.length - helperSuffix.length];
  if (![outerPath.pathExtension.lowercaseString isEqualToString:@"app"])
    return false;
  NSString *expectedParent = [outerPath
      stringByAppendingString:@"/Contents/MacOS/hra"];
  NSString *gatewayPath = [outerPath stringByAppendingString:
      @"/Contents/Resources/runtime/bin/oprte-gateway"];
  char resolvedOuter[PATH_MAX];
  char resolvedHelper[PATH_MAX];
  char resolvedParent[PATH_MAX];
  char resolvedGateway[PATH_MAX];
  memset(resolvedOuter, 0, sizeof(resolvedOuter));
  memset(resolvedHelper, 0, sizeof(resolvedHelper));
  memset(resolvedParent, 0, sizeof(resolvedParent));
  memset(resolvedGateway, 0, sizeof(resolvedGateway));
  const char *outer = outerPath.fileSystemRepresentation;
  const char *helper = helperPath.fileSystemRepresentation;
  const char *parent = parentPath.fileSystemRepresentation;
  const char *expected = expectedParent.fileSystemRepresentation;
  const char *gateway = gatewayPath.fileSystemRepresentation;
  if (outer == NULL || helper == NULL || parent == NULL || expected == NULL ||
      gateway == NULL || strcmp(parent, expected) != 0 ||
      realpath(outer, resolvedOuter) == NULL || strcmp(outer, resolvedOuter) != 0 ||
      realpath(helper, resolvedHelper) == NULL || strcmp(helper, resolvedHelper) != 0 ||
      realpath(parent, resolvedParent) == NULL || strcmp(parent, resolvedParent) != 0 ||
      realpath(gateway, resolvedGateway) == NULL || strcmp(gateway, resolvedGateway) != 0)
    return false;
  *outParentPath = parentPath;
  *outGatewayPath = gatewayPath;
  *outOuterPath = outerPath;
  *outHelperPath = helperPath;
  return true;
}

static bool HRAReleaseCertificateDataMatches(
    NSData *certificate,
    const uint8_t expectedSHA1[CC_SHA1_DIGEST_LENGTH],
    const uint8_t expectedSHA256[CC_SHA256_DIGEST_LENGTH]) {
  if (![certificate isKindOfClass:[NSData class]] || certificate.length == 0 ||
      certificate.length > UINT32_MAX) return false;
  uint8_t sha1[CC_SHA1_DIGEST_LENGTH];
  uint8_t sha256[CC_SHA256_DIGEST_LENGTH];
  memset(sha1, 0, sizeof(sha1));
  memset(sha256, 0, sizeof(sha256));
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  bool exact = CC_SHA1(
          certificate.bytes, (CC_LONG)certificate.length, sha1) != NULL &&
      CC_SHA256(
          certificate.bytes, (CC_LONG)certificate.length, sha256) != NULL &&
      memcmp(sha1, expectedSHA1, sizeof(sha1)) == 0 &&
      memcmp(sha256, expectedSHA256, sizeof(sha256)) == 0;
#pragma clang diagnostic pop
  HRASecureZero(sha1, sizeof(sha1));
  HRASecureZero(sha256, sizeof(sha256));
  return exact;
}

static bool HRAReleaseCodeInformationIsExact(
    NSDictionary *information,
    NSString *identifier) {
  NSArray<NSData *> *certificates = HRACertificateChain(information);
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
      certificates.count == 2 &&
      HRAReleaseCertificateDataMatches(
          certificates[0],
          HRAReleaseLeafCertificateSHA1,
          HRAReleaseLeafCertificateSHA256) &&
      HRAReleaseCertificateDataMatches(
          certificates[1],
          HRAReleaseRootCertificateSHA1,
          HRAReleaseRootCertificateSHA256) &&
      HRAExactCodeDirectoryHash(information) != nil;
}

static bool HRAExactFileMetadataMatches(
    const struct stat *left,
    const struct stat *right) {
  return left != NULL && right != NULL &&
      left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
      left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
      left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
      left->st_size == right->st_size &&
      left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
      left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
      left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
      left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static bool HRAOpenStableAuthorityPath(
    NSString *path,
    bool directory,
    int *outDescriptor,
    struct stat *outMetadata) {
  if (path == nil || outDescriptor == NULL || outMetadata == NULL) return false;
  const char *canonical = path.fileSystemRepresentation;
  if (canonical == NULL) return false;
  struct stat pathBefore;
  struct stat opened;
  struct stat pathAfter;
  memset(&pathBefore, 0, sizeof(pathBefore));
  memset(&opened, 0, sizeof(opened));
  memset(&pathAfter, 0, sizeof(pathAfter));
  if (lstat(canonical, &pathBefore) != 0 ||
      (directory ? !S_ISDIR(pathBefore.st_mode)
                 : (!S_ISREG(pathBefore.st_mode) || pathBefore.st_nlink != 1))) {
    return false;
  }
  int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
  if (directory) flags |= O_DIRECTORY;
  int descriptor = open(canonical, flags);
  char descriptorPath[PATH_MAX];
  memset(descriptorPath, 0, sizeof(descriptorPath));
  if (descriptor < 0 || fstat(descriptor, &opened) != 0 ||
      lstat(canonical, &pathAfter) != 0 ||
      fcntl(descriptor, F_GETPATH, descriptorPath) != 0 ||
      strcmp(descriptorPath, canonical) != 0 ||
      !HRAExactFileMetadataMatches(&pathBefore, &opened) ||
      !HRAExactFileMetadataMatches(&pathBefore, &pathAfter)) {
    if (descriptor >= 0) close(descriptor);
    return false;
  }
  *outDescriptor = descriptor;
  *outMetadata = opened;
  return true;
}

static bool HRAHeldAuthorityPathRemainsExact(
    NSString *path,
    int descriptor,
    const struct stat *expectedMetadata) {
  if (path == nil || descriptor < 0 || expectedMetadata == NULL) return false;
  const char *canonical = path.fileSystemRepresentation;
  struct stat opened;
  struct stat named;
  char descriptorPath[PATH_MAX];
  memset(&opened, 0, sizeof(opened));
  memset(&named, 0, sizeof(named));
  memset(descriptorPath, 0, sizeof(descriptorPath));
  return canonical != NULL &&
      fstat(descriptor, &opened) == 0 && lstat(canonical, &named) == 0 &&
      fcntl(descriptor, F_GETPATH, descriptorPath) == 0 &&
      strcmp(descriptorPath, canonical) == 0 &&
      HRAExactFileMetadataMatches(expectedMetadata, &opened) &&
      HRAExactFileMetadataMatches(expectedMetadata, &named);
}

static bool HRAInstallAuthorizedParentCache(
    NSString *outerPath,
    NSString *helperPath,
    NSString *parentPath,
    NSString *gatewayPath,
    const uint8_t parentCDHash[HRA_MACOS_CDHASH_LENGTH]) {
  if (outerPath == nil || helperPath == nil || parentPath == nil ||
      gatewayPath == nil || parentCDHash == NULL) return false;
  NSString *infoPath = [outerPath
      stringByAppendingString:@"/Contents/Info.plist"];
  NSString *codeResourcesPath = [outerPath stringByAppendingString:
      @"/Contents/_CodeSignature/CodeResources"];
  NSString *rendererPath = [outerPath stringByAppendingString:
      @"/Contents/Resources/frontend/dist"];
  int parentDescriptor = -1;
  int helperDescriptor = -1;
  int outerDescriptor = -1;
  int infoDescriptor = -1;
  int codeResourcesDescriptor = -1;
  int rendererDescriptor = -1;
  struct stat parentMetadata;
  struct stat helperMetadata;
  struct stat outerMetadata;
  struct stat infoMetadata;
  struct stat codeResourcesMetadata;
  struct stat rendererMetadata;
  memset(&parentMetadata, 0, sizeof(parentMetadata));
  memset(&helperMetadata, 0, sizeof(helperMetadata));
  memset(&outerMetadata, 0, sizeof(outerMetadata));
  memset(&infoMetadata, 0, sizeof(infoMetadata));
  memset(&codeResourcesMetadata, 0, sizeof(codeResourcesMetadata));
  memset(&rendererMetadata, 0, sizeof(rendererMetadata));
  bool exact = HRAOpenStableAuthorityPath(
          parentPath, false, &parentDescriptor, &parentMetadata) &&
      HRAOpenStableAuthorityPath(
          helperPath, false, &helperDescriptor, &helperMetadata) &&
      HRAOpenStableAuthorityPath(
          outerPath, true, &outerDescriptor, &outerMetadata) &&
      HRAOpenStableAuthorityPath(
          infoPath, false, &infoDescriptor, &infoMetadata) &&
      HRAOpenStableAuthorityPath(
          codeResourcesPath,
          false,
          &codeResourcesDescriptor,
          &codeResourcesMetadata) &&
      HRAOpenStableAuthorityPath(
          rendererPath, true, &rendererDescriptor, &rendererMetadata);
  if (!exact) {
    if (parentDescriptor >= 0) close(parentDescriptor);
    if (helperDescriptor >= 0) close(helperDescriptor);
    if (outerDescriptor >= 0) close(outerDescriptor);
    if (infoDescriptor >= 0) close(infoDescriptor);
    if (codeResourcesDescriptor >= 0) close(codeResourcesDescriptor);
    if (rendererDescriptor >= 0) close(rendererDescriptor);
    return false;
  }
  if (HRAAuthorizedParentDescriptor >= 0) close(HRAAuthorizedParentDescriptor);
  if (HRAAuthorizedHelperDescriptor >= 0) close(HRAAuthorizedHelperDescriptor);
  if (HRAAuthorizedOuterDescriptor >= 0) close(HRAAuthorizedOuterDescriptor);
  if (HRAAuthorizedInfoDescriptor >= 0) close(HRAAuthorizedInfoDescriptor);
  if (HRAAuthorizedCodeResourcesDescriptor >= 0)
    close(HRAAuthorizedCodeResourcesDescriptor);
  if (HRAAuthorizedRendererDescriptor >= 0)
    close(HRAAuthorizedRendererDescriptor);
  HRAAuthorizedParentDescriptor = parentDescriptor;
  HRAAuthorizedHelperDescriptor = helperDescriptor;
  HRAAuthorizedOuterDescriptor = outerDescriptor;
  HRAAuthorizedInfoDescriptor = infoDescriptor;
  HRAAuthorizedCodeResourcesDescriptor = codeResourcesDescriptor;
  HRAAuthorizedRendererDescriptor = rendererDescriptor;
  HRAAuthorizedParentMetadata = parentMetadata;
  HRAAuthorizedHelperMetadata = helperMetadata;
  HRAAuthorizedOuterMetadata = outerMetadata;
  HRAAuthorizedInfoMetadata = infoMetadata;
  HRAAuthorizedCodeResourcesMetadata = codeResourcesMetadata;
  HRAAuthorizedRendererMetadata = rendererMetadata;
  memcpy(HRAAuthorizedParentCDHash,
         parentCDHash,
         sizeof(HRAAuthorizedParentCDHash));
  HRAAuthorizedOuterPath = [outerPath copy];
  HRAAuthorizedHelperPath = [helperPath copy];
  HRAAuthorizedParentPath = [parentPath copy];
  HRAAuthorizedGatewayPath = [gatewayPath copy];
  HRAAuthorizedInfoPath = [infoPath copy];
  HRAAuthorizedCodeResourcesPath = [codeResourcesPath copy];
  HRAAuthorizedRendererPath = [rendererPath copy];
  return true;
}

static bool HRAAuthorizedBundlePathsRemainStable(void) {
  return HRAHeldAuthorityPathRemainsExact(
          HRAAuthorizedParentPath,
          HRAAuthorizedParentDescriptor,
          &HRAAuthorizedParentMetadata) &&
      HRAHeldAuthorityPathRemainsExact(
          HRAAuthorizedHelperPath,
          HRAAuthorizedHelperDescriptor,
          &HRAAuthorizedHelperMetadata) &&
      HRAHeldAuthorityPathRemainsExact(
          HRAAuthorizedOuterPath,
          HRAAuthorizedOuterDescriptor,
          &HRAAuthorizedOuterMetadata) &&
      HRAHeldAuthorityPathRemainsExact(
          HRAAuthorizedInfoPath,
          HRAAuthorizedInfoDescriptor,
          &HRAAuthorizedInfoMetadata) &&
      HRAHeldAuthorityPathRemainsExact(
          HRAAuthorizedCodeResourcesPath,
          HRAAuthorizedCodeResourcesDescriptor,
          &HRAAuthorizedCodeResourcesMetadata) &&
      HRAHeldAuthorityPathRemainsExact(
          HRAAuthorizedRendererPath,
          HRAAuthorizedRendererDescriptor,
          &HRAAuthorizedRendererMetadata);
}

static bool HRAParentIdentityIsAuthorized(
    pid_t parentProcess,
    const audit_token_t *parentAuditToken,
    pid_t gatewayProcess,
    uint64_t gatewayStartSeconds,
    uint64_t gatewayStartMicroseconds,
    bool installSessionCache) {
  if (!HRAAuditTokenNamesExactParent(parentAuditToken, parentProcess))
    return false;
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
  NSString *outerPath = nil;
  NSString *helperPath = nil;
  NSString *parentPath = nil;
  NSString *gatewayPath = nil;
  if (!HRAReleaseBundlePathsAreExact(
          parentProcess,
          &outerPath,
          &helperPath,
          &parentPath,
          &gatewayPath)) return false;
  const char *outerBytes = outerPath.fileSystemRepresentation;
  const char *helperBytes = helperPath.fileSystemRepresentation;
  const char *parentBytes = parentPath.fileSystemRepresentation;
  const char *gatewayBytes = gatewayPath.fileSystemRepresentation;
  if (outerBytes == NULL || helperBytes == NULL || parentBytes == NULL ||
      gatewayBytes == NULL) return false;
  uint8_t helperDescriptorCDHash[HRA_MACOS_CDHASH_LENGTH];
  uint8_t parentDescriptorCDHash[HRA_MACOS_CDHASH_LENGTH];
  memset(helperDescriptorCDHash, 0, sizeof(helperDescriptorCDHash));
  memset(parentDescriptorCDHash, 0, sizeof(parentDescriptorCDHash));
  if (!hra_macos_release_helper_identity_is_exact(
          helperBytes,
          strlen(helperBytes),
          helperDescriptorCDHash) ||
      !hra_macos_parent_payload_identity_is_exact(
          parentBytes,
          strlen(parentBytes),
          parentDescriptorCDHash)) {
    HRASecureZero(helperDescriptorCDHash, sizeof(helperDescriptorCDHash));
    HRASecureZero(parentDescriptorCDHash, sizeof(parentDescriptorCDHash));
    return false;
  }
#endif
  SecCodeRef selfCode = NULL;
  if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) != errSecSuccess ||
      selfCode == NULL) {
    return false;
  }
  OSStatus selfStatus = SecCodeCheckValidity(
      selfCode, kSecCSStrictValidate, NULL);
  NSDictionary *selfInformation = selfStatus == errSecSuccess
      ? HRACopySigningInformationForCode(selfCode)
      : nil;
  CFRelease(selfCode);
  if (selfInformation == nil ||
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
      !HRAReleaseCodeInformationIsExact(
          selfInformation, HRAKeychainCustodianIdentifier) ||
      memcmp(HRAExactCodeDirectoryHash(selfInformation).bytes,
             helperDescriptorCDHash,
             sizeof(helperDescriptorCDHash)) != 0 ||
#endif
      ![selfInformation[(__bridge NSString *)kSecCodeInfoIdentifier]
          isEqualToString:HRAKeychainCustodianIdentifier]) {
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
    HRASecureZero(helperDescriptorCDHash, sizeof(helperDescriptorCDHash));
    HRASecureZero(parentDescriptorCDHash, sizeof(parentDescriptorCDHash));
#endif
    return false;
  }

  NSData *auditTokenData = [NSData
      dataWithBytes:parentAuditToken length:sizeof(*parentAuditToken)];
  NSDictionary *attributes = @{
    (__bridge NSString *)kSecGuestAttributePid: @(parentProcess),
    (__bridge NSString *)kSecGuestAttributeAudit: auditTokenData,
  };
  SecCodeRef parentCode = NULL;
  if (SecCodeCopyGuestWithAttributes(
          NULL,
          (__bridge CFDictionaryRef)attributes,
          kSecCSDefaultFlags,
          &parentCode) != errSecSuccess || parentCode == NULL) {
    return false;
  }
  OSStatus parentStatus = SecCodeCheckValidity(
      parentCode, kSecCSStrictValidate, NULL);
  NSDictionary *parentInformation = parentStatus == errSecSuccess
      ? HRACopySigningInformationForCode(parentCode)
      : nil;
  CFRelease(parentCode);
  if (parentInformation == nil ||
      !HRAAuditTokenNamesExactParent(parentAuditToken, parentProcess)) {
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
    HRASecureZero(helperDescriptorCDHash, sizeof(helperDescriptorCDHash));
    HRASecureZero(parentDescriptorCDHash, sizeof(parentDescriptorCDHash));
#endif
    return false;
  }
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
  NSData *dynamicCDHash = HRAExactCodeDirectoryHash(parentInformation);
  bool exact = HRAReleaseCodeInformationIsExact(
          parentInformation, @"kitchen.hraness") &&
      dynamicCDHash.length == sizeof(parentDescriptorCDHash) &&
      memcmp(dynamicCDHash.bytes,
             parentDescriptorCDHash,
             sizeof(parentDescriptorCDHash)) == 0 &&
      hra_macos_gateway_generation_is_exact(
          gatewayBytes,
          strlen(gatewayBytes),
          gatewayProcess,
          parentProcess,
          gatewayStartSeconds,
          gatewayStartMicroseconds) &&
      hra_macos_release_outer_bundle_is_exact(
          outerBytes, strlen(outerBytes)) &&
      HRAAuditTokenNamesExactParent(parentAuditToken, parentProcess);
  if (exact && installSessionCache) {
    exact = HRAInstallAuthorizedParentCache(
        outerPath,
        helperPath,
        parentPath,
        gatewayPath,
        parentDescriptorCDHash);
  }
  HRASecureZero(helperDescriptorCDHash, sizeof(helperDescriptorCDHash));
  HRASecureZero(parentDescriptorCDHash, sizeof(parentDescriptorCDHash));
  return exact;
#endif
  return false;
}

static bool HRAAuthorizedParentRemainsLive(void) {
  pid_t expected = HRAAuthorizedParentProcess;
  if (expected <= 1 || !HRAAuthorizedParentAuditTokenPresent ||
      HRAAuthorizedParentDescriptor < 0 || HRAAuthorizedParentPath == nil ||
      HRAAuthorizedGatewayPath == nil ||
      !HRAAuditTokenNamesExactParent(
          &HRAAuthorizedParentAuditToken, expected)) return false;
  if (!HRAAuthorizedBundlePathsRemainStable() ||
      ![HRAProcessPath(expected) isEqualToString:HRAAuthorizedParentPath]) {
    return false;
  }
  bool exact = HRAParentIdentityIsAuthorized(
      expected,
      &HRAAuthorizedParentAuditToken,
      HRAAuthorizedGatewayProcess,
      HRAAuthorizedGatewayStartSeconds,
      HRAAuthorizedGatewayStartMicroseconds,
      false);
  return exact && HRAAuthorizedBundlePathsRemainStable() &&
      HRAAuditTokenNamesExactParent(
          &HRAAuthorizedParentAuditToken, expected) &&
      hra_macos_gateway_generation_remains_exact(
          HRAAuthorizedGatewayPath.fileSystemRepresentation,
          strlen(HRAAuthorizedGatewayPath.fileSystemRepresentation),
          HRAAuthorizedGatewayProcess,
          expected,
          HRAAuthorizedGatewayStartSeconds,
          HRAAuthorizedGatewayStartMicroseconds);
}

static bool HRAWriteAll(int descriptor, const uint8_t *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(descriptor, bytes + offset, length - offset);
    if (written > 0) {
      offset += (size_t)written;
      continue;
    }
    if (written < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

static bool HRAConfigurePipeWriterNoSigPipe(int descriptor) {
#if defined(F_SETNOSIGPIPE)
  return descriptor >= 0 && fcntl(descriptor, F_SETNOSIGPIPE, 1) == 0;
#else
  (void)descriptor;
  return false;
#endif
}

static const char *_Nullable HRAExactFileSystemRepresentation(
    NSString *path,
    const char *expectedBytes,
    size_t expectedLength) {
  if (path == nil || expectedBytes == NULL || expectedLength == 0 ||
      expectedLength > 4096) {
    return NULL;
  }
  const char *representation = path.fileSystemRepresentation;
  if (representation == NULL ||
      strnlen(representation, expectedLength + 1) != expectedLength ||
      memcmp(representation, expectedBytes, expectedLength) != 0) {
    return NULL;
  }
  return representation;
}

static NSMutableData *_Nullable HRAReadBoundedStandardInput(void) {
  NSMutableData *input = [NSMutableData data];
  uint8_t buffer[128];
  memset(buffer, 0, sizeof(buffer));
  while (true) {
    ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (count == 0) break;
    if (count < 0) {
      if (errno == EINTR) continue;
      HRASecureZero(buffer, sizeof(buffer));
      if (input.length > 0) HRASecureZero(input.mutableBytes, input.length);
      return nil;
    }
    if (input.length + (NSUInteger)count > HRACustodianMaximumRequestBytes) {
      HRASecureZero(buffer, sizeof(buffer));
      if (input.length > 0) HRASecureZero(input.mutableBytes, input.length);
      return nil;
    }
    [input appendBytes:buffer length:(NSUInteger)count];
    HRASecureZero(buffer, sizeof(buffer));
  }
  HRASecureZero(buffer, sizeof(buffer));
  return input.length == 0 ? nil : input;
}

static NSString *_Nullable HRACanonicalInstallEnvelope(id _Nullable value) {
  if (![value isKindOfClass:[NSString class]]) return nil;
  NSString *text = value;
  NSData *encoded = [text dataUsingEncoding:NSUTF8StringEncoding];
  if (encoded.length == 0 || encoded.length > 256) return nil;
  id parsed = [NSJSONSerialization JSONObjectWithData:encoded options:0 error:nil];
  if (![parsed isKindOfClass:[NSDictionary class]]) return nil;
  NSDictionary *object = parsed;
  if (object.count != 3 ||
      !HRAJSONIntegerIsExactlyOne(object[@"version"]) ||
      ![object[@"algorithm"] isEqual:@"hkdf-sha256"] ||
      ![object[@"key"] isKindOfClass:[NSString class]]) {
    return nil;
  }
  NSString *key = object[@"key"];
  if (key.length != 43) return nil;
  NSCharacterSet *invalid =
      [[NSCharacterSet characterSetWithCharactersInString:
          @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"]
          invertedSet];
  if ([key rangeOfCharacterFromSet:invalid].location != NSNotFound) return nil;
  NSString *standard = [[key stringByReplacingOccurrencesOfString:@"-"
                                                        withString:@"+"]
      stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
  standard = [standard stringByAppendingString:@"="];
  NSData *decoded = [[NSData alloc] initWithBase64EncodedString:standard
                                                        options:0];
  if (decoded.length != 32) return nil;
  NSString *roundTrip = [decoded base64EncodedStringWithOptions:0];
  roundTrip = [[roundTrip stringByReplacingOccurrencesOfString:@"+"
                                                     withString:@"-"]
      stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
  while ([roundTrip hasSuffix:@"="]) {
    roundTrip = [roundTrip substringToIndex:roundTrip.length - 1];
  }
  if (![roundTrip isEqualToString:key]) return nil;
  NSString *canonical = [NSString stringWithFormat:
      @"{\"version\":1,\"algorithm\":\"hkdf-sha256\",\"key\":\"%@\"}",
      key];
  return [canonical isEqualToString:text] ? canonical : nil;
}

static bool HRAAuthorizedLoginKeychainRemainsStable(void) {
  if (HRAAuthorizedLoginKeychainDescriptor < 0 ||
      HRAAuthorizedLoginKeychainPath == nil) return false;
  const char *canonical =
      HRAAuthorizedLoginKeychainPath.fileSystemRepresentation;
  struct stat opened;
  struct stat named;
  char descriptorPath[PATH_MAX];
  memset(&opened, 0, sizeof(opened));
  memset(&named, 0, sizeof(named));
  memset(descriptorPath, 0, sizeof(descriptorPath));
  if (canonical == NULL ||
      fstat(HRAAuthorizedLoginKeychainDescriptor, &opened) != 0 ||
      lstat(canonical, &named) != 0 ||
      fcntl(
          HRAAuthorizedLoginKeychainDescriptor,
          F_GETPATH,
          descriptorPath) != 0 ||
      strcmp(descriptorPath, canonical) != 0) return false;
  const struct stat *expected = &HRAAuthorizedLoginKeychainMetadata;
#define HRA_KEYCHAIN_STABLE_FIELDS_MATCH(candidate) \
  ((candidate).st_dev == expected->st_dev && \
   (candidate).st_ino == expected->st_ino && \
   (candidate).st_mode == expected->st_mode && \
   (candidate).st_nlink == expected->st_nlink && \
   (candidate).st_uid == expected->st_uid && \
   (candidate).st_gid == expected->st_gid && \
   (candidate).st_flags == expected->st_flags)
  bool exact = HRA_KEYCHAIN_STABLE_FIELDS_MATCH(opened) &&
      HRA_KEYCHAIN_STABLE_FIELDS_MATCH(named);
#undef HRA_KEYCHAIN_STABLE_FIELDS_MATCH
  return exact;
}

static SecKeychainRef _Nullable HRACopyExactLoginKeychain(void) {
  struct passwd passwordEntry;
  struct passwd *passwordResult = NULL;
  char passwordBuffer[16384];
  memset(&passwordEntry, 0, sizeof(passwordEntry));
  memset(passwordBuffer, 0, sizeof(passwordBuffer));
  if (getpwuid_r(
          geteuid(),
          &passwordEntry,
          passwordBuffer,
          sizeof(passwordBuffer),
          &passwordResult) != 0 ||
      passwordResult != &passwordEntry || passwordEntry.pw_dir == NULL ||
      passwordEntry.pw_dir[0] != '/' ||
      strnlen(passwordEntry.pw_dir, PATH_MAX) >= PATH_MAX) {
    return NULL;
  }
  char canonicalHome[PATH_MAX];
  char expectedPath[PATH_MAX];
  memset(canonicalHome, 0, sizeof(canonicalHome));
  memset(expectedPath, 0, sizeof(expectedPath));
  if (realpath(passwordEntry.pw_dir, canonicalHome) == NULL ||
      strcmp(passwordEntry.pw_dir, canonicalHome) != 0) return NULL;
  static const char suffix[] = "/Library/Keychains/login.keychain-db";
  size_t homeLength = strlen(canonicalHome);
  if (homeLength > sizeof(expectedPath) - sizeof(suffix)) return NULL;
  memcpy(expectedPath, canonicalHome, homeLength);
  memcpy(expectedPath + homeLength, suffix, sizeof(suffix));

  SecKeychainRef keychain = NULL;
  UInt32 actualPathCapacity = sizeof(expectedPath);
  char actualPath[PATH_MAX];
  memset(actualPath, 0, sizeof(actualPath));
  if (SecKeychainCopyDefault(&keychain) != errSecSuccess || keychain == NULL ||
      SecKeychainGetPath(
          keychain, &actualPathCapacity, actualPath) != errSecSuccess ||
      actualPathCapacity == 0 || actualPathCapacity > sizeof(actualPath) ||
      strnlen(actualPath, sizeof(actualPath)) >= sizeof(actualPath) ||
      strcmp(actualPath, expectedPath) != 0) {
    if (keychain != NULL) CFRelease(keychain);
    return NULL;
  }
  NSString *path = [[NSFileManager defaultManager]
      stringWithFileSystemRepresentation:expectedPath
                                  length:strlen(expectedPath)];
  if (path == nil) {
    CFRelease(keychain);
    return NULL;
  }
  if (HRAAuthorizedLoginKeychainDescriptor < 0) {
    int descriptor = -1;
    struct stat metadata;
    memset(&metadata, 0, sizeof(metadata));
    if (!HRAOpenStableAuthorityPath(path, false, &descriptor, &metadata) ||
        metadata.st_uid != geteuid() ||
        (((uint32_t)metadata.st_mode & 0022u) != 0)) {
      if (descriptor >= 0) close(descriptor);
      CFRelease(keychain);
      return NULL;
    }
    HRAAuthorizedLoginKeychainDescriptor = descriptor;
    HRAAuthorizedLoginKeychainMetadata = metadata;
    HRAAuthorizedLoginKeychainPath = [path copy];
  } else if (![path isEqualToString:HRAAuthorizedLoginKeychainPath] ||
      !HRAAuthorizedLoginKeychainRemainsStable()) {
    CFRelease(keychain);
    return NULL;
  }
  return keychain;
}

static NSDictionary *_Nullable HRAKeychainQueryForAccount(NSString *account) {
  SecKeychainRef keychain = HRACopyExactLoginKeychain();
  if (keychain == NULL) return nil;
  CFDictionaryRef query = hra_macos_copy_no_ui_generic_password_query(
      keychain,
      (__bridge CFStringRef)HRAHarnessKeychainService,
      (__bridge CFStringRef)account);
  CFRelease(keychain);
  return query == NULL ? nil : CFBridgingRelease(query);
}

static NSMutableDictionary *HRAKeychainAddAttributes(
    NSDictionary *query) {
  if (query == nil) return nil;
  CFMutableDictionaryRef attributes =
      hra_macos_copy_generic_password_add_attributes(
          (__bridge CFDictionaryRef)query);
  return attributes == NULL ? nil : CFBridgingRelease(attributes);
}

static NSDictionary *_Nullable HRAKeychainQuery(void) {
  return HRAKeychainQueryForAccount(HRAHarnessKeychainAccount);
}

static NSDictionary *_Nullable HRAReconciliationKeychainQuery(void) {
  return HRAKeychainQueryForAccount(HRAHarnessReconciliationAccount);
}

static bool HRAInstallEnvelopeItemAccessIsStrict(SecKeychainItemRef item) {
  if (item == NULL || CFGetTypeID(item) != SecKeychainItemGetTypeID() ||
      !HRAAuthorizedParentRemainsLive()) {
    return false;
  }
  bool exact = hra_macos_install_envelope_item_access_is_strict(item);
  return exact && HRAAuthorizedParentRemainsLive();
}

static OSStatus HRAAuthorizedSecItemCopyMatching(
    CFDictionaryRef query,
    CFTypeRef _Nullable *_Nullable result) {
  if (query == NULL || !HRAAuthorizedParentRemainsLive() ||
      !HRAAuthorizedLoginKeychainRemainsStable()) return errSecAuthFailed;
  OSStatus status = SecItemCopyMatching(query, result);
  if (!HRAAuthorizedLoginKeychainRemainsStable() ||
      !HRAAuthorizedParentRemainsLive()) {
    if (result != NULL && *result != NULL) {
      CFRelease(*result);
      *result = NULL;
    }
    return errSecAuthFailed;
  }
  return status;
}

static OSStatus HRAAuthorizedSecItemAdd(CFDictionaryRef attributes) {
  if (attributes == NULL || !HRAAuthorizedParentRemainsLive() ||
      !HRAAuthorizedLoginKeychainRemainsStable()) return errSecAuthFailed;
  OSStatus status = SecItemAdd(attributes, NULL);
  return HRAAuthorizedLoginKeychainRemainsStable() &&
      HRAAuthorizedParentRemainsLive() ? status : errSecAuthFailed;
}

static OSStatus HRAAuthorizedSecItemUpdate(
    CFDictionaryRef query,
    CFDictionaryRef attributes) {
  if (query == NULL || attributes == NULL ||
      !HRAAuthorizedParentRemainsLive() ||
      !HRAAuthorizedLoginKeychainRemainsStable()) return errSecAuthFailed;
  OSStatus status = SecItemUpdate(query, attributes);
  return HRAAuthorizedLoginKeychainRemainsStable() &&
      HRAAuthorizedParentRemainsLive() ? status : errSecAuthFailed;
}

static OSStatus HRAAuthorizedSecItemDelete(CFDictionaryRef query) {
  if (query == NULL || !HRAAuthorizedParentRemainsLive() ||
      !HRAAuthorizedLoginKeychainRemainsStable()) return errSecAuthFailed;
  OSStatus status = SecItemDelete(query);
  return HRAAuthorizedLoginKeychainRemainsStable() &&
      HRAAuthorizedParentRemainsLive() ? status : errSecAuthFailed;
}

static HRAKeychainReadState HRAReadInstallEnvelope(
    NSString *_Nullable *_Nonnull outValue) {
  *outValue = nil;
  if (!HRAAuthorizedParentRemainsLive()) return HRAKeychainReadFailure;
  NSMutableDictionary *query = [HRAKeychainQuery() mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecReturnRef] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  CFTypeRef raw = NULL;
  OSStatus status = HRAAuthorizedSecItemCopyMatching(
      (__bridge CFDictionaryRef)query, &raw);
  if (status == errSecItemNotFound) return HRAKeychainReadAbsent;
  if (status != errSecSuccess || raw == NULL ||
      CFGetTypeID(raw) != CFDictionaryGetTypeID()) {
    if (raw != NULL) CFRelease(raw);
    return HRAKeychainReadFailure;
  }
  NSDictionary *result = CFBridgingRelease(raw);
  NSData *data = result[(__bridge id)kSecValueData];
  SecKeychainItemRef item = (__bridge SecKeychainItemRef)
      result[(__bridge id)kSecValueRef];
  if (![data isKindOfClass:[NSData class]] ||
      !HRAInstallEnvelopeItemAccessIsStrict(item)) {
    return HRAKeychainReadFailure;
  }
  NSString *text = [[NSString alloc] initWithData:data
                                         encoding:NSUTF8StringEncoding];
  NSString *canonical = HRACanonicalInstallEnvelope(text);
  if (canonical == nil) return HRAKeychainReadFailure;
  *outValue = canonical;
  return HRAKeychainReadPresent;
}

static bool HRASetInstallEnvelopeIfAbsent(
    NSString *value,
    bool *outCreated,
    NSString *_Nullable *_Nonnull outAuthoritative) {
  NSString *canonical = HRACanonicalInstallEnvelope(value);
  if (canonical == nil) return false;
  if (!HRAAuthorizedParentRemainsLive()) return false;
  NSMutableDictionary *item = HRAKeychainAddAttributes(HRAKeychainQuery());
  item[(__bridge id)kSecValueData] =
      [canonical dataUsingEncoding:NSUTF8StringEncoding];
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  if (access == NULL) return false;
  item[(__bridge id)kSecAttrAccess] = (__bridge id)access;
  OSStatus status = HRAAuthorizedSecItemAdd(
      (__bridge CFDictionaryRef)item);
  CFRelease(access);
  if (status != errSecSuccess && status != errSecDuplicateItem) return false;
  *outCreated = status == errSecSuccess;
  NSString *authoritative = nil;
  if (HRAReadInstallEnvelope(&authoritative) != HRAKeychainReadPresent ||
      authoritative == nil) {
    return false;
  }
  *outAuthoritative = authoritative;
  return true;
}

static bool HRADeleteInstallEnvelope(bool *outDeleted) {
  if (!HRAAuthorizedParentRemainsLive()) return false;
  OSStatus status = HRAAuthorizedSecItemDelete(
      (__bridge CFDictionaryRef)HRAKeychainQuery());
  if (status != errSecSuccess && status != errSecItemNotFound) return false;
  *outDeleted = status == errSecSuccess;
  NSString *unexpected = nil;
  return HRAReadInstallEnvelope(&unexpected) == HRAKeychainReadAbsent;
}

static NSString *_Nullable HRACanonicalReconciliationMarker(
    id _Nullable value) {
  if (![value isKindOfClass:[NSString class]]) return nil;
  NSString *text = value;
  NSData *encoded = [text dataUsingEncoding:NSUTF8StringEncoding];
  if (encoded.length == 0 || encoded.length > 320) return nil;
  id parsed = [NSJSONSerialization JSONObjectWithData:encoded options:0 error:nil];
  if (![parsed isKindOfClass:[NSDictionary class]]) return nil;
  NSDictionary *object = parsed;
  if (object.count != 6 ||
      !HRAJSONIntegerIsExactlyOne(object[@"version"]) ||
      ![object[@"phase"] isKindOfClass:[NSString class]] ||
      ![object[@"bridgeCDHash"] isEqual:HRALegacyGatewayCDHashHex] ||
      ![object[@"legacyState"] isKindOfClass:[NSString class]] ||
      ![object[@"envelopeState"] isKindOfClass:[NSString class]]) {
    return nil;
  }
  NSString *phase = object[@"phase"];
  NSString *legacyState = object[@"legacyState"];
  NSString *envelopeState = object[@"envelopeState"];
  id digestValue = object[@"envelopeSHA256"];
  bool prepared = [phase isEqual:@"prepared"];
  bool committed = [phase isEqual:@"committed"];
  bool legacyAbsent = [legacyState isEqual:@"absent"];
  bool legacyPresent = [legacyState isEqual:@"present"];
  bool envelopeAbsent = [envelopeState isEqual:@"absent"];
  bool envelopePresent = [envelopeState isEqual:@"present"];
  if ((!prepared && !committed) || (!legacyAbsent && !legacyPresent) ||
      (!envelopeAbsent && !envelopePresent)) {
    return nil;
  }
  NSString *digest = nil;
  if ([digestValue isKindOfClass:[NSString class]]) {
    digest = digestValue;
    NSCharacterSet *invalid =
        [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"]
            invertedSet];
    if (digest.length != 64 ||
        [digest rangeOfCharacterFromSet:invalid].location != NSNotFound) {
      return nil;
    }
  } else if (digestValue != [NSNull null]) {
    return nil;
  }
  if (prepared) {
    if (!envelopePresent || digest == nil) return nil;
  } else if (envelopeAbsent) {
    if (!legacyAbsent || digest != nil) return nil;
  } else if (digest == nil) {
    return nil;
  }
  NSString *digestJSON = digest == nil
      ? @"null"
      : [NSString stringWithFormat:@"\"%@\"", digest];
  NSString *canonical = [NSString stringWithFormat:
      @"{\"version\":1,\"phase\":\"%@\",\"bridgeCDHash\":\"%@\","
       @"\"legacyState\":\"%@\",\"envelopeState\":\"%@\","
       @"\"envelopeSHA256\":%@}",
      phase,
      HRALegacyGatewayCDHashHex,
      legacyState,
      envelopeState,
      digestJSON];
  return [canonical isEqualToString:text] ? canonical : nil;
}

static NSDictionary *_Nullable HRAReconciliationMarkerObject(
    NSString *canonical) {
  NSData *encoded = [canonical dataUsingEncoding:NSUTF8StringEncoding];
  id parsed = [NSJSONSerialization JSONObjectWithData:encoded options:0 error:nil];
  return [parsed isKindOfClass:[NSDictionary class]] ? parsed : nil;
}

static HRAKeychainReadState HRAReadReconciliationMarker(
    NSString *_Nullable *_Nonnull outValue) {
  *outValue = nil;
  if (!HRAAuthorizedParentRemainsLive()) return HRAKeychainReadFailure;
  NSMutableDictionary *query =
      [HRAReconciliationKeychainQuery() mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  CFTypeRef raw = NULL;
  OSStatus status = HRAAuthorizedSecItemCopyMatching(
      (__bridge CFDictionaryRef)query, &raw);
  if (status == errSecItemNotFound) return HRAKeychainReadAbsent;
  if (status != errSecSuccess || raw == NULL ||
      CFGetTypeID(raw) != CFDataGetTypeID()) {
    if (raw != NULL) CFRelease(raw);
    return HRAKeychainReadFailure;
  }
  NSData *data = CFBridgingRelease(raw);
  NSString *text = [[NSString alloc] initWithData:data
                                         encoding:NSUTF8StringEncoding];
  NSString *canonical = HRACanonicalReconciliationMarker(text);
  if (canonical == nil) return HRAKeychainReadFailure;
  *outValue = canonical;
  return HRAKeychainReadPresent;
}

static bool HRAReconciliationTransitionIsAllowed(
    NSString *_Nullable existing,
    NSString *desired,
    bool prepareAction) {
  NSDictionary *next = HRAReconciliationMarkerObject(desired);
  if (next == nil) return false;
  NSString *nextPhase = next[@"phase"];
  if (prepareAction != [nextPhase isEqual:@"prepared"]) return false;
  if (existing == nil) {
    if (prepareAction) {
      return [next[@"legacyState"] isEqual:@"present"] &&
          [next[@"envelopeState"] isEqual:@"present"] &&
          [next[@"envelopeSHA256"] isKindOfClass:[NSString class]];
    }
    return [next[@"phase"] isEqual:@"committed"] &&
        [next[@"legacyState"] isEqual:@"absent"] &&
        [next[@"envelopeState"] isEqual:@"absent"] &&
        [next[@"envelopeSHA256"] isEqual:[NSNull null]];
  }
  if ([existing isEqualToString:desired]) return true;
  NSDictionary *prior = HRAReconciliationMarkerObject(existing);
  if (prior == nil) return false;
  if (prepareAction) {
    return [prior[@"phase"] isEqual:@"committed"] &&
        [prior[@"legacyState"] isEqual:@"absent"] &&
        [prior[@"envelopeState"] isEqual:@"absent"] &&
        [prior[@"envelopeSHA256"] isEqual:[NSNull null]] &&
        [next[@"legacyState"] isEqual:@"absent"] &&
        [next[@"envelopeState"] isEqual:@"present"] &&
        [next[@"envelopeSHA256"] isKindOfClass:[NSString class]];
  }
  if (![next[@"phase"] isEqual:@"committed"]) return false;
  if ([prior[@"phase"] isEqual:@"prepared"]) {
    bool finalize =
        [prior[@"legacyState"] isEqual:next[@"legacyState"]] &&
        [prior[@"envelopeState"] isEqual:next[@"envelopeState"]] &&
        [prior[@"envelopeSHA256"] isEqual:next[@"envelopeSHA256"]];
    bool rollbackNative =
        [prior[@"legacyState"] isEqual:@"absent"] &&
        [next[@"legacyState"] isEqual:@"absent"] &&
        [next[@"envelopeState"] isEqual:@"absent"] &&
        [next[@"envelopeSHA256"] isEqual:[NSNull null]];
    return finalize || rollbackNative;
  }
  return false;
}

static NSString *_Nullable HRASHA256Hex(NSString *value) {
  uint8_t encoded[256];
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  char hex[CC_SHA256_DIGEST_LENGTH * 2 + 1];
  memset(encoded, 0, sizeof(encoded));
  memset(digest, 0, sizeof(digest));
  memset(hex, 0, sizeof(hex));
  NSUInteger encodedLength = 0;
  if (![value getBytes:encoded
             maxLength:sizeof(encoded)
            usedLength:&encodedLength
              encoding:NSUTF8StringEncoding
               options:0
                 range:NSMakeRange(0, value.length)
        remainingRange:NULL] || encodedLength == 0 ||
      encodedLength > UINT32_MAX ||
      CC_SHA256(encoded, (CC_LONG)encodedLength, digest) == NULL) {
    HRASecureZero(encoded, sizeof(encoded));
    HRASecureZero(digest, sizeof(digest));
    HRASecureZero(hex, sizeof(hex));
    return nil;
  }
  static const char alphabet[] = "0123456789abcdef";
  for (size_t index = 0; index < sizeof(digest); index += 1) {
    hex[index * 2] = alphabet[digest[index] >> 4];
    hex[index * 2 + 1] = alphabet[digest[index] & 0x0f];
  }
  NSString *result = [[NSString alloc]
      initWithBytes:hex
             length:sizeof(digest) * 2
           encoding:NSASCIIStringEncoding];
  HRASecureZero(encoded, sizeof(encoded));
  HRASecureZero(digest, sizeof(digest));
  HRASecureZero(hex, sizeof(hex));
  return result;
}

static bool HRACommittedMarkerMatchesInstallEnvelope(NSString *marker) {
  NSDictionary *object = HRAReconciliationMarkerObject(marker);
  if (object == nil || ![object[@"phase"] isEqual:@"committed"])
    return false;
  NSString *envelope = nil;
  HRAKeychainReadState state = HRAReadInstallEnvelope(&envelope);
  if ([object[@"envelopeState"] isEqual:@"absent"]) {
    return state == HRAKeychainReadAbsent &&
        [object[@"envelopeSHA256"] isEqual:[NSNull null]];
  }
  if (state != HRAKeychainReadPresent || envelope == nil) return false;
  NSString *digest = HRASHA256Hex(envelope);
  return digest != nil && [digest isEqual:object[@"envelopeSHA256"]];
}

static bool HRAWriteReconciliationMarker(
    NSString *value,
    bool prepareAction,
    NSString *_Nullable *_Nonnull outAuthoritative) {
  *outAuthoritative = nil;
  NSString *desired = HRACanonicalReconciliationMarker(value);
  if (desired == nil || !HRAAuthorizedParentRemainsLive()) return false;
  NSString *existing = nil;
  HRAKeychainReadState state = HRAReadReconciliationMarker(&existing);
  if (state == HRAKeychainReadFailure ||
      !HRAReconciliationTransitionIsAllowed(
          state == HRAKeychainReadPresent ? existing : nil,
          desired,
          prepareAction)) {
    return false;
  }
  if (!prepareAction && !HRACommittedMarkerMatchesInstallEnvelope(desired))
    return false;
  if (state == HRAKeychainReadAbsent) {
    NSMutableDictionary *item = HRAKeychainAddAttributes(
        HRAReconciliationKeychainQuery());
    item[(__bridge id)kSecValueData] =
        [desired dataUsingEncoding:NSUTF8StringEncoding];
    if (HRAAuthorizedSecItemAdd(
            (__bridge CFDictionaryRef)item) != errSecSuccess)
      return false;
  } else if (![existing isEqualToString:desired]) {
    NSDictionary *attributes = @{
      (__bridge id)kSecValueData:
          [desired dataUsingEncoding:NSUTF8StringEncoding],
    };
    if (HRAAuthorizedSecItemUpdate(
            (__bridge CFDictionaryRef)HRAReconciliationKeychainQuery(),
            (__bridge CFDictionaryRef)attributes) != errSecSuccess) {
      return false;
    }
  }
  NSString *readback = nil;
  if (HRAReadReconciliationMarker(&readback) !=
          HRAKeychainReadPresent ||
      ![readback isEqualToString:desired]) {
    return false;
  }
  *outAuthoritative = readback;
  return true;
}

static bool HRADeleteReconciliationMarker(bool *outDeleted) {
  if (!HRAAuthorizedParentRemainsLive()) return false;
  OSStatus status = HRAAuthorizedSecItemDelete(
      (__bridge CFDictionaryRef)HRAReconciliationKeychainQuery());
  if (status != errSecSuccess && status != errSecItemNotFound) return false;
  *outDeleted = status == errSecSuccess;
  if (!HRAAuthorizedParentRemainsLive()) return false;
  NSMutableDictionary *query =
      [HRAReconciliationKeychainQuery() mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  CFTypeRef raw = NULL;
  OSStatus readStatus = HRAAuthorizedSecItemCopyMatching(
      (__bridge CFDictionaryRef)query, &raw);
  if (raw != NULL) CFRelease(raw);
  return readStatus == errSecItemNotFound;
}

static bool HRAWriteJSONResponse(NSDictionary *response) {
  if ([response[@"ok"] isEqual:@YES] &&
      !HRAAuthorizedParentRemainsLive()) return false;
  if (![NSJSONSerialization isValidJSONObject:response]) return false;
  NSData *data = [NSJSONSerialization dataWithJSONObject:response
                                                  options:0
                                                    error:nil];
  if (data.length == 0 || data.length > HRACustodianMaximumResponseBytes) {
    return false;
  }
  return HRAWriteAll(STDOUT_FILENO, data.bytes, data.length);
}

static int HRAHexNibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

static bool HRAParseAuditToken(const char *text, audit_token_t *outToken) {
  if (text == NULL || outToken == NULL || strlen(text) != sizeof(*outToken) * 2)
    return false;
  uint8_t bytes[sizeof(*outToken)];
  memset(bytes, 0, sizeof(bytes));
  for (size_t index = 0; index < sizeof(bytes); index += 1) {
    int high = HRAHexNibble(text[index * 2]);
    int low = HRAHexNibble(text[index * 2 + 1]);
    if (high < 0 || low < 0) {
      HRASecureZero(bytes, sizeof(bytes));
      return false;
    }
    bytes[index] = (uint8_t)((high << 4) | low);
  }
  memcpy(outToken, bytes, sizeof(bytes));
  HRASecureZero(bytes, sizeof(bytes));
  return true;
}

static bool HRAParseCanonicalUInt64(
    const char *text,
    uint64_t maximum,
    uint64_t *outValue) {
  if (text == NULL || outValue == NULL || text[0] == '\0' ||
      (text[0] == '0' && text[1] != '\0')) return false;
  uint64_t value = 0;
  for (size_t index = 0; text[index] != '\0'; index += 1) {
    if (text[index] < '0' || text[index] > '9') return false;
    uint64_t digit = (uint64_t)(text[index] - '0');
    if (value > (maximum - digit) / 10) return false;
    value = value * 10 + digit;
  }
  *outValue = value;
  return true;
}

static bool HRAReadParentAuthorizationArguments(
    audit_token_t *outToken,
    pid_t *outGatewayProcess,
    uint64_t *outGatewayStartSeconds,
    uint64_t *outGatewayStartMicroseconds) {
  int argumentCount = *_NSGetArgc();
  char **arguments = *_NSGetArgv();
  uint64_t process = 0;
  return argumentCount == 6 && arguments != NULL &&
      strcmp(arguments[1], "--hra-parent-audit-token-v1") == 0 &&
      HRAParseAuditToken(arguments[2], outToken) &&
      HRAParseCanonicalUInt64(arguments[3], INT_MAX, &process) && process > 1 &&
      HRAParseCanonicalUInt64(
          arguments[4], UINT64_MAX, outGatewayStartSeconds) &&
      *outGatewayStartSeconds > 0 &&
      HRAParseCanonicalUInt64(
          arguments[5], 999999, outGatewayStartMicroseconds) &&
      (*outGatewayProcess = (pid_t)process) > 1;
}

static void HRAClearAuthorizedParent(void) {
  HRAAuthorizedParentProcess = -1;
  HRASecureZero(
      &HRAAuthorizedParentAuditToken,
      sizeof(HRAAuthorizedParentAuditToken));
  HRAAuthorizedParentAuditTokenPresent = false;
  HRAAuthorizedGatewayProcess = -1;
  HRAAuthorizedGatewayStartSeconds = 0;
  HRAAuthorizedGatewayStartMicroseconds = 0;
  if (HRAAuthorizedParentDescriptor >= 0)
    close(HRAAuthorizedParentDescriptor);
  if (HRAAuthorizedHelperDescriptor >= 0)
    close(HRAAuthorizedHelperDescriptor);
  if (HRAAuthorizedOuterDescriptor >= 0)
    close(HRAAuthorizedOuterDescriptor);
  if (HRAAuthorizedInfoDescriptor >= 0)
    close(HRAAuthorizedInfoDescriptor);
  if (HRAAuthorizedCodeResourcesDescriptor >= 0)
    close(HRAAuthorizedCodeResourcesDescriptor);
  if (HRAAuthorizedRendererDescriptor >= 0)
    close(HRAAuthorizedRendererDescriptor);
  if (HRAAuthorizedLoginKeychainDescriptor >= 0)
    close(HRAAuthorizedLoginKeychainDescriptor);
  HRAAuthorizedParentDescriptor = -1;
  HRAAuthorizedHelperDescriptor = -1;
  HRAAuthorizedOuterDescriptor = -1;
  HRAAuthorizedInfoDescriptor = -1;
  HRAAuthorizedCodeResourcesDescriptor = -1;
  HRAAuthorizedRendererDescriptor = -1;
  HRAAuthorizedLoginKeychainDescriptor = -1;
  memset(&HRAAuthorizedParentMetadata, 0, sizeof(HRAAuthorizedParentMetadata));
  memset(&HRAAuthorizedHelperMetadata, 0, sizeof(HRAAuthorizedHelperMetadata));
  memset(&HRAAuthorizedOuterMetadata, 0, sizeof(HRAAuthorizedOuterMetadata));
  memset(&HRAAuthorizedInfoMetadata, 0, sizeof(HRAAuthorizedInfoMetadata));
  memset(&HRAAuthorizedCodeResourcesMetadata,
         0,
         sizeof(HRAAuthorizedCodeResourcesMetadata));
  memset(&HRAAuthorizedRendererMetadata,
         0,
         sizeof(HRAAuthorizedRendererMetadata));
  memset(&HRAAuthorizedLoginKeychainMetadata,
         0,
         sizeof(HRAAuthorizedLoginKeychainMetadata));
  HRASecureZero(
      HRAAuthorizedParentCDHash, sizeof(HRAAuthorizedParentCDHash));
  HRAAuthorizedOuterPath = nil;
  HRAAuthorizedHelperPath = nil;
  HRAAuthorizedParentPath = nil;
  HRAAuthorizedGatewayPath = nil;
  HRAAuthorizedInfoPath = nil;
  HRAAuthorizedCodeResourcesPath = nil;
  HRAAuthorizedRendererPath = nil;
  HRAAuthorizedLoginKeychainPath = nil;
}

int hra_keychain_custodian_main(void) {
  @autoreleasepool {
    audit_token_t parentAuditToken;
    memset(&parentAuditToken, 0, sizeof(parentAuditToken));
    pid_t gatewayProcess = -1;
    uint64_t gatewayStartSeconds = 0;
    uint64_t gatewayStartMicroseconds = 0;
    if (!HRAReadParentAuthorizationArguments(
            &parentAuditToken,
            &gatewayProcess,
            &gatewayStartSeconds,
            &gatewayStartMicroseconds)) return 1;
    pid_t parentProcess = getppid();
    if (!HRAParentIdentityIsAuthorized(
            parentProcess,
            &parentAuditToken,
            gatewayProcess,
            gatewayStartSeconds,
            gatewayStartMicroseconds,
            true)) {
      HRASecureZero(&parentAuditToken, sizeof(parentAuditToken));
      return 1;
    }
    HRAAuthorizedParentProcess = parentProcess;
    HRAAuthorizedParentAuditToken = parentAuditToken;
    HRAAuthorizedParentAuditTokenPresent = true;
    HRAAuthorizedGatewayProcess = gatewayProcess;
    HRAAuthorizedGatewayStartSeconds = gatewayStartSeconds;
    HRAAuthorizedGatewayStartMicroseconds = gatewayStartMicroseconds;
    HRASecureZero(&parentAuditToken, sizeof(parentAuditToken));
    NSMutableData *input = HRAReadBoundedStandardInput();
    id parsed = input == nil
        ? nil
        : [NSJSONSerialization JSONObjectWithData:input options:0 error:nil];
    if (input.length > 0) HRASecureZero(input.mutableBytes, input.length);
    if (![parsed isKindOfClass:[NSDictionary class]]) {
      HRAWriteJSONResponse(@{ @"ok": @NO, @"version": @1 });
      HRAClearAuthorizedParent();
      return 1;
    }
    NSDictionary *request = parsed;
    if (!HRAJSONIntegerIsExactlyOne(request[@"version"]) ||
        ![request[@"action"] isKindOfClass:[NSString class]]) {
      HRAWriteJSONResponse(@{ @"ok": @NO, @"version": @1 });
      HRAClearAuthorizedParent();
      return 1;
    }
    NSString *action = request[@"action"];
    if ([action isEqual:@"authorize"] && request.count == 2) {
#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
      int status = HRAWriteJSONResponse(@{
        @"authorization": @"hra-parent-v1",
        @"gatewayFileSha256":
            [NSString stringWithUTF8String:
                HRAExpectedGatewayFileSHA256Hex],
        @"ok": @YES,
        @"rendererAuthoritySha256":
            [NSString stringWithUTF8String:
                HRAExpectedRendererAuthorityRootSHA256Hex],
        @"version": @1,
      }) ? 0 : 1;
      HRAClearAuthorizedParent();
      return status;
#endif
    } else if ([action isEqual:@"status"] && request.count == 2) {
      NSString *value = nil;
      HRAKeychainReadState state = HRAReadInstallEnvelope(&value);
      if (state == HRAKeychainReadAbsent) {
        int status = HRAWriteJSONResponse(@{
          @"ok": @YES,
          @"state": @"absent",
          @"strictAcl": @NO,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
      if (state == HRAKeychainReadPresent && value != nil) {
        NSString *digest = HRASHA256Hex(value);
        if (digest != nil) {
          int status = HRAWriteJSONResponse(@{
            @"envelopeSha256": digest,
            @"ok": @YES,
            @"state": @"present",
            @"strictAcl": @YES,
            @"version": @1,
          }) ? 0 : 1;
          HRAClearAuthorizedParent();
          return status;
        }
      }
    } else if ([action isEqual:@"read"] && request.count == 2) {
      NSString *value = nil;
      HRAKeychainReadState state = HRAReadInstallEnvelope(&value);
      if (state == HRAKeychainReadAbsent) {
        int status = HRAWriteJSONResponse(@{
          @"ok": @YES,
          @"state": @"absent",
          @"strictAcl": @NO,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
      if (state == HRAKeychainReadPresent && value != nil) {
        int status = HRAWriteJSONResponse(@{
          @"ok": @YES,
          @"state": @"present",
          @"strictAcl": @YES,
          @"value": value,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
    } else if ([action isEqual:@"setIfAbsent"] && request.count == 3) {
      bool created = false;
      NSString *authoritative = nil;
      if (HRASetInstallEnvelopeIfAbsent(
              request[@"value"], &created, &authoritative) &&
          authoritative != nil) {
        int status = HRAWriteJSONResponse(@{
          @"created": @(created),
          @"ok": @YES,
          @"strictAcl": @YES,
          @"value": authoritative,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
    } else if ([action isEqual:@"delete"] && request.count == 2) {
      bool deleted = false;
      if (HRADeleteInstallEnvelope(&deleted)) {
        int status = HRAWriteJSONResponse(@{
          @"deleted": @(deleted),
          @"ok": @YES,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
    } else if ([action isEqual:@"markerRead"] && request.count == 2) {
      NSString *value = nil;
      HRAKeychainReadState state = HRAReadReconciliationMarker(&value);
      if (state == HRAKeychainReadAbsent) {
        int status = HRAWriteJSONResponse(@{
          @"ok": @YES,
          @"state": @"absent",
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
      if (state == HRAKeychainReadPresent && value != nil) {
        int status = HRAWriteJSONResponse(@{
          @"ok": @YES,
          @"state": @"present",
          @"value": value,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
    } else if (([action isEqual:@"markerPrepare"] ||
                [action isEqual:@"markerCommit"]) && request.count == 3) {
      NSString *authoritative = nil;
      if (HRAWriteReconciliationMarker(
              request[@"value"],
              [action isEqual:@"markerPrepare"],
              &authoritative) && authoritative != nil) {
        int status = HRAWriteJSONResponse(@{
          @"ok": @YES,
          @"value": authoritative,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
    } else if ([action isEqual:@"markerDelete"] && request.count == 2) {
      bool deleted = false;
      if (HRADeleteReconciliationMarker(&deleted)) {
        int status = HRAWriteJSONResponse(@{
          @"deleted": @(deleted),
          @"ok": @YES,
          @"version": @1,
        }) ? 0 : 1;
        HRAClearAuthorizedParent();
        return status;
      }
    }
    HRAWriteJSONResponse(@{ @"ok": @NO, @"version": @1 });
    HRAClearAuthorizedParent();
    return 1;
  }
}

static NSDictionary *_Nullable HRASigningInformationForStaticCode(
    SecStaticCodeRef code) {
  CFDictionaryRef information = NULL;
  if (SecCodeCopySigningInformation(
          code, kSecCSSigningInformation, &information) != errSecSuccess ||
      information == NULL) {
    return nil;
  }
  return CFBridgingRelease(information);
}

static NSData *_Nullable HRACodeDirectoryHash(NSDictionary *information) {
  id value = information[(__bridge NSString *)kSecCodeInfoUnique];
  return [value isKindOfClass:[NSData class]] && [value length] > 0 &&
          [value length] <= 64
      ? value
      : nil;
}

static bool HRAFileMetadataIdentityMatches(
    const struct stat *left,
    const struct stat *right) {
  return left != NULL && right != NULL &&
      left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
      left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
      left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
      left->st_size == right->st_size &&
      left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
      left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
      left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
      left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static bool HRALegacyGatewayFileMetadataIsExact(
    const struct stat *metadata,
    bool allowUnsealedDevelopment) {
  if (metadata == NULL || !S_ISREG(metadata->st_mode) ||
      metadata->st_nlink != 1 || metadata->st_uid != geteuid() ||
      metadata->st_size != HRALegacyGatewayByteLength) {
    return false;
  }
  mode_t permissions = metadata->st_mode & 07777;
  return permissions == 0755 ||
      (allowUnsealedDevelopment && permissions == 0700);
}

static bool HRAPathResolvesToItself(NSString *path) {
  const char *representation = path.fileSystemRepresentation;
  if (representation == NULL || representation[0] != '/') return false;
  char resolved[PATH_MAX];
  memset(resolved, 0, sizeof(resolved));
  if (realpath(representation, resolved) == NULL) return false;
  return strcmp(representation, resolved) == 0;
}

static bool HRAOpenedDescriptorNamesPath(int descriptor, NSString *path) {
  const char *representation = path.fileSystemRepresentation;
  if (descriptor < 0 || representation == NULL) return false;
  char expected[PATH_MAX];
  char actual[PATH_MAX];
  memset(expected, 0, sizeof(expected));
  memset(actual, 0, sizeof(actual));
  if (realpath(representation, expected) == NULL ||
      fcntl(descriptor, F_GETPATH, actual) != 0) {
    return false;
  }
  char canonicalActual[PATH_MAX];
  memset(canonicalActual, 0, sizeof(canonicalActual));
  if (realpath(actual, canonicalActual) == NULL) return false;
  return strcmp(expected, canonicalActual) == 0;
}

static bool HRAHashDescriptorIsExact(
    int descriptor,
    const uint8_t expected[CC_SHA256_DIGEST_LENGTH]) {
  if (descriptor < 0 || expected == NULL || lseek(descriptor, 0, SEEK_SET) != 0)
    return false;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  CC_SHA256_CTX context;
  memset(&context, 0, sizeof(context));
  uint8_t buffer[64 * 1024];
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  memset(buffer, 0, sizeof(buffer));
  memset(digest, 0, sizeof(digest));
  bool success = CC_SHA256_Init(&context) == 1;
  off_t length = 0;
  while (success) {
    ssize_t count = read(descriptor, buffer, sizeof(buffer));
    if (count > 0) {
      if (length > HRALegacyGatewayByteLength - count ||
          CC_SHA256_Update(&context, buffer, (CC_LONG)count) != 1) {
        success = false;
        break;
      }
      length += count;
      continue;
    }
    if (count == 0) break;
    if (errno == EINTR) continue;
    success = false;
  }
  success = success && length == HRALegacyGatewayByteLength &&
      CC_SHA256_Final(digest, &context) == 1 &&
      memcmp(digest, expected, CC_SHA256_DIGEST_LENGTH) == 0;
  HRASecureZero(buffer, sizeof(buffer));
  HRASecureZero(digest, sizeof(digest));
  HRASecureZero(&context, sizeof(context));
#pragma clang diagnostic pop
  return success;
}

static bool HRALegacyGatewayDescriptorRemainsExact(
    NSString *path,
    int descriptor,
    const struct stat *openedMetadata,
    bool allowUnsealedDevelopment) {
  struct stat pathMetadata;
  struct stat descriptorMetadata;
  struct stat afterHashMetadata;
  memset(&pathMetadata, 0, sizeof(pathMetadata));
  memset(&descriptorMetadata, 0, sizeof(descriptorMetadata));
  memset(&afterHashMetadata, 0, sizeof(afterHashMetadata));
  if (lstat(path.fileSystemRepresentation, &pathMetadata) != 0 ||
      fstat(descriptor, &descriptorMetadata) != 0 ||
      !HRALegacyGatewayFileMetadataIsExact(
          &pathMetadata, allowUnsealedDevelopment) ||
      !HRAFileMetadataIdentityMatches(openedMetadata, &pathMetadata) ||
      !HRAFileMetadataIdentityMatches(openedMetadata, &descriptorMetadata) ||
      !HRAOpenedDescriptorNamesPath(descriptor, path) ||
      !HRAHashDescriptorIsExact(descriptor, HRALegacyGatewaySHA256) ||
      fstat(descriptor, &afterHashMetadata) != 0 ||
      !HRAFileMetadataIdentityMatches(openedMetadata, &afterHashMetadata)) {
    return false;
  }
  return true;
}

static int HRAOpenExactLegacyGateway(
    NSString *path,
    bool allowUnsealedDevelopment,
    struct stat *outMetadata) {
  if (outMetadata == NULL) return -1;
  memset(outMetadata, 0, sizeof(*outMetadata));
  struct stat pathMetadata;
  memset(&pathMetadata, 0, sizeof(pathMetadata));
  if (lstat(path.fileSystemRepresentation, &pathMetadata) != 0 ||
      !HRALegacyGatewayFileMetadataIsExact(
          &pathMetadata, allowUnsealedDevelopment)) {
    return -1;
  }
  int descriptor = open(
      path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) return -1;
  struct stat descriptorMetadata;
  memset(&descriptorMetadata, 0, sizeof(descriptorMetadata));
  if (fstat(descriptor, &descriptorMetadata) != 0 ||
      !HRAFileMetadataIdentityMatches(&pathMetadata, &descriptorMetadata) ||
      !HRALegacyGatewayDescriptorRemainsExact(
          path,
          descriptor,
          &descriptorMetadata,
          allowUnsealedDevelopment)) {
    close(descriptor);
    return -1;
  }
  *outMetadata = descriptorMetadata;
  return descriptor;
}

static bool HRACertificateMatchesHashes(
    SecCertificateRef certificate,
    const uint8_t expectedSHA1[CC_SHA1_DIGEST_LENGTH],
    const uint8_t expectedSHA256[CC_SHA256_DIGEST_LENGTH]) {
  if (certificate == NULL || expectedSHA1 == NULL || expectedSHA256 == NULL)
    return false;
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
  bool matches = bytes != NULL && length > 0 && length <= UINT32_MAX &&
      CC_SHA1(bytes, (CC_LONG)length, sha1) != NULL &&
      CC_SHA256(bytes, (CC_LONG)length, sha256) != NULL &&
      memcmp(sha1, expectedSHA1, sizeof(sha1)) == 0 &&
      memcmp(sha256, expectedSHA256, sizeof(sha256)) == 0;
#pragma clang diagnostic pop
  CFRelease(raw);
  return matches;
}

static bool HRALegacyGatewayCertificateMetadataIsExact(
    NSDictionary *information,
    bool requireAvailableLeaf) {
  id rawCertificates =
      information[(__bridge NSString *)kSecCodeInfoCertificates];
  NSArray *certificates = nil;
  if (rawCertificates != nil) {
    if (![rawCertificates isKindOfClass:[NSArray class]]) return false;
    certificates = rawCertificates;
  } else {
    id rawTrust = information[(__bridge NSString *)kSecCodeInfoTrust];
    if (rawTrust != nil) {
      if (CFGetTypeID((__bridge CFTypeRef)rawTrust) != SecTrustGetTypeID())
        return false;
      CFArrayRef chain = SecTrustCopyCertificateChain(
          (__bridge SecTrustRef)rawTrust);
      certificates = chain == NULL ? nil : CFBridgingRelease(chain);
    }
  }
  if (certificates == nil || certificates.count == 0)
    return !requireAvailableLeaf;
  if (certificates.count != 1 && certificates.count != 2) return false;
  id leaf = certificates[0];
  if (CFGetTypeID((__bridge CFTypeRef)leaf) != SecCertificateGetTypeID() ||
      !HRACertificateMatchesHashes(
          (__bridge SecCertificateRef)leaf,
          HRAPreviewLeafCertificateSHA1,
          HRAPreviewLeafCertificateSHA256)) {
    return false;
  }
  if (certificates.count == 2) {
    id root = certificates[1];
    if (CFGetTypeID((__bridge CFTypeRef)root) != SecCertificateGetTypeID() ||
        !HRACertificateMatchesHashes(
            (__bridge SecCertificateRef)root,
            HRAPreviewRootCertificateSHA1,
            HRAPreviewRootCertificateSHA256)) {
      return false;
    }
  }
  return true;
}

static bool HRACodeDesignatedRequirementIsExact(SecStaticCodeRef code) {
  if (code == NULL) return false;
  SecRequirementRef requirement = NULL;
  if (SecCodeCopyDesignatedRequirement(
          code, kSecCSDefaultFlags, &requirement) != errSecSuccess ||
      requirement == NULL) {
    return false;
  }
  CFStringRef text = NULL;
  OSStatus status = SecRequirementCopyString(
      requirement, kSecCSDefaultFlags, &text);
  CFRelease(requirement);
  if (status != errSecSuccess || text == NULL) return false;
  bool exact = [(__bridge NSString *)text
      isEqualToString:HRALegacyGatewayRequirement];
  CFRelease(text);
  return exact;
}

static bool HRACodeOriginPathIsExact(
    SecStaticCodeRef code,
    NSString *expectedPath) {
  CFURLRef rawPath = NULL;
  if (code == NULL || expectedPath == nil ||
      SecCodeCopyPath(code, kSecCSDefaultFlags, &rawPath) != errSecSuccess ||
      rawPath == NULL) {
    return false;
  }
  NSURL *path = CFBridgingRelease(rawPath);
  return [path.path isEqualToString:expectedPath];
}

static bool HRAOuterBundleIsSealed(void) {
  NSString *bundlePath = NSBundle.mainBundle.bundleURL.path;
  if (bundlePath == nil ||
      ![bundlePath.pathExtension.lowercaseString isEqualToString:@"app"])
    return false;
  char resolved[PATH_MAX];
  memset(resolved, 0, sizeof(resolved));
  const char *bundleBytes = bundlePath.fileSystemRepresentation;
  if (bundleBytes == NULL || realpath(bundleBytes, resolved) == NULL ||
      strcmp(bundleBytes, resolved) != 0) return false;
  return hra_macos_release_outer_bundle_is_exact(
      bundleBytes, strlen(bundleBytes));
}

static NSDictionary *_Nullable HRACopyStaticCustodianIdentity(
    NSString *path,
    bool allowUnsealedDevelopment) {
  NSURL *resources = NSBundle.mainBundle.resourceURL;
  if (!allowUnsealedDevelopment) {
    if (resources == nil || !HRAOuterBundleIsSealed()) {
      return nil;
    } else {
      NSString *expected = [resources.path
          stringByAppendingPathComponent:
              @"runtime/bin/oprte-keychain-custodian"];
      if (![path isEqualToString:expected] ||
          !HRAPathResolvesToItself(path)) return nil;
    }
  }
  struct stat metadata;
  if (lstat(path.fileSystemRepresentation, &metadata) != 0 ||
      !S_ISREG(metadata.st_mode) || S_ISLNK(metadata.st_mode) ||
      metadata.st_nlink != 1 || (metadata.st_mode & 0111) == 0) {
    return nil;
  }
  uint8_t descriptorCDHash[HRA_MACOS_CDHASH_LENGTH];
  memset(descriptorCDHash, 0, sizeof(descriptorCDHash));
  const char *pathBytes = path.fileSystemRepresentation;
  if (!allowUnsealedDevelopment &&
      (pathBytes == NULL || !hra_macos_release_helper_identity_is_exact(
          pathBytes, strlen(pathBytes), descriptorCDHash))) {
    HRASecureZero(descriptorCDHash, sizeof(descriptorCDHash));
    return nil;
  }
  SecStaticCodeRef code = NULL;
  if (SecStaticCodeCreateWithPath(
          (__bridge CFURLRef)[NSURL fileURLWithPath:path],
          kSecCSDefaultFlags,
          &code) != errSecSuccess || code == NULL) {
    return nil;
  }
  OSStatus status = SecStaticCodeCheckValidity(
      code,
      kSecCSStrictValidate | kSecCSCheckAllArchitectures,
      NULL);
  NSDictionary *information = status == errSecSuccess
      ? HRASigningInformationForStaticCode(code)
      : nil;
  CFRelease(code);
  NSString *identifier = information[(__bridge NSString *)kSecCodeInfoIdentifier];
  NSData *hash = information == nil ? nil : HRACodeDirectoryHash(information);
  if (![identifier isEqualToString:HRAKeychainCustodianIdentifier] || hash == nil ||
      (!allowUnsealedDevelopment &&
       (!HRAReleaseCodeInformationIsExact(
            information, HRAKeychainCustodianIdentifier) ||
        hash.length != sizeof(descriptorCDHash) ||
        memcmp(hash.bytes,
               descriptorCDHash,
               sizeof(descriptorCDHash)) != 0))) {
    HRASecureZero(descriptorCDHash, sizeof(descriptorCDHash));
    return nil;
  }
  NSString *team = information[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
  NSDictionary *result = @{
    @"hash": hash,
    @"identifier": identifier,
    @"path": path,
    @"release": @(!allowUnsealedDevelopment),
    @"team": [team isKindOfClass:[NSString class]] ? team : @"",
  };
  HRASecureZero(descriptorCDHash, sizeof(descriptorCDHash));
  return result;
}

static bool HRADynamicCustodianMatches(
    pid_t processIdentifier,
    NSDictionary *expected) {
  NSDictionary *attributes = @{
    (__bridge NSString *)kSecGuestAttributePid: @(processIdentifier),
  };
  SecCodeRef code = NULL;
  if (SecCodeCopyGuestWithAttributes(
          NULL,
          (__bridge CFDictionaryRef)attributes,
          kSecCSDefaultFlags,
          &code) != errSecSuccess || code == NULL) {
    return false;
  }
  OSStatus status = SecCodeCheckValidity(code, kSecCSStrictValidate, NULL);
  CFDictionaryRef raw = NULL;
  if (status == errSecSuccess) {
    status = SecCodeCopySigningInformation(
        code, kSecCSSigningInformation, &raw);
  }
  CFRelease(code);
  if (status != errSecSuccess || raw == NULL) return false;
  NSDictionary *actual = CFBridgingRelease(raw);
  NSData *hash = HRACodeDirectoryHash(actual);
  NSString *identifier = actual[(__bridge NSString *)kSecCodeInfoIdentifier];
  NSString *team = actual[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
  if (![team isKindOfClass:[NSString class]]) team = @"";
  NSString *path = expected[@"path"];
  const char *pathBytes = path.fileSystemRepresentation;
  const char *identifierBytes = [expected[@"identifier"] UTF8String];
  bool release = [expected[@"release"] isEqual:@YES];
  bool selfManagedDynamic = !release ||
      (pathBytes != NULL && identifierBytes != NULL &&
       hra_macos_self_managed_dynamic_code_matches(
           processIdentifier,
           pathBytes,
           strlen(pathBytes),
           identifierBytes,
           strlen(identifierBytes),
           expected[@"hash"] == nil ? NULL : [expected[@"hash"] bytes],
           HRA_MACOS_CODE_DIRECTORY_RUNTIME));
  return hash != nil && selfManagedDynamic &&
      (!release || HRAReleaseCodeInformationIsExact(
          actual, HRAKeychainCustodianIdentifier)) &&
      [hash isEqual:expected[@"hash"]] &&
      [identifier isEqual:expected[@"identifier"]] &&
      [team isEqual:expected[@"team"]];
}

static bool HRALegacyGatewayIdentityIsExact(
    SecStaticCodeRef code,
    NSDictionary *information,
    NSString *expectedPath,
    bool requireAvailableLeaf) {
  NSString *identifier =
      information[(__bridge NSString *)kSecCodeInfoIdentifier];
  id team = information[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
  id flags = information[(__bridge NSString *)kSecCodeInfoFlags];
  NSData *hash = HRACodeDirectoryHash(information);
  return [identifier isEqualToString:HRALegacyGatewayIdentifier] &&
      team == nil && [flags isKindOfClass:[NSNumber class]] &&
      [(NSNumber *)flags unsignedIntValue] == kSecCodeSignatureRuntime &&
      hash.length == sizeof(HRALegacyGatewayCDHash) &&
      memcmp(hash.bytes,
             HRALegacyGatewayCDHash,
             sizeof(HRALegacyGatewayCDHash)) == 0 &&
      HRACodeDesignatedRequirementIsExact(code) &&
      HRACodeOriginPathIsExact(code, expectedPath) &&
      HRALegacyGatewayCertificateMetadataIsExact(
          information, requireAvailableLeaf);
}

static SecRequirementRef _Nullable HRACreateLegacyGatewayRequirement(void) {
  SecRequirementRef requirement = NULL;
  if (SecRequirementCreateWithString(
          (__bridge CFStringRef)HRALegacyGatewayRequirement,
          kSecCSDefaultFlags,
          &requirement) != errSecSuccess) {
    return NULL;
  }
  return requirement;
}

static bool HRASelfManagedLegacyGatewayIdentityIsExact(
    NSString *path,
    const struct stat *metadata,
    HRAMacOSSelfManagedCodeIdentity *outIdentity) {
  if (path == nil || metadata == NULL || outIdentity == NULL)
    return false;
  const char *canonicalPath = path.fileSystemRepresentation;
  const char *identifier = HRALegacyGatewayIdentifier.UTF8String;
  size_t canonicalPathLength = canonicalPath == NULL
      ? 0
      : strlen(canonicalPath);
  size_t identifierLength = identifier == NULL ? 0 : strlen(identifier);
  if (canonicalPathLength == 0 || canonicalPathLength >= PATH_MAX ||
      identifierLength == 0) {
    return false;
  }
  HRAMacOSSelfManagedCodeExpectation expectation;
  memset(&expectation, 0, sizeof(expectation));
  expectation.canonical_path = canonicalPath;
  expectation.canonical_path_length = canonicalPathLength;
  expectation.identifier = identifier;
  expectation.identifier_length = identifierLength;
  expectation.expected_uid = (uint32_t)metadata->st_uid;
  expectation.expected_permissions =
      (uint32_t)metadata->st_mode & 07777u;
  expectation.expected_code_directory_flags =
      HRA_MACOS_CODE_DIRECTORY_RUNTIME;
  expectation.expected_hash_type =
      HRA_MACOS_CODE_DIRECTORY_HASH_SHA256;
  expectation.expected_page_size_shift = 12;
  memcpy(expectation.leaf_certificate_sha1,
         HRAPreviewLeafCertificateSHA1,
         sizeof(HRAPreviewLeafCertificateSHA1));
  memcpy(expectation.leaf_certificate_sha256,
         HRAPreviewLeafCertificateSHA256,
         sizeof(HRAPreviewLeafCertificateSHA256));
  memcpy(expectation.root_certificate_sha1,
         HRAPreviewRootCertificateSHA1,
         sizeof(HRAPreviewRootCertificateSHA1));
  memcpy(expectation.root_certificate_sha256,
         HRAPreviewRootCertificateSHA256,
         sizeof(HRAPreviewRootCertificateSHA256));
  HRAMacOSSelfManagedCodeIdentity identity;
  memset(&identity, 0, sizeof(identity));
  bool exact = hra_macos_verify_self_managed_code_identity(
      &expectation, &identity) &&
      identity.device == (uint64_t)metadata->st_dev &&
      identity.inode == (uint64_t)metadata->st_ino &&
      identity.byte_length == (uint64_t)metadata->st_size &&
      identity.mode == (uint32_t)metadata->st_mode &&
      identity.link_count == (uint32_t)metadata->st_nlink &&
      identity.uid == (uint32_t)metadata->st_uid &&
      identity.gid == (uint32_t)metadata->st_gid &&
      identity.byte_length == (uint64_t)HRALegacyGatewayByteLength &&
      identity.code_directory_flags ==
          HRA_MACOS_CODE_DIRECTORY_RUNTIME &&
      identity.hash_type == HRA_MACOS_CODE_DIRECTORY_HASH_SHA256 &&
      identity.page_size_shift == 12 &&
      memcmp(identity.cdhash,
             HRALegacyGatewayCDHash,
             sizeof(HRALegacyGatewayCDHash)) == 0;
  if (exact) *outIdentity = identity;
  HRASecureZero(&identity, sizeof(identity));
  return exact;
}

static bool HRASelfManagedLegacyGatewayDynamicIdentityIsExact(
    pid_t processIdentifier,
    NSString *path,
    const HRAMacOSSelfManagedCodeIdentity *expectedIdentity) {
  if (path == nil || expectedIdentity == NULL) return false;
  const char *canonicalPath = path.fileSystemRepresentation;
  const char *identifier = HRALegacyGatewayIdentifier.UTF8String;
  size_t canonicalPathLength = canonicalPath == NULL
      ? 0
      : strlen(canonicalPath);
  size_t identifierLength = identifier == NULL ? 0 : strlen(identifier);
  return canonicalPathLength > 0 && identifierLength > 0 &&
      hra_macos_self_managed_dynamic_code_matches(
          processIdentifier,
          canonicalPath,
          canonicalPathLength,
          identifier,
          identifierLength,
          expectedIdentity->cdhash,
          HRA_MACOS_CODE_DIRECTORY_RUNTIME);
}

static void HRARecordLegacyHarnessCustodyFailure(
    HRALegacyHarnessCustodyFailureSubstage *outFailureSubstage,
    HRALegacyHarnessCustodyFailureSubstage failureSubstage) {
  if (outFailureSubstage != NULL &&
      *outFailureSubstage == HRALegacyHarnessCustodyFailureNone) {
    *outFailureSubstage = failureSubstage;
  }
}

static NSDictionary *_Nullable HRACopyStaticLegacyGatewayIdentity(
    NSString *path,
    bool allowUnsealedDevelopment,
    int *outDescriptor,
    struct stat *outMetadata,
    HRAMacOSSelfManagedCodeIdentity *outSelfManagedIdentity,
    HRALegacyHarnessCustodyFailureSubstage *outFailureSubstage) {
  if (outDescriptor == NULL || outMetadata == NULL ||
      outSelfManagedIdentity == NULL) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureStaticBundle);
    return nil;
  }
  *outDescriptor = -1;
  memset(outMetadata, 0, sizeof(*outMetadata));
  memset(outSelfManagedIdentity, 0, sizeof(*outSelfManagedIdentity));
  NSURL *resources = NSBundle.mainBundle.resourceURL;
  if (!allowUnsealedDevelopment) {
    if (resources == nil || !HRAOuterBundleIsSealed()) {
      HRARecordLegacyHarnessCustodyFailure(
          outFailureSubstage,
          HRALegacyHarnessCustodyFailureStaticBundle);
      return nil;
    }
    NSString *expected = [resources.path
        stringByAppendingPathComponent:HRALegacyGatewayRelativePath];
    if (![path isEqualToString:expected] || !HRAPathResolvesToItself(path)) {
      HRARecordLegacyHarnessCustodyFailure(
          outFailureSubstage,
          HRALegacyHarnessCustodyFailureStaticBundle);
      return nil;
    }
  }
  int descriptor = HRAOpenExactLegacyGateway(
      path, allowUnsealedDevelopment, outMetadata);
  if (descriptor < 0) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureStaticBundle);
    return nil;
  }
  SecStaticCodeRef code = NULL;
  if (SecStaticCodeCreateWithPath(
          (__bridge CFURLRef)[NSURL fileURLWithPath:path],
          kSecCSDefaultFlags,
          &code) != errSecSuccess || code == NULL) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureStaticSecurityMetadata);
    close(descriptor);
    return nil;
  }
  SecRequirementRef requirement = HRACreateLegacyGatewayRequirement();
  if (requirement == NULL) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureStaticSecurityMetadata);
    CFRelease(code);
    close(descriptor);
    return nil;
  }
  // Preserve the platform validity check where the self-managed Preview root
  // is locally trusted. Exact immutable identity below remains authoritative
  // when a host deliberately has no such trust-store entry.
  OSStatus platformValidity = SecStaticCodeCheckValidity(
      code,
      kSecCSStrictValidate | kSecCSCheckAllArchitectures,
      requirement);
  (void)platformValidity;
  CFRelease(requirement);
  NSDictionary *information = HRASigningInformationForStaticCode(code);
  HRAMacOSSelfManagedCodeIdentity selfManagedIdentity;
  memset(&selfManagedIdentity, 0, sizeof(selfManagedIdentity));
  bool selfManagedExact = HRASelfManagedLegacyGatewayIdentityIsExact(
      path, outMetadata, &selfManagedIdentity);
  if (!selfManagedExact) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureStaticSelfManaged);
  }
  bool securityMetadataExact = selfManagedExact && information != nil &&
      HRALegacyGatewayIdentityIsExact(
          code, information, path, false);
  if (selfManagedExact && !securityMetadataExact) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureStaticSecurityMetadata);
  }
  bool descriptorExact = securityMetadataExact &&
      HRALegacyGatewayDescriptorRemainsExact(
          path, descriptor, outMetadata, allowUnsealedDevelopment);
  if (securityMetadataExact && !descriptorExact) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureStaticBundle);
  }
  bool exact = selfManagedExact && securityMetadataExact && descriptorExact;
  CFRelease(code);
  if (!exact) {
    close(descriptor);
    memset(outMetadata, 0, sizeof(*outMetadata));
    HRASecureZero(&selfManagedIdentity, sizeof(selfManagedIdentity));
    return nil;
  }
  *outDescriptor = descriptor;
  *outSelfManagedIdentity = selfManagedIdentity;
  HRASecureZero(&selfManagedIdentity, sizeof(selfManagedIdentity));
  return information;
}

static bool HRADynamicLegacyGatewayMatches(
    pid_t processIdentifier,
    NSString *expectedPath,
    const HRAMacOSSelfManagedCodeIdentity *expectedSelfManagedIdentity,
    HRALegacyHarnessCustodyFailureSubstage *outFailureSubstage) {
  NSDictionary *attributes = @{
    (__bridge NSString *)kSecGuestAttributePid: @(processIdentifier),
  };
  SecCodeRef code = NULL;
  if (SecCodeCopyGuestWithAttributes(
          NULL,
          (__bridge CFDictionaryRef)attributes,
          kSecCSDefaultFlags,
          &code) != errSecSuccess || code == NULL) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureDynamicSecurityMetadata);
    return false;
  }
  SecRequirementRef requirement = HRACreateLegacyGatewayRequirement();
  if (requirement == NULL) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureDynamicSecurityMetadata);
    CFRelease(code);
    return false;
  }
  OSStatus platformValidity = SecCodeCheckValidity(
      code, kSecCSStrictValidate, requirement);
  (void)platformValidity;
  CFRelease(requirement);
  CFDictionaryRef raw = NULL;
  OSStatus status = SecCodeCopySigningInformation(
      code,
      kSecCSSigningInformation | kSecCSDynamicInformation,
      &raw);
  NSDictionary *information = status == errSecSuccess && raw != NULL
      ? CFBridgingRelease(raw)
      : nil;
  id rawDynamicStatus =
      information[(__bridge NSString *)kSecCodeInfoStatus];
  bool dynamicallyValid =
      [rawDynamicStatus isKindOfClass:[NSNumber class]] &&
      ([(NSNumber *)rawDynamicStatus unsignedIntValue] &
       kSecCodeStatusValid) == kSecCodeStatusValid;
  SecStaticCodeRef staticCode = NULL;
  status = SecCodeCopyStaticCode(
      code, kSecCSUseAllArchitectures, &staticCode);
  bool pidHashExact = HRASelfManagedLegacyGatewayDynamicIdentityIsExact(
      processIdentifier, expectedPath, expectedSelfManagedIdentity);
  if (!pidHashExact) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureDynamicPidHash);
  }
  bool securityMetadataExact = pidHashExact &&
      dynamicallyValid &&
      HRALegacyGatewayIdentityIsExact(
          staticCode, information, expectedPath, false);
  bool exact = status == errSecSuccess && securityMetadataExact;
  if (pidHashExact && !exact) {
    HRARecordLegacyHarnessCustodyFailure(
        outFailureSubstage,
        HRALegacyHarnessCustodyFailureDynamicSecurityMetadata);
  }
  if (staticCode != NULL) CFRelease(staticCode);
  CFRelease(code);
  return status == errSecSuccess && pidHashExact && securityMetadataExact;
}

static uint64_t HRAMonotonicMilliseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static bool HRADeadlineFromTimeout(
    uint64_t start,
    uint32_t timeoutMilliseconds,
    uint64_t *outDeadline) {
  if (start == 0 || timeoutMilliseconds == 0 || outDeadline == NULL ||
      UINT64_MAX - start < timeoutMilliseconds) {
    return false;
  }
  *outDeadline = start + timeoutMilliseconds;
  return true;
}

static bool HRADeadlineHasTime(uint64_t deadline) {
  uint64_t now = HRAMonotonicMilliseconds();
  return deadline > 0 && now > 0 && now < deadline;
}

static int HRADeadlineRemainingMilliseconds(uint64_t deadline) {
  uint64_t now = HRAMonotonicMilliseconds();
  if (deadline == 0 || now == 0 || now >= deadline) return 0;
  uint64_t remaining = deadline - now;
  return (int)(remaining > INT_MAX ? INT_MAX : remaining);
}

static uint64_t HRACleanupDeadline(uint32_t timeoutMilliseconds) {
  uint64_t now = HRAMonotonicMilliseconds();
  uint64_t deadline = 0;
  return HRADeadlineFromTimeout(now, timeoutMilliseconds, &deadline)
      ? deadline
      : 0;
}

static bool HRAWaitForChildAndReap(
    pid_t processIdentifier,
    uint64_t deadline,
    int *outStatus) {
  if (processIdentifier <= 1 || deadline == 0 ||
      outStatus == NULL) return false;
  while (true) {
    if (!HRADeadlineHasTime(deadline)) return false;
    int status = 0;
    pid_t waited = waitpid(processIdentifier, &status, WNOHANG);
    if (waited == processIdentifier) {
      *outStatus = status;
      return HRADeadlineHasTime(deadline);
    }
    if (waited < 0 && errno != EINTR) return false;
    int remaining = HRADeadlineRemainingMilliseconds(deadline);
    if (remaining <= 0) return false;
    struct timespec pause = {
      .tv_sec = 0,
      .tv_nsec = (long)(remaining < 5 ? remaining : 5) * 1000 * 1000,
    };
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
}

static bool HRAReapExitedChild(
    pid_t processIdentifier,
    int *outStatus) {
  if (processIdentifier <= 1 || outStatus == NULL) return false;
  while (true) {
    int status = 0;
    pid_t waited = waitpid(processIdentifier, &status, 0);
    if (waited == processIdentifier) {
      *outStatus = status;
      return true;
    }
    if (waited < 0 && errno == EINTR) continue;
    return false;
  }
}

static HRAChildLeaseObservation HRAObserveChildLease(
    pid_t processIdentifier,
    siginfo_t *outExitInformation) {
  if (processIdentifier <= 1 || outExitInformation == NULL)
    return HRAChildLeaseAmbiguous;
  while (true) {
    memset(outExitInformation, 0, sizeof(*outExitInformation));
    errno = 0;
    int status = waitid(
        P_PID,
        (id_t)processIdentifier,
        outExitInformation,
        WEXITED | WNOWAIT | WNOHANG);
    if (status == 0) return HRAChildLeaseRetained;
    if (errno == EINTR) continue;
    return errno == ECHILD
        ? HRAChildLeaseLost
        : HRAChildLeaseAmbiguous;
  }
}

static bool HRAChildExitInformationIsTerminal(
    const siginfo_t *information,
    pid_t expectedProcessIdentifier) {
  return information != NULL &&
      information->si_pid == expectedProcessIdentifier &&
      (information->si_code == CLD_EXITED ||
       information->si_code == CLD_KILLED ||
       information->si_code == CLD_DUMPED);
}

static bool HRAKillAndReapUnregistered(
    pid_t processIdentifier,
    uint64_t deadline) {
  siginfo_t exitInformation;
  if (processIdentifier <= 1 || deadline == 0 ||
      HRAObserveChildLease(processIdentifier, &exitInformation) !=
          HRAChildLeaseRetained ||
      (kill(processIdentifier, SIGKILL) != 0 && errno != ESRCH)) {
    return false;
  }
  int status = 0;
  return HRAWaitForChildAndReap(processIdentifier, deadline, &status);
}

static bool HRAWaitForChildExitUnreaped(
    pid_t processIdentifier,
    uint64_t deadline,
    siginfo_t *outExitInformation,
    bool *outLeaseLost) {
  if (processIdentifier <= 1 || deadline == 0 ||
      outExitInformation == NULL || outLeaseLost == NULL) return false;
  *outLeaseLost = false;
  while (true) {
    if (!HRADeadlineHasTime(deadline)) return false;
    HRAChildLeaseObservation observation = HRAObserveChildLease(
        processIdentifier, outExitInformation);
    if (observation == HRAChildLeaseLost ||
        observation == HRAChildLeaseAmbiguous) {
      *outLeaseLost = true;
      return false;
    }
    if (HRAChildExitInformationIsTerminal(
            outExitInformation, processIdentifier)) {
      return HRADeadlineHasTime(deadline);
    }
    int remaining = HRADeadlineRemainingMilliseconds(deadline);
    if (remaining <= 0) return false;
    struct timespec pause = {
      .tv_sec = 0,
      .tv_nsec = (long)(remaining < 5 ? remaining : 5) * 1000 * 1000,
    };
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
}

static bool HRABeginCustodianOperation(uint64_t *outGeneration) {
  if (outGeneration == NULL) return false;
  os_unfair_lock_lock(&HRACustodianProcessLock);
  bool admitted = HRACustodianGenerationPrepared &&
      !HRACustodianGenerationCancelled &&
      !HRACustodianUntrackedRetirementUnproven &&
      atomic_load(&HRACurrentCustodianProcess) == -1;
  *outGeneration = HRACustodianGeneration;
  os_unfair_lock_unlock(&HRACustodianProcessLock);
  return admitted;
}

static bool HRARegisterAndResumeCustodianProcess(
    pid_t processIdentifier,
    uint64_t generation,
    uint64_t deadline,
    bool *outRegistered) {
  if (processIdentifier <= 1 || outRegistered == NULL) return false;
  *outRegistered = false;
  os_unfair_lock_lock(&HRACustodianProcessLock);
  bool registered = HRACustodianGenerationPrepared &&
      !HRACustodianGenerationCancelled &&
      !HRACustodianUntrackedRetirementUnproven &&
      HRACustodianGeneration == generation &&
      atomic_load(&HRACurrentCustodianProcess) == -1 &&
      HRADeadlineHasTime(deadline);
  if (registered) {
    atomic_store(&HRACurrentCustodianProcess, (int)processIdentifier);
    *outRegistered = true;
    registered = kill(processIdentifier, SIGCONT) == 0;
  }
  os_unfair_lock_unlock(&HRACustodianProcessLock);
  return registered;
}

static void HRAMarkCustodianUntrackedRetirementUnproven(void) {
  os_unfair_lock_lock(&HRACustodianProcessLock);
  HRACustodianUntrackedRetirementUnproven = true;
  if (atomic_load(&HRACurrentCustodianProcess) == -1) {
    atomic_store(
        &HRACurrentCustodianProcess,
        HRACustodianRetirementUnproven);
  }
  os_unfair_lock_unlock(&HRACustodianProcessLock);
}

static bool HRARetireRegisteredCustodianProcess(
    pid_t processIdentifier,
    uint64_t deadline,
    bool terminate,
    int *outStatus) {
  if (processIdentifier <= 1 || deadline == 0 || outStatus == NULL) {
    return false;
  }
  *outStatus = INT_MIN;
  os_unfair_lock_lock(&HRACustodianProcessLock);
  if (atomic_load(&HRACurrentCustodianProcess) != processIdentifier) {
    bool alreadyRetired =
        atomic_load(&HRACurrentCustodianProcess) == -1;
    os_unfair_lock_unlock(&HRACustodianProcessLock);
    return alreadyRetired;
  }
  siginfo_t leaseInformation;
  HRAChildLeaseObservation lease = HRAObserveChildLease(
      processIdentifier, &leaseInformation);
  if (lease != HRAChildLeaseRetained) {
    atomic_store(
        &HRACurrentCustodianProcess,
        HRACustodianRetirementUnproven);
    HRACustodianUntrackedRetirementUnproven = true;
    os_unfair_lock_unlock(&HRACustodianProcessLock);
    return false;
  }
  bool signalled = !terminate ||
      kill(processIdentifier, SIGKILL) == 0 || errno == ESRCH;
  os_unfair_lock_unlock(&HRACustodianProcessLock);
  if (!signalled) return false;

  siginfo_t exitInformation;
  bool leaseLost = false;
  if (!HRAWaitForChildExitUnreaped(
          processIdentifier,
          deadline,
          &exitInformation,
          &leaseLost)) {
    if (leaseLost) {
      os_unfair_lock_lock(&HRACustodianProcessLock);
      if (atomic_load(&HRACurrentCustodianProcess) == processIdentifier) {
        atomic_store(
            &HRACurrentCustodianProcess,
            HRACustodianRetirementUnproven);
        HRACustodianUntrackedRetirementUnproven = true;
      }
      os_unfair_lock_unlock(&HRACustodianProcessLock);
    }
    return false;
  }
  os_unfair_lock_lock(&HRACustodianProcessLock);
  if (atomic_load(&HRACurrentCustodianProcess) != processIdentifier) {
    os_unfair_lock_unlock(&HRACustodianProcessLock);
    return false;
  }
  // The unreaped child still reserves its PID while this synchronized state
  // transition removes all signal paths to the numeric identifier.
  atomic_store(&HRACurrentCustodianProcess, HRAProcessRetiring);
  os_unfair_lock_unlock(&HRACustodianProcessLock);

  int status = 0;
  // WNOWAIT already proved this exact child exited while its PID remained
  // leased. Reap unconditionally after the nonsignal transition; deadline
  // expiry disqualifies success but must not strand a zombie.
  bool reaped = HRAReapExitedChild(processIdentifier, &status);
  if (reaped) *outStatus = status;
  bool timely = reaped && HRADeadlineHasTime(deadline);
  os_unfair_lock_lock(&HRACustodianProcessLock);
  if (atomic_load(&HRACurrentCustodianProcess) == HRAProcessRetiring) {
    atomic_store(
        &HRACurrentCustodianProcess,
        reaped ? -1 : HRACustodianRetirementUnproven);
  }
  os_unfair_lock_unlock(&HRACustodianProcessLock);
  return timely;
}

static void HRAPoisonUnretiredCustodianProcess(pid_t processIdentifier) {
  os_unfair_lock_lock(&HRACustodianProcessLock);
  int current = atomic_load(&HRACurrentCustodianProcess);
  if (current == processIdentifier || current == HRAProcessRetiring) {
    atomic_store(
        &HRACurrentCustodianProcess,
        HRACustodianRetirementUnproven);
  }
  os_unfair_lock_unlock(&HRACustodianProcessLock);
}

static bool HRABeginLegacyGatewayOperation(uint64_t *outGeneration) {
  if (outGeneration == NULL) return false;
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  bool admitted = HRALegacyGatewayGenerationPrepared &&
      !HRALegacyGatewayGenerationCancelled &&
      !HRALegacyUntrackedRetirementUnproven &&
      atomic_load(&HRACurrentLegacyGatewayProcess) == -1;
  *outGeneration = HRALegacyGatewayGeneration;
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  return admitted;
}

static bool HRARegisterAndResumeLegacyGatewayProcess(
    pid_t processIdentifier,
    uint64_t generation,
    uint64_t deadline,
    bool *outRegistered) {
  if (processIdentifier <= 1 || outRegistered == NULL) return false;
  *outRegistered = false;
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  bool registered = HRALegacyGatewayGenerationPrepared &&
      !HRALegacyGatewayGenerationCancelled &&
      !HRALegacyUntrackedRetirementUnproven &&
      HRALegacyGatewayGeneration == generation &&
      atomic_load(&HRACurrentLegacyGatewayProcess) == -1 &&
      HRADeadlineHasTime(deadline);
  if (registered) {
    atomic_store(&HRACurrentLegacyGatewayProcess, (int)processIdentifier);
    *outRegistered = true;
    registered = kill(processIdentifier, SIGCONT) == 0;
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  return registered;
}

static void HRAMarkLegacyUntrackedRetirementUnproven(void) {
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  HRALegacyUntrackedRetirementUnproven = true;
  if (atomic_load(&HRACurrentLegacyGatewayProcess) == -1) {
    atomic_store(
        &HRACurrentLegacyGatewayProcess,
        HRALegacyRetirementUnproven);
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
}

// proc_listpids deliberately includes both allproc and zombproc. A zombie has
// no executable state and cannot create another descendant, so retirement must
// distinguish it from a live process instead of depending on another process
// eventually collecting it. Every listed PID is re-read to close enumeration,
// exit, group-change, and PID-reuse races; any ambiguous state fails closed.
static bool HRALegacyProcessGroupHasNoLiveMembers(
    pid_t groupLeader,
    bool ignoreUnreapedLeader) {
  pid_t members[1024];
  memset(members, 0, sizeof(members));
  int listedBytes = proc_listpids(
      PROC_PGRP_ONLY,
      (uint32_t)groupLeader,
      members,
      (int)sizeof(members));
  if (listedBytes < 0 || listedBytes >= (int)sizeof(members) ||
      listedBytes % (int)sizeof(pid_t) != 0) {
    return false;
  }
  size_t count = (size_t)listedBytes / sizeof(pid_t);
  for (size_t index = 0; index < count; index += 1) {
    pid_t member = members[index];
    if (member <= 0 || (ignoreUnreapedLeader && member == groupLeader)) {
      continue;
    }
    struct proc_bsdinfo information;
    memset(&information, 0, sizeof(information));
    errno = 0;
    int informationBytes = proc_pidinfo(
        member,
        PROC_PIDTBSDINFO,
        0,
        &information,
        (int)sizeof(information));
    if (informationBytes == 0 && errno == ESRCH) continue;
    if (informationBytes != (int)sizeof(information) ||
        information.pbi_pid != (uint32_t)member) {
      return false;
    }
    if (information.pbi_pgid != (uint32_t)groupLeader) continue;
    if (information.pbi_status != SZOMB) return false;
  }
  return true;
}

static bool HRAWaitForExitedLegacyLeaderAndGroupQuiescence(
    pid_t groupLeader,
    uint64_t deadline,
    bool *outLeaseLost) {
  if (groupLeader <= 1 || deadline == 0 || outLeaseLost == NULL) return false;
  *outLeaseLost = false;
  while (true) {
    if (!HRADeadlineHasTime(deadline)) return false;
    siginfo_t exitInformation;
    HRAChildLeaseObservation observation = HRAObserveChildLease(
        groupLeader, &exitInformation);
    if (observation != HRAChildLeaseRetained) {
      *outLeaseLost = true;
      return false;
    }
    bool leaderExited = HRAChildExitInformationIsTerminal(
        &exitInformation, groupLeader);
    if (leaderExited && HRALegacyProcessGroupHasNoLiveMembers(
            groupLeader, true)) {
      return HRADeadlineHasTime(deadline);
    }
    int remaining = HRADeadlineRemainingMilliseconds(deadline);
    if (remaining <= 0) return false;
    struct timespec pause = {
      .tv_sec = 0,
      .tv_nsec = (long)(remaining < 5 ? remaining : 5) * 1000 * 1000,
    };
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
}

/// Kills the complete group and proves that no member retains executable state
/// while the unreaped leader still reserves its numeric PID/PGID. It then
/// removes every signal path and reaps the leader. The pre-reap proof is the
/// authoritative retirement boundary: after it succeeds, every descendant is
/// inert and no member can create or admit another process. Re-querying the
/// numeric PGID after reap would instead observe an unrelated reuse race.
static bool HRAContainAndReapRegisteredLegacyProcessGroup(
    pid_t groupLeader,
    uint64_t deadline,
    int *outStatus) {
  if (groupLeader <= 1 || deadline == 0 || outStatus == NULL) return false;
  *outStatus = INT_MIN;
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  if (atomic_load(&HRACurrentLegacyGatewayProcess) != groupLeader) {
    bool alreadyRetired =
        atomic_load(&HRACurrentLegacyGatewayProcess) == -1;
    os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
    return alreadyRetired;
  }
  siginfo_t leaseInformation;
  HRAChildLeaseObservation lease = HRAObserveChildLease(
      groupLeader, &leaseInformation);
  if (lease != HRAChildLeaseRetained) {
    atomic_store(
        &HRACurrentLegacyGatewayProcess,
        HRALegacyRetirementUnproven);
    HRALegacyUntrackedRetirementUnproven = true;
    os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
    return false;
  }
  errno = 0;
  int signalStatus = kill(-groupLeader, SIGKILL);
  int signalError = errno;
  // Darwin reports EPERM when this process group contains only an unreaped
  // zombie leader. EPERM never proves retirement: it only permits the exact
  // leader-exit and no-live-member proof below to decide. A live or ambiguous
  // member remains visible there and fails closed at the deadline.
  bool signalAttemptAdmissible = signalStatus == 0 ||
      signalError == ESRCH || signalError == EPERM;
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  bool leaseLost = false;
  if (!signalAttemptAdmissible ||
      !HRAWaitForExitedLegacyLeaderAndGroupQuiescence(
          groupLeader, deadline, &leaseLost)) {
    if (leaseLost) {
      os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
      if (atomic_load(&HRACurrentLegacyGatewayProcess) == groupLeader) {
        atomic_store(
            &HRACurrentLegacyGatewayProcess,
            HRALegacyRetirementUnproven);
        HRALegacyUntrackedRetirementUnproven = true;
      }
      os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
    }
    return false;
  }
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  if (atomic_load(&HRACurrentLegacyGatewayProcess) != groupLeader) {
    os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
    return false;
  }
  // The unreaped leader still reserves both PID and PGID. Remove the PGID from
  // every signal path under the cancellation lock before releasing that lease.
  atomic_store(&HRACurrentLegacyGatewayProcess, HRAProcessRetiring);
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);

  int status = 0;
  bool reaped = HRAReapExitedChild(groupLeader, &status);
  if (reaped) *outStatus = status;
  bool timely = reaped && HRADeadlineHasTime(deadline);
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  if (atomic_load(&HRACurrentLegacyGatewayProcess) == HRAProcessRetiring) {
    atomic_store(
        &HRACurrentLegacyGatewayProcess,
        reaped ? -1 : HRALegacyRetirementUnproven);
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  return timely;
}

static void HRAPoisonUnretiredLegacyProcess(pid_t processIdentifier) {
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  int current = atomic_load(&HRACurrentLegacyGatewayProcess);
  if (current == processIdentifier || current == HRAProcessRetiring) {
    atomic_store(
        &HRACurrentLegacyGatewayProcess,
        HRALegacyRetirementUnproven);
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
}

static bool HRACopySelfAuditToken(audit_token_t *outToken) {
  if (outToken == NULL) return false;
  memset(outToken, 0, sizeof(*outToken));
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  return task_info(
      mach_task_self(),
      TASK_AUDIT_TOKEN,
      (task_info_t)outToken,
      &count) == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT &&
      audit_token_to_pid(*outToken) == getpid() &&
      audit_token_to_pidversion(*outToken) > 0;
}

static bool HRACustodianChildGenerationIsExact(
    pid_t processIdentifier,
    bool requireStopped,
    uint64_t *outStartSeconds,
    uint64_t *outStartMicroseconds) {
  if (processIdentifier <= 1 || outStartSeconds == NULL ||
      outStartMicroseconds == NULL) return false;
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
      information.pbi_ppid != (uint32_t)getpid() ||
      (requireStopped && information.pbi_status != SSTOP) ||
      information.pbi_start_tvsec == 0) {
    return false;
  }
  *outStartSeconds = information.pbi_start_tvsec;
  *outStartMicroseconds = information.pbi_start_tvusec;
  return true;
}

static void HRAEncodeAuditTokenHex(
    const audit_token_t *token,
    char output[sizeof(audit_token_t) * 2 + 1]) {
  static const char alphabet[] = "0123456789abcdef";
  const uint8_t *bytes = (const uint8_t *)token;
  for (size_t index = 0; index < sizeof(*token); index += 1) {
    output[index * 2] = alphabet[bytes[index] >> 4];
    output[index * 2 + 1] = alphabet[bytes[index] & 0x0f];
  }
  output[sizeof(*token) * 2] = '\0';
}

bool hra_macos_run_attested_keychain_custodian(
    const char *path,
    size_t path_length,
    const uint8_t *request,
    size_t request_length,
    uint8_t *response,
    size_t response_capacity,
    size_t *out_response_length,
    uint32_t timeout_milliseconds,
    bool allow_unsealed_development) {
  @autoreleasepool {
    if (path == NULL || path_length == 0 || path_length > 4096 ||
        memchr(path, '\0', path_length) != NULL || request == NULL ||
        request_length == 0 ||
        request_length > HRACustodianMaximumRequestBytes ||
        response == NULL || response_capacity == 0 ||
        response_capacity > HRACustodianMaximumResponseBytes ||
        out_response_length == NULL || timeout_milliseconds == 0 ||
        timeout_milliseconds > 60000 ||
        !hra_macos_child_process_policy_is_exact() ||
        !hra_macos_custody_probe_parent_remains_live_or_retire()) {
      return false;
    }
    *out_response_length = 0;
    uint8_t requestCopy[HRACustodianMaximumRequestBytes];
    memset(requestCopy, 0, sizeof(requestCopy));
    memcpy(requestCopy, request, request_length);
    const uint64_t operationStart = HRAMonotonicMilliseconds();
    uint64_t operationDeadline = 0;
    uint64_t generation = 0;
    if (!HRADeadlineFromTimeout(
            operationStart, timeout_milliseconds, &operationDeadline) ||
        !HRABeginCustodianOperation(&generation)) {
      HRASecureZero(requestCopy, sizeof(requestCopy));
      return false;
    }
    NSString *helperPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    if (helperPath.length == 0 ||
        !HRAPathResolvesToItself(helperPath)) {
      HRASecureZero(requestCopy, sizeof(requestCopy));
      return false;
    }
    NSDictionary *identity = HRACopyStaticCustodianIdentity(
        helperPath, allow_unsealed_development);
    const char *spawnPath = HRAExactFileSystemRepresentation(
        helperPath, path, path_length);
    if (identity == nil || spawnPath == NULL ||
        !HRADeadlineHasTime(operationDeadline)) {
      HRASecureZero(requestCopy, sizeof(requestCopy));
      return false;
    }
    NSString *gatewayPath = [[helperPath stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:@"oprte-gateway"];
    const char *gatewayBytes = gatewayPath.fileSystemRepresentation;
    pid_t gatewayProcess = -1;
    uint64_t gatewayStartSeconds = 0;
    uint64_t gatewayStartMicroseconds = 0;
    audit_token_t selfAuditToken;
    memset(&selfAuditToken, 0, sizeof(selfAuditToken));
    char auditTokenHex[sizeof(audit_token_t) * 2 + 1];
    char gatewayProcessText[32];
    char gatewaySecondsText[32];
    char gatewayMicrosecondsText[32];
    memset(auditTokenHex, 0, sizeof(auditTokenHex));
    memset(gatewayProcessText, 0, sizeof(gatewayProcessText));
    memset(gatewaySecondsText, 0, sizeof(gatewaySecondsText));
    memset(gatewayMicrosecondsText, 0, sizeof(gatewayMicrosecondsText));
    if (gatewayBytes == NULL ||
        !hra_macos_copy_attested_gateway_generation(
            gatewayBytes,
            strlen(gatewayBytes),
            &gatewayProcess,
            &gatewayStartSeconds,
            &gatewayStartMicroseconds) ||
        !HRACopySelfAuditToken(&selfAuditToken)) {
      HRASecureZero(requestCopy, sizeof(requestCopy));
      HRASecureZero(&selfAuditToken, sizeof(selfAuditToken));
      return false;
    }
    HRAEncodeAuditTokenHex(&selfAuditToken, auditTokenHex);
    HRASecureZero(&selfAuditToken, sizeof(selfAuditToken));
    if (snprintf(gatewayProcessText,
                 sizeof(gatewayProcessText),
                 "%d",
                 gatewayProcess) <= 0 ||
        snprintf(gatewaySecondsText,
                 sizeof(gatewaySecondsText),
                 "%llu",
                 (unsigned long long)gatewayStartSeconds) <= 0 ||
        snprintf(gatewayMicrosecondsText,
                 sizeof(gatewayMicrosecondsText),
                 "%llu",
                 (unsigned long long)gatewayStartMicroseconds) <= 0) {
      HRASecureZero(requestCopy, sizeof(requestCopy));
      HRASecureZero(auditTokenHex, sizeof(auditTokenHex));
      return false;
    }

    int inputPipe[2] = {-1, -1};
    int outputPipe[2] = {-1, -1};
    if (pipe(inputPipe) != 0 || pipe(outputPipe) != 0) {
      if (inputPipe[0] >= 0) close(inputPipe[0]);
      if (inputPipe[1] >= 0) close(inputPipe[1]);
      if (outputPipe[0] >= 0) close(outputPipe[0]);
      if (outputPipe[1] >= 0) close(outputPipe[1]);
      HRASecureZero(requestCopy, sizeof(requestCopy));
      return false;
    }
    if (!HRAConfigurePipeWriterNoSigPipe(inputPipe[1])) {
      close(inputPipe[0]); close(inputPipe[1]);
      close(outputPipe[0]); close(outputPipe[1]);
      HRASecureZero(requestCopy, sizeof(requestCopy));
      return false;
    }
    posix_spawnattr_t attributes = NULL;
    posix_spawn_file_actions_t actions = NULL;
    bool initializedAttributes = posix_spawnattr_init(&attributes) == 0;
    bool initializedActions = initializedAttributes &&
        posix_spawn_file_actions_init(&actions) == 0;
    if (!initializedActions) {
      if (initializedAttributes) posix_spawnattr_destroy(&attributes);
      close(inputPipe[0]); close(inputPipe[1]);
      close(outputPipe[0]); close(outputPipe[1]);
      HRASecureZero(requestCopy, sizeof(requestCopy));
      return false;
    }
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
    short flags = POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT |
        POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    bool configured = signalSetsConfigured &&
        posix_spawnattr_setflags(&attributes, flags) == 0 &&
        posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0 &&
        posix_spawnattr_setsigdefault(
            &attributes, &childSignalDefaults) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO) == 0 &&
        posix_spawn_file_actions_addopen(
            &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawn_file_actions_addclose(&actions, inputPipe[1]) == 0 &&
        posix_spawn_file_actions_addclose(&actions, outputPipe[0]) == 0;
    char *argv[] = {
      (char *)spawnPath,
      "--hra-parent-audit-token-v1",
      auditTokenHex,
      gatewayProcessText,
      gatewaySecondsText,
      gatewayMicrosecondsText,
      NULL,
    };
    char *emptyEnvironment[] = {NULL};
    pid_t processIdentifier = -1;
    int spawnStatus = configured
        && hra_macos_custody_probe_parent_remains_live_or_retire()
        ? posix_spawn(&processIdentifier, spawnPath, &actions, &attributes,
                      argv, emptyEnvironment)
        : EINVAL;
    HRASecureZero(auditTokenHex, sizeof(auditTokenHex));
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    close(inputPipe[0]);
    close(outputPipe[1]);
    if (spawnStatus != 0 || processIdentifier <= 1) {
      close(inputPipe[1]);
      close(outputPipe[0]);
      HRASecureZero(requestCopy, sizeof(requestCopy));
      return false;
    }
    bool success = false;
    bool registered = false;
    bool spawned = true;
    uint64_t custodianStartSeconds = 0;
    uint64_t custodianStartMicroseconds = 0;
    uint64_t custodianStartSecondsAfter = 0;
    uint64_t custodianStartMicrosecondsAfter = 0;
    uint8_t helperCDHashAfter[HRA_MACOS_CDHASH_LENGTH];
    memset(helperCDHashAfter, 0, sizeof(helperCDHashAfter));
    if (!hra_macos_custody_probe_parent_remains_live_or_retire() ||
        !HRACustodianChildGenerationIsExact(
            processIdentifier,
            true,
            &custodianStartSeconds,
            &custodianStartMicroseconds) ||
        !HRADynamicCustodianMatches(processIdentifier, identity) ||
        (!allow_unsealed_development &&
         !hra_macos_release_helper_identity_is_exact(
             spawnPath, strlen(spawnPath), helperCDHashAfter)) ||
        (!allow_unsealed_development &&
         ([(NSData *)identity[@"hash"] length] != sizeof(helperCDHashAfter) ||
          memcmp([(NSData *)identity[@"hash"] bytes],
                 helperCDHashAfter,
                 sizeof(helperCDHashAfter)) != 0)) ||
        !HRACustodianChildGenerationIsExact(
            processIdentifier,
            true,
            &custodianStartSecondsAfter,
            &custodianStartMicrosecondsAfter) ||
        custodianStartSecondsAfter != custodianStartSeconds ||
        custodianStartMicrosecondsAfter != custodianStartMicroseconds ||
        !HRADeadlineHasTime(operationDeadline) ||
        !hra_macos_custody_probe_parent_remains_live_or_retire() ||
        !HRARegisterAndResumeCustodianProcess(
            processIdentifier,
            generation,
            operationDeadline,
            &registered)) {
      HRASecureZero(helperCDHashAfter, sizeof(helperCDHashAfter));
      goto cleanup;
    }
    HRASecureZero(helperCDHashAfter, sizeof(helperCDHashAfter));
    if (!HRADeadlineHasTime(operationDeadline) ||
        !hra_macos_custody_probe_parent_remains_live_or_retire() ||
        !HRAWriteAll(inputPipe[1], requestCopy, request_length) ||
        !HRADeadlineHasTime(operationDeadline)) goto cleanup;
    close(inputPipe[1]);
    inputPipe[1] = -1;
    int currentFlags = fcntl(outputPipe[0], F_GETFL, 0);
    if (currentFlags < 0 ||
        fcntl(outputPipe[0], F_SETFL, currentFlags | O_NONBLOCK) != 0) {
      goto cleanup;
    }
    size_t responseLength = 0;
    bool reachedEOF = false;
    while (!reachedEOF) {
      if (!hra_macos_custody_probe_parent_remains_live_or_retire())
        goto cleanup;
      int remaining = HRADeadlineRemainingMilliseconds(operationDeadline);
      if (remaining <= 0) goto cleanup;
      struct pollfd descriptor = {
        .fd = outputPipe[0],
        .events = POLLIN | POLLHUP,
        .revents = 0,
      };
      int pollMilliseconds = remaining < 10 ? remaining : 10;
      int pollStatus = poll(&descriptor, 1, pollMilliseconds);
      if (pollStatus < 0 && errno == EINTR) continue;
      if (pollStatus == 0) continue;
      if (pollStatus < 0 ||
          (descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
        goto cleanup;
      }
      while (true) {
        if (responseLength == response_capacity) goto cleanup;
        ssize_t count = read(
            outputPipe[0], response + responseLength,
            response_capacity - responseLength);
        if (count > 0) {
          responseLength += (size_t)count;
          continue;
        }
        if (count == 0) {
          reachedEOF = true;
          break;
        }
        if (errno == EINTR) {
          if (!HRADeadlineHasTime(operationDeadline)) goto cleanup;
          continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        goto cleanup;
      }
    }
    int status = 0;
    if (!HRARetireRegisteredCustodianProcess(
            processIdentifier,
            operationDeadline,
            false,
            &status)) goto cleanup;
    if (!hra_macos_custody_probe_parent_remains_live_or_retire())
      goto cleanup;
    registered = false;
    spawned = false;
    processIdentifier = -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        responseLength == 0 || !HRADeadlineHasTime(operationDeadline)) {
      goto cleanup;
    }
    *out_response_length = responseLength;
    success = true;

  cleanup:
    if (inputPipe[1] >= 0) close(inputPipe[1]);
    if (outputPipe[0] >= 0) close(outputPipe[0]);
    if (registered && processIdentifier > 1) {
      int ignoredStatus = INT_MIN;
      uint64_t cleanupDeadline = HRACleanupDeadline(
          HRACustodianReapTimeoutMilliseconds);
      if (!HRARetireRegisteredCustodianProcess(
              processIdentifier,
              cleanupDeadline,
              true,
              &ignoredStatus)) {
        HRAPoisonUnretiredCustodianProcess(processIdentifier);
      }
    } else if (spawned && processIdentifier > 1) {
      uint64_t cleanupDeadline = HRACleanupDeadline(
          HRACustodianReapTimeoutMilliseconds);
      if (!HRAKillAndReapUnregistered(
              processIdentifier, cleanupDeadline)) {
        HRAMarkCustodianUntrackedRetirementUnproven();
      }
    }
    HRASecureZero(requestCopy, sizeof(requestCopy));
    if (!success && response_capacity > 0) {
      HRASecureZero(response, response_capacity);
    }
    return success;
  }
}

void hra_macos_prepare_attested_keychain_custodian_operations(void) {
  bool childPolicyExact = hra_macos_child_process_policy_is_exact();
  os_unfair_lock_lock(&HRACustodianProcessLock);
  bool available = childPolicyExact &&
      atomic_load(&HRACurrentCustodianProcess) == -1 &&
      !HRACustodianUntrackedRetirementUnproven &&
      HRACustodianGeneration != UINT64_MAX;
  if (available) {
    HRACustodianGeneration += 1;
    HRACustodianGenerationPrepared = true;
    HRACustodianGenerationCancelled = false;
  } else {
    HRACustodianGenerationPrepared = false;
    HRACustodianGenerationCancelled = true;
  }
  os_unfair_lock_unlock(&HRACustodianProcessLock);
}

void hra_macos_cancel_attested_keychain_custodian(void) {
  os_unfair_lock_lock(&HRACustodianProcessLock);
  HRACustodianGenerationCancelled = true;
  int processIdentifier = atomic_load(&HRACurrentCustodianProcess);
  if (processIdentifier > 1) {
    siginfo_t exitInformation;
    HRAChildLeaseObservation lease = HRAObserveChildLease(
        (pid_t)processIdentifier, &exitInformation);
    if (lease == HRAChildLeaseRetained) {
      (void)kill((pid_t)processIdentifier, SIGKILL);
    } else {
      atomic_store(
          &HRACurrentCustodianProcess,
          HRACustodianRetirementUnproven);
      HRACustodianUntrackedRetirementUnproven = true;
    }
  }
  os_unfair_lock_unlock(&HRACustodianProcessLock);
}

bool hra_macos_run_attested_legacy_harness_custody(
    const char *path,
    size_t path_length,
    bool delete_action,
    uint8_t *response,
    size_t response_capacity,
    size_t *out_response_length,
    HRALegacyHarnessCustodyFailureSubstage *out_failure_substage,
    uint32_t timeout_milliseconds,
    bool allow_unsealed_development) {
  @autoreleasepool {
    if (out_failure_substage != NULL) {
      *out_failure_substage = HRALegacyHarnessCustodyFailureNone;
    }
    if (path == NULL || path_length == 0 || path_length > 4096 ||
        memchr(path, '\0', path_length) != NULL || response == NULL ||
        response_capacity == 0 ||
        response_capacity > HRACustodianMaximumResponseBytes ||
        out_response_length == NULL || out_failure_substage == NULL ||
        timeout_milliseconds == 0 ||
        timeout_milliseconds > 60000 ||
        !hra_macos_child_process_policy_is_exact()) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureAdmission);
      return false;
    }
    *out_response_length = 0;
    const uint64_t operationStart = HRAMonotonicMilliseconds();
    uint64_t operationDeadline = 0;
    uint64_t generation = 0;
    if (!HRADeadlineFromTimeout(
            operationStart, timeout_milliseconds, &operationDeadline) ||
        !HRABeginLegacyGatewayOperation(&generation)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureAdmission);
      return false;
    }
    NSString *gatewayPath = [[NSFileManager defaultManager]
        stringWithFileSystemRepresentation:path length:path_length];
    int gatewayDescriptor = -1;
    struct stat gatewayMetadata;
    memset(&gatewayMetadata, 0, sizeof(gatewayMetadata));
    HRAMacOSSelfManagedCodeIdentity gatewaySelfManagedIdentity;
    memset(&gatewaySelfManagedIdentity, 0, sizeof(gatewaySelfManagedIdentity));
    if (gatewayPath.length == 0 ||
        !HRAPathResolvesToItself(gatewayPath) ||
        HRACopyStaticLegacyGatewayIdentity(
            gatewayPath,
            allow_unsealed_development,
            &gatewayDescriptor,
            &gatewayMetadata,
            &gatewaySelfManagedIdentity,
            out_failure_substage) == nil) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureStaticBundle);
      return false;
    }
    const char *spawnPath = HRAExactFileSystemRepresentation(
        gatewayPath, path, path_length);
    if (spawnPath == NULL || !HRADeadlineHasTime(operationDeadline)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureSpawn);
      close(gatewayDescriptor);
      return false;
    }

    char temporaryDirectory[] =
        "/private/tmp/oprte-legacy-custody.XXXXXX";
    if (mkdtemp(temporaryDirectory) == NULL ||
        chmod(temporaryDirectory, 0700) != 0) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureSpawn);
      close(gatewayDescriptor);
      return false;
    }
    struct stat temporaryMetadata;
    if (lstat(temporaryDirectory, &temporaryMetadata) != 0 ||
        !S_ISDIR(temporaryMetadata.st_mode) ||
        temporaryMetadata.st_uid != geteuid() ||
        (temporaryMetadata.st_mode & 07777) != 0700) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureSpawn);
      close(gatewayDescriptor);
      (void)rmdir(temporaryDirectory);
      return false;
    }
    char temporaryEnvironment[PATH_MAX + 8];
    int temporaryEnvironmentLength = snprintf(
        temporaryEnvironment,
        sizeof(temporaryEnvironment),
        "TMPDIR=%s",
        temporaryDirectory);
    if (temporaryEnvironmentLength <= 0 ||
        (size_t)temporaryEnvironmentLength >= sizeof(temporaryEnvironment)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureSpawn);
      close(gatewayDescriptor);
      (void)rmdir(temporaryDirectory);
      return false;
    }

    int outputPipe[2] = {-1, -1};
    if (pipe(outputPipe) != 0) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureSpawn);
      close(gatewayDescriptor);
      (void)rmdir(temporaryDirectory);
      return false;
    }
    posix_spawnattr_t attributes = NULL;
    posix_spawn_file_actions_t actions = NULL;
    bool initializedAttributes = posix_spawnattr_init(&attributes) == 0;
    bool initializedActions = initializedAttributes &&
        posix_spawn_file_actions_init(&actions) == 0;
    if (!initializedActions) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureSpawn);
      if (initializedAttributes) posix_spawnattr_destroy(&attributes);
      close(outputPipe[0]);
      close(outputPipe[1]);
      close(gatewayDescriptor);
      (void)rmdir(temporaryDirectory);
      return false;
    }
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
        POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP |
        POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    bool configured = signalSetsConfigured &&
        posix_spawnattr_setflags(&attributes, flags) == 0 &&
        posix_spawnattr_setpgroup(&attributes, 0) == 0 &&
        posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0 &&
        posix_spawnattr_setsigdefault(
            &attributes, &childSignalDefaults) == 0 &&
        posix_spawn_file_actions_addchdir_np(
            &actions, temporaryDirectory) == 0 &&
        posix_spawn_file_actions_addopen(
            &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_adddup2(
            &actions, outputPipe[1], STDOUT_FILENO) == 0 &&
        posix_spawn_file_actions_addopen(
            &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawn_file_actions_addclose(&actions, outputPipe[0]) == 0;
    const char *script = delete_action
        ? HRALegacyHarnessDeleteScript
        : HRALegacyHarnessReadScript;
    char *argv[] = {
      (char *)spawnPath,
      (char *)"--no-env-file",
      (char *)"--no-install",
      (char *)"--no-addons",
      (char *)"--no-orphans",
      (char *)"--config=/dev/null",
      (char *)"--cwd",
      temporaryDirectory,
      (char *)"--eval",
      (char *)script,
      NULL,
    };
    char *environment[] = {
      (char *)"BUN_BE_BUN=1",
      temporaryEnvironment,
      NULL,
    };
    pid_t processIdentifier = -1;
    int spawnStatus = configured
        ? posix_spawn(&processIdentifier,
                      spawnPath,
                      &actions,
                      &attributes,
                      argv,
                      environment)
        : EINVAL;
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    close(outputPipe[1]);
    if (spawnStatus != 0 || processIdentifier <= 1) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureSpawn);
      close(outputPipe[0]);
      close(gatewayDescriptor);
      (void)rmdir(temporaryDirectory);
      return false;
    }
    bool success = false;
    bool registered = false;
    bool spawned = true;
    if (!HRALegacyGatewayDescriptorRemainsExact(
            gatewayPath,
            gatewayDescriptor,
            &gatewayMetadata,
            allow_unsealed_development)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureDescriptorBeforeDynamic);
      goto cleanup;
    }
    if (!HRADynamicLegacyGatewayMatches(
            processIdentifier,
            gatewayPath,
            &gatewaySelfManagedIdentity,
            out_failure_substage)) {
      goto cleanup;
    }
    if (!HRALegacyGatewayDescriptorRemainsExact(
            gatewayPath,
            gatewayDescriptor,
            &gatewayMetadata,
            allow_unsealed_development)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureDescriptorAfterDynamic);
      goto cleanup;
    }
    if (!HRADeadlineHasTime(operationDeadline) ||
        !HRARegisterAndResumeLegacyGatewayProcess(
            processIdentifier,
            generation,
            operationDeadline,
            &registered)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureResume);
      goto cleanup;
    }
    int currentFlags = fcntl(outputPipe[0], F_GETFL, 0);
    if (currentFlags < 0 ||
        fcntl(outputPipe[0], F_SETFL, currentFlags | O_NONBLOCK) != 0) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureOutput);
      goto cleanup;
    }
    size_t responseLength = 0;
    bool reachedEOF = false;
    while (!reachedEOF) {
      int remaining = HRADeadlineRemainingMilliseconds(operationDeadline);
      if (remaining <= 0) {
        HRARecordLegacyHarnessCustodyFailure(
            out_failure_substage,
            HRALegacyHarnessCustodyFailureOutput);
        goto cleanup;
      }
      struct pollfd descriptor = {
        .fd = outputPipe[0],
        .events = POLLIN | POLLHUP,
        .revents = 0,
      };
      int pollStatus = poll(&descriptor, 1, remaining);
      if (pollStatus < 0 && errno == EINTR) continue;
      if (pollStatus <= 0 ||
          (descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
        HRARecordLegacyHarnessCustodyFailure(
            out_failure_substage,
            HRALegacyHarnessCustodyFailureOutput);
        goto cleanup;
      }
      while (true) {
        if (responseLength == response_capacity) {
          HRARecordLegacyHarnessCustodyFailure(
              out_failure_substage,
              HRALegacyHarnessCustodyFailureOutput);
          goto cleanup;
        }
        ssize_t count = read(outputPipe[0],
                             response + responseLength,
                             response_capacity - responseLength);
        if (count > 0) {
          responseLength += (size_t)count;
          continue;
        }
        if (count == 0) {
          reachedEOF = true;
          break;
        }
        if (errno == EINTR) {
          if (!HRADeadlineHasTime(operationDeadline)) {
            HRARecordLegacyHarnessCustodyFailure(
                out_failure_substage,
                HRALegacyHarnessCustodyFailureOutput);
            goto cleanup;
          }
          continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        HRARecordLegacyHarnessCustodyFailure(
            out_failure_substage,
            HRALegacyHarnessCustodyFailureOutput);
        goto cleanup;
      }
    }
    siginfo_t exitInformation;
    bool leaseLost = false;
    if (!HRAWaitForChildExitUnreaped(
            processIdentifier,
            operationDeadline,
            &exitInformation,
            &leaseLost)) {
      if (leaseLost) {
        HRAPoisonUnretiredLegacyProcess(processIdentifier);
        HRAMarkLegacyUntrackedRetirementUnproven();
      }
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureExit);
      goto cleanup;
    }
    if (exitInformation.si_code != CLD_EXITED ||
        exitInformation.si_status != 0 || responseLength == 0 ||
        !HRADeadlineHasTime(operationDeadline)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureExit);
      goto cleanup;
    }
    int status = 0;
    uint64_t retirementDeadline = HRACleanupDeadline(
        HRALegacyGroupQuiescenceTimeoutMilliseconds);
    if (!HRAContainAndReapRegisteredLegacyProcessGroup(
            processIdentifier, retirementDeadline, &status)) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureGroupRetirement);
      goto cleanup;
    }
    registered = false;
    spawned = false;
    processIdentifier = -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureExit);
      goto cleanup;
    }
    *out_response_length = responseLength;
    success = true;

  cleanup:
    close(gatewayDescriptor);
    close(outputPipe[0]);
    if (registered && processIdentifier > 1) {
      int ignoredStatus = INT_MIN;
      uint64_t cleanupDeadline = HRACleanupDeadline(
          HRALegacyGroupQuiescenceTimeoutMilliseconds);
      if (!HRAContainAndReapRegisteredLegacyProcessGroup(
              processIdentifier, cleanupDeadline, &ignoredStatus)) {
        HRARecordLegacyHarnessCustodyFailure(
            out_failure_substage,
            HRALegacyHarnessCustodyFailureGroupRetirement);
        HRAPoisonUnretiredLegacyProcess(processIdentifier);
      }
    } else if (spawned && processIdentifier > 1) {
      uint64_t cleanupDeadline = HRACleanupDeadline(
          HRALegacyGroupQuiescenceTimeoutMilliseconds);
      if (!HRAKillAndReapUnregistered(
              processIdentifier, cleanupDeadline)) {
        HRARecordLegacyHarnessCustodyFailure(
            out_failure_substage,
            HRALegacyHarnessCustodyFailureGroupRetirement);
        HRAMarkLegacyUntrackedRetirementUnproven();
      }
    }
    if (rmdir(temporaryDirectory) != 0) {
      HRARecordLegacyHarnessCustodyFailure(
          out_failure_substage,
          HRALegacyHarnessCustodyFailureGroupRetirement);
      success = false;
    }
    if (!success && response_capacity > 0) {
      HRASecureZero(response, response_capacity);
    }
    return success;
  }
}

void hra_macos_prepare_attested_legacy_harness_custody_operations(void) {
  bool childPolicyExact = hra_macos_child_process_policy_is_exact();
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  bool available = childPolicyExact &&
      atomic_load(&HRACurrentLegacyGatewayProcess) == -1 &&
      !HRALegacyUntrackedRetirementUnproven &&
      HRALegacyGatewayGeneration != UINT64_MAX;
  if (available) {
    HRALegacyGatewayGeneration += 1;
    HRALegacyGatewayGenerationPrepared = true;
    HRALegacyGatewayGenerationCancelled = false;
  } else {
    HRALegacyGatewayGenerationPrepared = false;
    HRALegacyGatewayGenerationCancelled = true;
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
}

void hra_macos_cancel_attested_legacy_harness_custody(void) {
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  HRALegacyGatewayGenerationCancelled = true;
  int processIdentifier = atomic_load(&HRACurrentLegacyGatewayProcess);
  if (processIdentifier > 1) {
    siginfo_t exitInformation;
    HRAChildLeaseObservation lease = HRAObserveChildLease(
        (pid_t)processIdentifier, &exitInformation);
    if (lease == HRAChildLeaseRetained) {
      (void)kill(-(pid_t)processIdentifier, SIGKILL);
    } else {
      atomic_store(
          &HRACurrentLegacyGatewayProcess,
          HRALegacyRetirementUnproven);
      HRALegacyUntrackedRetirementUnproven = true;
    }
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
}

#if defined(HRA_LEGACY_ATTESTATION_PROBE)
// Darwin-only release probe. It deliberately calls the production static
// verifier and never spawns the gateway or enters any SecItem operation.
int main(int argumentCount, const char *arguments[]) {
  @autoreleasepool {
    if (argumentCount != 2 || arguments == NULL || arguments[1] == NULL)
      return 64;
    NSString *path = [NSString stringWithUTF8String:arguments[1]];
    NSString *requiredSuffix = [@"/Contents/Resources/"
        stringByAppendingString:HRALegacyGatewayRelativePath];
    if (path.length == 0 || !path.isAbsolutePath ||
        ![path hasSuffix:requiredSuffix]) {
      return 65;
    }
    int descriptor = -1;
    struct stat metadata;
    memset(&metadata, 0, sizeof(metadata));
    HRAMacOSSelfManagedCodeIdentity selfManagedIdentity;
    memset(&selfManagedIdentity, 0, sizeof(selfManagedIdentity));
    HRALegacyHarnessCustodyFailureSubstage failureSubstage =
        HRALegacyHarnessCustodyFailureNone;
    NSDictionary *identity = HRACopyStaticLegacyGatewayIdentity(
        path,
        true,
        &descriptor,
        &metadata,
        &selfManagedIdentity,
        &failureSubstage);
    bool exact = identity != nil && descriptor >= 0 &&
        HRALegacyGatewayDescriptorRemainsExact(
            path, descriptor, &metadata, true);
    if (descriptor >= 0) close(descriptor);
    return exact ? 0 : 1;
  }
}
#elif defined(HRA_LEGACY_GROUP_RETIREMENT_PROBE)
static bool HRAReadLegacyGroupProbeReady(
    int descriptor,
    uint64_t deadline) {
  while (true) {
    int remaining = HRADeadlineRemainingMilliseconds(deadline);
    if (remaining <= 0) return false;
    struct pollfd pollDescriptor = {
      .fd = descriptor,
      .events = POLLIN | POLLHUP,
      .revents = 0,
    };
    int pollStatus = poll(&pollDescriptor, 1, remaining);
    if (pollStatus < 0 && errno == EINTR) continue;
    if (pollStatus <= 0 ||
        (pollDescriptor.revents & (POLLERR | POLLNVAL)) != 0) {
      return false;
    }
    uint8_t marker = 0;
    ssize_t count = read(descriptor, &marker, sizeof(marker));
    if (count == (ssize_t)sizeof(marker)) return marker == 0x51;
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
}

static void HRARunLegacyGroupProbeChild(
    int readyDescriptor,
    int controlDescriptor,
    bool zombieDescendant) {
  if (setpgid(0, 0) != 0) _exit(70);
  pid_t descendant = fork();
  if (descendant < 0) _exit(71);
  if (descendant == 0) {
    close(readyDescriptor);
    close(controlDescriptor);
    if (zombieDescendant) _exit(0);
    while (true) pause();
  }
  if (zombieDescendant) {
    siginfo_t exitInformation;
    memset(&exitInformation, 0, sizeof(exitInformation));
    while (waitid(
               P_PID,
               (id_t)descendant,
               &exitInformation,
               WEXITED | WNOWAIT) != 0) {
      if (errno != EINTR) _exit(72);
    }
    if (!HRAChildExitInformationIsTerminal(
            &exitInformation, descendant)) _exit(73);
  } else if (kill(descendant, 0) != 0) {
    _exit(74);
  }
  const uint8_t readyMarker = 0x51;
  if (!HRAWriteAll(
          readyDescriptor, &readyMarker, sizeof(readyMarker))) {
    _exit(75);
  }
  close(readyDescriptor);
  uint8_t controlMarker = 0;
  ssize_t controlCount;
  do {
    controlCount = read(
        controlDescriptor, &controlMarker, sizeof(controlMarker));
  } while (controlCount < 0 && errno == EINTR);
  close(controlDescriptor);
  if (controlCount != (ssize_t)sizeof(controlMarker) ||
      controlMarker != 0x72) {
    _exit(76);
  }
  if (!zombieDescendant &&
      kill(descendant, SIGKILL) != 0 && errno != ESRCH) {
    _exit(77);
  }
  int descendantStatus = 0;
  while (waitpid(descendant, &descendantStatus, 0) < 0) {
    if (errno != EINTR) _exit(78);
  }
  _exit(0);
}

static void HRAKillLegacyGroupProbe(pid_t groupLeader) {
  if (groupLeader <= 1) return;
  if (getpgid(groupLeader) == groupLeader) {
    (void)kill(-groupLeader, SIGKILL);
  } else {
    (void)kill(groupLeader, SIGKILL);
  }
}

static int HRARunExitedLegacyGroupRetirementProbeFixture(
    bool liveDescendant) {
  int readyPipe[2] = {-1, -1};
  int controlPipe[2] = {-1, -1};
  if (pipe(readyPipe) != 0 || pipe(controlPipe) != 0) {
    if (readyPipe[0] >= 0) close(readyPipe[0]);
    if (readyPipe[1] >= 0) close(readyPipe[1]);
    if (controlPipe[0] >= 0) close(controlPipe[0]);
    if (controlPipe[1] >= 0) close(controlPipe[1]);
    return 20;
  }
  pid_t groupLeader = fork();
  if (groupLeader == 0) {
    close(readyPipe[0]);
    close(controlPipe[1]);
    if (setpgid(0, 0) != 0) _exit(80);
    if (liveDescendant) {
      pid_t descendant = fork();
      if (descendant < 0) _exit(81);
      if (descendant == 0) {
        while (true) pause();
      }
    }
    const uint8_t readyMarker = 0x51;
    if (!HRAWriteAll(
            readyPipe[1], &readyMarker, sizeof(readyMarker))) {
      _exit(82);
    }
    close(readyPipe[1]);
    uint8_t controlMarker = 0;
    ssize_t controlCount;
    do {
      controlCount = read(
          controlPipe[0], &controlMarker, sizeof(controlMarker));
    } while (controlCount < 0 && errno == EINTR);
    close(controlPipe[0]);
    if (controlCount != (ssize_t)sizeof(controlMarker) ||
        controlMarker != 0x72) {
      _exit(83);
    }
    _exit(0);
  }
  close(readyPipe[1]);
  close(controlPipe[0]);
  if (groupLeader <= 1) {
    close(readyPipe[0]);
    close(controlPipe[1]);
    return 20;
  }
  uint64_t readyDeadline = HRACleanupDeadline(5000);
  bool ready = HRAReadLegacyGroupProbeReady(
      readyPipe[0], readyDeadline);
  bool exactGroup = ready && getpgid(groupLeader) == groupLeader;
  const uint8_t controlMarker = 0x72;
  bool released = exactGroup && HRAWriteAll(
      controlPipe[1], &controlMarker, sizeof(controlMarker));
  close(readyPipe[0]);
  close(controlPipe[1]);
  uint64_t exitDeadline = HRACleanupDeadline(5000);
  siginfo_t exitInformation;
  bool leaseLost = false;
  bool exited = released && HRAWaitForChildExitUnreaped(
      groupLeader, exitDeadline, &exitInformation, &leaseLost);
  (void)leaseLost;
  bool initialQuiescence = exited &&
      HRALegacyProcessGroupHasNoLiveMembers(groupLeader, true);
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  bool registered = exited &&
      atomic_load(&HRACurrentLegacyGatewayProcess) == -1;
  if (registered) {
    atomic_store(&HRACurrentLegacyGatewayProcess, (int)groupLeader);
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  int status = INT_MIN;
  uint64_t containmentDeadline = HRACleanupDeadline(5000);
  bool contained = registered &&
      HRAContainAndReapRegisteredLegacyProcessGroup(
          groupLeader, containmentDeadline, &status);
  if (!contained) {
    HRAKillLegacyGroupProbe(groupLeader);
    uint64_t cleanupDeadline = HRACleanupDeadline(1000);
    int ignoredStatus = 0;
    (void)HRAWaitForChildAndReap(
        groupLeader, cleanupDeadline, &ignoredStatus);
    os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
    int current = atomic_load(&HRACurrentLegacyGatewayProcess);
    if (current == groupLeader || current == HRAProcessRetiring) {
      atomic_store(&HRACurrentLegacyGatewayProcess, -1);
    }
    os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  }
  if (!exited || exitInformation.si_code != CLD_EXITED ||
      exitInformation.si_status != 0) return 21;
  if (!exactGroup) return 22;
  if (initialQuiescence != !liveDescendant) return 26;
  if (!registered) return 23;
  if (!contained) return 24;
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
      atomic_load(&HRACurrentLegacyGatewayProcess) != -1) return 25;
  return 0;
}

static bool HRARunLegacyGroupRetirementProbeFixture(
    bool zombieDescendant,
    bool expectedInitialQuiescence) {
  int readyPipe[2] = {-1, -1};
  int controlPipe[2] = {-1, -1};
  if (pipe(readyPipe) != 0 || pipe(controlPipe) != 0) {
    if (readyPipe[0] >= 0) close(readyPipe[0]);
    if (readyPipe[1] >= 0) close(readyPipe[1]);
    if (controlPipe[0] >= 0) close(controlPipe[0]);
    if (controlPipe[1] >= 0) close(controlPipe[1]);
    return false;
  }
  pid_t groupLeader = fork();
  if (groupLeader == 0) {
    close(readyPipe[0]);
    close(controlPipe[1]);
    HRARunLegacyGroupProbeChild(
        readyPipe[1], controlPipe[0], zombieDescendant);
  }
  close(readyPipe[1]);
  close(controlPipe[0]);
  if (groupLeader <= 1) {
    close(readyPipe[0]);
    close(controlPipe[1]);
    return false;
  }
  uint64_t deadline = HRACleanupDeadline(5000);
  bool ready = HRAReadLegacyGroupProbeReady(readyPipe[0], deadline);
  bool exactGroup = ready && getpgid(groupLeader) == groupLeader;
  bool initialQuiescence = exactGroup &&
      HRALegacyProcessGroupHasNoLiveMembers(groupLeader, true);
  os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
  bool registered =
      atomic_load(&HRACurrentLegacyGatewayProcess) == -1;
  if (registered) {
    atomic_store(&HRACurrentLegacyGatewayProcess, (int)groupLeader);
  }
  os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  int status = INT_MIN;
  uint64_t containmentDeadline = HRACleanupDeadline(5000);
  bool contained = registered &&
      HRAContainAndReapRegisteredLegacyProcessGroup(
          groupLeader, containmentDeadline, &status);
  close(readyPipe[0]);
  close(controlPipe[1]);
  if (!contained) {
    HRAKillLegacyGroupProbe(groupLeader);
    uint64_t cleanupDeadline = HRACleanupDeadline(1000);
    int ignoredStatus = 0;
    (void)HRAWaitForChildAndReap(
        groupLeader, cleanupDeadline, &ignoredStatus);
    os_unfair_lock_lock(&HRALegacyGatewayProcessLock);
    int current = atomic_load(&HRACurrentLegacyGatewayProcess);
    if (current == groupLeader || current == HRAProcessRetiring) {
      atomic_store(&HRACurrentLegacyGatewayProcess, -1);
    }
    os_unfair_lock_unlock(&HRALegacyGatewayProcessLock);
  }
  return ready && exactGroup &&
      initialQuiescence == expectedInitialQuiescence && registered &&
      contained && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL &&
      atomic_load(&HRACurrentLegacyGatewayProcess) == -1;
}

// Darwin-only process-state probe. It creates synthetic process groups and
// never launches HRA, the legacy gateway, or any Keychain operation.
int main(int argumentCount, const char *arguments[]) {
  (void)arguments;
  if (argumentCount != 1) return 64;
  bool zombieAccepted =
      HRARunLegacyGroupRetirementProbeFixture(true, true);
  bool liveRejected =
      HRARunLegacyGroupRetirementProbeFixture(false, false);
  int exitedLeaderResult =
      HRARunExitedLegacyGroupRetirementProbeFixture(false);
  int exitedLeaderWithDescendantResult =
      HRARunExitedLegacyGroupRetirementProbeFixture(true);
  if (!zombieAccepted) return 10;
  if (!liveRejected) return 11;
  if (exitedLeaderResult != 0) return exitedLeaderResult;
  if (exitedLeaderWithDescendantResult != 0) {
    return exitedLeaderWithDescendantResult + 10;
  }
  return 0;
}
#endif
