#import "macos_keychain_access_control.h"

#import <dlfcn.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

static NSString *const HRAInstallEnvelopeAccessDescription =
    @"HRA Harness installation key";
// Audited from the signed v0.1.15/build-16 custodian used by the only
// prepared-sidecar migration this release supports.
static NSString *const HRAV015PreparedCustodianCodeDirectoryHash =
    @"cbcee12b447830e5be86177dffdfa1e69b73bc84";

CFDictionaryRef _Nullable hra_macos_copy_no_ui_generic_password_query(
    SecKeychainRef keychain,
    CFStringRef service,
    CFStringRef account) {
  @autoreleasepool {
    if (keychain == NULL || service == NULL || account == NULL ||
        CFGetTypeID(keychain) != SecKeychainGetTypeID() ||
        CFGetTypeID(service) != CFStringGetTypeID() ||
        CFGetTypeID(account) != CFStringGetTypeID()) return NULL;
    LAContext *authenticationContext = [[LAContext alloc] init];
    authenticationContext.interactionNotAllowed = YES;
    NSDictionary *query = @{
      (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrService: (__bridge NSString *)service,
      (__bridge id)kSecAttrAccount: (__bridge NSString *)account,
      (__bridge id)kSecMatchSearchList: @[(__bridge id)keychain],
      (__bridge id)kSecUseAuthenticationUI:
          (__bridge id)kSecUseAuthenticationUIFail,
      (__bridge id)kSecUseAuthenticationContext: authenticationContext,
    };
    return (__bridge_retained CFDictionaryRef)query;
  }
}

CFMutableDictionaryRef _Nullable
hra_macos_copy_generic_password_add_attributes(CFDictionaryRef rawQuery) {
  @autoreleasepool {
    if (rawQuery == NULL ||
        CFGetTypeID(rawQuery) != CFDictionaryGetTypeID()) return NULL;
    NSDictionary *query = (__bridge NSDictionary *)rawQuery;
    NSArray *searchList = query[(__bridge id)kSecMatchSearchList];
    if (query.count != 6 ||
        query[(__bridge id)kSecClass] != (__bridge id)kSecClassGenericPassword ||
        ![query[(__bridge id)kSecAttrService] isKindOfClass:[NSString class]] ||
        ![query[(__bridge id)kSecAttrAccount] isKindOfClass:[NSString class]] ||
        ![searchList isKindOfClass:[NSArray class]] || searchList.count != 1 ||
        CFGetTypeID((__bridge CFTypeRef)searchList[0]) !=
            SecKeychainGetTypeID() ||
        query[(__bridge id)kSecUseAuthenticationUI] !=
            (__bridge id)kSecUseAuthenticationUIFail ||
        ![query[(__bridge id)kSecUseAuthenticationContext]
            isKindOfClass:[LAContext class]] ||
        !((LAContext *)query[(__bridge id)kSecUseAuthenticationContext])
            .interactionNotAllowed) return NULL;
    NSMutableDictionary *attributes = [query mutableCopy];
    [attributes removeObjectForKey:(__bridge id)kSecUseAuthenticationUI];
    [attributes removeObjectForKey:(__bridge id)kSecUseAuthenticationContext];
    [attributes removeObjectForKey:(__bridge id)kSecMatchSearchList];
    attributes[(__bridge id)kSecUseKeychain] = searchList[0];
    return (__bridge_retained CFMutableDictionaryRef)attributes;
  }
}

static bool HRAACLAuthorizationsMatch(
    CFArrayRef authorizations,
    NSArray *expected) {
  if (authorizations == NULL || expected == nil ||
      CFGetTypeID(authorizations) != CFArrayGetTypeID() ||
      CFArrayGetCount(authorizations) != (CFIndex)expected.count) {
    return false;
  }
  NSMutableSet *actual = [NSMutableSet set];
  for (CFIndex index = 0; index < CFArrayGetCount(authorizations); index++) {
    CFTypeRef raw = CFArrayGetValueAtIndex(authorizations, index);
    if (raw == NULL || CFGetTypeID(raw) != CFStringGetTypeID()) return false;
    [actual addObject:(__bridge NSString *)raw];
  }
  return actual.count == expected.count &&
      [actual isEqualToSet:[NSSet setWithArray:expected]];
}

typedef NS_OPTIONS(uint8_t, HRAInstallEnvelopeACLKind) {
  HRAInstallEnvelopeACLKindDecrypt = 1 << 0,
  HRAInstallEnvelopeACLKindEncrypt = 1 << 1,
  HRAInstallEnvelopeACLKindIntegrity = 1 << 2,
  HRAInstallEnvelopeACLKindPartitionID = 1 << 3,
  HRAInstallEnvelopeACLKindChangeACL = 1 << 4,
};

static const uint8_t HRAInstallEnvelopeSensitiveACLKinds =
    HRAInstallEnvelopeACLKindDecrypt |
    HRAInstallEnvelopeACLKindEncrypt |
    HRAInstallEnvelopeACLKindChangeACL;
static const uint8_t HRAInstallEnvelopeSystemACLKinds =
    HRAInstallEnvelopeACLKindIntegrity |
    HRAInstallEnvelopeACLKindPartitionID;

static uint8_t HRAExactInstallEnvelopeACLKind(CFArrayRef authorizations) {
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[
            (__bridge NSString *)kSecACLAuthorizationDecrypt,
            (__bridge NSString *)kSecACLAuthorizationDerive,
            (__bridge NSString *)kSecACLAuthorizationExportClear,
            (__bridge NSString *)kSecACLAuthorizationExportWrapped,
            (__bridge NSString *)kSecACLAuthorizationMAC,
            (__bridge NSString *)kSecACLAuthorizationSign,
          ])) return HRAInstallEnvelopeACLKindDecrypt;
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[(__bridge NSString *)kSecACLAuthorizationEncrypt])) {
    return HRAInstallEnvelopeACLKindEncrypt;
  }
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[(__bridge NSString *)kSecACLAuthorizationIntegrity])) {
    return HRAInstallEnvelopeACLKindIntegrity;
  }
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[(__bridge NSString *)kSecACLAuthorizationPartitionID])) {
    return HRAInstallEnvelopeACLKindPartitionID;
  }
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[(__bridge NSString *)kSecACLAuthorizationChangeACL])) {
    return HRAInstallEnvelopeACLKindChangeACL;
  }
  return 0;
}

typedef OSStatus (*HRASecTrustedApplicationCopyRequirement)(
    SecTrustedApplicationRef application,
    SecRequirementRef _Nullable *_Nonnull requirement);

#if defined(HRA_KEYCHAIN_ACCESS_CONTROL_TESTING)
static bool HRAForceRequirementSPIUnavailableForTest = false;

void hra_macos_keychain_access_control_test_force_requirement_spi_unavailable(
    bool unavailable) {
  HRAForceRequirementSPIUnavailableForTest = unavailable;
}
#endif

static HRASecTrustedApplicationCopyRequirement
HRACopyTrustedApplicationRequirementFunction(void) {
#if defined(HRA_KEYCHAIN_ACCESS_CONTROL_TESTING)
  if (HRAForceRequirementSPIUnavailableForTest) return NULL;
#endif
  return (HRASecTrustedApplicationCopyRequirement)dlsym(
      RTLD_DEFAULT, "SecTrustedApplicationCopyRequirement");
}

static bool HRATrustedApplicationMatchesCurrentExactHelper(
    SecTrustedApplicationRef candidate,
    SecTrustedApplicationRef expected) {
  if (candidate == NULL || expected == NULL ||
      CFGetTypeID(candidate) != SecTrustedApplicationGetTypeID() ||
      CFGetTypeID(expected) != SecTrustedApplicationGetTypeID()) {
    return false;
  }
  HRASecTrustedApplicationCopyRequirement copyRequirement =
      HRACopyTrustedApplicationRequirementFunction();
  if (copyRequirement == NULL) return false;
  CFDataRef candidatePath = NULL;
  CFDataRef expectedPath = NULL;
  SecRequirementRef candidateRequirement = NULL;
  SecRequirementRef expectedRequirement = NULL;
  CFDataRef candidateRequirementData = NULL;
  CFDataRef expectedRequirementData = NULL;
  bool exact = SecTrustedApplicationCopyData(candidate, &candidatePath) ==
          errSecSuccess &&
      candidatePath != NULL &&
      SecTrustedApplicationCopyData(expected, &expectedPath) ==
          errSecSuccess &&
      expectedPath != NULL && CFEqual(candidatePath, expectedPath) &&
      copyRequirement(candidate, &candidateRequirement) == errSecSuccess &&
      candidateRequirement != NULL &&
      copyRequirement(expected, &expectedRequirement) == errSecSuccess &&
      expectedRequirement != NULL &&
      SecRequirementCopyData(
          candidateRequirement,
          kSecCSDefaultFlags,
          &candidateRequirementData) == errSecSuccess &&
      candidateRequirementData != NULL &&
      SecRequirementCopyData(
          expectedRequirement,
          kSecCSDefaultFlags,
          &expectedRequirementData) == errSecSuccess &&
      expectedRequirementData != NULL &&
      CFEqual(candidateRequirementData, expectedRequirementData);
  if (expectedRequirementData != NULL) CFRelease(expectedRequirementData);
  if (candidateRequirementData != NULL) CFRelease(candidateRequirementData);
  if (expectedRequirement != NULL) CFRelease(expectedRequirement);
  if (candidateRequirement != NULL) CFRelease(candidateRequirement);
  if (expectedPath != NULL) CFRelease(expectedPath);
  if (candidatePath != NULL) CFRelease(candidatePath);
  return exact;
}

static int HRAExactLowercaseHexNibble(unichar character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  return -1;
}

static bool HRAStringIsExactLowercaseHex(
    NSString *text,
    NSUInteger expectedLength) {
  if (![text isKindOfClass:[NSString class]] ||
      text.length != expectedLength) return false;
  for (NSUInteger index = 0; index < text.length; index += 1) {
    if (HRAExactLowercaseHexNibble([text characterAtIndex:index]) < 0)
      return false;
  }
  return true;
}

static NSData *_Nullable HRADataFromBoundedLowercaseHex(NSString *text) {
  if (![text isKindOfClass:[NSString class]] || text.length < 2 ||
      text.length > 8192 || text.length % 2 != 0) return nil;
  NSMutableData *data = [NSMutableData dataWithLength:text.length / 2];
  uint8_t *bytes = data.mutableBytes;
  for (NSUInteger index = 0; index < text.length; index += 2) {
    int high = HRAExactLowercaseHexNibble([text characterAtIndex:index]);
    int low = HRAExactLowercaseHexNibble([text characterAtIndex:index + 1]);
    if (high < 0 || low < 0) return nil;
    bytes[index / 2] = (uint8_t)((high << 4) | low);
  }
  return data;
}

static NSString *_Nullable HRACurrentExactCodeDirectoryHashHex(void) {
  SecCodeRef selfCode = NULL;
  if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) != errSecSuccess ||
      selfCode == NULL) return nil;
  CFDictionaryRef rawInformation = NULL;
  OSStatus status = SecCodeCopySigningInformation(
      selfCode, kSecCSSigningInformation, &rawInformation);
  CFRelease(selfCode);
  if (status != errSecSuccess || rawInformation == NULL) return nil;
  NSDictionary *information = CFBridgingRelease(rawInformation);
  id rawHash = information[(__bridge NSString *)kSecCodeInfoUnique];
  if (![rawHash isKindOfClass:[NSData class]] ||
      [(NSData *)rawHash length] != 20) return nil;
  const uint8_t *bytes = [(NSData *)rawHash bytes];
  NSMutableString *hex = [NSMutableString stringWithCapacity:40];
  for (NSUInteger index = 0; index < 20; index += 1) {
    [hex appendFormat:@"%02x", bytes[index]];
  }
  return hex.length == 40 ? hex : nil;
}

static bool HRAIntegrityDescriptionIsExact(CFStringRef description) {
  return description != NULL &&
      HRAStringIsExactLowercaseHex((__bridge NSString *)description, 64);
}

// Security.framework may emit byte-distinct XML serializations. Validate the
// exact semantic partition set after bounded lowercase-hex XML plist decoding.
static NSArray<NSString *> *_Nullable HRAExactPartitionCodeDirectoryHashes(
    CFStringRef description) {
  if (description == NULL) return nil;
  NSData *propertyListData = HRADataFromBoundedLowercaseHex(
      (__bridge NSString *)description);
  if (propertyListData == nil) return nil;
  NSPropertyListFormat format = NSPropertyListOpenStepFormat;
  id propertyList = [NSPropertyListSerialization
      propertyListWithData:propertyListData
      options:NSPropertyListImmutable
      format:&format
      error:nil];
  if (format != NSPropertyListXMLFormat_v1_0 ||
      ![propertyList isKindOfClass:[NSDictionary class]] ||
      [(NSDictionary *)propertyList count] != 1) return nil;
  id partitions = ((NSDictionary *)propertyList)[@"Partitions"];
  if (![partitions isKindOfClass:[NSArray class]] ||
      [(NSArray *)partitions count] < 1 ||
      [(NSArray *)partitions count] > 2) return nil;
  static NSString *const prefix = @"cdhash:";
  NSMutableArray<NSString *> *hashes = [NSMutableArray array];
  for (id rawPartition in (NSArray *)partitions) {
    if (![rawPartition isKindOfClass:[NSString class]] ||
        ![(NSString *)rawPartition hasPrefix:prefix]) return nil;
    NSString *hash = [(NSString *)rawPartition
        substringFromIndex:prefix.length];
    if (!HRAStringIsExactLowercaseHex(hash, 40) ||
        [hashes containsObject:hash]) return nil;
    [hashes addObject:hash];
  }
  return hashes;
}

typedef NS_ENUM(NSUInteger, HRAPartitionPayloadPolicy) {
  HRAPartitionPayloadCurrent = 0,
  HRAPartitionPayloadPreparedV015 = 1,
  HRAPartitionPayloadV015ToCurrentTransition = 2,
};

static bool HRAPartitionDescriptionMatchesPolicy(
    CFStringRef description,
    HRAPartitionPayloadPolicy policy) {
  NSArray<NSString *> *actual =
      HRAExactPartitionCodeDirectoryHashes(description);
  NSString *current = HRACurrentExactCodeDirectoryHashHex();
  if (actual == nil || current == nil) return false;
  if (policy == HRAPartitionPayloadCurrent) {
    return actual.count == 1 && [actual[0] isEqualToString:current];
  }
  if (policy == HRAPartitionPayloadPreparedV015) {
    return actual.count == 1 &&
        [actual[0] isEqualToString:
            HRAV015PreparedCustodianCodeDirectoryHash];
  }
  return actual.count == 2 &&
      [actual containsObject:current] &&
      [actual containsObject:HRAV015PreparedCustodianCodeDirectoryHash];
}

static bool HRAInstallEnvelopeAccessHasExactShape(
    SecAccessRef access,
    SecTrustedApplicationRef expectedApplication,
    bool acceptDraftShape,
    bool acceptStoredShape,
    HRAPartitionPayloadPolicy partitionPolicy) {
  if (access == NULL || expectedApplication == NULL ||
      CFGetTypeID(access) != SecAccessGetTypeID() ||
      CFGetTypeID(expectedApplication) !=
          SecTrustedApplicationGetTypeID()) return false;
  CFArrayRef aclList = NULL;
  bool exact = SecAccessCopyACLList(access, &aclList) == errSecSuccess &&
      aclList != NULL;
  CFIndex aclCount = exact ? CFArrayGetCount(aclList) : 0;
  exact = exact && ((acceptDraftShape && aclCount == 3) ||
      (acceptStoredShape && aclCount == 5));
  uint8_t observedKinds = 0;
  for (CFIndex index = 0;
       exact && index < aclCount;
       index += 1) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(aclList, index);
    CFArrayRef applications = NULL;
    CFStringRef description = NULL;
    CFArrayRef authorizations = NULL;
    SecKeychainPromptSelector prompt = 0;
    bool aclExact = acl != NULL && CFGetTypeID(acl) == SecACLGetTypeID() &&
        SecACLCopyContents(
            acl, &applications, &description, &prompt) == errSecSuccess;
    if (aclExact) authorizations = SecACLCopyAuthorizations(acl);
    uint8_t kind = aclExact
        ? HRAExactInstallEnvelopeACLKind(authorizations)
        : 0;
    bool isSensitive = (kind & HRAInstallEnvelopeSensitiveACLKinds) != 0;
    bool isSystem = (kind & HRAInstallEnvelopeSystemACLKinds) != 0;
    aclExact = aclExact && prompt == 0 && kind != 0 &&
        (observedKinds & kind) == 0;
    if (aclExact && isSensitive) {
      aclExact = applications != NULL &&
          CFArrayGetCount(applications) == 1 && description != NULL &&
          CFEqual(
              description,
              (__bridge CFStringRef)HRAInstallEnvelopeAccessDescription) &&
          HRATrustedApplicationMatchesCurrentExactHelper(
              (SecTrustedApplicationRef)CFArrayGetValueAtIndex(
                  applications, 0),
              expectedApplication);
    } else if (aclExact && isSystem) {
      aclExact = applications == NULL &&
          ((kind == HRAInstallEnvelopeACLKindIntegrity &&
            HRAIntegrityDescriptionIsExact(description)) ||
           (kind == HRAInstallEnvelopeACLKindPartitionID &&
            HRAPartitionDescriptionMatchesPolicy(
                description, partitionPolicy)));
    } else {
      aclExact = false;
    }
    observedKinds |= kind;
    if (authorizations != NULL) CFRelease(authorizations);
    if (description != NULL) CFRelease(description);
    if (applications != NULL) CFRelease(applications);
    if (!aclExact) exact = false;
  }
  if (aclList != NULL) CFRelease(aclList);
  uint8_t expectedKinds = aclCount == 3
      ? HRAInstallEnvelopeSensitiveACLKinds
      : HRAInstallEnvelopeSensitiveACLKinds |
          HRAInstallEnvelopeSystemACLKinds;
  return exact && observedKinds == expectedKinds;
}

SecAccessRef _Nullable hra_macos_copy_strict_install_envelope_access(void) {
  @autoreleasepool {
    SecTrustedApplicationRef trusted = NULL;
    SecAccessRef access = NULL;
    if (SecTrustedApplicationCreateFromPath(NULL, &trusted) != errSecSuccess ||
        trusted == NULL) {
      if (trusted != NULL) CFRelease(trusted);
      return NULL;
    }
    NSArray *trustedApplications = @[(__bridge id)trusted];
    OSStatus status = SecAccessCreate(
        (__bridge CFStringRef)HRAInstallEnvelopeAccessDescription,
        (__bridge CFArrayRef)trustedApplications,
        &access);
    CFArrayRef aclList = NULL;
    if (status == errSecSuccess && access != NULL) {
      status = SecAccessCopyACLList(access, &aclList);
    }
    if (status == errSecSuccess &&
        (aclList == NULL || CFArrayGetCount(aclList) != 3)) {
      status = errSecAuthFailed;
    }
    uint8_t observedKinds = 0;
    for (CFIndex index = 0;
         status == errSecSuccess && index < CFArrayGetCount(aclList);
         index += 1) {
      SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(aclList, index);
      CFArrayRef authorizations = acl == NULL
          ? NULL
          : SecACLCopyAuthorizations(acl);
      uint8_t kind = HRAExactInstallEnvelopeACLKind(authorizations);
      if (authorizations != NULL) CFRelease(authorizations);
      if (acl == NULL || kind == 0 || (observedKinds & kind) != 0 ||
          SecACLSetContents(
              acl,
              (__bridge CFArrayRef)trustedApplications,
              (__bridge CFStringRef)HRAInstallEnvelopeAccessDescription,
              0) != errSecSuccess) {
        status = errSecAuthFailed;
      }
      observedKinds |= kind;
    }
    if (aclList != NULL) CFRelease(aclList);
    if (status == errSecSuccess &&
        (observedKinds != HRAInstallEnvelopeSensitiveACLKinds ||
         !HRAInstallEnvelopeAccessHasExactShape(
             access,
             trusted,
             true,
             false,
             HRAPartitionPayloadCurrent))) {
      status = errSecAuthFailed;
    }
    CFRelease(trusted);
    if (status == errSecSuccess) return access;
    if (access != NULL) CFRelease(access);
    return NULL;
  }
}

static bool HRAInstallEnvelopeAccessMatchesCurrentExactHelper(
    SecAccessRef access,
    bool acceptDraftShape,
    bool acceptStoredShape,
    HRAPartitionPayloadPolicy partitionPolicy) {
  @autoreleasepool {
    if (access == NULL || CFGetTypeID(access) != SecAccessGetTypeID())
      return false;
    SecTrustedApplicationRef expectedApplication = NULL;
    bool exact = SecTrustedApplicationCreateFromPath(
            NULL, &expectedApplication) == errSecSuccess &&
        expectedApplication != NULL &&
        HRAInstallEnvelopeAccessHasExactShape(
            access,
            expectedApplication,
            acceptDraftShape,
            acceptStoredShape,
            partitionPolicy);
    if (expectedApplication != NULL) CFRelease(expectedApplication);
    return exact;
  }
}

bool hra_macos_install_envelope_access_is_strict(SecAccessRef access) {
  return HRAInstallEnvelopeAccessMatchesCurrentExactHelper(
      access, true, true, HRAPartitionPayloadCurrent);
}

bool hra_macos_install_envelope_item_access_is_strict(
    SecKeychainItemRef item) {
  @autoreleasepool {
    if (item == NULL || CFGetTypeID(item) != SecKeychainItemGetTypeID())
      return false;
    SecAccessRef access = NULL;
    bool exact = SecKeychainItemCopyAccess(item, &access) == errSecSuccess &&
        access != NULL &&
        HRAInstallEnvelopeAccessMatchesCurrentExactHelper(
            access, false, true, HRAPartitionPayloadCurrent);
    if (access != NULL) CFRelease(access);
    return exact;
  }
}

bool hra_macos_install_envelope_access_is_prepared_migration_source(
    SecAccessRef access) {
  return HRAInstallEnvelopeAccessMatchesCurrentExactHelper(
      access, false, true, HRAPartitionPayloadPreparedV015);
}

bool hra_macos_install_envelope_access_is_prepared_migration_transition(
    SecAccessRef access) {
  return HRAInstallEnvelopeAccessMatchesCurrentExactHelper(
      access,
      false,
      true,
      HRAPartitionPayloadV015ToCurrentTransition);
}

bool hra_macos_install_envelope_item_access_is_prepared_migration_source(
    SecKeychainItemRef item) {
  @autoreleasepool {
    if (item == NULL || CFGetTypeID(item) != SecKeychainItemGetTypeID())
      return false;
    SecAccessRef access = NULL;
    bool exact = SecKeychainItemCopyAccess(item, &access) == errSecSuccess &&
        access != NULL &&
        hra_macos_install_envelope_access_is_prepared_migration_source(access);
    if (access != NULL) CFRelease(access);
    return exact;
  }
}

bool hra_macos_install_envelope_item_access_is_prepared_migration_transition(
    SecKeychainItemRef item) {
  @autoreleasepool {
    if (item == NULL || CFGetTypeID(item) != SecKeychainItemGetTypeID())
      return false;
    SecAccessRef access = NULL;
    bool exact = SecKeychainItemCopyAccess(item, &access) == errSecSuccess &&
        access != NULL &&
        hra_macos_install_envelope_access_is_prepared_migration_transition(
            access);
    if (access != NULL) CFRelease(access);
    return exact;
  }
}
