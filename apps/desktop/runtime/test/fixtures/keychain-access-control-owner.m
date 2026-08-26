#import "../../../src/macos_keychain_access_control.h"

#import <dlfcn.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#if defined(HRA_KEYCHAIN_ACL_FIXTURE_DEBUG)
#define HRA_FIXTURE_DEBUG(message) fputs(message "\n", stderr)
#else
#define HRA_FIXTURE_DEBUG(message) ((void)0)
#endif

static NSString *const HRAFixturePassword = @"hra-acl-test-v1";
static NSString *const HRAFixtureService = @"hra.keychain-acl.fixture";
static NSString *const HRAFixtureAccount = @"installation-master";
static NSString *const HRAFixtureEnvelope =
    @"{\"version\":1,\"algorithm\":\"hkdf-sha256\",\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
static NSString *const HRAFixtureDecoyEnvelope =
    @"{\"version\":1,\"algorithm\":\"hkdf-sha256\",\"key\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\"}";
static NSString *const HRAFixtureIntegrityDescription =
    @"0000000000000000000000000000000000000000000000000000000000000000";
static NSString *const HRAFixtureAccessDescription =
    @"HRA Harness installation key";
static NSString *const HRAV015PreparedCustodianCodeDirectoryHash =
    @"cbcee12b447830e5be86177dffdfa1e69b73bc84";
static NSString *const HRAC17InstalledCustodianCodeDirectoryHash =
    @"b253f5d9d52fa12beb486f8f9a35d4e8430b86ab";

static NSDictionary *HRAFixtureQuery(SecKeychainRef keychain) {
  CFDictionaryRef query = hra_macos_copy_no_ui_generic_password_query(
      keychain,
      (__bridge CFStringRef)HRAFixtureService,
      (__bridge CFStringRef)HRAFixtureAccount);
  return query == NULL ? nil : CFBridgingRelease(query);
}

static bool HRAQueryTransformsAreExact(SecKeychainRef keychain) {
  NSDictionary *query = HRAFixtureQuery(keychain);
  NSArray *searchList = query[(__bridge id)kSecMatchSearchList];
  LAContext *context = query[(__bridge id)kSecUseAuthenticationContext];
  bool exact = query != nil && query.count == 6 &&
      query[(__bridge id)kSecClass] == (__bridge id)kSecClassGenericPassword &&
      [query[(__bridge id)kSecAttrService] isEqual:HRAFixtureService] &&
      [query[(__bridge id)kSecAttrAccount] isEqual:HRAFixtureAccount] &&
      [searchList isKindOfClass:[NSArray class]] && searchList.count == 1 &&
      searchList[0] == (__bridge id)keychain &&
      query[(__bridge id)kSecUseAuthenticationUI] ==
          (__bridge id)kSecUseAuthenticationUIFail &&
      [context isKindOfClass:[LAContext class]] &&
      context.interactionNotAllowed;
  CFMutableDictionaryRef rawAttributes = exact
      ? hra_macos_copy_generic_password_add_attributes(
          (__bridge CFDictionaryRef)query)
      : NULL;
  NSDictionary *attributes = rawAttributes == NULL
      ? nil
      : CFBridgingRelease(rawAttributes);
  return exact && attributes.count == 4 &&
      attributes[(__bridge id)kSecClass] ==
          (__bridge id)kSecClassGenericPassword &&
      [attributes[(__bridge id)kSecAttrService] isEqual:HRAFixtureService] &&
      [attributes[(__bridge id)kSecAttrAccount] isEqual:HRAFixtureAccount] &&
      attributes[(__bridge id)kSecUseKeychain] == (__bridge id)keychain;
}

static NSDictionary *_Nullable HRAReadExactItem(
    SecKeychainRef keychain,
    OSStatus *outStatus) {
  NSMutableDictionary *query = [HRAFixtureQuery(keychain) mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecReturnRef] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  CFTypeRef raw = NULL;
  *outStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &raw);
  if (*outStatus != errSecSuccess || raw == NULL ||
      CFGetTypeID(raw) != CFDictionaryGetTypeID()) {
    if (raw != NULL) CFRelease(raw);
    return nil;
  }
  return CFBridgingRelease(raw);
}

static bool HRAReadbackHasExactValueAndAccessStrictness(
    SecKeychainRef keychain,
    NSString *expectedValue,
    bool expectedStrict) {
  OSStatus status = errSecInternalError;
  NSDictionary *result = HRAReadExactItem(keychain, &status);
  if (status != errSecSuccess || result == nil) return false;
  NSData *expected = [expectedValue dataUsingEncoding:NSUTF8StringEncoding];
  NSData *actual = result[(__bridge id)kSecValueData];
  SecKeychainItemRef item = (__bridge SecKeychainItemRef)
      result[(__bridge id)kSecValueRef];
  return [actual isKindOfClass:[NSData class]] &&
      [actual isEqualToData:expected] &&
      hra_macos_install_envelope_item_access_is_strict(item) == expectedStrict;
}

static bool HRAReadbackHasExactValueAndStrictAccess(
    SecKeychainRef keychain,
    NSString *expectedValue) {
  return HRAReadbackHasExactValueAndAccessStrictness(
      keychain, expectedValue, true);
}

static bool HRAReadbackIsExact(SecKeychainRef keychain) {
  return HRAReadbackHasExactValueAndStrictAccess(
      keychain, HRAFixtureEnvelope);
}

static bool HRAReadbackValueIsExact(
    SecKeychainRef keychain,
    NSString *expectedValue) {
  OSStatus status = errSecInternalError;
  NSDictionary *result = HRAReadExactItem(keychain, &status);
  NSData *expected = [expectedValue dataUsingEncoding:NSUTF8StringEncoding];
  NSData *actual = result[(__bridge id)kSecValueData];
  return status == errSecSuccess && result != nil &&
      [actual isKindOfClass:[NSData class]] &&
      [actual isEqualToData:expected];
}

static CFIndex HRAAccessACLCount(SecAccessRef access) {
  CFArrayRef aclList = NULL;
  CFIndex count = SecAccessCopyACLList(access, &aclList) == errSecSuccess &&
      aclList != NULL
      ? CFArrayGetCount(aclList)
      : -1;
  if (aclList != NULL) CFRelease(aclList);
  return count;
}

static NSString *_Nullable HRAFixtureHexFromData(NSData *data) {
  if (![data isKindOfClass:[NSData class]] || data.length == 0) return nil;
  const uint8_t *bytes = data.bytes;
  NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
  for (NSUInteger index = 0; index < data.length; index += 1) {
    [hex appendFormat:@"%02x", bytes[index]];
  }
  return hex.length == data.length * 2 ? hex : nil;
}

static NSString *_Nullable HRAFixtureCurrentCodeDirectoryHashHex(void) {
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
  return [rawHash isKindOfClass:[NSData class]] &&
          [(NSData *)rawHash length] == 20
      ? HRAFixtureHexFromData(rawHash)
      : nil;
}

static NSString *_Nullable HRAFixturePropertyListDescription(
    id propertyList) {
  NSError *error = nil;
  NSData *data = [NSPropertyListSerialization
      dataWithPropertyList:propertyList
      format:NSPropertyListXMLFormat_v1_0
      options:0
      error:&error];
  return error == nil ? HRAFixtureHexFromData(data) : nil;
}

static NSString *_Nullable HRAFixtureCurrentPartitionValue(void) {
  NSString *codeDirectoryHash = HRAFixtureCurrentCodeDirectoryHashHex();
  return codeDirectoryHash == nil
      ? nil
      : [@"cdhash:" stringByAppendingString:codeDirectoryHash];
}

static NSString *_Nullable HRAFixturePartitionDescription(void) {
  NSString *partitionValue = HRAFixtureCurrentPartitionValue();
  return partitionValue == nil
      ? nil
      : HRAFixturePropertyListDescription(@{
          @"Partitions": @[partitionValue],
        });
}

static NSString *_Nullable HRAFixturePartitionDescriptionForHashes(
    NSArray<NSString *> *codeDirectoryHashes) {
  if (![codeDirectoryHashes isKindOfClass:[NSArray class]] ||
      codeDirectoryHashes.count == 0) return nil;
  NSMutableArray<NSString *> *partitions = [NSMutableArray array];
  for (id rawHash in codeDirectoryHashes) {
    if (![rawHash isKindOfClass:[NSString class]] ||
        [(NSString *)rawHash length] != 40) return nil;
    [partitions addObject:
        [@"cdhash:" stringByAppendingString:(NSString *)rawHash]];
  }
  return HRAFixturePropertyListDescription(@{
    @"Partitions": partitions,
  });
}

static NSString *_Nullable HRAFixturePartitionDescriptionForHash(
    NSString *codeDirectoryHash) {
  return HRAFixturePartitionDescriptionForHashes(@[codeDirectoryHash]);
}

static bool HRAAppendACL(
    SecAccessRef access,
    NSArray *_Nullable applications,
    NSString *description,
    SecKeychainPromptSelector prompt,
    NSArray *authorizations) {
  if (access == NULL || description == nil || authorizations == nil)
    return false;
  SecACLRef acl = NULL;
  OSStatus status = SecACLCreateWithSimpleContents(
      access,
      applications == nil ? NULL : (__bridge CFArrayRef)applications,
      (__bridge CFStringRef)description,
      prompt,
      &acl);
  if (status == errSecSuccess && acl != NULL) {
    status = SecACLUpdateAuthorizations(
        acl, (__bridge CFArrayRef)authorizations);
  }
  if (acl != NULL) CFRelease(acl);
  return status == errSecSuccess;
}

static bool HRAAppendSystemACL(
    SecAccessRef access,
    CFStringRef authorization,
    NSString *description) {
  return HRAAppendACL(
      access,
      nil,
      description,
      0,
      @[(__bridge NSString *)authorization]);
}

static bool HRAAugmentedMetadataIsRejected(
    NSString *integrityDescription,
    SecKeychainPromptSelector integrityPrompt,
    NSString *partitionDescription,
    SecKeychainPromptSelector partitionPrompt) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  bool rejected = access != NULL &&
      HRAAppendACL(
          access,
          nil,
          integrityDescription,
          integrityPrompt,
          @[(__bridge NSString *)kSecACLAuthorizationIntegrity]) &&
      HRAAppendACL(
          access,
          nil,
          partitionDescription,
          partitionPrompt,
          @[(__bridge NSString *)kSecACLAuthorizationPartitionID]) &&
      HRAAccessACLCount(access) == 5 &&
      !hra_macos_install_envelope_access_is_strict(access);
  if (access != NULL) CFRelease(access);
  return rejected;
}

static bool HRAMetadataValidatorsRejectMalformedACLs(void) {
  NSString *partitionDescription = HRAFixturePartitionDescription();
  NSString *partitionValue = HRAFixtureCurrentPartitionValue();
  NSString *malformedPropertyList = HRAFixtureHexFromData(
      [@"not a property list" dataUsingEncoding:NSUTF8StringEncoding]);
  NSString *wrongHashPartition = HRAFixturePropertyListDescription(@{
    @"Partitions": @[
      @"cdhash:0000000000000000000000000000000000000000",
    ],
  });
  NSString *extraPartition = partitionValue == nil
      ? nil
      : HRAFixturePropertyListDescription(@{
          @"Partitions": @[
            partitionValue,
            @"cdhash:0000000000000000000000000000000000000000",
          ],
        });
  NSString *extraKey = partitionValue == nil
      ? nil
      : HRAFixturePropertyListDescription(@{
          @"Partitions": @[partitionValue],
          @"Unexpected": @YES,
        });
  NSString *missingPartitions = HRAFixturePropertyListDescription(@{});
  NSString *wrongTypePartitions = HRAFixturePropertyListDescription(@{
    @"Partitions": partitionValue ?: @"cdhash:invalid",
  });
  NSString *uppercasePartition = partitionDescription.uppercaseString;
  NSString *oddLengthPartition = partitionDescription.length > 0
      ? [partitionDescription substringToIndex:partitionDescription.length - 1]
      : nil;
  NSString *integrity63 = [@"" stringByPaddingToLength:63
      withString:@"0"
      startingAtIndex:0];
  NSString *integrity65 = [@"" stringByPaddingToLength:65
      withString:@"0"
      startingAtIndex:0];
  if (partitionDescription == nil || partitionValue == nil ||
      malformedPropertyList == nil || wrongHashPartition == nil ||
      extraPartition == nil || extraKey == nil ||
      missingPartitions == nil || wrongTypePartitions == nil ||
      uppercasePartition == nil || oddLengthPartition == nil) return false;
  return HRAAugmentedMetadataIsRejected(
          @"00", 0, partitionDescription, 0) &&
      HRAAugmentedMetadataIsRejected(
          integrity63, 0, partitionDescription, 0) &&
      HRAAugmentedMetadataIsRejected(
          integrity65, 0, partitionDescription, 0) &&
      HRAAugmentedMetadataIsRejected(
          @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          0,
          partitionDescription,
          0) &&
      HRAAugmentedMetadataIsRejected(
          @"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
          0,
          partitionDescription,
          0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, @"zz", 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, malformedPropertyList, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, wrongHashPartition, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, extraPartition, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, extraKey, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, missingPartitions, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, wrongTypePartitions, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, uppercasePartition, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription, 0, oddLengthPartition, 0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription,
          kSecKeychainPromptRequirePassphase,
          partitionDescription,
          0) &&
      HRAAugmentedMetadataIsRejected(
          HRAFixtureIntegrityDescription,
          0,
          partitionDescription,
          kSecKeychainPromptRequirePassphase);
}

static SecAccessRef _Nullable HRACopyPersistedProjectionAccess(void) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  NSString *partitionDescription = HRAFixturePartitionDescription();
  bool exact = access != NULL && partitionDescription != nil &&
      HRAAccessACLCount(access) == 3 &&
      hra_macos_install_envelope_access_is_strict(access) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationIntegrity,
          HRAFixtureIntegrityDescription) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationPartitionID,
          partitionDescription) &&
      HRAAccessACLCount(access) == 5 &&
      hra_macos_install_envelope_access_is_strict(access);
  if (exact) return access;
  if (access != NULL) CFRelease(access);
  return NULL;
}

static SecAccessRef _Nullable
HRACopyPreparedMigrationProjectionAccessForHashes(
    NSArray<NSString *> *codeDirectoryHashes) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  NSString *partitionDescription =
      HRAFixturePartitionDescriptionForHashes(codeDirectoryHashes);
  bool exact = access != NULL && partitionDescription != nil &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationIntegrity,
          HRAFixtureIntegrityDescription) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationPartitionID,
          partitionDescription) &&
      HRAAccessACLCount(access) == 5;
  if (exact) return access;
  if (access != NULL) CFRelease(access);
  return NULL;
}

static SecAccessRef _Nullable
HRACopyPreparedMigrationProjectionAccess(NSString *codeDirectoryHash) {
  return HRACopyPreparedMigrationProjectionAccessForHashes(
      @[codeDirectoryHash]);
}

static bool HRAPreparedMigrationSourcesAreExactlyAudited(void) {
  SecAccessRef v015 = HRACopyPreparedMigrationProjectionAccess(
      HRAV015PreparedCustodianCodeDirectoryHash);
  SecAccessRef c17 = HRACopyPreparedMigrationProjectionAccess(
      HRAC17InstalledCustodianCodeDirectoryHash);
  SecAccessRef wrongValidHash = HRACopyPreparedMigrationProjectionAccess(
      @"0000000000000000000000000000000000000000");
  SecAccessRef predecessorPair =
      HRACopyPreparedMigrationProjectionAccessForHashes(@[
        HRAV015PreparedCustodianCodeDirectoryHash,
        HRAC17InstalledCustodianCodeDirectoryHash,
      ]);
  bool exact = v015 != NULL && c17 != NULL && wrongValidHash != NULL &&
      predecessorPair != NULL &&
      hra_macos_install_envelope_access_is_prepared_migration_source(
          v015) &&
      hra_macos_install_envelope_access_is_prepared_migration_source(c17) &&
      !hra_macos_install_envelope_access_is_strict(v015) &&
      !hra_macos_install_envelope_access_is_strict(c17) &&
      !hra_macos_install_envelope_access_is_prepared_migration_transition(
          v015) &&
      !hra_macos_install_envelope_access_is_prepared_migration_transition(
          c17) &&
      !hra_macos_install_envelope_access_is_prepared_migration_source(
          wrongValidHash) &&
      !hra_macos_install_envelope_access_is_prepared_migration_source(
          predecessorPair) &&
      !hra_macos_install_envelope_access_is_prepared_migration_transition(
          predecessorPair);
  if (predecessorPair != NULL) CFRelease(predecessorPair);
  if (wrongValidHash != NULL) CFRelease(wrongValidHash);
  if (c17 != NULL) CFRelease(c17);
  if (v015 != NULL) CFRelease(v015);
  return exact;
}

static bool HRAPreparedMigrationTransitionPolicyIsExact(void) {
  NSString *current = HRAFixtureCurrentCodeDirectoryHashHex();
  NSString *v015 = HRAV015PreparedCustodianCodeDirectoryHash;
  NSString *c17 = HRAC17InstalledCustodianCodeDirectoryHash;
  NSString *wrong = @"0000000000000000000000000000000000000000";
  NSString *nonHex = @"gggggggggggggggggggggggggggggggggggggggg";
  if (current == nil || [current isEqualToString:v015] ||
      [current isEqualToString:c17] || [current isEqualToString:wrong]) {
    return false;
  }
  NSArray<NSArray<NSString *> *> *accepted = @[
    @[v015, current],
    @[current, v015],
    @[c17, current],
    @[current, c17],
  ];
  NSArray<NSArray<NSString *> *> *rejected = @[
    @[v015],
    @[c17],
    @[current],
    @[v015, c17],
    @[v015, wrong],
    @[c17, wrong],
    @[current, wrong],
    @[v015, v015],
    @[c17, c17],
    @[current, current],
    @[v015, c17, current],
    @[v015, current, wrong],
    @[c17, current, wrong],
    @[v015.uppercaseString, current],
    @[c17.uppercaseString, current],
    @[nonHex, current],
  ];
  for (NSArray<NSString *> *hashes in accepted) {
    SecAccessRef access =
        HRACopyPreparedMigrationProjectionAccessForHashes(hashes);
    bool exact = access != NULL &&
        hra_macos_install_envelope_access_is_prepared_migration_transition(
            access) &&
        !hra_macos_install_envelope_access_is_prepared_migration_source(
            access) &&
        !hra_macos_install_envelope_access_is_strict(access);
    if (access != NULL) CFRelease(access);
    if (!exact) return false;
  }
  for (NSArray<NSString *> *hashes in rejected) {
    SecAccessRef access =
        HRACopyPreparedMigrationProjectionAccessForHashes(hashes);
    bool exact = access != NULL &&
        !hra_macos_install_envelope_access_is_prepared_migration_transition(
            access);
    if (access != NULL) CFRelease(access);
    if (!exact) return false;
  }
  SecAccessRef currentOnly =
      HRACopyPreparedMigrationProjectionAccess(current);
  bool finalStrictOnly = currentOnly != NULL &&
      hra_macos_install_envelope_access_is_strict(currentOnly) &&
      !hra_macos_install_envelope_access_is_prepared_migration_source(
          currentOnly) &&
      !hra_macos_install_envelope_access_is_prepared_migration_transition(
          currentOnly);
  if (currentOnly != NULL) CFRelease(currentOnly);
  if (!finalStrictOnly) return false;
  return true;
}

static bool HRAUnavailableRequirementSPIFailsClosed(void) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  if (access == NULL ||
      !hra_macos_install_envelope_access_is_strict(access)) {
    if (access != NULL) CFRelease(access);
    return false;
  }
  hra_macos_keychain_access_control_test_force_requirement_spi_unavailable(
      true);
  bool rejected = !hra_macos_install_envelope_access_is_strict(access);
  hra_macos_keychain_access_control_test_force_requirement_spi_unavailable(
      false);
  bool restored = hra_macos_install_envelope_access_is_strict(access);
  CFRelease(access);
  return rejected && restored;
}

static bool HRAAccessWithAdditionalSensitiveSubjectIsRejected(
    const char *untrustedExecutable) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  SecTrustedApplicationRef untrusted = NULL;
  CFArrayRef aclList = NULL;
  bool mutated = access != NULL &&
      SecTrustedApplicationCreateFromPath(
          untrustedExecutable, &untrusted) == errSecSuccess &&
      untrusted != NULL &&
      SecAccessCopyACLList(access, &aclList) == errSecSuccess &&
      aclList != NULL;
  bool foundEncrypt = false;
  for (CFIndex index = 0;
       mutated && !foundEncrypt && index < CFArrayGetCount(aclList);
       index += 1) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(aclList, index);
    CFArrayRef authorizations = acl == NULL
        ? NULL
        : SecACLCopyAuthorizations(acl);
    bool isEncrypt = authorizations != NULL &&
        CFArrayGetCount(authorizations) == 1 &&
        CFEqual(
            CFArrayGetValueAtIndex(authorizations, 0),
            kSecACLAuthorizationEncrypt);
    if (isEncrypt) {
      CFArrayRef applications = NULL;
      CFStringRef description = NULL;
      SecKeychainPromptSelector prompt = 0;
      mutated = SecACLCopyContents(
              acl, &applications, &description, &prompt) == errSecSuccess &&
          applications != NULL && CFArrayGetCount(applications) == 1 &&
          description != NULL && prompt == 0;
      if (mutated) {
        NSArray *expanded = @[
          (__bridge id)CFArrayGetValueAtIndex(applications, 0),
          (__bridge id)untrusted,
        ];
        mutated = SecACLSetContents(
                acl,
                (__bridge CFArrayRef)expanded,
                description,
                prompt) == errSecSuccess;
      }
      if (description != NULL) CFRelease(description);
      if (applications != NULL) CFRelease(applications);
      foundEncrypt = true;
    }
    if (authorizations != NULL) CFRelease(authorizations);
  }
  bool rejected = mutated && foundEncrypt &&
      !hra_macos_install_envelope_access_is_strict(access);
  if (aclList != NULL) CFRelease(aclList);
  if (untrusted != NULL) CFRelease(untrusted);
  if (access != NULL) CFRelease(access);
  return rejected;
}

typedef OSStatus (*HRAFixtureCopyTrustedApplicationRequirement)(
    SecTrustedApplicationRef application,
    SecRequirementRef _Nullable *_Nonnull requirement);
typedef OSStatus (*HRAFixtureCreateTrustedApplicationFromRequirement)(
    const char *description,
    SecRequirementRef requirement,
    SecTrustedApplicationRef _Nullable *_Nonnull application);

static bool HRAAccessWithSamePathDifferentRequirementIsRejected(void) {
  HRAFixtureCopyTrustedApplicationRequirement copyRequirement =
      (HRAFixtureCopyTrustedApplicationRequirement)dlsym(
          RTLD_DEFAULT, "SecTrustedApplicationCopyRequirement");
  HRAFixtureCreateTrustedApplicationFromRequirement createFromRequirement =
      (HRAFixtureCreateTrustedApplicationFromRequirement)dlsym(
          RTLD_DEFAULT, "SecTrustedApplicationCreateFromRequirement");
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  SecTrustedApplicationRef current = NULL;
  SecTrustedApplicationRef different = NULL;
  SecRequirementRef requestedDifferentRequirement = NULL;
  SecRequirementRef currentRequirement = NULL;
  SecRequirementRef storedDifferentRequirement = NULL;
  CFDataRef currentPath = NULL;
  CFDataRef differentPath = NULL;
  CFDataRef currentRequirementData = NULL;
  CFDataRef differentRequirementData = NULL;
  CFArrayRef aclList = NULL;
  uint8_t setupStage = 1;
  bool exactSetup = access != NULL && copyRequirement != NULL &&
      createFromRequirement != NULL;
  if (exactSetup) {
    setupStage = 2;
    exactSetup = SecTrustedApplicationCreateFromPath(
        NULL, &current) == errSecSuccess && current != NULL;
  }
  if (exactSetup) {
    setupStage = 3;
    exactSetup = SecTrustedApplicationCopyData(
        current, &currentPath) == errSecSuccess && currentPath != NULL;
  }
  if (exactSetup) {
    setupStage = 4;
    exactSetup = SecRequirementCreateWithString(
        CFSTR("identifier \"org.hraness.hra.different-requirement\""),
        kSecCSDefaultFlags,
        &requestedDifferentRequirement) == errSecSuccess &&
        requestedDifferentRequirement != NULL;
  }
  if (exactSetup) {
    setupStage = 5;
    exactSetup = createFromRequirement(
        (const char *)CFDataGetBytePtr(currentPath),
        requestedDifferentRequirement,
        &different) == errSecSuccess && different != NULL;
  }
  if (exactSetup) {
    setupStage = 6;
    exactSetup = SecTrustedApplicationCopyData(
        different, &differentPath) == errSecSuccess &&
        differentPath != NULL && CFEqual(currentPath, differentPath);
  }
  if (exactSetup) {
    setupStage = 7;
    exactSetup = copyRequirement(
        current, &currentRequirement) == errSecSuccess &&
        currentRequirement != NULL;
  }
  if (exactSetup) {
    setupStage = 8;
    exactSetup = copyRequirement(
        different, &storedDifferentRequirement) == errSecSuccess &&
        storedDifferentRequirement != NULL;
  }
  if (exactSetup) {
    setupStage = 9;
    exactSetup = SecRequirementCopyData(
        currentRequirement,
        kSecCSDefaultFlags,
        &currentRequirementData) == errSecSuccess &&
        currentRequirementData != NULL;
  }
  if (exactSetup) {
    setupStage = 10;
    exactSetup = SecRequirementCopyData(
        storedDifferentRequirement,
        kSecCSDefaultFlags,
        &differentRequirementData) == errSecSuccess &&
        differentRequirementData != NULL &&
        !CFEqual(currentRequirementData, differentRequirementData);
  }
  if (exactSetup) {
    setupStage = 11;
    exactSetup = SecAccessCopyACLList(access, &aclList) == errSecSuccess &&
        aclList != NULL;
  }
  bool replacedEncrypt = false;
  for (CFIndex index = 0;
       exactSetup && !replacedEncrypt && index < CFArrayGetCount(aclList);
       index += 1) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(aclList, index);
    CFArrayRef authorizations = acl == NULL
        ? NULL
        : SecACLCopyAuthorizations(acl);
    bool isEncrypt = authorizations != NULL &&
        CFArrayGetCount(authorizations) == 1 &&
        CFEqual(
            CFArrayGetValueAtIndex(authorizations, 0),
            kSecACLAuthorizationEncrypt);
    if (isEncrypt) {
      CFArrayRef applications = NULL;
      CFStringRef description = NULL;
      SecKeychainPromptSelector prompt = 0;
      exactSetup = SecACLCopyContents(
              acl, &applications, &description, &prompt) == errSecSuccess &&
          applications != NULL && CFArrayGetCount(applications) == 1 &&
          description != NULL && prompt == 0 &&
          SecACLSetContents(
              acl,
              (__bridge CFArrayRef)@[(__bridge id)different],
              description,
              prompt) == errSecSuccess;
      if (description != NULL) CFRelease(description);
      if (applications != NULL) CFRelease(applications);
      replacedEncrypt = true;
    }
    if (authorizations != NULL) CFRelease(authorizations);
  }
  bool rejected = exactSetup && replacedEncrypt &&
      !hra_macos_install_envelope_access_is_strict(access);
#if defined(HRA_KEYCHAIN_ACL_FIXTURE_DEBUG)
  if (!exactSetup)
    fprintf(stderr, "same-path-different-requirement-setup-failed:%u\n", setupStage);
  else if (!replacedEncrypt) fputs("same-path-encrypt-not-replaced\n", stderr);
  else if (!rejected) fputs("same-path-different-requirement-accepted\n", stderr);
#endif
  if (aclList != NULL) CFRelease(aclList);
  if (differentRequirementData != NULL) CFRelease(differentRequirementData);
  if (currentRequirementData != NULL) CFRelease(currentRequirementData);
  if (storedDifferentRequirement != NULL)
    CFRelease(storedDifferentRequirement);
  if (currentRequirement != NULL) CFRelease(currentRequirement);
  if (differentPath != NULL) CFRelease(differentPath);
  if (currentPath != NULL) CFRelease(currentPath);
  if (requestedDifferentRequirement != NULL)
    CFRelease(requestedDifferentRequirement);
  if (different != NULL) CFRelease(different);
  if (current != NULL) CFRelease(current);
  if (access != NULL) CFRelease(access);
  return rejected;
}

static bool HRAUnknownACLIsRejected(void) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  bool rejected = access != NULL &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationIntegrity,
          HRAFixtureIntegrityDescription) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationChangeOwner,
          @"change_owner") &&
      HRAAccessACLCount(access) == 5 &&
      !hra_macos_install_envelope_access_is_strict(access);
  if (access != NULL) CFRelease(access);
  return rejected;
}

static bool HRADuplicateACLIsRejected(void) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  bool rejected = access != NULL &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationIntegrity,
          HRAFixtureIntegrityDescription) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationIntegrity,
          HRAFixtureIntegrityDescription) &&
      HRAAccessACLCount(access) == 5 &&
      !hra_macos_install_envelope_access_is_strict(access);
  if (access != NULL) CFRelease(access);
  return rejected;
}

static bool HRASubjectfulSystemACLIsRejected(void) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  SecTrustedApplicationRef trusted = NULL;
  NSString *partitionDescription = HRAFixturePartitionDescription();
  bool rejected = access != NULL &&
      SecTrustedApplicationCreateFromPath(NULL, &trusted) == errSecSuccess &&
      trusted != NULL &&
      HRAAppendACL(
          access,
          @[(__bridge id)trusted],
          HRAFixtureIntegrityDescription,
          0,
          @[(__bridge NSString *)kSecACLAuthorizationIntegrity]) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationPartitionID,
          partitionDescription) &&
      HRAAccessACLCount(access) == 5 &&
      !hra_macos_install_envelope_access_is_strict(access);
  if (trusted != NULL) CFRelease(trusted);
  if (access != NULL) CFRelease(access);
  return rejected;
}

static bool HRAEmptyApplicationListOnSystemACLIsRejected(void) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  NSString *partitionDescription = HRAFixturePartitionDescription();
  bool rejected = access != NULL && partitionDescription != nil &&
      HRAAppendACL(
          access,
          @[],
          HRAFixtureIntegrityDescription,
          0,
          @[(__bridge NSString *)kSecACLAuthorizationIntegrity]) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationPartitionID,
          partitionDescription) &&
      HRAAccessACLCount(access) == 5 &&
      !hra_macos_install_envelope_access_is_strict(access);
  if (access != NULL) CFRelease(access);
  return rejected;
}

static bool HRASystemACLWithSensitiveDescriptionIsRejected(void) {
  SecAccessRef access = hra_macos_copy_strict_install_envelope_access();
  NSString *partitionDescription = HRAFixturePartitionDescription();
  bool rejected = access != NULL &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationIntegrity,
          HRAFixtureAccessDescription) &&
      HRAAppendSystemACL(
          access,
          kSecACLAuthorizationPartitionID,
          partitionDescription) &&
      HRAAccessACLCount(access) == 5 &&
      !hra_macos_install_envelope_access_is_strict(access);
  if (access != NULL) CFRelease(access);
  return rejected;
}

static uint8_t HRAMalformedAccessFailure(
    const char *untrustedExecutable) {
  if (!HRAAccessWithAdditionalSensitiveSubjectIsRejected(
          untrustedExecutable)) {
    HRA_FIXTURE_DEBUG("extra-sensitive-subject-not-rejected");
    return 1;
  }
  if (!HRAUnknownACLIsRejected()) {
    HRA_FIXTURE_DEBUG("unknown-acl-not-rejected");
    return 2;
  }
  if (!HRADuplicateACLIsRejected()) {
    HRA_FIXTURE_DEBUG("duplicate-acl-not-rejected");
    return 3;
  }
  if (!HRASubjectfulSystemACLIsRejected()) {
    HRA_FIXTURE_DEBUG("subjectful-system-acl-not-rejected");
    return 4;
  }
  if (!HRAEmptyApplicationListOnSystemACLIsRejected()) {
    HRA_FIXTURE_DEBUG("empty-system-application-list-not-rejected");
    return 5;
  }
  if (!HRASystemACLWithSensitiveDescriptionIsRejected()) {
    HRA_FIXTURE_DEBUG("system-sensitive-description-not-rejected");
    return 6;
  }
  if (!HRAMetadataValidatorsRejectMalformedACLs()) {
    HRA_FIXTURE_DEBUG("system-metadata-validator-accepted-malformed-acl");
    return 7;
  }
  if (!HRAAccessWithSamePathDifferentRequirementIsRejected()) {
    HRA_FIXTURE_DEBUG("same-path-different-requirement-not-rejected");
    return 8;
  }
  if (!HRAPreparedMigrationSourcesAreExactlyAudited()) {
    HRA_FIXTURE_DEBUG("prepared-migration-sources-not-exactly-audited");
    return 9;
  }
  if (!HRAPreparedMigrationTransitionPolicyIsExact()) {
    HRA_FIXTURE_DEBUG("prepared-migration-transition-policy-not-exact");
    return 10;
  }
  if (!HRAUnavailableRequirementSPIFailsClosed()) {
    HRA_FIXTURE_DEBUG("missing-requirement-spi-did-not-fail-closed");
    return 11;
  }
  return 0;
}

static bool HRAStoredSubjectsMatchOnlyOwner(
    SecKeychainRef keychain,
    const char *ownerExecutable,
    const char *untrustedExecutable) {
  OSStatus itemStatus = errSecInternalError;
  NSDictionary *result = HRAReadExactItem(keychain, &itemStatus);
  SecKeychainItemRef item = result == nil
      ? NULL
      : (__bridge SecKeychainItemRef)result[(__bridge id)kSecValueRef];
  SecTrustedApplicationRef owner = NULL;
  SecTrustedApplicationRef untrusted = NULL;
  CFDataRef ownerData = NULL;
  CFDataRef untrustedData = NULL;
  SecAccessRef access = NULL;
  CFArrayRef aclList = NULL;
  bool exact = itemStatus == errSecSuccess && item != NULL &&
      SecTrustedApplicationCreateFromPath(ownerExecutable, &owner) ==
          errSecSuccess && owner != NULL &&
      SecTrustedApplicationCreateFromPath(untrustedExecutable, &untrusted) ==
          errSecSuccess && untrusted != NULL &&
      SecTrustedApplicationCopyData(owner, &ownerData) == errSecSuccess &&
      ownerData != NULL &&
      SecTrustedApplicationCopyData(untrusted, &untrustedData) ==
          errSecSuccess && untrustedData != NULL &&
      !CFEqual(ownerData, untrustedData) &&
      SecKeychainItemCopyAccess(item, &access) == errSecSuccess &&
      access != NULL &&
      SecAccessCopyACLList(access, &aclList) == errSecSuccess &&
      aclList != NULL && CFArrayGetCount(aclList) == 5 &&
      hra_macos_install_envelope_item_access_is_strict(item);
  NSUInteger sensitiveCount = 0;
  NSUInteger systemCount = 0;
  for (CFIndex index = 0;
       exact && index < CFArrayGetCount(aclList);
       index += 1) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(aclList, index);
    CFArrayRef applications = NULL;
    CFStringRef description = NULL;
    SecKeychainPromptSelector prompt = 0;
    exact = acl != NULL &&
        SecACLCopyContents(
            acl, &applications, &description, &prompt) == errSecSuccess;
    CFDataRef storedData = NULL;
    if (exact && applications == NULL) {
      systemCount += 1;
    } else if (exact && CFArrayGetCount(applications) == 1) {
      SecTrustedApplicationRef stored =
          (SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, 0);
      exact = stored != NULL &&
          SecTrustedApplicationCopyData(stored, &storedData) ==
              errSecSuccess && storedData != NULL &&
          CFEqual(storedData, ownerData) &&
          !CFEqual(storedData, untrustedData);
      sensitiveCount += 1;
    } else {
      exact = false;
    }
    if (storedData != NULL) CFRelease(storedData);
    if (description != NULL) CFRelease(description);
    if (applications != NULL) CFRelease(applications);
  }
  if (aclList != NULL) CFRelease(aclList);
  if (access != NULL) CFRelease(access);
  if (untrustedData != NULL) CFRelease(untrustedData);
  if (ownerData != NULL) CFRelease(ownerData);
  if (untrusted != NULL) CFRelease(untrusted);
  if (owner != NULL) CFRelease(owner);
  return exact && sensitiveCount == 3 && systemCount == 2;
}

int main(int argumentCount, const char *arguments[]) {
  @autoreleasepool {
    if (argumentCount != 3 || arguments[1][0] != '/' ||
        arguments[2][0] != '/') return 2;
    const char *keychainPath = arguments[1];
    const char *untrustedExecutable = arguments[2];
    NSString *decoyPath = [[NSString stringWithUTF8String:keychainPath]
        stringByAppendingString:@".decoy"];
    CFArrayRef searchBefore = NULL;
    CFArrayRef searchAfterCreate = NULL;
    CFArrayRef searchAfterDelete = NULL;
    SecKeychainRef keychain = NULL;
    SecKeychainRef decoyKeychain = NULL;
    SecAccessRef access = NULL;
    SecAccessRef persistedProjectionAccess = NULL;
    NSMutableDictionary *add = nil;
    NSMutableDictionary *decoyAdd = nil;
    int result = 3;
    if (SecKeychainCopySearchList(&searchBefore) != errSecSuccess ||
        searchBefore == NULL) goto cleanup;
    HRA_FIXTURE_DEBUG("search-before");
    OSStatus created = SecKeychainCreate(
        keychainPath,
        (UInt32)[HRAFixturePassword lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
        HRAFixturePassword.UTF8String,
        false,
        NULL,
        &keychain);
    if (created != errSecSuccess || keychain == NULL) {
      result = 4;
      goto cleanup;
    }
    OSStatus decoyCreated = SecKeychainCreate(
        decoyPath.fileSystemRepresentation,
        (UInt32)[HRAFixturePassword lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
        HRAFixturePassword.UTF8String,
        false,
        NULL,
        &decoyKeychain);
    if (decoyCreated != errSecSuccess || decoyKeychain == NULL) {
      result = 5;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("keychain-created");
    if (SecKeychainCopySearchList(&searchAfterCreate) != errSecSuccess ||
        searchAfterCreate == NULL || !CFEqual(searchBefore, searchAfterCreate)) {
      result = 6;
      goto cleanup;
    }
    access = hra_macos_copy_strict_install_envelope_access();
    persistedProjectionAccess = HRACopyPersistedProjectionAccess();
    if (access == NULL || HRAAccessACLCount(access) != 3 ||
        !hra_macos_install_envelope_access_is_strict(access) ||
        persistedProjectionAccess == NULL ||
        !HRAQueryTransformsAreExact(keychain) ||
        !HRAQueryTransformsAreExact(decoyKeychain)) {
      result = 7;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("access-created");
    add = [HRAFixtureQuery(keychain) mutableCopy];
    [add removeObjectForKey:(__bridge id)kSecUseAuthenticationUI];
    [add removeObjectForKey:(__bridge id)kSecUseAuthenticationContext];
    [add removeObjectForKey:(__bridge id)kSecMatchSearchList];
    add[(__bridge id)kSecUseKeychain] = (__bridge id)keychain;
    add[(__bridge id)kSecValueData] =
        [HRAFixtureEnvelope dataUsingEncoding:NSUTF8StringEncoding];
    add[(__bridge id)kSecAttrAccess] =
        (__bridge id)persistedProjectionAccess;
    decoyAdd = CFBridgingRelease(
        hra_macos_copy_generic_password_add_attributes(
            (__bridge CFDictionaryRef)HRAFixtureQuery(decoyKeychain)));
    decoyAdd[(__bridge id)kSecValueData] =
        [HRAFixtureDecoyEnvelope dataUsingEncoding:NSUTF8StringEncoding];
    decoyAdd[(__bridge id)kSecAttrAccess] = (__bridge id)access;
    if (decoyAdd == nil ||
        SecItemAdd((__bridge CFDictionaryRef)decoyAdd, NULL) !=
            errSecSuccess ||
        !HRAReadbackHasExactValueAndAccessStrictness(
            decoyKeychain, HRAFixtureDecoyEnvelope, false) ||
        SecItemDelete((__bridge CFDictionaryRef)HRAFixtureQuery(decoyKeychain)) !=
            errSecSuccess) {
      result = 8;
      goto cleanup;
    }
    decoyAdd[(__bridge id)kSecAttrAccess] =
        (__bridge id)persistedProjectionAccess;
    if (SecItemAdd((__bridge CFDictionaryRef)decoyAdd, NULL) !=
            errSecSuccess ||
        !HRAReadbackHasExactValueAndStrictAccess(
            decoyKeychain, HRAFixtureDecoyEnvelope)) {
      result = 9;
      goto cleanup;
    }
    if (SecItemAdd((__bridge CFDictionaryRef)add, NULL) != errSecSuccess ||
        !HRAReadbackIsExact(keychain)) {
      result = 9;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("item-created");
    if (SecItemAdd((__bridge CFDictionaryRef)add, NULL) !=
            errSecDuplicateItem ||
        !HRAReadbackIsExact(keychain)) {
      result = 10;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("duplicate-read");
    uint8_t malformedFailure = HRAMalformedAccessFailure(
        untrustedExecutable);
    if (malformedFailure != 0) {
      result = 10 + malformedFailure;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("malformed-acls-rejected");
    if (!HRAStoredSubjectsMatchOnlyOwner(
            keychain, arguments[0], untrustedExecutable) ||
        !HRAReadbackIsExact(keychain)) {
      result = 12;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("untrusted-subject-rejected");
    if (!HRAReadbackValueIsExact(keychain, HRAFixtureEnvelope) ||
        !HRAReadbackValueIsExact(
            decoyKeychain, HRAFixtureDecoyEnvelope)) {
      result = 13;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("custom-search-list-rejected");
    if (SecItemDelete((__bridge CFDictionaryRef)HRAFixtureQuery(keychain)) !=
        errSecSuccess) {
      result = 14;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("item-deleted");
    OSStatus absentStatus = errSecInternalError;
    if (HRAReadExactItem(keychain, &absentStatus) != nil ||
        absentStatus != errSecItemNotFound) {
      result = 15;
      goto cleanup;
    }
    result = 0;

  cleanup:
    HRA_FIXTURE_DEBUG("cleanup");
    if (persistedProjectionAccess != NULL)
      CFRelease(persistedProjectionAccess);
    if (access != NULL) CFRelease(access);
    if (decoyKeychain != NULL) {
      SecKeychainDelete(decoyKeychain);
      CFRelease(decoyKeychain);
    }
    if (keychain != NULL) {
      SecKeychainDelete(keychain);
      CFRelease(keychain);
    }
    if (SecKeychainCopySearchList(&searchAfterDelete) != errSecSuccess ||
        searchAfterDelete == NULL || searchBefore == NULL ||
        !CFEqual(searchBefore, searchAfterDelete)) {
      result = 16;
    }
    if (searchAfterDelete != NULL) CFRelease(searchAfterDelete);
    if (searchAfterCreate != NULL) CFRelease(searchAfterCreate);
    if (searchBefore != NULL) CFRelease(searchBefore);
    if (result == 0) {
      fputs("{\"created\":true,\"customSearchListScoped\":true,\"deleted\":true,\"duplicateCreated\":false,\"loginKeychainChanged\":false,\"malformedAclRejected\":true,\"migrationPartitionPinned\":true,\"migrationTransitionExact\":true,\"noPromptQueryExact\":true,\"ok\":true,\"requirementSpiFailClosed\":true,\"samePathRequirementRejected\":true,\"storedDraftRejected\":true,\"strictAcl\":true,\"systemPayloadProjectionAccepted\":true,\"untrustedSubjectExcluded\":true,\"version\":1}\n", stdout);
    }
    return result;
  }
}
