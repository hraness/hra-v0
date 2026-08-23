#import "../../../src/macos_keychain_access_control.h"

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

static bool HRAReadbackIsExact(SecKeychainRef keychain) {
  OSStatus status = errSecInternalError;
  NSDictionary *result = HRAReadExactItem(keychain, &status);
  if (status != errSecSuccess || result == nil) return false;
  NSData *expected = [HRAFixtureEnvelope dataUsingEncoding:NSUTF8StringEncoding];
  NSData *actual = result[(__bridge id)kSecValueData];
  SecKeychainItemRef item = (__bridge SecKeychainItemRef)
      result[(__bridge id)kSecValueRef];
  return [actual isKindOfClass:[NSData class]] &&
      [actual isEqualToData:expected] &&
      hra_macos_install_envelope_item_access_is_strict(item);
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
      aclList != NULL && CFArrayGetCount(aclList) == 3;
  for (CFIndex index = 0;
       exact && index < CFArrayGetCount(aclList);
       index += 1) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(aclList, index);
    CFArrayRef applications = NULL;
    CFStringRef description = NULL;
    SecKeychainPromptSelector prompt = 0;
    exact = acl != NULL &&
        SecACLCopyContents(
            acl, &applications, &description, &prompt) == errSecSuccess &&
        applications != NULL && CFArrayGetCount(applications) == 1;
    CFDataRef storedData = NULL;
    if (exact) {
      SecTrustedApplicationRef stored =
          (SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, 0);
      exact = stored != NULL &&
          SecTrustedApplicationCopyData(stored, &storedData) ==
              errSecSuccess && storedData != NULL &&
          CFEqual(storedData, ownerData) &&
          !CFEqual(storedData, untrustedData);
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
  return exact;
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
    if (access == NULL || !HRAQueryTransformsAreExact(keychain) ||
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
    add[(__bridge id)kSecAttrAccess] = (__bridge id)access;
    decoyAdd = CFBridgingRelease(
        hra_macos_copy_generic_password_add_attributes(
            (__bridge CFDictionaryRef)HRAFixtureQuery(decoyKeychain)));
    decoyAdd[(__bridge id)kSecValueData] =
        [HRAFixtureDecoyEnvelope dataUsingEncoding:NSUTF8StringEncoding];
    decoyAdd[(__bridge id)kSecAttrAccess] = (__bridge id)access;
    if (decoyAdd == nil ||
        SecItemAdd((__bridge CFDictionaryRef)decoyAdd, NULL) !=
            errSecSuccess ||
        !HRAReadbackValueIsExact(decoyKeychain, HRAFixtureDecoyEnvelope)) {
      result = 8;
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
    if (!HRAStoredSubjectsMatchOnlyOwner(
            keychain, arguments[0], untrustedExecutable) ||
        !HRAReadbackIsExact(keychain)) {
      result = 11;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("untrusted-subject-rejected");
    if (!HRAReadbackValueIsExact(keychain, HRAFixtureEnvelope) ||
        !HRAReadbackValueIsExact(
            decoyKeychain, HRAFixtureDecoyEnvelope)) {
      result = 12;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("custom-search-list-rejected");
    if (SecItemDelete((__bridge CFDictionaryRef)HRAFixtureQuery(keychain)) !=
        errSecSuccess) {
      result = 13;
      goto cleanup;
    }
    HRA_FIXTURE_DEBUG("item-deleted");
    OSStatus absentStatus = errSecInternalError;
    if (HRAReadExactItem(keychain, &absentStatus) != nil ||
        absentStatus != errSecItemNotFound) {
      result = 14;
      goto cleanup;
    }
    result = 0;

  cleanup:
    HRA_FIXTURE_DEBUG("cleanup");
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
      result = 15;
    }
    if (searchAfterDelete != NULL) CFRelease(searchAfterDelete);
    if (searchAfterCreate != NULL) CFRelease(searchAfterCreate);
    if (searchBefore != NULL) CFRelease(searchBefore);
    if (result == 0) {
      fputs("{\"created\":true,\"customSearchListScoped\":true,\"deleted\":true,\"duplicateCreated\":false,\"loginKeychainChanged\":false,\"noPromptQueryExact\":true,\"ok\":true,\"strictAcl\":true,\"untrustedSubjectExcluded\":true,\"version\":1}\n", stdout);
    }
    return result;
  }
}
