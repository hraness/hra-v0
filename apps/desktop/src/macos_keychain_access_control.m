#import "macos_keychain_access_control.h"

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

static NSString *const HRAInstallEnvelopeAccessDescription =
    @"HRA Harness installation key";

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

static uint8_t HRAExactInstallEnvelopeACLKind(CFArrayRef authorizations) {
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[(__bridge NSString *)kSecACLAuthorizationEncrypt])) return 1;
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[
            (__bridge NSString *)kSecACLAuthorizationDecrypt,
            (__bridge NSString *)kSecACLAuthorizationDerive,
            (__bridge NSString *)kSecACLAuthorizationExportClear,
            (__bridge NSString *)kSecACLAuthorizationExportWrapped,
            (__bridge NSString *)kSecACLAuthorizationMAC,
            (__bridge NSString *)kSecACLAuthorizationSign,
          ])) return 2;
  if (HRAACLAuthorizationsMatch(
          authorizations,
          @[(__bridge NSString *)kSecACLAuthorizationChangeACL])) return 4;
  return 0;
}

static bool HRATrustedApplicationMatchesCurrentExactHelper(
    SecTrustedApplicationRef candidate,
    CFDataRef expectedData) {
  if (candidate == NULL || expectedData == NULL ||
      CFGetTypeID(candidate) != SecTrustedApplicationGetTypeID()) {
    return false;
  }
  CFDataRef actualData = NULL;
  bool exact = SecTrustedApplicationCopyData(candidate, &actualData) ==
          errSecSuccess &&
      actualData != NULL && CFEqual(actualData, expectedData);
  if (actualData != NULL) CFRelease(actualData);
  return exact;
}

static bool HRAInstallEnvelopeAccessIsStrict(
    SecAccessRef access,
    CFDataRef expectedApplicationData) {
  if (access == NULL || expectedApplicationData == NULL ||
      CFGetTypeID(access) != SecAccessGetTypeID()) return false;
  CFArrayRef aclList = NULL;
  bool exact = SecAccessCopyACLList(access, &aclList) == errSecSuccess &&
      aclList != NULL && CFArrayGetCount(aclList) == 3;
  uint8_t observedKinds = 0;
  for (CFIndex index = 0;
       exact && index < CFArrayGetCount(aclList);
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
    aclExact = aclExact && applications != NULL &&
        CFArrayGetCount(applications) == 1 && prompt == 0 &&
        description != NULL &&
        CFEqual(
            description,
            (__bridge CFStringRef)HRAInstallEnvelopeAccessDescription) &&
        kind != 0 && (observedKinds & kind) == 0 &&
        HRATrustedApplicationMatchesCurrentExactHelper(
            (SecTrustedApplicationRef)CFArrayGetValueAtIndex(
                applications, 0),
            expectedApplicationData);
    observedKinds |= kind;
    if (authorizations != NULL) CFRelease(authorizations);
    if (description != NULL) CFRelease(description);
    if (applications != NULL) CFRelease(applications);
    if (!aclExact) exact = false;
  }
  if (aclList != NULL) CFRelease(aclList);
  return exact && observedKinds == 7;
}

SecAccessRef _Nullable hra_macos_copy_strict_install_envelope_access(void) {
  @autoreleasepool {
    SecTrustedApplicationRef trusted = NULL;
    CFDataRef trustedData = NULL;
    SecAccessRef access = NULL;
    if (SecTrustedApplicationCreateFromPath(NULL, &trusted) != errSecSuccess ||
        trusted == NULL ||
        SecTrustedApplicationCopyData(trusted, &trustedData) != errSecSuccess ||
        trustedData == NULL) {
      if (trustedData != NULL) CFRelease(trustedData);
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
        (observedKinds != 7 ||
         !HRAInstallEnvelopeAccessIsStrict(access, trustedData))) {
      status = errSecAuthFailed;
    }
    CFRelease(trustedData);
    CFRelease(trusted);
    if (status == errSecSuccess) return access;
    if (access != NULL) CFRelease(access);
    return NULL;
  }
}

bool hra_macos_install_envelope_item_access_is_strict(
    SecKeychainItemRef item) {
  @autoreleasepool {
    if (item == NULL || CFGetTypeID(item) != SecKeychainItemGetTypeID())
      return false;
    SecTrustedApplicationRef expectedApplication = NULL;
    CFDataRef expectedData = NULL;
    SecAccessRef access = NULL;
    bool exact = SecTrustedApplicationCreateFromPath(
            NULL, &expectedApplication) == errSecSuccess &&
        expectedApplication != NULL &&
        SecTrustedApplicationCopyData(
            expectedApplication, &expectedData) == errSecSuccess &&
        expectedData != NULL &&
        SecKeychainItemCopyAccess(item, &access) == errSecSuccess &&
        access != NULL &&
        HRAInstallEnvelopeAccessIsStrict(access, expectedData);
    if (access != NULL) CFRelease(access);
    if (expectedData != NULL) CFRelease(expectedData);
    if (expectedApplication != NULL) CFRelease(expectedApplication);
    return exact;
  }
}
