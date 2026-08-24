#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

static NSString *const HRAFixturePassword = @"hra-acl-test-v1";

#if defined(HRA_KEYCHAIN_ACL_FIXTURE_DEBUG)
#define HRA_FIXTURE_DEBUG(message) fputs(message "\n", stderr)
#else
#define HRA_FIXTURE_DEBUG(message) ((void)0)
#endif

int main(int argumentCount, const char *arguments[]) {
  @autoreleasepool {
    if (argumentCount != 2 || arguments[1][0] != '/') return 2;
    SecKeychainRef keychain = NULL;
    if (SecKeychainOpen(arguments[1], &keychain) != errSecSuccess ||
        keychain == NULL) return 3;
    HRA_FIXTURE_DEBUG("untrusted-open");
    OSStatus unlocked = SecKeychainUnlock(
        keychain,
        (UInt32)[HRAFixturePassword lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
        HRAFixturePassword.UTF8String,
        true);
    if (unlocked != errSecSuccess) {
      CFRelease(keychain);
      return 4;
    }
    HRA_FIXTURE_DEBUG("untrusted-unlock");
    LAContext *authenticationContext = [[LAContext alloc] init];
    authenticationContext.interactionNotAllowed = YES;
    NSDictionary *query = @{
      (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrService: @"hra.keychain-acl.fixture",
      (__bridge id)kSecAttrAccount: @"installation-master",
      (__bridge id)kSecMatchSearchList: @[(__bridge id)keychain],
      (__bridge id)kSecUseAuthenticationUI:
          (__bridge id)kSecUseAuthenticationUIFail,
      (__bridge id)kSecUseAuthenticationContext: authenticationContext,
    };
    NSMutableDictionary *readQuery = [query mutableCopy];
    readQuery[(__bridge id)kSecReturnData] = @YES;
    readQuery[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef raw = NULL;
    OSStatus read = SecItemCopyMatching(
        (__bridge CFDictionaryRef)readQuery, &raw);
    HRA_FIXTURE_DEBUG("untrusted-read");
    if (raw != NULL) CFRelease(raw);
    NSDictionary *replacement = @{
      (__bridge id)kSecValueData:
          [@"unauthorized" dataUsingEncoding:NSUTF8StringEncoding],
    };
    OSStatus updated = SecItemUpdate(
        (__bridge CFDictionaryRef)query,
        (__bridge CFDictionaryRef)replacement);
    HRA_FIXTURE_DEBUG("untrusted-update");
    OSStatus deleted = SecItemDelete((__bridge CFDictionaryRef)query);
    HRA_FIXTURE_DEBUG("untrusted-delete");
    CFRelease(keychain);
    return read != errSecSuccess && updated != errSecSuccess &&
        deleted != errSecSuccess ? 0 : 5;
  }
}
