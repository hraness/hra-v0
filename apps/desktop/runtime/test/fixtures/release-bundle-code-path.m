#if defined(HRA_RELEASE_BUNDLE_PATH_HOST)

#include <errno.h>
#include <unistd.h>

int main(void) {
  unsigned char byte = 0;
  ssize_t count;
  do {
    count = read(STDIN_FILENO, &byte, 1);
  } while (count < 0 && errno == EINTR);
  return count >= 0 ? 0 : 70;
}

#else

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <stdio.h>

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc != 4) return 64;
    NSString *hostPath = [NSString stringWithUTF8String:argv[1]];
    NSString *expectedBundlePath = [NSString stringWithUTF8String:argv[2]];
    NSString *expectedMainExecutablePath =
        [NSString stringWithUTF8String:argv[3]];
    SecStaticCodeRef code = NULL;
    CFURLRef rawPath = NULL;
    CFDictionaryRef information = NULL;
    bool exact = hostPath != nil && expectedBundlePath != nil &&
        expectedMainExecutablePath != nil &&
        SecStaticCodeCreateWithPath(
            (__bridge CFURLRef)[NSURL fileURLWithPath:hostPath],
            kSecCSDefaultFlags,
            &code) == errSecSuccess && code != NULL &&
        SecStaticCodeCheckValidity(
            code,
            kSecCSStrictValidate | kSecCSCheckAllArchitectures,
            NULL) == errSecSuccess &&
        SecCodeCopyPath((SecCodeRef)code, kSecCSDefaultFlags, &rawPath) ==
            errSecSuccess && rawPath != NULL &&
        [[(__bridge NSURL *)rawPath path]
            isEqualToString:expectedBundlePath] &&
        SecCodeCopySigningInformation(
            (SecCodeRef)code,
            kSecCSSigningInformation,
            &information) == errSecSuccess && information != NULL;
    CFTypeRef rawMainExecutable = exact
        ? CFDictionaryGetValue(information, kSecCodeInfoMainExecutable)
        : NULL;
    exact = exact && rawMainExecutable != NULL &&
        CFGetTypeID(rawMainExecutable) == CFURLGetTypeID() &&
        [[(__bridge NSURL *)rawMainExecutable path]
            isEqualToString:expectedMainExecutablePath];
    if (information != NULL) CFRelease(information);
    if (rawPath != NULL) CFRelease(rawPath);
    if (code != NULL) CFRelease(code);
    if (!exact) return 70;
    fputs("{\"ok\":true,\"version\":1}\n", stdout);
    return 0;
  }
}

#endif
