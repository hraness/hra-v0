#ifndef HRA_MACOS_KEYCHAIN_ACCESS_CONTROL_H
#define HRA_MACOS_KEYCHAIN_ACCESS_CONTROL_H

#include <stdbool.h>
#include <Security/Security.h>

/// Creates the exact no-prompt generic-password query used by custody. The
/// query is scoped to exactly one supplied Keychain and contains no result or
/// value keys. The caller owns the result.
CFDictionaryRef _Nullable hra_macos_copy_no_ui_generic_password_query(
    SecKeychainRef _Nonnull keychain,
    CFStringRef _Nonnull service,
    CFStringRef _Nonnull account);

/// Converts the exact no-prompt query into an exact create-only attributes
/// dictionary: query-only UI/search keys are removed and the same sole
/// Keychain becomes kSecUseKeychain. The caller owns the result.
CFMutableDictionaryRef _Nullable
hra_macos_copy_generic_password_add_attributes(
    CFDictionaryRef _Nonnull query);

/// Creates the exact helper-only, zero-prompt ACL used by the canonical
/// installation-envelope generic-password item. The caller owns the result.
SecAccessRef _Nullable hra_macos_copy_strict_install_envelope_access(void);

/// Requires the stored item to have exactly the constructor's authorization
/// partition and the currently executing helper as the sole trusted app for
/// every ACL. Nil/all-app lists, prompts, duplicate tags, and unknown tags fail.
bool hra_macos_install_envelope_item_access_is_strict(
    SecKeychainItemRef _Nullable item);

#endif
