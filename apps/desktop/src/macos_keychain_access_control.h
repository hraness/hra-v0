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

/// Classifies either the exact three-ACL constructor draft or the exact
/// five-ACL persisted shape. The currently executing helper remains the sole
/// trusted app on every sensitive ACL, while system-managed payload ACLs carry
/// no trusted-application list. Stored items use the stricter API below.
bool hra_macos_install_envelope_access_is_strict(
    SecAccessRef _Nullable access);

/// Requires the exact persisted five-ACL Keychain shape, including macOS's
/// system-managed integrity and current-helper partition-ID payload ACLs. Each
/// carries no trusted-application list. Three-ACL constructor drafts, nil or
/// all-app lists on sensitive ACLs, application subjects on system ACLs,
/// prompts, duplicate tags, unknown tags, and every other shape fail.
bool hra_macos_install_envelope_item_access_is_strict(
    SecKeychainItemRef _Nullable item);

/// Public-projection classifier used by deterministic native fixtures for an
/// exact singleton audited prepared migration source. Production uses the item
/// API.
bool hra_macos_install_envelope_access_is_prepared_migration_source(
    SecAccessRef _Nullable access);

/// Classifies only a transient exact semantic partition set containing the
/// current-helper CDHash and exactly one audited predecessor CDHash in a
/// bounded lowercase-hex XML plist. It exists for the explicit user-authorized
/// migration and is never a final strict state.
bool hra_macos_install_envelope_access_is_prepared_migration_transition(
    SecAccessRef _Nullable access);

/// Requires the exact persisted five-ACL source shape accepted solely by the
/// prepared migration. Core ACLs must name the current helper by exact path and
/// exact designated-requirement bytes. System metadata remains strict, while
/// the exact singleton semantic partition set in its bounded lowercase-hex XML
/// plist may still name one authorized prior build.
bool hra_macos_install_envelope_item_access_is_prepared_migration_source(
    SecKeychainItemRef _Nullable item);

bool hra_macos_install_envelope_item_access_is_prepared_migration_transition(
    SecKeychainItemRef _Nullable item);

#if defined(HRA_KEYCHAIN_ACCESS_CONTROL_TESTING)
/// Deterministic fail-closed fixture seam for an unavailable requirement SPI.
void hra_macos_keychain_access_control_test_force_requirement_spi_unavailable(
    bool unavailable);
#endif

#endif
