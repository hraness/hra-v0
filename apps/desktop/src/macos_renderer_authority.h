#ifndef HRA_MACOS_RENDERER_AUTHORITY_H
#define HRA_MACOS_RENDERER_AUTHORITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  const char *relative_path;
  size_t relative_path_length;
  uint8_t type;
  uint32_t permissions;
  uint64_t byte_length;
  uint8_t sha256[32];
} HRAMacOSRendererAuthorityEntry;

extern const HRAMacOSRendererAuthorityEntry
    HRAExpectedRendererAuthorityEntries[];
extern const size_t HRAExpectedRendererAuthorityEntryCount;
extern const uint8_t HRAExpectedRendererAuthorityRootSHA256[32];
extern const char HRAExpectedRendererAuthorityRootSHA256Hex[65];

/// Proves the complete packaged renderer tree against the non-circular
/// authority compiled into the host/helper. Every entry is opened no-follow,
/// held through enumeration and hashing, and rechecked before success.
bool hra_macos_renderer_authority_is_exact(
    const char *root_path,
    size_t root_path_length);

/// Native SDK's patched scheme handler calls this on the exact NSData bytes
/// it is about to send to WebKit. The callback is intentionally mandatory in
/// HRA's linked host and closes the tree-check/file-reopen race.
bool native_sdk_appkit_asset_bytes_are_authorized(
    const char *root_path,
    size_t root_path_length,
    const char *relative_path,
    size_t relative_path_length,
    const uint8_t *bytes,
    size_t byte_length);

#endif
