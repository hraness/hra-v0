#ifndef HRA_MACOS_RELEASE_VALIDATION_STATUS_H
#define HRA_MACOS_RELEASE_VALIDATION_STATUS_H

#include <Security/SecBase.h>
#include <Security/cssmerr.h>
#include <stdbool.h>

// The private release root is deliberately absent from platform trust stores.
// A trust result is admissible only after the independent self-managed parser
// has proved the exact pinned certificate chain, CMS, CodeDirectory, and slots.
static inline bool hra_macos_release_validation_status_is_admissible(
    bool pinned_self_managed_identity_is_exact,
    OSStatus status) {
  return pinned_self_managed_identity_is_exact &&
      (status == errSecSuccess || status == CSSMERR_TP_NOT_TRUSTED);
}

// CMSDecoderCopyAllCerts does not promise certificate order. Accept exactly
// one pinned leaf and one pinned root, in either order, with no ambiguous,
// duplicate, or unrelated certificate.
static inline bool hra_macos_release_record_certificate_role(
    bool is_leaf,
    bool is_root,
    bool *found_leaf,
    bool *found_root) {
  if (found_leaf == NULL || found_root == NULL || is_leaf == is_root ||
      (is_leaf && *found_leaf) || (is_root && *found_root)) return false;
  *found_leaf |= is_leaf;
  *found_root |= is_root;
  return true;
}

static inline bool hra_macos_release_should_validate_embedded_certificate_set(
    bool security_certificate_chain_is_exact,
    bool validation_was_pinned_trust_failure) {
  return !security_certificate_chain_is_exact &&
      validation_was_pinned_trust_failure;
}

#endif
