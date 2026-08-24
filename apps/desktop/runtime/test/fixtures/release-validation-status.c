#include "macos_release_validation_status.h"

#include <Security/CSCommon.h>
#include <stdio.h>

typedef struct {
  bool pinned_identity_is_exact;
  OSStatus status;
  bool expected;
} HRAValidationCase;

typedef struct {
  bool first_is_leaf;
  bool first_is_root;
  bool second_is_leaf;
  bool second_is_root;
  bool expected;
} HRACertificateSetCase;

typedef struct {
  bool security_chain_is_exact;
  bool pinned_trust_failure;
  bool expected;
} HRAEmbeddedFallbackCase;

static bool certificate_set_case_is_exact(
    const HRACertificateSetCase *test) {
  bool found_leaf = false;
  bool found_root = false;
  return test != NULL &&
      hra_macos_release_record_certificate_role(
          test->first_is_leaf,
          test->first_is_root,
          &found_leaf,
          &found_root) &&
      hra_macos_release_record_certificate_role(
          test->second_is_leaf,
          test->second_is_root,
          &found_leaf,
          &found_root) &&
      found_leaf && found_root;
}

int main(void) {
  static const HRAValidationCase cases[] = {
    {true, errSecSuccess, true},
    {true, CSSMERR_TP_NOT_TRUSTED, true},
    {false, errSecSuccess, false},
    {false, CSSMERR_TP_NOT_TRUSTED, false},
    {true, CSSMERR_TP_VERIFICATION_FAILURE, false},
    {true, CSSMERR_TP_INVALID_CERTIFICATE, false},
    {true, CSSMERR_TP_CERT_EXPIRED, false},
    {true, CSSMERR_TP_CERT_REVOKED, false},
    {true, errSecCSSignatureFailed, false},
    {true, errSecCSResourcesInvalid, false},
    {true, errSecCSUnsigned, false},
    {true, errSecCSReqFailed, false},
    {true, (OSStatus)-1, false},
  };
  for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
    const HRAValidationCase *test = &cases[index];
    if (hra_macos_release_validation_status_is_admissible(
            test->pinned_identity_is_exact,
            test->status) != test->expected) {
      return (int)index + 1;
    }
  }
  static const HRACertificateSetCase certificate_cases[] = {
    {true, false, false, true, true},
    {false, true, true, false, true},
    {true, false, true, false, false},
    {false, true, false, true, false},
    {false, false, true, false, false},
    {true, false, false, false, false},
    {true, true, false, true, false},
    {true, false, true, true, false},
  };
  for (size_t index = 0;
       index < sizeof(certificate_cases) / sizeof(certificate_cases[0]);
       index++) {
    const HRACertificateSetCase *test = &certificate_cases[index];
    if (certificate_set_case_is_exact(test) != test->expected) {
      return (int)index + 32;
    }
  }
  static const HRAEmbeddedFallbackCase fallback_cases[] = {
    {false, true, true},
    {false, false, false},
    {true, true, false},
    {true, false, false},
  };
  for (size_t index = 0;
       index < sizeof(fallback_cases) / sizeof(fallback_cases[0]);
       index++) {
    const HRAEmbeddedFallbackCase *test = &fallback_cases[index];
    if (hra_macos_release_should_validate_embedded_certificate_set(
            test->security_chain_is_exact,
            test->pinned_trust_failure) != test->expected) {
      return (int)index + 48;
    }
  }
  return fputs("{\"ok\":true,\"version\":2}\n", stdout) < 0 ? 70 : 0;
}
