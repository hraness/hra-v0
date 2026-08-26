#ifndef HRA_MACOS_GATEWAY_ATTESTATION_H
#define HRA_MACOS_GATEWAY_ATTESTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
  pid_t process_identifier;
  int standard_input;
  int standard_output;
  uint64_t start_seconds;
  uint64_t start_microseconds;
} HRAMacOSAttestedGateway;

typedef enum {
  HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS = 0,
  HRA_MACOS_GATEWAY_GROUP_RETIREMENT_PENDING = 1,
  HRA_MACOS_GATEWAY_GROUP_RETIREMENT_QUIESCENT = 2,
} HRAMacOSGatewayGroupRetirementState;

/// Establishes the host thread's child-process lease policy before any child
/// can be spawned. SIGCHLD must use its default disposition without
/// SA_NOCLDWAIT and must be unblocked on the spawning thread so WNOWAIT keeps
/// every child PID reserved until an explicit reap.
bool hra_macos_establish_child_process_policy(void);

/// Rechecks the established policy without overwriting a later incompatible
/// SIGCHLD owner or thread mask.
bool hra_macos_child_process_policy_is_exact(void);

/// Observes one still-unreaped direct-child gateway after its process group
/// has been signalled. Quiescence requires an exact terminal WNOWAIT lease for
/// the leader and every remaining nonleader to be absent or a Darwin zombie.
/// Enumeration, lease, or process-information ambiguity is reported
/// separately so the host can fail closed instead of polling through it.
HRAMacOSGatewayGroupRetirementState
hra_macos_gateway_process_group_retirement_state(pid_t group_leader);

/// Exact diagnostic for a retained direct child. A terminal WNOWAIT lease
/// proves the child is an unreaped zombie while reserving its PID; every other
/// observation returns false.
bool hra_macos_gateway_retained_child_is_zombie(pid_t process_identifier);

/// Uses Darwin POSIX_SPAWN_START_SUSPENDED, authenticates the post-exec image,
/// stores its exact PID generation, and resumes it only after every static and
/// dynamic check succeeds. The caller owns the returned pipe descriptors.
bool hra_macos_spawn_attested_gateway(
    const char *path,
    size_t path_length,
    char *const environment[],
    HRAMacOSAttestedGateway *out_gateway);

/// Exact packaged custody probes are supervised as one native process group.
/// This performs the same post-exec suspended attestation as the production
/// launcher, but deliberately leaves the gateway in the already-isolated
/// probe host's process group. It must never be used by the ordinary runtime.
bool hra_macos_spawn_attested_gateway_for_custody_probe(
    const char *path,
    size_t path_length,
    char *const environment[],
    HRAMacOSAttestedGateway *out_gateway);

/// Copies the generation admitted by the last successful suspended launch and
/// revalidates that its exact gateway image is still live.
bool hra_macos_copy_attested_gateway_generation(
    const char *path,
    size_t path_length,
    pid_t *out_process_identifier,
    uint64_t *out_start_seconds,
    uint64_t *out_start_microseconds);

/// Removes one exact generation from the host's custody admission state.
void hra_macos_clear_attested_gateway_generation(
    pid_t process_identifier,
    uint64_t start_seconds,
    uint64_t start_microseconds);

/// Helper-only parent proof. The returned CDHash comes from a complete
/// no-follow CodeDirectory/page/special-slot/CMS proof under HRA's exact
/// locally self-managed release leaf and build-isolated root, then is matched
/// to Security.framework static data and the exact embedded DR.
bool hra_macos_parent_payload_identity_is_exact(
    const char *path,
    size_t path_length,
    uint8_t out_cdhash[20]);

/// Verifies the packaged helper under the same exact release authority. The
/// helper is nested code and therefore has no external bundle special slots.
bool hra_macos_release_helper_identity_is_exact(
    const char *path,
    size_t path_length,
    uint8_t out_cdhash[20]);

/// Strict all-architecture and nested-code validation of the exact outer app
/// under the pinned production DR. Platform trust-store state is not used as
/// an authority substitute for the self-managed executable proofs.
bool hra_macos_release_outer_bundle_is_exact(
    const char *path,
    size_t path_length);

/// Defense-in-depth check used inside the helper process. `expected_parent`
/// is the HRA host; the gateway must remain its direct exact child.
bool hra_macos_gateway_generation_is_exact(
    const char *path,
    size_t path_length,
    pid_t process_identifier,
    pid_t expected_parent,
    uint64_t start_seconds,
    uint64_t start_microseconds);

/// Lightweight session recheck after one complete gateway/renderer/static
/// proof. The original no-follow descriptor, vnode, PID generation, path, and
/// live Security.framework CDHash must all remain exact.
bool hra_macos_gateway_generation_remains_exact(
    const char *path,
    size_t path_length,
    pid_t process_identifier,
    pid_t expected_parent,
    uint64_t start_seconds,
    uint64_t start_microseconds);

#endif
