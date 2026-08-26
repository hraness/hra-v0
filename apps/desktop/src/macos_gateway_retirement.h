#ifndef HRA_MACOS_GATEWAY_RETIREMENT_H
#define HRA_MACOS_GATEWAY_RETIREMENT_H

#if defined(HRA_KEYCHAIN_CUSTODIAN_HELPER_BUILD)
#error "gateway retirement belongs only to the native HRA host"
#endif

#include <stdbool.h>
#include <sys/types.h>

typedef enum {
  HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS = 0,
  HRA_MACOS_GATEWAY_GROUP_RETIREMENT_PENDING = 1,
  HRA_MACOS_GATEWAY_GROUP_RETIREMENT_QUIESCENT = 2,
} HRAMacOSGatewayGroupRetirementState;

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

#endif
