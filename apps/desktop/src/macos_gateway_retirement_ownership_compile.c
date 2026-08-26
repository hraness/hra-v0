#include "macos_gateway_retirement.h"

typedef HRAMacOSGatewayGroupRetirementState (*HRARetirementStateFunction)(
    pid_t);
typedef bool (*HRARetainedZombieFunction)(pid_t);

_Static_assert(
    _Generic(
        &hra_macos_gateway_process_group_retirement_state,
        HRARetirementStateFunction: 1,
        default: 0),
    "the native host must compile the exact gateway retirement state API");
_Static_assert(
    _Generic(
        &hra_macos_gateway_retained_child_is_zombie,
        HRARetainedZombieFunction: 1,
        default: 0),
    "the native host must compile the exact retained-zombie diagnostic API");

int main(void) {
  return 0;
}
