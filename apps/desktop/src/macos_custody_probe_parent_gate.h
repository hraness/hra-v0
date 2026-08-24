#ifndef HRA_MACOS_CUSTODY_PROBE_PARENT_GATE_H
#define HRA_MACOS_CUSTODY_PROBE_PARENT_GATE_H

#include <stdbool.h>
#include <stddef.h>

enum {
  HRA_CUSTODY_PROBE_PARENT_LEASE_FD = 3,
};

/// Admits only an exact packaged probe child whose direct supervisor's full
/// process generation matches the strict decimal arguments. The fixed pipe
/// must yield exactly one `G` byte while its sole parent-owned writer remains
/// open. The read descriptor is retained as a lifetime lease and marked
/// close-on-exec before any gateway/helper can be created. Admission also
/// starts a native watcher and proves it is running before returning, so a
/// blocking gateway/helper operation cannot outlive the exact supervisor.
bool hra_macos_custody_probe_parent_gate(
    const char *process_identifier,
    size_t process_identifier_length,
    const char *start_seconds,
    size_t start_seconds_length,
    const char *start_microseconds,
    size_t start_microseconds_length);

/// In ordinary application mode no probe lease is active and this is a no-op.
/// In packaged probe mode it rechecks the exact direct-parent generation,
/// fresh host process group, and lifetime pipe. Parent loss, EOF/HUP, or any
/// extra byte kills the complete HRA/gateway/helper process group including
/// this process and therefore never returns false to caller code.
bool hra_macos_custody_probe_parent_remains_live_or_retire(void);

#endif
