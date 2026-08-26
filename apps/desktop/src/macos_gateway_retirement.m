#import "macos_gateway_retirement.h"

#import <errno.h>
#import <libproc.h>
#import <signal.h>
#import <stdint.h>
#import <string.h>
#import <sys/proc.h>
#import <sys/wait.h>

static bool HRAGatewayChildExitInformationIsTerminal(
    const siginfo_t *information,
    pid_t expectedProcessIdentifier) {
  return information != NULL &&
      information->si_pid == expectedProcessIdentifier &&
      (information->si_code == CLD_EXITED ||
       information->si_code == CLD_KILLED ||
       information->si_code == CLD_DUMPED);
}

// proc_listpids deliberately includes both allproc and zombproc. A zombie has
// no executable state and cannot create another descendant, so a retired
// production generation must not depend on launchd eventually collecting it.
// The direct-child leader remains WNOWAIT-unreaped throughout this proof,
// reserving its PID and PGID. Every listed nonleader is re-read to close exit,
// group-change, and PID-reuse races; any ambiguous observation fails closed.
HRAMacOSGatewayGroupRetirementState
hra_macos_gateway_process_group_retirement_state(pid_t groupLeader) {
  if (groupLeader <= 1) {
    return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS;
  }

  siginfo_t exitInformation;
  while (true) {
    memset(&exitInformation, 0, sizeof(exitInformation));
    errno = 0;
    int status = waitid(
        P_PID,
        (id_t)groupLeader,
        &exitInformation,
        WEXITED | WNOWAIT | WNOHANG);
    if (status == 0) break;
    if (errno == EINTR) continue;
    return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS;
  }
  if (exitInformation.si_pid == 0) {
    return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_PENDING;
  }
  if (!HRAGatewayChildExitInformationIsTerminal(
          &exitInformation, groupLeader)) {
    return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS;
  }

  pid_t members[1024];
  memset(members, 0, sizeof(members));
  int listedBytes = proc_listpids(
      PROC_PGRP_ONLY,
      (uint32_t)groupLeader,
      members,
      (int)sizeof(members));
  if (listedBytes < 0 || listedBytes >= (int)sizeof(members) ||
      listedBytes % (int)sizeof(pid_t) != 0) {
    return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS;
  }
  size_t count = (size_t)listedBytes / sizeof(pid_t);
  for (size_t index = 0; index < count; index += 1) {
    pid_t member = members[index];
    if (member <= 0) {
      return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS;
    }
    if (member == groupLeader) continue;

    struct proc_bsdinfo information;
    memset(&information, 0, sizeof(information));
    errno = 0;
    int informationBytes = proc_pidinfo(
        member,
        PROC_PIDTBSDINFO,
        0,
        &information,
        (int)sizeof(information));
    if (informationBytes == 0 && errno == ESRCH) continue;
    if (informationBytes != (int)sizeof(information) ||
        information.pbi_pid != (uint32_t)member) {
      return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_AMBIGUOUS;
    }
    if (information.pbi_pgid != (uint32_t)groupLeader) continue;
    if (information.pbi_status != SZOMB) {
      return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_PENDING;
    }
  }
  return HRA_MACOS_GATEWAY_GROUP_RETIREMENT_QUIESCENT;
}

bool hra_macos_gateway_retained_child_is_zombie(
    pid_t processIdentifier) {
  if (processIdentifier <= 1) return false;
  siginfo_t exitInformation;
  while (true) {
    memset(&exitInformation, 0, sizeof(exitInformation));
    errno = 0;
    int status = waitid(
        P_PID,
        (id_t)processIdentifier,
        &exitInformation,
        WEXITED | WNOWAIT | WNOHANG);
    if (status == 0) break;
    if (errno == EINTR) continue;
    return false;
  }
  if (!HRAGatewayChildExitInformationIsTerminal(
          &exitInformation, processIdentifier)) {
    return false;
  }
  return true;
}
