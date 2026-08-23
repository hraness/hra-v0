#include "macos_custody_probe_parent_gate.h"

#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <spawn.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <unistd.h>

static bool HRAWriteAll(int descriptor, const void *rawBytes, size_t length) {
  const unsigned char *bytes = rawBytes;
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = write(descriptor, bytes + offset, length - offset);
    if (count > 0) {
      offset += (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

static bool HRACopySelfAuditToken(audit_token_t *outToken) {
  if (outToken == NULL) return false;
  memset(outToken, 0, sizeof(*outToken));
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  return task_info(
      mach_task_self(),
      TASK_AUDIT_TOKEN,
      (task_info_t)outToken,
      &count) == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT &&
      audit_token_to_pid(*outToken) == getpid() &&
      audit_token_to_pidversion(*outToken) > 0;
}

static void HRAEncodeAuditToken(
    const audit_token_t *token,
    char output[sizeof(audit_token_t) * 2 + 1]) {
  static const char digits[] = "0123456789abcdef";
  const unsigned char *bytes = (const unsigned char *)token;
  for (size_t index = 0; index < sizeof(*token); index += 1) {
    output[index * 2] = digits[bytes[index] >> 4];
    output[index * 2 + 1] = digits[bytes[index] & 0x0f];
  }
  output[sizeof(*token) * 2] = '\0';
}

static bool HRACompanionPaths(
    const char *parentPath,
    char helperPath[PATH_MAX],
    char gatewayPath[PATH_MAX]) {
  static const char hostSuffix[] = "/Contents/MacOS/hra";
  static const char helperSuffix[] =
      "/Contents/Resources/runtime/bin/oprte-keychain-custodian";
  static const char gatewaySuffix[] =
      "/Contents/Resources/runtime/bin/oprte-gateway";
  if (parentPath == NULL || parentPath[0] != '/') return false;
  size_t parentLength = strlen(parentPath);
  size_t hostSuffixLength = sizeof(hostSuffix) - 1;
  if (parentLength <= hostSuffixLength ||
      strcmp(parentPath + parentLength - hostSuffixLength, hostSuffix) != 0) {
    return false;
  }
  size_t rootLength = parentLength - hostSuffixLength;
  if (rootLength + sizeof(helperSuffix) > PATH_MAX ||
      rootLength + sizeof(gatewaySuffix) > PATH_MAX) return false;
  memcpy(helperPath, parentPath, rootLength);
  memcpy(helperPath + rootLength, helperSuffix, sizeof(helperSuffix));
  memcpy(gatewayPath, parentPath, rootLength);
  memcpy(gatewayPath + rootLength, gatewaySuffix, sizeof(gatewaySuffix));
  return true;
}

static bool HRAKillAndReapStoppedChild(pid_t processIdentifier) {
  if (processIdentifier <= 1 || kill(processIdentifier, SIGKILL) != 0)
    return false;
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(processIdentifier, &status, 0);
  } while (waited < 0 && errno == EINTR);
  return waited == processIdentifier && WIFSIGNALED(status) &&
      WTERMSIG(status) == SIGKILL;
}

static bool HRAReadStoppedGatewayGeneration(
    pid_t processIdentifier,
    const char *gatewayPath,
    uint64_t *outSeconds,
    uint64_t *outMicroseconds) {
  if (processIdentifier <= 1 || gatewayPath == NULL ||
      outSeconds == NULL || outMicroseconds == NULL) return false;
  struct proc_bsdinfo information;
  memset(&information, 0, sizeof(information));
  int bytes = proc_pidinfo(
      processIdentifier,
      PROC_PIDTBSDINFO,
      0,
      &information,
      (int)sizeof(information));
  char actualPath[PROC_PIDPATHINFO_MAXSIZE];
  memset(actualPath, 0, sizeof(actualPath));
  int pathLength = proc_pidpath(
      processIdentifier, actualPath, (uint32_t)sizeof(actualPath));
  if (bytes != (int)sizeof(information) ||
      information.pbi_pid != (uint32_t)processIdentifier ||
      information.pbi_ppid != (uint32_t)getpid() ||
      information.pbi_status != SSTOP ||
      information.pbi_start_tvsec == 0 || pathLength <= 0 ||
      strcmp(actualPath, gatewayPath) != 0) return false;
  *outSeconds = information.pbi_start_tvsec;
  *outMicroseconds = information.pbi_start_tvusec;
  return true;
}

static bool HRASpawnStoppedGateway(
    const char *gatewayPath,
    pid_t *outProcessIdentifier,
    uint64_t *outSeconds,
    uint64_t *outMicroseconds) {
  if (gatewayPath == NULL || outProcessIdentifier == NULL ||
      outSeconds == NULL || outMicroseconds == NULL) return false;
  *outProcessIdentifier = -1;
  *outSeconds = 0;
  *outMicroseconds = 0;
  posix_spawnattr_t attributes = NULL;
  posix_spawn_file_actions_t actions = NULL;
  bool initializedAttributes = posix_spawnattr_init(&attributes) == 0;
  bool initializedActions = initializedAttributes &&
      posix_spawn_file_actions_init(&actions) == 0;
  sigset_t childSignalMask;
  sigset_t childSignalDefaults;
  bool signalSetsConfigured = sigemptyset(&childSignalMask) == 0 &&
      sigemptyset(&childSignalDefaults) == 0 &&
      sigaddset(&childSignalDefaults, SIGTERM) == 0 &&
      sigaddset(&childSignalDefaults, SIGINT) == 0 &&
      sigaddset(&childSignalDefaults, SIGHUP) == 0 &&
      sigaddset(&childSignalDefaults, SIGQUIT) == 0 &&
      sigaddset(&childSignalDefaults, SIGPIPE) == 0 &&
      sigaddset(&childSignalDefaults, SIGCHLD) == 0;
  short flags = POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT |
      POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
  bool configured = initializedActions && signalSetsConfigured &&
      posix_spawnattr_setflags(&attributes, flags) == 0 &&
      posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0 &&
      posix_spawnattr_setsigdefault(&attributes, &childSignalDefaults) == 0 &&
      posix_spawn_file_actions_addopen(
          &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
      posix_spawn_file_actions_addopen(
          &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
      posix_spawn_file_actions_addopen(
          &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0;
  char *arguments[] = {(char *)gatewayPath, NULL};
  char *emptyEnvironment[] = {NULL};
  pid_t child = -1;
  int spawnStatus = configured
      ? posix_spawn(
          &child,
          gatewayPath,
          &actions,
          &attributes,
          arguments,
          emptyEnvironment)
      : EINVAL;
  if (initializedActions) posix_spawn_file_actions_destroy(&actions);
  if (initializedAttributes) posix_spawnattr_destroy(&attributes);
  if (spawnStatus != 0 || child <= 1) return false;
  if (!HRAReadStoppedGatewayGeneration(
          child, gatewayPath, outSeconds, outMicroseconds)) {
    (void)HRAKillAndReapStoppedChild(child);
    return false;
  }
  *outProcessIdentifier = child;
  return true;
}

int main(int argc, const char *argv[]) {
  if (argc != 6 ||
      strcmp(argv[1], "--custody-authorization-probe") != 0 ||
      strcmp(argv[2], "--hra-probe-parent-v1") != 0) {
    return 64;
  }
  if (!hra_macos_custody_probe_parent_gate(
          argv[3],
          strlen(argv[3]),
          argv[4],
          strlen(argv[4]),
          argv[5],
          strlen(argv[5])) ||
      !hra_macos_custody_probe_parent_remains_live_or_retire()) return 70;
  char helperPath[PATH_MAX];
  char gatewayPath[PATH_MAX];
  memset(helperPath, 0, sizeof(helperPath));
  memset(gatewayPath, 0, sizeof(gatewayPath));
  audit_token_t auditToken;
  char auditTokenHex[sizeof(audit_token_t) * 2 + 1];
  char gatewayProcessText[32];
  char gatewaySecondsText[32];
  char gatewayMicrosecondsText[32];
  memset(gatewayProcessText, 0, sizeof(gatewayProcessText));
  memset(gatewaySecondsText, 0, sizeof(gatewaySecondsText));
  memset(gatewayMicrosecondsText, 0, sizeof(gatewayMicrosecondsText));
  if (!HRACompanionPaths(argv[0], helperPath, gatewayPath) ||
      !HRACopySelfAuditToken(&auditToken)) return 70;
  HRAEncodeAuditToken(&auditToken, auditTokenHex);
  memset(&auditToken, 0, sizeof(auditToken));

  // Keep the exact bundled gateway in the post-exec suspended state for the
  // whole helper authorization attempt. This gives the helper a real direct
  // child generation to authenticate while ensuring the negative never lets
  // gateway code drive a custody operation.
  pid_t gatewayProcess = -1;
  uint64_t gatewayStartSeconds = 0;
  uint64_t gatewayStartMicroseconds = 0;
  if (!HRASpawnStoppedGateway(
          gatewayPath,
          &gatewayProcess,
          &gatewayStartSeconds,
          &gatewayStartMicroseconds) ||
      snprintf(
          gatewayProcessText,
          sizeof(gatewayProcessText),
          "%d",
          gatewayProcess) <= 0 ||
      snprintf(
          gatewaySecondsText,
          sizeof(gatewaySecondsText),
          "%llu",
          (unsigned long long)gatewayStartSeconds) <= 0 ||
      snprintf(
          gatewayMicrosecondsText,
          sizeof(gatewayMicrosecondsText),
          "%llu",
          (unsigned long long)gatewayStartMicroseconds) <= 0) {
    if (gatewayProcess > 1) (void)HRAKillAndReapStoppedChild(gatewayProcess);
    return 70;
  }

  int inputPipe[2] = {-1, -1};
  int outputPipe[2] = {-1, -1};
  if (pipe(inputPipe) != 0 || pipe(outputPipe) != 0) {
    if (inputPipe[0] >= 0) close(inputPipe[0]);
    if (inputPipe[1] >= 0) close(inputPipe[1]);
    if (outputPipe[0] >= 0) close(outputPipe[0]);
    if (outputPipe[1] >= 0) close(outputPipe[1]);
    (void)HRAKillAndReapStoppedChild(gatewayProcess);
    return 70;
  }
  posix_spawnattr_t attributes = NULL;
  posix_spawn_file_actions_t actions = NULL;
  bool initializedAttributes = posix_spawnattr_init(&attributes) == 0;
  bool initializedActions = initializedAttributes &&
      posix_spawn_file_actions_init(&actions) == 0;
  sigset_t childSignalMask;
  sigset_t childSignalDefaults;
  bool signalSetsConfigured = sigemptyset(&childSignalMask) == 0 &&
      sigemptyset(&childSignalDefaults) == 0 &&
      sigaddset(&childSignalDefaults, SIGTERM) == 0 &&
      sigaddset(&childSignalDefaults, SIGINT) == 0 &&
      sigaddset(&childSignalDefaults, SIGHUP) == 0 &&
      sigaddset(&childSignalDefaults, SIGQUIT) == 0 &&
      sigaddset(&childSignalDefaults, SIGPIPE) == 0 &&
      sigaddset(&childSignalDefaults, SIGCHLD) == 0;
  short flags = POSIX_SPAWN_CLOEXEC_DEFAULT |
      POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
  bool configured = initializedActions && signalSetsConfigured &&
      posix_spawnattr_setflags(&attributes, flags) == 0 &&
      posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0 &&
      posix_spawnattr_setsigdefault(&attributes, &childSignalDefaults) == 0 &&
      posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO) == 0 &&
      posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO) == 0 &&
      posix_spawn_file_actions_addopen(
          &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
      posix_spawn_file_actions_addclose(&actions, inputPipe[1]) == 0 &&
      posix_spawn_file_actions_addclose(&actions, outputPipe[0]) == 0;
  char *arguments[] = {
    helperPath,
    "--hra-parent-audit-token-v1",
    auditTokenHex,
    gatewayProcessText,
    gatewaySecondsText,
    gatewayMicrosecondsText,
    NULL,
  };
  char *emptyEnvironment[] = {NULL};
  pid_t child = -1;
  int spawnStatus = configured
      ? posix_spawn(
          &child,
          helperPath,
          &actions,
          &attributes,
          arguments,
          emptyEnvironment)
      : EINVAL;
  if (initializedActions) posix_spawn_file_actions_destroy(&actions);
  if (initializedAttributes) posix_spawnattr_destroy(&attributes);
  close(inputPipe[0]);
  close(outputPipe[1]);
  if (spawnStatus != 0 || child <= 1) {
    close(inputPipe[1]);
    close(outputPipe[0]);
    (void)HRAKillAndReapStoppedChild(gatewayProcess);
    return 70;
  }

  static const char request[] = "{\"action\":\"authorize\",\"version\":1}";
  bool requestWritten = HRAWriteAll(
      inputPipe[1], request, sizeof(request) - 1);
  close(inputPipe[1]);
  unsigned char response[1024];
  size_t responseLength = 0;
  while (responseLength < sizeof(response)) {
    ssize_t count = read(
        outputPipe[0],
        response + responseLength,
        sizeof(response) - responseLength);
    if (count > 0) {
      responseLength += (size_t)count;
      continue;
    }
    if (count == 0) break;
    if (errno == EINTR) continue;
    requestWritten = false;
    break;
  }
  close(outputPipe[0]);
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  memset(auditTokenHex, 0, sizeof(auditTokenHex));
  memset(gatewayProcessText, 0, sizeof(gatewayProcessText));
  memset(gatewaySecondsText, 0, sizeof(gatewaySecondsText));
  memset(gatewayMicrosecondsText, 0, sizeof(gatewayMicrosecondsText));
  bool gatewayRetired = HRAKillAndReapStoppedChild(gatewayProcess);
  if (!requestWritten || waited != child || !gatewayRetired) return 70;
  if (responseLength == 0 && WIFEXITED(status) && WEXITSTATUS(status) != 0) {
    return 1;
  }
  if (responseLength > 0 && HRAWriteAll(STDOUT_FILENO, response, responseLength)) {
    return 0;
  }
  return 70;
}
