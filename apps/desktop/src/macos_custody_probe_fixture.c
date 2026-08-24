#include "macos_custody_probe_parent_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static const char *HRABasename(const char *path) {
  const char *separator = strrchr(path, '/');
  return separator == NULL ? path : separator + 1;
}

static bool HRARecordBirths(const char *behavior, pid_t descendant) {
  const char *temporary = getenv("TMPDIR");
  if (temporary == NULL || temporary[0] != '/' || strlen(temporary) >= PATH_MAX)
    return false;
  char path[PATH_MAX];
  int length = snprintf(
      path,
      sizeof(path),
      "%s/%s.pids",
      temporary,
      behavior);
  if (length <= 0 || (size_t)length >= sizeof(path)) return false;
  int descriptor = open(
      path,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      0600);
  if (descriptor < 0) return false;
  char body[128];
  int bodyLength = snprintf(
      body,
      sizeof(body),
      "%d\n%d\n",
      getpid(),
      descendant);
  bool written = bodyLength > 0 && (size_t)bodyLength < sizeof(body) &&
      HRAWriteAll(descriptor, body, (size_t)bodyLength) &&
      fsync(descriptor) == 0;
  close(descriptor);
  return written;
}

static bool HRAWriteSmokeMarker(void) {
  const char *root = getenv("HRA_PACKAGE_SMOKE_ROOT");
  if (root == NULL || root[0] != '/' || strlen(root) >= PATH_MAX) return false;
  char path[PATH_MAX];
  int length = snprintf(path, sizeof(path), "%s/gateway-ready.json", root);
  if (length <= 0 || (size_t)length >= sizeof(path)) return false;
  static const char marker[] =
      "{\"bunVersion\":\"1.3.14\",\"codexVersion\":\"codex-cli fixture\","
      "\"gitVersion\":\"git version fixture\",\"schemaVersion\":1}\n";
  int descriptor = open(
      path,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      0600);
  if (descriptor < 0) return false;
  bool written = HRAWriteAll(
      descriptor, marker, sizeof(marker) - 1) && fsync(descriptor) == 0;
  close(descriptor);
  return written;
}

static void HRAPauseForever(void) {
  while (true) pause();
}

int main(int argc, const char *argv[]) {
  const char *behavior = HRABasename(argv[0]);
  bool authorize = argc == 6 &&
      strcmp(argv[1], "--custody-authorization-probe") == 0;
  bool status = argc == 6 &&
      strcmp(argv[1], "--custody-status-probe") == 0;
  bool smoke = argc == 6 &&
      strcmp(argv[1], "--package-smoke-probe") == 0 &&
      getenv("HRA_PACKAGE_SMOKE_ROOT") != NULL;
  if (!authorize && !status && !smoke) return 64;
  if (strcmp(argv[2], "--hra-probe-parent-v1") != 0 ||
      !hra_macos_custody_probe_parent_gate(
          argv[3],
          strlen(argv[3]),
          argv[4],
          strlen(argv[4]),
          argv[5],
          strlen(argv[5])) ||
      !hra_macos_custody_probe_parent_remains_live_or_retire()) return 70;

  if (strstr(behavior, "success") != NULL) {
    if (!HRARecordBirths(behavior, 0)) return 70;
    if (authorize) {
      static const char receipt[] =
          "{\"authorization\":\"hra-parent-v1\","
          "\"gatewayFileSha256\":\"0000000000000000000000000000000000000000000000000000000000000000\","
          "\"keychainAccessed\":false,\"ok\":true,"
          "\"rendererAuthoritySha256\":\"1111111111111111111111111111111111111111111111111111111111111111\","
          "\"version\":1}\n";
      return HRAWriteAll(STDOUT_FILENO, receipt, sizeof(receipt) - 1) ? 0 : 70;
    }
    if (status) {
      static const char receipt[] =
          "{\"schemaVersion\":1,\"state\":\"absent\"}\n";
      return HRAWriteAll(STDOUT_FILENO, receipt, sizeof(receipt) - 1) ? 0 : 70;
    }
    if (!HRAWriteSmokeMarker()) return 70;
    HRAPauseForever();
  }

  if (strstr(behavior, "stopped") != NULL) {
    if (!HRARecordBirths(behavior, 0)) return 70;
    if (raise(SIGSTOP) != 0) return 70;
    return 70;
  }

  pid_t descendant = fork();
  if (descendant < 0) return 70;
  if (descendant == 0) HRAPauseForever();
  if (!HRARecordBirths(behavior, descendant)) return 70;
  if (strstr(behavior, "overflow") != NULL) {
    unsigned char output[2048];
    memset(output, 'x', sizeof(output));
    if (!HRAWriteAll(STDOUT_FILENO, output, sizeof(output))) return 70;
  }
  HRAPauseForever();
}
