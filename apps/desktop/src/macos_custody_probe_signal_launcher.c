#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

enum {
  HRAProbeParentLeaseDescriptor = 3,
  HRAProbeGoByte = 'G',
};

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

static bool HRAInstallHostileChildPolicy(void) {
  struct sigaction ignored;
  memset(&ignored, 0, sizeof(ignored));
  ignored.sa_handler = SIG_IGN;
  ignored.sa_flags = SA_NOCLDWAIT;
  sigset_t blocked;
  return sigemptyset(&ignored.sa_mask) == 0 &&
      sigaction(SIGCHLD, &ignored, NULL) == 0 &&
      sigemptyset(&blocked) == 0 &&
      sigaddset(&blocked, SIGTERM) == 0 &&
      sigaddset(&blocked, SIGINT) == 0 &&
      sigaddset(&blocked, SIGHUP) == 0 &&
      sigaddset(&blocked, SIGQUIT) == 0 &&
      sigprocmask(SIG_SETMASK, &blocked, NULL) == 0;
}

static bool HRAInstallLeaseDescriptor(int sourceDescriptor) {
  if (sourceDescriptor < 0) return false;
  if (sourceDescriptor != HRAProbeParentLeaseDescriptor &&
      dup2(sourceDescriptor, HRAProbeParentLeaseDescriptor) < 0) return false;
  if (sourceDescriptor != HRAProbeParentLeaseDescriptor)
    close(sourceDescriptor);
  int flags = fcntl(HRAProbeParentLeaseDescriptor, F_GETFD);
  return flags >= 0 && fcntl(
      HRAProbeParentLeaseDescriptor,
      F_SETFD,
      flags & ~FD_CLOEXEC) == 0;
}

static bool HRAWaitForExactChild(pid_t child, int *outStatus) {
  if (child <= 1 || outStatus == NULL) return false;
  while (true) {
    pid_t waited = waitpid(child, outStatus, 0);
    if (waited == child) return true;
    if (waited < 0 && errno == EINTR) continue;
    return false;
  }
}

static int HRAChildResult(int status) {
  return WIFEXITED(status) ? WEXITSTATUS(status) : 70;
}

static bool HRAWaitForMarker(const char *path) {
  if (path == NULL || path[0] != '/' || strlen(path) >= PATH_MAX) return false;
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 5 * 1000 * 1000};
  for (size_t attempt = 0; attempt < 400; attempt += 1) {
    struct stat metadata;
    if (lstat(path, &metadata) == 0) return S_ISREG(metadata.st_mode);
    if (errno != ENOENT) return false;
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
  return false;
}

static bool HRASpawnLifetimeGated(
    char *const arguments[],
    bool queueExtraByte,
    pid_t *outChild,
    int *outWriter) {
  if (arguments == NULL || arguments[0] == NULL ||
      arguments[0][0] != '/' || outChild == NULL || outWriter == NULL) {
    return false;
  }
  int gate[2] = {-1, -1};
  if (pipe(gate) != 0) return false;
  pid_t child = fork();
  if (child < 0) {
    close(gate[0]);
    close(gate[1]);
    return false;
  }
  if (child == 0) {
    close(gate[1]);
    if (setpgid(0, 0) != 0 || !HRAInstallLeaseDescriptor(gate[0]) ||
        !HRAInstallHostileChildPolicy()) {
      _exit(71);
    }
    execve(arguments[0], arguments, environ);
    _exit(71);
  }
  close(gate[0]);
  unsigned char bytes[] = {HRAProbeGoByte, 'X'};
  size_t byteCount = queueExtraByte ? sizeof(bytes) : 1;
  if (!HRAWriteAll(gate[1], bytes, byteCount)) {
    close(gate[1]);
    int status = 0;
    (void)HRAWaitForExactChild(child, &status);
    return false;
  }
  *outChild = child;
  *outWriter = gate[1];
  return true;
}

static int HRARunLifetimeGate(char *const arguments[]) {
  pid_t child = -1;
  int writer = -1;
  if (!HRASpawnLifetimeGated(arguments, false, &child, &writer)) return 70;
  int status = 0;
  bool waited = HRAWaitForExactChild(child, &status);
  close(writer);
  return waited ? HRAChildResult(status) : 70;
}

static int HRARunExtraLifetimeGate(char *const arguments[]) {
  pid_t child = -1;
  int writer = -1;
  if (!HRASpawnLifetimeGated(arguments, true, &child, &writer)) return 70;
  int status = 0;
  bool waited = HRAWaitForExactChild(child, &status);
  close(writer);
  return waited ? HRAChildResult(status) : 70;
}

static int HRAParentExitAfterMarker(
    const char *marker,
    char *const arguments[]) {
  pid_t child = -1;
  int writer = -1;
  if (!HRASpawnLifetimeGated(arguments, false, &child, &writer)) return 70;
  (void)child;
  (void)writer;
  // Process exit closes the sole writer while S and H are still live.
  return HRAWaitForMarker(marker) ? 0 : 70;
}

static int HRAAbandonGateAfterMarker(
    const char *marker,
    char *const arguments[]) {
  pid_t child = -1;
  int writer = -1;
  if (!HRASpawnLifetimeGated(arguments, false, &child, &writer)) return 70;
  if (!HRAWaitForMarker(marker)) {
    close(writer);
    return 70;
  }
  // The launcher remains the exact live parent while deliberately abandoning
  // only the lifetime writer. S must treat EOF/HUP as authority loss.
  close(writer);
  int status = 0;
  return HRAWaitForExactChild(child, &status)
      ? HRAChildResult(status)
      : 70;
}

static int HRAKillSupervisorAfterMarker(
    const char *marker,
    char *const arguments[]) {
  pid_t child = -1;
  int writer = -1;
  if (!HRASpawnLifetimeGated(arguments, false, &child, &writer)) return 70;
  if (!HRAWaitForMarker(marker) || kill(child, SIGKILL) != 0) {
    close(writer);
    return 70;
  }
  int status = 0;
  bool exact = HRAWaitForExactChild(child, &status) &&
      WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
  close(writer);
  return exact ? 0 : 70;
}

static int HRACancelSupervisorAfterMarker(
    const char *marker,
    char *const arguments[]) {
  pid_t child = -1;
  int writer = -1;
  if (!HRASpawnLifetimeGated(arguments, false, &child, &writer)) return 70;
  if (!HRAWaitForMarker(marker) || kill(child, SIGTERM) != 0) {
    close(writer);
    return 70;
  }
  int status = 0;
  bool waited = HRAWaitForExactChild(child, &status);
  close(writer);
  return waited ? HRAChildResult(status) : 70;
}

int main(int argc, char *argv[]) {
  if (argc >= 3 && strcmp(argv[1], "--lifetime-gate") == 0) {
    return HRARunLifetimeGate(&argv[2]);
  }
  if (argc >= 3 && strcmp(argv[1], "--extra-lifetime-gate") == 0) {
    return HRARunExtraLifetimeGate(&argv[2]);
  }
  if (argc >= 5 && strcmp(argv[1], "--parent-exit-after-marker") == 0) {
    return HRAParentExitAfterMarker(argv[2], &argv[3]);
  }
  if (argc >= 5 && strcmp(argv[1], "--abandon-gate-after-marker") == 0) {
    return HRAAbandonGateAfterMarker(argv[2], &argv[3]);
  }
  if (argc >= 5 && strcmp(argv[1], "--kill-supervisor-after-marker") == 0) {
    return HRAKillSupervisorAfterMarker(argv[2], &argv[3]);
  }
  if (argc >= 5 && strcmp(argv[1], "--cancel-supervisor-after-marker") == 0) {
    return HRACancelSupervisorAfterMarker(argv[2], &argv[3]);
  }
  if (argc >= 3 && strcmp(argv[1], "--verifier-fd3-collision") == 0) {
    close(HRAProbeParentLeaseDescriptor);
    if (!HRAInstallHostileChildPolicy()) return 70;
    execve(argv[2], &argv[2], environ);
    return 71;
  }
  if (argc < 2 || argv[1] == NULL || argv[1][0] != '/') return 64;
  if (!HRAInstallHostileChildPolicy()) return 70;
  execve(argv[1], &argv[1], environ);
  return errno == 0 ? 70 : 71;
}
