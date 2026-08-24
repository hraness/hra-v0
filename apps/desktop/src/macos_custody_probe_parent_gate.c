#include "macos_custody_probe_parent_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
  HRAProbeGateTimeoutMilliseconds = 30000,
  HRAProbeGatePollMilliseconds = 10,
  HRAProbeWatcherStartupMilliseconds = 1000,
  HRAProbeGoByte = 'G',
};

typedef enum {
  HRAProbeWatcherIdle = 0,
  HRAProbeWatcherRunning = 1,
  HRAProbeWatcherFailed = 2,
} HRAProbeWatcherState;

typedef struct {
  pid_t processIdentifier;
  uint64_t startSeconds;
  uint64_t startMicroseconds;
  pid_t processGroup;
  int leaseDescriptor;
} HRAProbeParentAuthority;

static HRAProbeParentAuthority HRAProbeParent = {
  .processIdentifier = -1,
  .processGroup = -1,
  .leaseDescriptor = -1,
};
static _Atomic bool HRAProbeParentActive = false;
static _Atomic int HRAProbeWatcher = HRAProbeWatcherIdle;

static bool HRAParseCanonicalUInt64(
    const char *text,
    size_t length,
    uint64_t maximum,
    uint64_t *outValue) {
  if (text == NULL || length == 0 || outValue == NULL ||
      (length > 1 && text[0] == '0')) return false;
  uint64_t value = 0;
  for (size_t index = 0; index < length; index += 1) {
    if (text[index] < '0' || text[index] > '9') return false;
    uint64_t digit = (uint64_t)(text[index] - '0');
    if (value > (maximum - digit) / 10) return false;
    value = value * 10 + digit;
  }
  *outValue = value;
  return true;
}

static uint64_t HRAMonotonicMilliseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
    return 0;
  uint64_t seconds = (uint64_t)now.tv_sec;
  if (seconds > UINT64_MAX / 1000) return 0;
  return seconds * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static bool HRAParentGenerationIsExact(
    const HRAProbeParentAuthority *expected) {
  if (expected == NULL || expected->processIdentifier <= 1 ||
      expected->processGroup <= 1 ||
      getppid() != expected->processIdentifier ||
      getpid() != expected->processGroup ||
      getpgrp() != expected->processGroup) return false;
  struct proc_bsdinfo information;
  memset(&information, 0, sizeof(information));
  int bytes = proc_pidinfo(
      expected->processIdentifier,
      PROC_PIDTBSDINFO,
      0,
      &information,
      (int)sizeof(information));
  return bytes == (int)sizeof(information) &&
      information.pbi_pid == (uint32_t)expected->processIdentifier &&
      information.pbi_status != SZOMB &&
      information.pbi_start_tvsec == expected->startSeconds &&
      information.pbi_start_tvusec == expected->startMicroseconds;
}

static bool HRALifetimeLeaseIsExact(int descriptor) {
  if (descriptor != HRA_CUSTODY_PROBE_PARENT_LEASE_FD) return false;
  struct pollfd pollDescriptor = {
    .fd = descriptor,
    .events = POLLIN | POLLHUP,
    .revents = 0,
  };
  int status;
  do {
    status = poll(&pollDescriptor, 1, 0);
  } while (status < 0 && errno == EINTR);
  if (status < 0 || (pollDescriptor.revents &
          (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) return false;
  return true;
}

static _Noreturn void HRARetireProbeProcessGroup(void) {
  // The gate admits only a fresh group leader. One signal to group zero is
  // therefore scoped to this exact HRA host and its probe-only descendants.
  (void)kill(0, SIGKILL);
  _exit(70);
}

static void *HRAWatchProbeParent(void *unused) {
  (void)unused;
  if (!atomic_load_explicit(&HRAProbeParentActive, memory_order_acquire) ||
      !HRAParentGenerationIsExact(&HRAProbeParent) ||
      !HRALifetimeLeaseIsExact(HRAProbeParent.leaseDescriptor)) {
    atomic_store_explicit(
        &HRAProbeWatcher, HRAProbeWatcherFailed, memory_order_release);
    HRARetireProbeProcessGroup();
  }
  atomic_store_explicit(
      &HRAProbeWatcher, HRAProbeWatcherRunning, memory_order_release);
  while (true) {
    if (!HRAParentGenerationIsExact(&HRAProbeParent) ||
        !HRALifetimeLeaseIsExact(HRAProbeParent.leaseDescriptor)) {
      HRARetireProbeProcessGroup();
    }
    struct timespec pause = {
      .tv_sec = 0,
      .tv_nsec = HRAProbeGatePollMilliseconds * 1000 * 1000,
    };
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
      HRARetireProbeProcessGroup();
    }
  }
}

static bool HRAStartProbeParentWatcher(void) {
  pthread_attr_t attributes;
  if (pthread_attr_init(&attributes) != 0) return false;
  bool configured = pthread_attr_setdetachstate(
      &attributes, PTHREAD_CREATE_DETACHED) == 0;
  pthread_t watcher;
  int createStatus = configured
      ? pthread_create(&watcher, &attributes, HRAWatchProbeParent, NULL)
      : EINVAL;
  int destroyStatus = pthread_attr_destroy(&attributes);
  if (createStatus != 0 || destroyStatus != 0) return false;

  uint64_t start = HRAMonotonicMilliseconds();
  if (start == 0 || UINT64_MAX - start < HRAProbeWatcherStartupMilliseconds)
    return false;
  uint64_t deadline = start + HRAProbeWatcherStartupMilliseconds;
  while (true) {
    int state = atomic_load_explicit(&HRAProbeWatcher, memory_order_acquire);
    if (state == HRAProbeWatcherRunning) {
      return HRAParentGenerationIsExact(&HRAProbeParent) &&
          HRALifetimeLeaseIsExact(HRAProbeParent.leaseDescriptor);
    }
    if (state == HRAProbeWatcherFailed) return false;
    uint64_t now = HRAMonotonicMilliseconds();
    if (now == 0 || now >= deadline ||
        !HRAParentGenerationIsExact(&HRAProbeParent) ||
        !HRALifetimeLeaseIsExact(HRAProbeParent.leaseDescriptor)) {
      return false;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
}

static bool HRAReadAdmissionByte(
    HRAProbeParentAuthority *authority) {
  struct stat metadata;
  memset(&metadata, 0, sizeof(metadata));
  int descriptor = HRA_CUSTODY_PROBE_PARENT_LEASE_FD;
  int descriptorFlags = fcntl(descriptor, F_GETFD);
  int statusFlags = fcntl(descriptor, F_GETFL);
  if (descriptorFlags < 0 || statusFlags < 0 ||
      fstat(descriptor, &metadata) != 0 || !S_ISFIFO(metadata.st_mode) ||
      fcntl(descriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) != 0 ||
      fcntl(descriptor, F_SETFL, statusFlags | O_NONBLOCK) != 0) return false;
  uint64_t start = HRAMonotonicMilliseconds();
  if (start == 0 || UINT64_MAX - start < HRAProbeGateTimeoutMilliseconds)
    return false;
  uint64_t deadline = start + HRAProbeGateTimeoutMilliseconds;
  bool admitted = false;
  while (true) {
    if (!HRAParentGenerationIsExact(authority)) return false;
    uint64_t now = HRAMonotonicMilliseconds();
    if (now == 0 || now >= deadline) return false;
    struct pollfd pollDescriptor = {
      .fd = descriptor,
      .events = POLLIN | POLLHUP,
      .revents = 0,
    };
    int remaining = (int)(deadline - now);
    int wait = remaining < HRAProbeGatePollMilliseconds
        ? remaining
        : HRAProbeGatePollMilliseconds;
    int pollStatus = poll(&pollDescriptor, 1, wait);
    if (pollStatus < 0 && errno == EINTR) continue;
    if (pollStatus < 0 ||
        (pollDescriptor.revents & (POLLERR | POLLNVAL)) != 0) return false;
    if ((pollDescriptor.revents & (POLLIN | POLLHUP)) == 0) continue;
    unsigned char byte = 0;
    ssize_t count = read(descriptor, &byte, 1);
    if (count < 0 && (errno == EINTR || errno == EAGAIN ||
        errno == EWOULDBLOCK)) continue;
    if (count != 1 || admitted || byte != HRAProbeGoByte) return false;
    admitted = true;
    // The writer is a lifetime lease. A queued extra byte, EOF, or HUP at the
    // admission boundary is already a failed lease rather than a valid GO.
    if (!HRALifetimeLeaseIsExact(descriptor)) return false;
    return HRAParentGenerationIsExact(authority);
  }
}

bool hra_macos_custody_probe_parent_gate(
    const char *processIdentifier,
    size_t processIdentifierLength,
    const char *startSeconds,
    size_t startSecondsLength,
    const char *startMicroseconds,
    size_t startMicrosecondsLength) {
  if (atomic_load_explicit(&HRAProbeParentActive, memory_order_acquire))
    return false;
  uint64_t process = 0;
  HRAProbeParentAuthority authority = {
    .processIdentifier = -1,
    .processGroup = getpid(),
    .leaseDescriptor = HRA_CUSTODY_PROBE_PARENT_LEASE_FD,
  };
  if (!HRAParseCanonicalUInt64(
          processIdentifier,
          processIdentifierLength,
          INT_MAX,
          &process) || process <= 1 ||
      !HRAParseCanonicalUInt64(
          startSeconds,
          startSecondsLength,
          UINT64_MAX,
          &authority.startSeconds) || authority.startSeconds == 0 ||
      !HRAParseCanonicalUInt64(
          startMicroseconds,
          startMicrosecondsLength,
          999999,
          &authority.startMicroseconds)) return false;
  authority.processIdentifier = (pid_t)process;
  if (!HRAParentGenerationIsExact(&authority) ||
      !HRAReadAdmissionByte(&authority) ||
      !HRAParentGenerationIsExact(&authority) ||
      !HRALifetimeLeaseIsExact(authority.leaseDescriptor)) return false;
  HRAProbeParent = authority;
  atomic_store_explicit(
      &HRAProbeParentActive, true, memory_order_release);
  if (!HRAStartProbeParentWatcher()) {
    atomic_store_explicit(
        &HRAProbeWatcher, HRAProbeWatcherFailed, memory_order_release);
    return false;
  }
  return hra_macos_custody_probe_parent_remains_live_or_retire();
}

bool hra_macos_custody_probe_parent_remains_live_or_retire(void) {
  if (!atomic_load_explicit(&HRAProbeParentActive, memory_order_acquire))
    return true;
  if (!HRAParentGenerationIsExact(&HRAProbeParent) ||
      !HRALifetimeLeaseIsExact(HRAProbeParent.leaseDescriptor)) {
    HRARetireProbeProcessGroup();
  }
  return true;
}
