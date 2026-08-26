#include "macos_gateway_attestation.h"
#include "macos_self_managed_code_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// This executable is the sole signal authority for a packaged host probe and
// every exact probe-only descendant. The build verifier invokes its installed
// artifact; packaging also nests and signs the exact artifact for recovery.
// The host remains WNOWAIT-unreaped until the process group has no executable
// members, so neither its PID nor its PGID can be reused before the one-signal
// cleanup boundary is complete.

#ifndef HRA_CUSTODY_PROBE_TIMEOUT_MILLISECONDS
#define HRA_CUSTODY_PROBE_TIMEOUT_MILLISECONDS 60000
#endif
#ifndef HRA_CUSTODY_PROBE_CLEANUP_MILLISECONDS
#define HRA_CUSTODY_PROBE_CLEANUP_MILLISECONDS 5000
#endif

enum {
  HRAProbeMaximumOutputBytes = 1024,
  HRAProbeTimeoutMilliseconds = HRA_CUSTODY_PROBE_TIMEOUT_MILLISECONDS,
  HRAProbeCleanupMilliseconds = HRA_CUSTODY_PROBE_CLEANUP_MILLISECONDS,
  HRAProbeMaximumGroupMembers = 256,
  HRAProbeEnvironmentEntries = 9,
  HRAProbeParentLeaseDescriptor = 3,
  HRAProbeGoByte = 'G',
  HRAProbeGatePollMilliseconds = 10,
  HRAProbeAuthorityCleanupGraceMilliseconds =
      HRAProbeCleanupMilliseconds + 500,
};

typedef enum {
  HRAProbeAuthorize,
  HRAProbeAuthorizeHostileSignals,
#if defined(HRA_CUSTODY_PROBE_ADVERSARIAL_BUILD)
  HRAProbeRejectAuthorize,
#endif
  HRAProbeStatus,
  HRAProbeSmoke,
} HRAProbeMode;

typedef struct {
  dev_t device;
  ino_t inode;
  mode_t mode;
  nlink_t links;
  uid_t owner;
  gid_t group;
  off_t size;
  struct timespec modified;
  struct timespec changed;
} HRAProbeFileIdentity;

typedef struct {
  pid_t processIdentifier;
  uint64_t startSeconds;
  uint64_t startMicroseconds;
} HRAProbeParentGeneration;

typedef struct {
  int descriptor;
} HRAProbeLease;

typedef struct {
  char storage[HRAProbeEnvironmentEntries][PATH_MAX + 64];
  char *values[HRAProbeEnvironmentEntries + 1];
  size_t count;
} HRAProbeEnvironment;

typedef struct {
  int descriptor;
  uint8_t bytes[HRAProbeMaximumOutputBytes];
  size_t length;
  bool eof;
} HRAProbePipe;

#if defined(HRA_CUSTODY_PROBE_CANDIDATE_BUILD) || \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
typedef enum {
  HRAAuthorityWatcherIdle = 0,
  HRAAuthorityWatcherRunning = 1,
  HRAAuthorityWatcherFailed = 2,
} HRAAuthorityWatcherState;
#endif

static volatile sig_atomic_t HRACancellationRequested = 0;
#if defined(HRA_CUSTODY_PROBE_CANDIDATE_BUILD) || \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
static HRAProbeParentGeneration HRAWatchedParentGeneration;
static HRAProbeLease HRAWatchedAuthorityLease = {.descriptor = -1};
static _Atomic bool HRAAuthorityWatcherActive = false;
static _Atomic int HRAAuthorityWatcher = HRAAuthorityWatcherIdle;
static _Atomic bool HRAAuthorityLost = false;
static _Atomic bool HRAHostRetirementCompleted = false;
#endif

static void HRARequestCancellation(int signalNumber) {
  (void)signalNumber;
  HRACancellationRequested = 1;
}

static bool HRACancellationOrAuthorityLost(void) {
  bool lost = false;
#if defined(HRA_CUSTODY_PROBE_CANDIDATE_BUILD) || \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
  lost = atomic_load_explicit(&HRAAuthorityLost, memory_order_acquire);
#endif
  return HRACancellationRequested != 0 || lost;
}

static bool HRAInstallSignalPolicy(void) {
  struct sigaction cancellation;
  memset(&cancellation, 0, sizeof(cancellation));
  cancellation.sa_handler = HRARequestCancellation;
  if (sigemptyset(&cancellation.sa_mask) != 0) return false;
  static const int cancellationSignals[] = {
    SIGTERM, SIGINT, SIGHUP, SIGQUIT,
  };
  for (size_t index = 0;
       index < sizeof(cancellationSignals) / sizeof(cancellationSignals[0]);
       index += 1) {
    if (sigaction(cancellationSignals[index], &cancellation, NULL) != 0)
      return false;
  }
  struct sigaction ignored;
  memset(&ignored, 0, sizeof(ignored));
  ignored.sa_handler = SIG_IGN;
  if (sigemptyset(&ignored.sa_mask) != 0 ||
      sigaction(SIGPIPE, &ignored, NULL) != 0) return false;

  // An invoking shell/test runner may itself ignore SIGCHLD, request
  // SA_NOCLDWAIT, or block cancellation signals. Both dispositions survive
  // exec and would invalidate the unreaped PID/PGID lease. Establish the
  // supervisor's complete signal state before it can create a child. Handlers
  // are installed first so a cancellation already pending in an inherited
  // blocked mask is captured when the explicit empty mask is applied.
  struct sigaction childExit;
  memset(&childExit, 0, sizeof(childExit));
  childExit.sa_handler = SIG_DFL;
  if (sigemptyset(&childExit.sa_mask) != 0 ||
      sigaction(SIGCHLD, &childExit, NULL) != 0) return false;
  sigset_t emptyMask;
  return sigemptyset(&emptyMask) == 0 &&
      sigprocmask(SIG_SETMASK, &emptyMask, NULL) == 0;
}

static bool HRACaptureParentGeneration(
    HRAProbeParentGeneration *outGeneration) {
  if (outGeneration == NULL) return false;
  pid_t processIdentifier = getppid();
  if (processIdentifier <= 1) return false;
  struct proc_bsdinfo information;
  memset(&information, 0, sizeof(information));
  int bytes = proc_pidinfo(
      processIdentifier,
      PROC_PIDTBSDINFO,
      0,
      &information,
      (int)sizeof(information));
  if (bytes != (int)sizeof(information) ||
      information.pbi_pid != (uint32_t)processIdentifier ||
      information.pbi_status == SZOMB || information.pbi_start_tvsec == 0) {
    return false;
  }
  *outGeneration = (HRAProbeParentGeneration){
    .processIdentifier = processIdentifier,
    .startSeconds = information.pbi_start_tvsec,
    .startMicroseconds = information.pbi_start_tvusec,
  };
  return true;
}

static bool HRACaptureSelfGeneration(
    HRAProbeParentGeneration *outGeneration) {
  if (outGeneration == NULL || getpid() <= 1) return false;
  struct proc_bsdinfo information;
  memset(&information, 0, sizeof(information));
  int bytes = proc_pidinfo(
      getpid(), PROC_PIDTBSDINFO, 0, &information, (int)sizeof(information));
  if (bytes != (int)sizeof(information) ||
      information.pbi_pid != (uint32_t)getpid() ||
      information.pbi_status == SZOMB || information.pbi_start_tvsec == 0) {
    return false;
  }
  *outGeneration = (HRAProbeParentGeneration){
    .processIdentifier = getpid(),
    .startSeconds = information.pbi_start_tvsec,
    .startMicroseconds = information.pbi_start_tvusec,
  };
  return true;
}

static bool HRAParentGenerationRemainsLive(
    const HRAProbeParentGeneration *expected) {
  if (expected == NULL || expected->processIdentifier <= 1 ||
      getppid() != expected->processIdentifier) return false;
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

static bool HRADeadlineFromNow(
    uint64_t milliseconds,
    uint64_t *outDeadline);
static bool HRADeadlineHasTime(uint64_t deadline);
static int HRADeadlinePollMilliseconds(uint64_t deadline);
static bool HRAWaitInformationIsTerminal(
    const siginfo_t *information,
    pid_t expectedProcess) {
  return information != NULL && information->si_pid == expectedProcess &&
      (information->si_code == CLD_EXITED ||
       information->si_code == CLD_KILLED ||
       information->si_code == CLD_DUMPED);
}

static bool HRAObserveLeaderExit(
    pid_t processIdentifier,
    siginfo_t *outInformation,
    bool *outExited);

static bool HRAProbeLeaseHasNoEvent(const HRAProbeLease *lease) {
  if (lease == NULL || lease->descriptor < 0) return true;
  struct pollfd descriptor = {
    .fd = lease->descriptor,
    .events = POLLIN | POLLHUP,
    .revents = 0,
  };
  int status;
  do {
    status = poll(&descriptor, 1, 0);
  } while (status < 0 && errno == EINTR);
  return status == 0 && descriptor.revents == 0;
}

static bool HRAInvokingAuthorityRemainsLive(
    const HRAProbeParentGeneration *parentGeneration,
    const HRAProbeLease *lease) {
  return HRAParentGenerationRemainsLive(parentGeneration) &&
      HRAProbeLeaseHasNoEvent(lease);
}

#if defined(HRA_CUSTODY_PROBE_CANDIDATE_BUILD) || \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
static _Noreturn void HRARetireSupervisor(void) {
  // Candidate admission proves this supervisor is a fresh process-group
  // leader, but the exact self signal is narrower than a group signal. Its
  // death closes the sole S->H writer; the host's native watcher then retires
  // its separately owned H/G/K group.
  (void)kill(getpid(), SIGKILL);
  _exit(70);
}

static void HRARecordAuthorityLoss(void) {
  atomic_store_explicit(&HRAAuthorityLost, true, memory_order_release);
  uint64_t deadline = 0;
  if (!HRADeadlineFromNow(
          HRAProbeAuthorityCleanupGraceMilliseconds, &deadline)) {
    HRARetireSupervisor();
  }
  while (HRADeadlineHasTime(deadline)) {
    if (atomic_load_explicit(
            &HRAHostRetirementCompleted, memory_order_acquire)) return;
    struct timespec pause = {
      .tv_sec = 0,
      .tv_nsec = HRAProbeGatePollMilliseconds * 1000 * 1000,
    };
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
      HRARetireSupervisor();
    }
  }
  HRARetireSupervisor();
}

static void *HRAWatchInvokingAuthority(void *unused) {
  (void)unused;
  if (!atomic_load_explicit(
          &HRAAuthorityWatcherActive, memory_order_acquire) ||
      !HRAInvokingAuthorityRemainsLive(
          &HRAWatchedParentGeneration, &HRAWatchedAuthorityLease)) {
    atomic_store_explicit(
        &HRAAuthorityWatcher, HRAAuthorityWatcherFailed,
        memory_order_release);
    HRARecordAuthorityLoss();
    return NULL;
  }
  atomic_store_explicit(
      &HRAAuthorityWatcher, HRAAuthorityWatcherRunning,
      memory_order_release);
  while (true) {
    if (!HRAInvokingAuthorityRemainsLive(
            &HRAWatchedParentGeneration, &HRAWatchedAuthorityLease)) {
      HRARecordAuthorityLoss();
      return NULL;
    }
    struct timespec pause = {
      .tv_sec = 0,
      .tv_nsec = HRAProbeGatePollMilliseconds * 1000 * 1000,
    };
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
      HRARecordAuthorityLoss();
      return NULL;
    }
  }
}

static bool HRAStartInvokingAuthorityWatcher(
    const HRAProbeParentGeneration *parentGeneration,
    const HRAProbeLease *authorityLease) {
  if (parentGeneration == NULL || authorityLease == NULL ||
      authorityLease->descriptor < 0 ||
      atomic_load_explicit(
          &HRAAuthorityWatcherActive, memory_order_acquire)) return false;
  HRAWatchedParentGeneration = *parentGeneration;
  HRAWatchedAuthorityLease = *authorityLease;
  atomic_store_explicit(
      &HRAAuthorityWatcherActive, true, memory_order_release);

  pthread_attr_t attributes;
  if (pthread_attr_init(&attributes) != 0) return false;
  bool configured = pthread_attr_setdetachstate(
      &attributes, PTHREAD_CREATE_DETACHED) == 0;
  pthread_t watcher;
  int createStatus = configured
      ? pthread_create(&watcher, &attributes, HRAWatchInvokingAuthority, NULL)
      : EINVAL;
  int destroyStatus = pthread_attr_destroy(&attributes);
  if (createStatus != 0 || destroyStatus != 0) return false;

  uint64_t deadline = 0;
  if (!HRADeadlineFromNow(1000, &deadline)) return false;
  while (HRADeadlineHasTime(deadline)) {
    int state = atomic_load_explicit(
        &HRAAuthorityWatcher, memory_order_acquire);
    if (state == HRAAuthorityWatcherRunning) {
      return HRAInvokingAuthorityRemainsLive(
          parentGeneration, authorityLease);
    }
    if (state == HRAAuthorityWatcherFailed) return false;
    if (!HRAInvokingAuthorityRemainsLive(
            parentGeneration, authorityLease)) return false;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
  return false;
}
#endif

#if defined(HRA_CUSTODY_PROBE_CANDIDATE_BUILD) || \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
static bool HRAAdmitCandidateLease(
    const HRAProbeParentGeneration *parentGeneration,
    HRAProbeLease *outLease) {
  if (parentGeneration == NULL || outLease == NULL ||
      getpid() <= 1 || getpgrp() != getpid()) return false;
  *outLease = (HRAProbeLease){.descriptor = -1};
  int descriptor = HRAProbeParentLeaseDescriptor;
  struct stat metadata;
  memset(&metadata, 0, sizeof(metadata));
  int descriptorFlags = fcntl(descriptor, F_GETFD);
  int statusFlags = fcntl(descriptor, F_GETFL);
  if (descriptorFlags < 0 || statusFlags < 0 ||
      fstat(descriptor, &metadata) != 0 || !S_ISFIFO(metadata.st_mode) ||
      fcntl(descriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) != 0 ||
      fcntl(descriptor, F_SETFL, statusFlags | O_NONBLOCK) != 0) return false;
  uint64_t deadline = 0;
  if (!HRADeadlineFromNow(
          HRAProbeTimeoutMilliseconds, &deadline)) return false;
  while (true) {
    if (!HRAParentGenerationRemainsLive(parentGeneration) ||
        !HRADeadlineHasTime(deadline)) return false;
    struct pollfd pollDescriptor = {
      .fd = descriptor,
      .events = POLLIN | POLLHUP,
      .revents = 0,
    };
    int timeout = HRADeadlinePollMilliseconds(deadline);
    if (timeout <= 0) return false;
    if (timeout > HRAProbeGatePollMilliseconds)
      timeout = HRAProbeGatePollMilliseconds;
    int status = poll(&pollDescriptor, 1, timeout);
    if (status < 0 && errno == EINTR) continue;
    if (status < 0 ||
        (pollDescriptor.revents & (POLLERR | POLLNVAL)) != 0) return false;
    if ((pollDescriptor.revents & (POLLIN | POLLHUP)) == 0) continue;
    unsigned char byte = 0;
    ssize_t count = read(descriptor, &byte, 1);
    if (count < 0 && (errno == EINTR || errno == EAGAIN ||
        errno == EWOULDBLOCK)) continue;
    if (count != 1 || byte != HRAProbeGoByte) return false;
    HRAProbeLease lease = {.descriptor = descriptor};
    if (!HRAInvokingAuthorityRemainsLive(parentGeneration, &lease))
      return false;
    *outLease = lease;
    return true;
  }
}
#endif

static uint64_t HRAMonotonicMilliseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return 0;
  uint64_t seconds = (uint64_t)now.tv_sec;
  if (seconds > UINT64_MAX / 1000) return 0;
  return seconds * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static bool HRADeadlineFromNow(
    uint64_t milliseconds,
    uint64_t *outDeadline) {
  uint64_t now = HRAMonotonicMilliseconds();
  if (now == 0 || milliseconds == 0 || outDeadline == NULL ||
      UINT64_MAX - now < milliseconds) return false;
  *outDeadline = now + milliseconds;
  return true;
}

static bool HRADeadlineHasTime(uint64_t deadline) {
  uint64_t now = HRAMonotonicMilliseconds();
  return deadline > 0 && now > 0 && now < deadline;
}

static int HRADeadlinePollMilliseconds(uint64_t deadline) {
  uint64_t now = HRAMonotonicMilliseconds();
  if (deadline == 0 || now == 0 || now >= deadline) return 0;
  uint64_t remaining = deadline - now;
  if (remaining > 25) remaining = 25;
  return (int)remaining;
}

static bool HRATimespecEquals(
    struct timespec left,
    struct timespec right) {
  return left.tv_sec == right.tv_sec && left.tv_nsec == right.tv_nsec;
}

static bool HRAFileIdentityFromStat(
    const struct stat *metadata,
    HRAProbeFileIdentity *outIdentity) {
  if (metadata == NULL || outIdentity == NULL ||
      !S_ISREG(metadata->st_mode) || metadata->st_nlink != 1 ||
      metadata->st_uid != geteuid() || metadata->st_size <= 0 ||
      (metadata->st_mode & 0111) == 0) return false;
  *outIdentity = (HRAProbeFileIdentity){
    .device = metadata->st_dev,
    .inode = metadata->st_ino,
    .mode = metadata->st_mode,
    .links = metadata->st_nlink,
    .owner = metadata->st_uid,
    .group = metadata->st_gid,
    .size = metadata->st_size,
    .modified = metadata->st_mtimespec,
    .changed = metadata->st_ctimespec,
  };
  return true;
}

static bool HRAFileIdentityEquals(
    const HRAProbeFileIdentity *left,
    const HRAProbeFileIdentity *right) {
  return left != NULL && right != NULL &&
      left->device == right->device && left->inode == right->inode &&
      left->mode == right->mode && left->links == right->links &&
      left->owner == right->owner && left->group == right->group &&
      left->size == right->size &&
      HRATimespecEquals(left->modified, right->modified) &&
      HRATimespecEquals(left->changed, right->changed);
}

static bool HRAHeldHostRemainsExact(
    int descriptor,
    const char *path,
    const HRAProbeFileIdentity *expected) {
  struct stat descriptorMetadata;
  struct stat pathMetadata;
  HRAProbeFileIdentity descriptorIdentity;
  HRAProbeFileIdentity pathIdentity;
  return descriptor >= 0 && path != NULL && expected != NULL &&
      fstat(descriptor, &descriptorMetadata) == 0 &&
      lstat(path, &pathMetadata) == 0 &&
      HRAFileIdentityFromStat(&descriptorMetadata, &descriptorIdentity) &&
      HRAFileIdentityFromStat(&pathMetadata, &pathIdentity) &&
      HRAFileIdentityEquals(expected, &descriptorIdentity) &&
      HRAFileIdentityEquals(expected, &pathIdentity);
}

static bool HRACanonicalRegularExecutable(
    const char *path,
    char canonical[PATH_MAX],
    int *outDescriptor,
    HRAProbeFileIdentity *outIdentity) {
  if (path == NULL || canonical == NULL || outDescriptor == NULL ||
      outIdentity == NULL || path[0] != '/' || strlen(path) >= PATH_MAX ||
      realpath(path, canonical) == NULL || strcmp(path, canonical) != 0) {
    return false;
  }
  int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) return false;
  struct stat metadata;
  bool exact = fstat(descriptor, &metadata) == 0 &&
      HRAFileIdentityFromStat(&metadata, outIdentity) &&
      HRAHeldHostRemainsExact(descriptor, path, outIdentity);
  if (!exact) {
    close(descriptor);
    return false;
  }
  *outDescriptor = descriptor;
  return true;
}

static bool HRACanonicalSmokeRoot(
    const char *path,
    char canonical[PATH_MAX]) {
  if (path == NULL || canonical == NULL || path[0] != '/' ||
      strlen(path) >= PATH_MAX || realpath(path, canonical) == NULL ||
      strcmp(path, canonical) != 0) return false;
  const char *leaf = strrchr(path, '/');
  struct stat metadata;
  return leaf != NULL &&
      strncmp(leaf + 1, "hra-package-smoke-", 18) == 0 &&
      lstat(path, &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
      metadata.st_nlink >= 2 && metadata.st_uid == geteuid() &&
      (metadata.st_mode & 0077) == 0;
}

static bool HRAEnvironmentAppend(
    HRAProbeEnvironment *environment,
    const char *key,
    const char *value) {
  if (environment == NULL || key == NULL || value == NULL ||
      environment->count >= HRAProbeEnvironmentEntries ||
      strchr(key, '=') != NULL) return false;
  size_t keyLength = strlen(key);
  size_t valueLength = strlen(value);
  if (keyLength == 0 || keyLength + valueLength + 2 >
      sizeof(environment->storage[0])) return false;
  char *entry = environment->storage[environment->count];
  memcpy(entry, key, keyLength);
  entry[keyLength] = '=';
  memcpy(entry + keyLength + 1, value, valueLength + 1);
  environment->values[environment->count] = entry;
  environment->count += 1;
  environment->values[environment->count] = NULL;
  return true;
}

static bool HRABuildEnvironment(
    HRAProbeEnvironment *environment,
    const char *smokeRoot) {
  if (environment == NULL) return false;
  memset(environment, 0, sizeof(*environment));
  if (!HRAEnvironmentAppend(environment, "LANG", "C") ||
      !HRAEnvironmentAppend(environment, "LC_ALL", "C") ||
      !HRAEnvironmentAppend(environment, "PATH", "/usr/bin:/bin")) {
    return false;
  }
  static const char *const inherited[] = {
    "HOME", "LOGNAME", "TMPDIR", "USER",
  };
  for (size_t index = 0; index < sizeof(inherited) / sizeof(inherited[0]);
       index += 1) {
    const char *value = getenv(inherited[index]);
    if (value != NULL && value[0] != '\0' &&
        !HRAEnvironmentAppend(environment, inherited[index], value)) {
      return false;
    }
  }
  return smokeRoot == NULL || HRAEnvironmentAppend(
      environment, "HRA_PACKAGE_SMOKE_ROOT", smokeRoot);
}

static bool HRASetCloseOnExec(int descriptor) {
  int flags = fcntl(descriptor, F_GETFD);
  return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool HRASetNonBlocking(int descriptor) {
  int flags = fcntl(descriptor, F_GETFL);
  return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool HRAProbeChildIsExactAndGated(
    pid_t processIdentifier,
    const char *hostPath,
    const uint8_t expectedCDHash[HRA_MACOS_CDHASH_LENGTH]) {
  struct proc_bsdinfo information;
  memset(&information, 0, sizeof(information));
  int bytes = proc_pidinfo(
      processIdentifier,
      PROC_PIDTBSDINFO,
      0,
      &information,
      (int)sizeof(information));
  bool metadataExact = bytes == (int)sizeof(information) &&
      information.pbi_pid == (uint32_t)processIdentifier &&
      information.pbi_ppid == (uint32_t)getpid() &&
      information.pbi_pgid == (uint32_t)processIdentifier &&
      information.pbi_status != SZOMB &&
      information.pbi_start_tvsec != 0;
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  (void)hostPath;
  (void)expectedCDHash;
  return metadataExact;
#else
  static const char identifier[] = "kitchen.hraness";
  return metadataExact &&
      hra_macos_self_managed_dynamic_code_matches(
          processIdentifier,
          hostPath,
          strlen(hostPath),
          identifier,
          sizeof(identifier) - 1,
          expectedCDHash,
          HRA_MACOS_CODE_DIRECTORY_RUNTIME);
#endif
}

static bool HRAProbeUntrustedChildIsGated(
    pid_t processIdentifier,
    const char *hostPath) {
  if (processIdentifier <= 1 || hostPath == NULL) return false;
  struct proc_bsdinfo information;
  char processPath[PROC_PIDPATHINFO_MAXSIZE];
  memset(&information, 0, sizeof(information));
  memset(processPath, 0, sizeof(processPath));
  int metadataBytes = proc_pidinfo(
      processIdentifier,
      PROC_PIDTBSDINFO,
      0,
      &information,
      (int)sizeof(information));
  int pathLength = proc_pidpath(
      processIdentifier, processPath, (uint32_t)sizeof(processPath));
  return metadataBytes == (int)sizeof(information) &&
      information.pbi_pid == (uint32_t)processIdentifier &&
      information.pbi_ppid == (uint32_t)getpid() &&
      information.pbi_pgid == (uint32_t)processIdentifier &&
      information.pbi_status != SZOMB &&
      information.pbi_start_tvsec != 0 && pathLength > 0 &&
      (size_t)pathLength < sizeof(processPath) &&
      processPath[pathLength] == '\0' && strcmp(processPath, hostPath) == 0;
}

static bool HRAWaitForProbeChildGate(
    pid_t processIdentifier,
    const char *hostPath,
    const uint8_t expectedCDHash[HRA_MACOS_CDHASH_LENGTH],
    bool untrustedHost,
    const HRAProbeParentGeneration *parentGeneration,
    const HRAProbeLease *authorityLease,
    uint64_t deadline) {
  while (HRADeadlineHasTime(deadline) &&
      HRAInvokingAuthorityRemainsLive(parentGeneration, authorityLease)) {
    if (untrustedHost
        ? HRAProbeUntrustedChildIsGated(processIdentifier, hostPath)
        : HRAProbeChildIsExactAndGated(
            processIdentifier, hostPath, expectedCDHash)) return true;
    siginfo_t exitInformation;
    bool exited = false;
    if (!HRAObserveLeaderExit(
            processIdentifier, &exitInformation, &exited) || exited) {
      return false;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
  return false;
}

static bool HRAStaticHostIdentityIsExact(
    const char *hostPath,
    const HRAProbeFileIdentity *expectedFileIdentity,
    int hostDescriptor,
    uint8_t outCDHash[HRA_MACOS_CDHASH_LENGTH]) {
  if (!HRAHeldHostRemainsExact(
          hostDescriptor, hostPath, expectedFileIdentity)) return false;
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  memset(outCDHash, 0x51, HRA_MACOS_CDHASH_LENGTH);
  return true;
#else
  return hra_macos_parent_payload_identity_is_exact(
      hostPath, strlen(hostPath), outCDHash);
#endif
}

static bool HRAProbeGroupHasNoLiveMembers(
    pid_t groupLeader,
    bool leaderExited) {
  if (groupLeader <= 1) return false;
  pid_t members[HRAProbeMaximumGroupMembers];
  memset(members, 0, sizeof(members));
  int listedBytes = proc_listpids(
      PROC_PGRP_ONLY,
      (uint32_t)groupLeader,
      members,
      (int)sizeof(members));
  if (listedBytes < 0 || listedBytes >= (int)sizeof(members) ||
      listedBytes % (int)sizeof(pid_t) != 0) return false;
  size_t count = (size_t)listedBytes / sizeof(pid_t);
  for (size_t index = 0; index < count; index += 1) {
    pid_t member = members[index];
    if (member <= 0) continue;
    if (member == groupLeader) {
      if (leaderExited) continue;
      return false;
    }
    struct proc_bsdinfo information;
    memset(&information, 0, sizeof(information));
    errno = 0;
    int bytes = proc_pidinfo(
        member,
        PROC_PIDTBSDINFO,
        0,
        &information,
        (int)sizeof(information));
    if (bytes == 0 && errno == ESRCH) continue;
    if (bytes != (int)sizeof(information) ||
        information.pbi_pid != (uint32_t)member) return false;
    if (information.pbi_pgid != (uint32_t)groupLeader) continue;
    if (information.pbi_status != SZOMB) return false;
  }
  return true;
}

static bool HRAObserveLeaderExit(
    pid_t processIdentifier,
    siginfo_t *outInformation,
    bool *outExited) {
  if (processIdentifier <= 1 || outInformation == NULL || outExited == NULL)
    return false;
  while (true) {
    *outExited = false;
    memset(outInformation, 0, sizeof(*outInformation));
    int status = waitid(
        P_PID,
        (id_t)processIdentifier,
        outInformation,
        WEXITED | WNOWAIT | WNOHANG);
    if (status == 0) {
      *outExited = HRAWaitInformationIsTerminal(
          outInformation, processIdentifier);
      return true;
    }
    if (errno != EINTR) return false;
  }
}

static bool HRADrainProbePipe(HRAProbePipe *pipe) {
  if (pipe == NULL || pipe->descriptor < 0 || pipe->eof) return pipe != NULL;
  while (true) {
    uint8_t extra = 0;
    uint8_t *target = pipe->length < sizeof(pipe->bytes)
        ? pipe->bytes + pipe->length
        : &extra;
    size_t capacity = pipe->length < sizeof(pipe->bytes)
        ? sizeof(pipe->bytes) - pipe->length
        : 1;
    ssize_t count = read(pipe->descriptor, target, capacity);
    if (count > 0) {
      if (pipe->length >= sizeof(pipe->bytes)) return false;
      pipe->length += (size_t)count;
      continue;
    }
    if (count == 0) {
      pipe->eof = true;
      return true;
    }
    if (errno == EINTR) continue;
    return errno == EAGAIN || errno == EWOULDBLOCK;
  }
}

static void HRAAbandonProbePipe(HRAProbePipe *pipe) {
  if (pipe == NULL) return;
  if (pipe->descriptor >= 0) close(pipe->descriptor);
  pipe->descriptor = -1;
  pipe->eof = true;
}

static bool HRAWaitForProbeActivity(
    HRAProbePipe *standardOutput,
    HRAProbePipe *standardError,
    const HRAProbeLease *authorityLease,
    uint64_t deadline) {
  struct pollfd descriptors[3];
  nfds_t count = 0;
  if (!standardOutput->eof) {
    descriptors[count++] = (struct pollfd){
      .fd = standardOutput->descriptor,
      .events = POLLIN | POLLHUP,
    };
  }
  if (!standardError->eof) {
    descriptors[count++] = (struct pollfd){
      .fd = standardError->descriptor,
      .events = POLLIN | POLLHUP,
    };
  }
  if (authorityLease != NULL && authorityLease->descriptor >= 0) {
    descriptors[count++] = (struct pollfd){
      .fd = authorityLease->descriptor,
      .events = POLLIN | POLLHUP,
    };
  }
  int timeout = HRADeadlinePollMilliseconds(deadline);
  if (timeout <= 0) return false;
  if (count == 0) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = timeout * 1000000L};
    return nanosleep(&pause, NULL) == 0 || errno == EINTR;
  }
  int status = poll(descriptors, count, timeout);
  if (status < 0) return errno == EINTR;
  if (status == 0) return true;
  for (nfds_t index = 0; index < count; index += 1) {
    if ((descriptors[index].revents &
            (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0 &&
        authorityLease != NULL &&
        descriptors[index].fd == authorityLease->descriptor) return false;
    if ((descriptors[index].revents & (POLLERR | POLLNVAL)) != 0) return false;
  }
  return true;
}

static bool HRAExactLowerHex(const uint8_t *bytes, size_t length) {
  if (bytes == NULL || length != 64) return false;
  for (size_t index = 0; index < length; index += 1) {
    uint8_t byte = bytes[index];
    if (!((byte >= '0' && byte <= '9') ||
          (byte >= 'a' && byte <= 'f'))) return false;
  }
  return true;
}

static bool HRAAuthorizeOutputIsCanonical(
    const uint8_t *bytes,
    size_t length) {
  static const char prefix[] =
      "{\"authorization\":\"hra-parent-v1\",\"gatewayFileSha256\":\"";
  static const char middle[] =
      "\",\"keychainAccessed\":false,\"ok\":true,"
      "\"rendererAuthoritySha256\":\"";
  static const char suffix[] = "\",\"version\":1}\n";
  size_t expected = sizeof(prefix) - 1 + 64 + sizeof(middle) - 1 + 64 +
      sizeof(suffix) - 1;
  if (bytes == NULL || length != expected) return false;
  size_t offset = 0;
  if (memcmp(bytes + offset, prefix, sizeof(prefix) - 1) != 0) return false;
  offset += sizeof(prefix) - 1;
  if (!HRAExactLowerHex(bytes + offset, 64)) return false;
  offset += 64;
  if (memcmp(bytes + offset, middle, sizeof(middle) - 1) != 0) return false;
  offset += sizeof(middle) - 1;
  if (!HRAExactLowerHex(bytes + offset, 64)) return false;
  offset += 64;
  return memcmp(bytes + offset, suffix, sizeof(suffix) - 1) == 0;
}

static bool HRAStatusOutputIsCanonical(
    const uint8_t *bytes,
    size_t length) {
  static const char absent[] = "{\"schemaVersion\":1,\"state\":\"absent\"}\n";
  static const char prefix[] = "{\"envelopeSha256\":\"";
  static const char suffix[] =
      "\",\"schemaVersion\":1,\"state\":\"present\",\"strictAcl\":true}\n";
  if (length == sizeof(absent) - 1 &&
      memcmp(bytes, absent, sizeof(absent) - 1) == 0) return true;
  size_t expected = sizeof(prefix) - 1 + 64 + sizeof(suffix) - 1;
  return bytes != NULL && length == expected &&
      memcmp(bytes, prefix, sizeof(prefix) - 1) == 0 &&
      HRAExactLowerHex(bytes + sizeof(prefix) - 1, 64) &&
      memcmp(
          bytes + sizeof(prefix) - 1 + 64,
          suffix,
          sizeof(suffix) - 1) == 0;
}

static bool HRAWriteAll(int descriptor, const uint8_t *bytes, size_t length) {
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

static bool HRAReapExactLeader(pid_t processIdentifier, int *outStatus) {
  if (processIdentifier <= 1 || outStatus == NULL) return false;
  while (true) {
    int status = 0;
    pid_t waited = waitpid(processIdentifier, &status, 0);
    if (waited == processIdentifier) {
      *outStatus = status;
      return true;
    }
    if (waited < 0 && errno == EINTR) continue;
    return false;
  }
}

static bool HRAWaitForExitAndQuiescence(
    pid_t processIdentifier,
    uint64_t deadline,
    siginfo_t *outExitInformation,
    HRAProbePipe *standardOutput,
    HRAProbePipe *standardError) {
  while (HRADeadlineHasTime(deadline)) {
    // Once the exact leader is retained WNOWAIT, outer authority loss only
    // disqualifies the receipt. It must never interrupt bounded group
    // quiescence and exact reap.
    (void)HRACancellationOrAuthorityLost();
    if (!HRADrainProbePipe(standardOutput) ||
        !HRADrainProbePipe(standardError)) return false;
    bool exited = false;
    siginfo_t information;
    if (!HRAObserveLeaderExit(processIdentifier, &information, &exited)) {
      continue;
    }
    if (exited && HRAProbeGroupHasNoLiveMembers(processIdentifier, true)) {
      *outExitInformation = information;
      return true;
    }
    if (!HRAWaitForProbeActivity(
            standardOutput, standardError, NULL, deadline))
      return false;
  }
  return false;
}

static int HRAParsePositiveMilliseconds(const char *text) {
  if (text == NULL || text[0] == '\0') return 0;
  uint64_t value = 0;
  for (const char *cursor = text; *cursor != '\0'; cursor += 1) {
    if (*cursor < '0' || *cursor > '9') return 0;
    value = value * 10 + (uint64_t)(*cursor - '0');
    if (value > 30000) return 0;
  }
  return value == 0 ? 0 : (int)value;
}

#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
static bool HRATestDelayPastProbePhase(void) {
  uint64_t delayDeadline = 0;
  if (!HRADeadlineFromNow(
          HRAProbeTimeoutMilliseconds + 250, &delayDeadline)) return false;
  while (HRADeadlineHasTime(delayDeadline)) {
    struct timespec pause = {
      .tv_sec = 0,
      .tv_nsec = HRAProbeGatePollMilliseconds * 1000 * 1000,
    };
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) return false;
  }
  return true;
}
#endif

static int HRARunProbe(
    HRAProbeMode mode,
    const HRAProbeParentGeneration *parentGeneration,
    const HRAProbeLease *authorityLease,
    const char *hostPath,
    const char *hostileSignalLauncherPath,
    const char *smokeRoot,
    int smokeDwellMilliseconds) {
  // The outer runner grants one admission phase for all static validation,
  // process construction, and the two live-image checks. Starting the clock
  // here prevents an expensive Security trust evaluation from receiving an
  // undeclared interval before the child gate is admitted.
  uint64_t admissionDeadline = 0;
  if (!HRADeadlineFromNow(
          HRAProbeTimeoutMilliseconds, &admissionDeadline)) return 70;
  bool hostileSignals = mode == HRAProbeAuthorizeHostileSignals;
  bool untrustedHost = false;
#if defined(HRA_CUSTODY_PROBE_ADVERSARIAL_BUILD)
  untrustedHost = mode == HRAProbeRejectAuthorize;
#endif
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  if (strstr(hostPath, "hra-static-admission-delay") != NULL &&
      !HRATestDelayPastProbePhase()) return 70;
#endif
  HRAProbeParentGeneration selfGeneration;
  memset(&selfGeneration, 0, sizeof(selfGeneration));
  char selfProcessText[32];
  char selfSecondsText[32];
  char selfMicrosecondsText[32];
  memset(selfProcessText, 0, sizeof(selfProcessText));
  memset(selfSecondsText, 0, sizeof(selfSecondsText));
  memset(selfMicrosecondsText, 0, sizeof(selfMicrosecondsText));
  if (!HRAInvokingAuthorityRemainsLive(parentGeneration, authorityLease) ||
      !HRACaptureSelfGeneration(&selfGeneration) ||
      snprintf(
          selfProcessText,
          sizeof(selfProcessText),
          "%d",
          selfGeneration.processIdentifier) <= 0 ||
      snprintf(
          selfSecondsText,
          sizeof(selfSecondsText),
          "%llu",
          (unsigned long long)selfGeneration.startSeconds) <= 0 ||
      snprintf(
          selfMicrosecondsText,
          sizeof(selfMicrosecondsText),
          "%llu",
          (unsigned long long)selfGeneration.startMicroseconds) <= 0) {
    return 70;
  }
  char canonicalHost[PATH_MAX];
  int hostDescriptor = -1;
  HRAProbeFileIdentity hostIdentity;
  memset(&hostIdentity, 0, sizeof(hostIdentity));
  if (!HRACanonicalRegularExecutable(
          hostPath, canonicalHost, &hostDescriptor, &hostIdentity)) return 70;

  uint8_t hostCDHash[HRA_MACOS_CDHASH_LENGTH];
  memset(hostCDHash, 0, sizeof(hostCDHash));
  if (!untrustedHost && !HRAStaticHostIdentityIsExact(
          canonicalHost,
          &hostIdentity,
          hostDescriptor,
          hostCDHash)) {
    close(hostDescriptor);
    return 70;
  }

  char canonicalLauncher[PATH_MAX];
  int launcherDescriptor = -1;
  HRAProbeFileIdentity launcherIdentity;
  memset(canonicalLauncher, 0, sizeof(canonicalLauncher));
  memset(&launcherIdentity, 0, sizeof(launcherIdentity));
  if (hostileSignals && !HRACanonicalRegularExecutable(
          hostileSignalLauncherPath,
          canonicalLauncher,
          &launcherDescriptor,
          &launcherIdentity)) {
    close(hostDescriptor);
    return 70;
  }

  HRAProbeEnvironment environment;
  if (!HRABuildEnvironment(&environment, smokeRoot)) {
    if (launcherDescriptor >= 0) close(launcherDescriptor);
    close(hostDescriptor);
    return 70;
  }

  int outputDescriptors[2] = {-1, -1};
  int errorDescriptors[2] = {-1, -1};
  int gateDescriptors[2] = {-1, -1};
  if (pipe(outputDescriptors) != 0 || pipe(errorDescriptors) != 0 ||
      pipe(gateDescriptors) != 0) {
    if (outputDescriptors[0] >= 0) close(outputDescriptors[0]);
    if (outputDescriptors[1] >= 0) close(outputDescriptors[1]);
    if (errorDescriptors[0] >= 0) close(errorDescriptors[0]);
    if (errorDescriptors[1] >= 0) close(errorDescriptors[1]);
    if (gateDescriptors[0] >= 0) close(gateDescriptors[0]);
    if (gateDescriptors[1] >= 0) close(gateDescriptors[1]);
    if (launcherDescriptor >= 0) close(launcherDescriptor);
    close(hostDescriptor);
    return 70;
  }
  bool pipesConfigured = HRASetCloseOnExec(outputDescriptors[0]) &&
      HRASetCloseOnExec(outputDescriptors[1]) &&
      HRASetCloseOnExec(errorDescriptors[0]) &&
      HRASetCloseOnExec(errorDescriptors[1]) &&
      HRASetCloseOnExec(gateDescriptors[0]) &&
      HRASetCloseOnExec(gateDescriptors[1]) &&
      HRASetNonBlocking(outputDescriptors[0]) &&
      HRASetNonBlocking(errorDescriptors[0]);

  posix_spawnattr_t attributes = NULL;
  posix_spawn_file_actions_t actions = NULL;
  bool initializedAttributes = pipesConfigured &&
      posix_spawnattr_init(&attributes) == 0;
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
      sigaddset(&childSignalDefaults, SIGPIPE) == 0;
  short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP |
      POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
  bool configured = initializedActions && signalSetsConfigured &&
      posix_spawnattr_setflags(&attributes, flags) == 0 &&
      posix_spawnattr_setpgroup(&attributes, 0) == 0 &&
      posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0 &&
      posix_spawnattr_setsigdefault(&attributes, &childSignalDefaults) == 0 &&
      // File actions are ordered. In verifier mode outputDescriptors[0] is
      // normally fd 3, so close every conflicting parent-side descriptor
      // before installing the host's fixed lifetime lease at fd 3.
      posix_spawn_file_actions_addclose(&actions, outputDescriptors[0]) == 0 &&
      posix_spawn_file_actions_addclose(&actions, errorDescriptors[0]) == 0 &&
      posix_spawn_file_actions_addclose(&actions, gateDescriptors[1]) == 0 &&
      posix_spawn_file_actions_addopen(
          &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
      posix_spawn_file_actions_adddup2(
          &actions, outputDescriptors[1], STDOUT_FILENO) == 0 &&
      posix_spawn_file_actions_adddup2(
          &actions, errorDescriptors[1], STDERR_FILENO) == 0 &&
      posix_spawn_file_actions_adddup2(
          &actions,
          gateDescriptors[0],
          HRAProbeParentLeaseDescriptor) == 0;
  char *authorizeArguments[] = {
    canonicalHost,
    "--custody-authorization-probe",
    "--hra-probe-parent-v1",
    selfProcessText,
    selfSecondsText,
    selfMicrosecondsText,
    NULL,
  };
  char *hostileAuthorizeArguments[] = {
    canonicalLauncher,
    canonicalHost,
    "--custody-authorization-probe",
    "--hra-probe-parent-v1",
    selfProcessText,
    selfSecondsText,
    selfMicrosecondsText,
    NULL,
  };
  char *statusArguments[] = {
    canonicalHost,
    "--custody-status-probe",
    "--hra-probe-parent-v1",
    selfProcessText,
    selfSecondsText,
    selfMicrosecondsText,
    NULL,
  };
  char *smokeArguments[] = {
    canonicalHost,
    "--package-smoke-probe",
    "--hra-probe-parent-v1",
    selfProcessText,
    selfSecondsText,
    selfMicrosecondsText,
    NULL,
  };
  bool authorizationArgumentsSelected = mode == HRAProbeAuthorize;
#if defined(HRA_CUSTODY_PROBE_ADVERSARIAL_BUILD)
  authorizationArgumentsSelected = authorizationArgumentsSelected ||
      mode == HRAProbeRejectAuthorize;
#endif
  char **arguments = authorizationArgumentsSelected
      ? authorizeArguments
      : mode == HRAProbeAuthorizeHostileSignals
          ? hostileAuthorizeArguments
          : mode == HRAProbeStatus ? statusArguments : smokeArguments;
  const char *spawnPath = hostileSignals ? canonicalLauncher : canonicalHost;
  pid_t processIdentifier = -1;
  int spawnStatus = configured
      && HRADeadlineHasTime(admissionDeadline)
      && !HRACancellationOrAuthorityLost()
      ? posix_spawn(
          &processIdentifier,
          spawnPath,
          &actions,
          &attributes,
          arguments,
          environment.values)
      : EINVAL;
  if (initializedActions) posix_spawn_file_actions_destroy(&actions);
  if (initializedAttributes) posix_spawnattr_destroy(&attributes);
  close(outputDescriptors[1]);
  close(errorDescriptors[1]);
  close(gateDescriptors[0]);
  outputDescriptors[1] = -1;
  errorDescriptors[1] = -1;
  gateDescriptors[0] = -1;
  if (spawnStatus != 0 || processIdentifier <= 1) {
    close(outputDescriptors[0]);
    close(errorDescriptors[0]);
    close(gateDescriptors[1]);
    if (launcherDescriptor >= 0) close(launcherDescriptor);
    close(hostDescriptor);
    return 70;
  }

  bool signalIssued = false;
  int testFailureExitCode = 70;
  bool admitted = HRADeadlineHasTime(admissionDeadline) &&
      getpgid(processIdentifier) == processIdentifier;
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  if (!admitted) testFailureExitCode = 71;
#endif
  admitted = admitted && HRAWaitForProbeChildGate(
      processIdentifier,
      canonicalHost,
      hostCDHash,
      untrustedHost,
      parentGeneration,
      authorityLease,
      admissionDeadline);
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  if (!admitted && testFailureExitCode == 70) testFailureExitCode = 72;
#endif
  admitted = admitted && HRAHeldHostRemainsExact(
      hostDescriptor, canonicalHost, &hostIdentity) &&
      (!hostileSignals || HRAHeldHostRemainsExact(
          launcherDescriptor, canonicalLauncher, &launcherIdentity));
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  if (!admitted && testFailureExitCode == 70) testFailureExitCode = 73;
#endif
  uint8_t repeatedCDHash[HRA_MACOS_CDHASH_LENGTH];
  memset(repeatedCDHash, 0, sizeof(repeatedCDHash));
  admitted = admitted && (untrustedHost ||
      (HRAStaticHostIdentityIsExact(
          canonicalHost,
          &hostIdentity,
          hostDescriptor,
          repeatedCDHash) &&
       memcmp(hostCDHash, repeatedCDHash, sizeof(hostCDHash)) == 0)) &&
      HRAWaitForProbeChildGate(
          processIdentifier,
          canonicalHost,
          hostCDHash,
          untrustedHost,
          parentGeneration,
          authorityLease,
          admissionDeadline) &&
      HRAHeldHostRemainsExact(
          hostDescriptor, canonicalHost, &hostIdentity) &&
      (!hostileSignals || HRAHeldHostRemainsExact(
          launcherDescriptor, canonicalLauncher, &launcherIdentity));
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  if (!admitted && testFailureExitCode == 70) testFailureExitCode = 74;
  if (admitted &&
      strstr(canonicalHost, "hra-final-admission-delay") != NULL &&
      !HRATestDelayPastProbePhase()) admitted = false;
#endif
  memset(repeatedCDHash, 0, sizeof(repeatedCDHash));
  admitted = admitted && HRADeadlineHasTime(admissionDeadline) &&
      !HRACancellationOrAuthorityLost() &&
      HRAInvokingAuthorityRemainsLive(parentGeneration, authorityLease);
  static const uint8_t admissionByte = HRAProbeGoByte;
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD)
  static const uint8_t invalidAdmissionBytes[] = {HRAProbeGoByte, 'X'};
  if (admitted && strstr(canonicalHost, "hra-inner-extra-byte") != NULL) {
    admitted = HRAWriteAll(
        gateDescriptors[1],
        invalidAdmissionBytes,
        sizeof(invalidAdmissionBytes));
  } else
#endif
  if (admitted) admitted = HRAWriteAll(
      gateDescriptors[1], &admissionByte, sizeof(admissionByte));

  HRAProbePipe standardOutput = {
    .descriptor = outputDescriptors[0],
  };
  HRAProbePipe standardError = {
    .descriptor = errorDescriptors[0],
  };
  uint64_t operationDeadline = 0;
  bool validDeadline = HRADeadlineFromNow(
      mode == HRAProbeSmoke
          ? (uint64_t)smokeDwellMilliseconds
          : HRAProbeTimeoutMilliseconds,
      &operationDeadline);
  bool operationFailed = !admitted || !validDeadline;
  bool smokeDwellComplete = false;
  siginfo_t exitInformation;
  memset(&exitInformation, 0, sizeof(exitInformation));
  bool leaderExited = false;

  while (!operationFailed && !smokeDwellComplete) {
    if (HRACancellationOrAuthorityLost() ||
        !HRAInvokingAuthorityRemainsLive(
            parentGeneration, authorityLease)) {
      operationFailed = true;
      break;
    }
    if (!HRADrainProbePipe(&standardOutput) ||
        !HRADrainProbePipe(&standardError) ||
        !HRAObserveLeaderExit(
            processIdentifier, &exitInformation, &leaderExited)) {
      operationFailed = true;
      break;
    }
    bool groupQuiescent = leaderExited &&
        HRAProbeGroupHasNoLiveMembers(processIdentifier, true);
    if (mode != HRAProbeSmoke && groupQuiescent &&
        standardOutput.eof && standardError.eof) break;
    if (mode == HRAProbeSmoke && leaderExited) {
      operationFailed = true;
      break;
    }
    if (!HRADeadlineHasTime(operationDeadline)) {
      if (mode == HRAProbeSmoke) {
        smokeDwellComplete = true;
      } else {
        operationFailed = true;
      }
      break;
    }
    if (!HRAWaitForProbeActivity(
            &standardOutput,
            &standardError,
            authorityLease,
            operationDeadline)) {
      operationFailed = true;
      break;
    }
  }

  if (HRACancellationOrAuthorityLost() ||
      !HRAInvokingAuthorityRemainsLive(parentGeneration, authorityLease)) {
    operationFailed = true;
  }
#if defined(HRA_CUSTODY_PROBE_SUPERVISOR_TEST_BUILD) && \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
  if (operationFailed && authorityLease->descriptor >= 0 &&
      strstr(canonicalHost, "hra-loss-retirement-stall") != NULL &&
      !HRAInvokingAuthorityRemainsLive(
          parentGeneration, authorityLease)) {
    // Prove the authority watcher remains armed after main observes loss. The
    // watcher must self-retire S only after a grace longer than ordinary H
    // cleanup, which closes S->H and exercises the host watcher fallback.
    struct timespec stall = {
      .tv_sec = HRAProbeAuthorityCleanupGraceMilliseconds / 1000 + 1,
      .tv_nsec = 0,
    };
    while (nanosleep(&stall, &stall) != 0 && errno == EINTR) {}
  }
#endif
  bool shouldSignal = smokeDwellComplete || operationFailed;
  if (shouldSignal) {
    bool observedExit = false;
    siginfo_t currentExit;
    memset(&currentExit, 0, sizeof(currentExit));
    bool observed = HRAObserveLeaderExit(
        processIdentifier, &currentExit, &observedExit);
    bool groupQuiescent = observed && observedExit &&
        HRAProbeGroupHasNoLiveMembers(processIdentifier, true);
    if (!groupQuiescent) {
      errno = 0;
      int signalStatus = kill(-processIdentifier, SIGKILL);
      int signalError = errno;
      signalIssued = true;
      if (signalStatus != 0 && signalError != ESRCH && signalError != EPERM) {
        operationFailed = true;
      }
    } else if (smokeDwellComplete) {
      // A smoke host must remain alive for its full dwell. Exiting on the
      // boundary without requiring the owned group signal is not success.
      operationFailed = true;
    }
  }

  // Once a failure or the deliberate smoke dwell requires containment, pipe
  // evidence is already ineligible. Close it before retirement so oversized,
  // malformed, or interrupted output cannot prevent WNOWAIT quiescence and
  // the exact child reap. The group kill above remains the sole signal.
  if (shouldSignal) {
    if (!HRADrainProbePipe(&standardOutput) ||
        !HRADrainProbePipe(&standardError)) operationFailed = true;
    HRAAbandonProbePipe(&standardOutput);
    HRAAbandonProbePipe(&standardError);
  }

  uint64_t cleanupDeadline = 0;
  bool cleanupReady = HRADeadlineFromNow(
      HRAProbeCleanupMilliseconds, &cleanupDeadline) &&
      HRAWaitForExitAndQuiescence(
          processIdentifier,
          cleanupDeadline,
          &exitInformation,
          &standardOutput,
          &standardError);
  // Drain once more while the leader still reserves PID and PGID. No signal
  // or process query is permitted after the exact reap below.
  bool outputDrained = HRADrainProbePipe(&standardOutput) &&
      HRADrainProbePipe(&standardError);
  int waitStatus = 0;
  bool reaped = cleanupReady &&
      HRAReapExactLeader(processIdentifier, &waitStatus);
#if defined(HRA_CUSTODY_PROBE_CANDIDATE_BUILD) || \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
  if (reaped) atomic_store_explicit(
      &HRAHostRetirementCompleted, true, memory_order_release);
#endif

  // The supervisor is the sole writer for the host's lifetime lease. Keep it
  // open through terminal observation, group quiescence, and exact reap. A
  // failed bounded cleanup closes it only as the final fail-safe, allowing the
  // host's native watcher to retire any otherwise uncontained descendants.
  close(gateDescriptors[1]);
  gateDescriptors[1] = -1;

  HRAAbandonProbePipe(&standardOutput);
  HRAAbandonProbePipe(&standardError);
  bool hostRemainedExact = HRAHeldHostRemainsExact(
      hostDescriptor, canonicalHost, &hostIdentity);
  bool launcherRemainedExact = !hostileSignals || HRAHeldHostRemainsExact(
      launcherDescriptor, canonicalLauncher, &launcherIdentity);
  uint8_t finalCDHash[HRA_MACOS_CDHASH_LENGTH];
  memset(finalCDHash, 0, sizeof(finalCDHash));
  hostRemainedExact = hostRemainedExact && (untrustedHost ||
      (HRAStaticHostIdentityIsExact(
          canonicalHost,
          &hostIdentity,
          hostDescriptor,
          finalCDHash) &&
       memcmp(hostCDHash, finalCDHash, sizeof(hostCDHash)) == 0));
  memset(finalCDHash, 0, sizeof(finalCDHash));
  memset(hostCDHash, 0, sizeof(hostCDHash));
  close(hostDescriptor);
  if (launcherDescriptor >= 0) close(launcherDescriptor);

  if (!cleanupReady || !outputDrained || !reaped || !hostRemainedExact ||
      !launcherRemainedExact ||
      HRACancellationOrAuthorityLost() ||
      !HRAInvokingAuthorityRemainsLive(parentGeneration, authorityLease))
    return testFailureExitCode;
  if (mode == HRAProbeSmoke) {
    return !operationFailed && smokeDwellComplete && signalIssued &&
        WIFSIGNALED(waitStatus) && WTERMSIG(waitStatus) == SIGKILL &&
        standardOutput.length == 0 && standardError.length == 0
        ? 0
        : testFailureExitCode;
  }
#if defined(HRA_CUSTODY_PROBE_ADVERSARIAL_BUILD)
  if (mode == HRAProbeRejectAuthorize) {
    return !operationFailed && !signalIssued &&
        WIFEXITED(waitStatus) && WEXITSTATUS(waitStatus) == 1 &&
        exitInformation.si_code == CLD_EXITED &&
        exitInformation.si_status == 1 &&
        standardOutput.length == 0 && standardError.length == 0
        ? 0
        : testFailureExitCode;
  }
#endif
  bool exitedCleanly = WIFEXITED(waitStatus) && WEXITSTATUS(waitStatus) == 0 &&
      exitInformation.si_code == CLD_EXITED && exitInformation.si_status == 0;
  bool outputExact = mode == HRAProbeAuthorize ||
      mode == HRAProbeAuthorizeHostileSignals
      ? HRAAuthorizeOutputIsCanonical(
          standardOutput.bytes, standardOutput.length)
      : HRAStatusOutputIsCanonical(
          standardOutput.bytes, standardOutput.length);
  if (operationFailed || signalIssued || !exitedCleanly ||
      !outputExact || standardError.length != 0) return testFailureExitCode;
  if (HRACancellationOrAuthorityLost() ||
      !HRAInvokingAuthorityRemainsLive(
          parentGeneration, authorityLease)) return testFailureExitCode;
  bool written = HRAWriteAll(
      STDOUT_FILENO, standardOutput.bytes, standardOutput.length);
  return written && !HRACancellationOrAuthorityLost() &&
      HRAInvokingAuthorityRemainsLive(parentGeneration, authorityLease)
      ? 0
      : testFailureExitCode;
}

int main(int argc, const char *argv[]) {
  if (!HRAInstallSignalPolicy()) return 70;
  HRAProbeMode mode;
  const char *hostPath = NULL;
  const char *hostileSignalLauncherPath = NULL;
  const char *smokeRoot = NULL;
  int smokeDwellMilliseconds = 0;

  if (argc == 3 && strcmp(argv[1], "authorize") == 0) {
    mode = HRAProbeAuthorize;
    hostPath = argv[2];
  } else if (argc == 4 &&
      strcmp(argv[1], "authorize-hostile-signals") == 0) {
    mode = HRAProbeAuthorizeHostileSignals;
    hostileSignalLauncherPath = argv[2];
    hostPath = argv[3];
  } else if (argc == 3 && strcmp(argv[1], "status") == 0) {
    mode = HRAProbeStatus;
    hostPath = argv[2];
#if defined(HRA_CUSTODY_PROBE_ADVERSARIAL_BUILD)
  } else if (argc == 3 && strcmp(argv[1], "reject-authorize") == 0) {
    mode = HRAProbeRejectAuthorize;
    hostPath = argv[2];
#endif
  } else if (argc == 5 && strcmp(argv[1], "smoke") == 0) {
    char canonicalSmokeRoot[PATH_MAX];
    smokeDwellMilliseconds = HRAParsePositiveMilliseconds(argv[4]);
    if (smokeDwellMilliseconds == 0 ||
        !HRACanonicalSmokeRoot(argv[3], canonicalSmokeRoot)) return 64;
    mode = HRAProbeSmoke;
    hostPath = argv[2];
    smokeRoot = argv[3];
  } else {
    return 64;
  }

  HRAProbeParentGeneration parentGeneration;
  memset(&parentGeneration, 0, sizeof(parentGeneration));
  if (!HRACaptureParentGeneration(&parentGeneration)) return 70;
  HRAProbeLease authorityLease = {.descriptor = -1};
#if defined(HRA_CUSTODY_PROBE_CANDIDATE_BUILD) || \
    defined(HRA_CUSTODY_PROBE_REQUIRE_PARENT_LEASE)
  if (!HRAAdmitCandidateLease(&parentGeneration, &authorityLease) ||
      !HRAStartInvokingAuthorityWatcher(
          &parentGeneration, &authorityLease)) return 70;
#endif
  return HRARunProbe(
      mode,
      &parentGeneration,
      &authorityLease,
      hostPath,
      hostileSignalLauncherPath,
      smokeRoot,
      smokeDwellMilliseconds);
}
