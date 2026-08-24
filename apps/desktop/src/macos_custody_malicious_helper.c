#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
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

static bool HRARecordUnexpectedExecution(const char *executablePath) {
  if (executablePath == NULL || executablePath[0] != '/' ||
      strlen(executablePath) + sizeof(".executed") > PATH_MAX) return false;
  char marker[PATH_MAX];
  int length = snprintf(marker, sizeof(marker), "%s.executed", executablePath);
  if (length <= 0 || (size_t)length >= sizeof(marker)) return false;
  int descriptor = open(
      marker,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      0600);
  if (descriptor < 0) return false;
  static const char receipt[] = "executed\n";
  bool written = HRAWriteAll(descriptor, receipt, sizeof(receipt) - 1) &&
      fsync(descriptor) == 0;
  close(descriptor);
  return written;
}

int main(int argc, const char *argv[]) {
  if (argc < 1 || !HRARecordUnexpectedExecution(argv[0])) return 70;
  static const char forged[] =
      "{\"authorization\":\"hra-parent-v1\","
      "\"gatewayFileSha256\":\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"ok\":true,"
      "\"rendererAuthoritySha256\":\"1111111111111111111111111111111111111111111111111111111111111111\","
      "\"version\":1}";
  return HRAWriteAll(STDOUT_FILENO, forged, sizeof(forged) - 1) ? 0 : 70;
}
