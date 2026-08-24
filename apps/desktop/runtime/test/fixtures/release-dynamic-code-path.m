#import "macos_self_managed_code_identity.h"

#import <errno.h>
#import <limits.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

static bool HRAParseLowerHexHash(
    const char *text,
    uint8_t outHash[HRA_MACOS_CDHASH_LENGTH]) {
  if (text == NULL || strlen(text) != HRA_MACOS_CDHASH_LENGTH * 2) {
    return false;
  }
  for (size_t index = 0; index < HRA_MACOS_CDHASH_LENGTH; index += 1) {
    unsigned int value = 0;
    char pair[3] = {text[index * 2], text[index * 2 + 1], '\0'};
    if (!((pair[0] >= '0' && pair[0] <= '9') ||
          (pair[0] >= 'a' && pair[0] <= 'f')) ||
        !((pair[1] >= '0' && pair[1] <= '9') ||
          (pair[1] >= 'a' && pair[1] <= 'f')) ||
        sscanf(pair, "%2x", &value) != 1 || value > UINT8_MAX) {
      return false;
    }
    outHash[index] = (uint8_t)value;
  }
  return true;
}

int main(int argc, const char *argv[]) {
  if (argc != 6) return 64;
  errno = 0;
  char *processEnd = NULL;
  long rawProcess = strtol(argv[1], &processEnd, 10);
  if (errno != 0 || processEnd == NULL || *processEnd != '\0' ||
      rawProcess <= 1 || rawProcess > INT_MAX) return 64;
  errno = 0;
  char *flagsEnd = NULL;
  unsigned long rawFlags = strtoul(argv[5], &flagsEnd, 10);
  if (errno != 0 || flagsEnd == NULL || *flagsEnd != '\0' ||
      rawFlags > UINT32_MAX) return 64;
  uint8_t cdHash[HRA_MACOS_CDHASH_LENGTH];
  memset(cdHash, 0, sizeof(cdHash));
  bool exact = HRAParseLowerHexHash(argv[4], cdHash) &&
      hra_macos_self_managed_dynamic_code_matches(
          (pid_t)rawProcess,
          argv[2],
          strlen(argv[2]),
          argv[3],
          strlen(argv[3]),
          cdHash,
          (uint32_t)rawFlags);
  memset(cdHash, 0, sizeof(cdHash));
  if (!exact) return 70;
  fputs("{\"ok\":true,\"version\":1}\n", stdout);
  return 0;
}
