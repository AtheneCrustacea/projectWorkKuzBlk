#include "kuzdriver_ioctl.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void print_status(int fd) {
  struct myblock_status st;
  if (ioctl(fd, MYBLOCK_IOCTL_GET_STATUS, &st) < 0) {
    perror("GET_STATUS");
    return;
  }
  printf("  locked:         %s\n", st.locked ? "yes" : "no");
  printf("  key_set:        %s\n", st.key_set ? "yes" : "no");
  printf("  crypto_enabled: %s\n", st.crypto_enabled ? "yes" : "no");
  printf("  reads:          %llu\n", (unsigned long long)st.reads);
  printf("  writes:         %llu\n", (unsigned long long)st.writes);
  printf("  bytes_read:     %llu\n", (unsigned long long)st.bytes_read);
  printf("  bytes_written:  %llu\n", (unsigned long long)st.bytes_written);
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s <device> <command>\n"
          "Commands:\n"
          "  status          show status\n"
          "  setkey          set default key (01 02 ... 20)\n"
          "  lock            lock device\n"
          "  unlock          unlock device\n"
          "  crypto-on       enable encryption/decryption\n"
          "  crypto-off      disable encryption/decryption\n",
          prog);
}

int main(int argc, char *argv[]) {
  const char *path, *cmd;
  struct myblock_key k;
  int fd, i;

  if (argc < 3) {
    usage(argv[0]);
    return 1;
  }

  path = argv[1];
  cmd = argv[2];

  fd = open(path, O_RDWR);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  if (strcmp(cmd, "status") == 0) {
    print_status(fd);
  } else if (strcmp(cmd, "setkey") == 0) {
    for (i = 0; i < 32; i++)
      k.key[i] = (unsigned char)(i + 1);
    if (ioctl(fd, MYBLOCK_IOCTL_SET_KEY, &k) < 0)
      perror("SET_KEY");
    else
      printf("[SET_KEY] ok\n");
  } else if (strcmp(cmd, "lock") == 0) {
    if (ioctl(fd, MYBLOCK_IOCTL_LOCK) < 0)
      perror("LOCK");
    else
      printf("[LOCK] ok\n");
  } else if (strcmp(cmd, "unlock") == 0) {
    if (ioctl(fd, MYBLOCK_IOCTL_UNLOCK) < 0)
      perror("UNLOCK");
    else
      printf("[UNLOCK] ok\n");
  } else if (strcmp(cmd, "crypto-on") == 0) {
    if (ioctl(fd, MYBLOCK_IOCTL_ENABLE_CRYPTO) < 0)
      perror("ENABLE_CRYPTO");
    else
      printf("[ENABLE_CRYPTO] ok\n");
  } else if (strcmp(cmd, "crypto-off") == 0) {
    if (ioctl(fd, MYBLOCK_IOCTL_DISABLE_CRYPTO) < 0)
      perror("DISABLE_CRYPTO");
    else
      printf("[DISABLE_CRYPTO] ok\n");
  } else {
    usage(argv[0]);
    close(fd);
    return 1;
  }

  close(fd);
  return 0;
}