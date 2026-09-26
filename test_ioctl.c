#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "kuzdriver_ioctl.h"

static void print_status(int fd) {
  struct myblock_status st;

  if (ioctl(fd, MYBLOCK_IOCTL_GET_STATUS, &st) < 0) {
    perror("ioctl(GET_STATUS)");
    return;
  }

  printf("  locked:        %s\n", st.locked ? "yes" : "no");
  printf("  key_set:       %s\n", st.key_set ? "yes" : "no");
  printf("  reads:         %llu\n", (unsigned long long)st.reads);
  printf("  writes:        %llu\n", (unsigned long long)st.writes);
  printf("  bytes_read:    %llu\n", (unsigned long long)st.bytes_read);
  printf("  bytes_written: %llu\n", (unsigned long long)st.bytes_written);
}

int main(int argc, char *argv[]) {
  const char *path = (argc > 1) ? argv[1] : "/dev/KuzEncDev0";
  struct myblock_key k;
  int fd, i;

  fd = open(path, O_RDWR);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  printf("=== Initial status ===\n");
  print_status(fd);

  // set key
  for (i = 0; i < 32; i++)
    k.key[i] = (unsigned char)(i + 1);

  if (ioctl(fd, MYBLOCK_IOCTL_SET_KEY, &k) < 0)
    perror("ioctl(SET_KEY)");
  else
    printf("\n[SET_KEY] ok\n");

  printf("=== After SET_KEY ===\n");
  print_status(fd);

  // block dev
  if (ioctl(fd, MYBLOCK_IOCTL_LOCK) < 0)
    perror("ioctl(LOCK)");
  else
    printf("\n[LOCK] ok\n");

  printf("=== After LOCK ===\n");
  print_status(fd);

  //unlock dev
  if (ioctl(fd, MYBLOCK_IOCTL_UNLOCK) < 0)
    perror("ioctl(UNLOCK)");
  else
    printf("\n[UNLOCK] ok\n");

  printf("=== After UNLOCK ===\n");
  print_status(fd);

  close(fd);
  return 0;
}