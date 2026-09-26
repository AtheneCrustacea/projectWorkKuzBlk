!#/bin/bash

sudo python3 -c "
import fcntl, struct
fd = open('/dev/KuzEncDev0', 'r+b')
# _IO('M', 2) = 0x4D02 (для LOCK)
fcntl.ioctl(fd, 0x4D02)
print('locked')
"

sudo dd if=/dev/zero of=/dev/KuzEncDev0 bs=512 count=1

# Разблокируем
sudo python3 -c "
import fcntl
fd = open('/dev/KuzEncDev0', 'r+b')
fcntl.ioctl(fd, 0x4D03)  # UNLOCK
print('unlocked')
"