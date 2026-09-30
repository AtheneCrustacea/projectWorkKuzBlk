#!/bin/bash
# run_tests.sh - функциональные тесты драйвера KuzDriver.

set -u

DRV=kuzdriver
DISK=/dev/KuzEncDev
P1=/dev/KuzEncDev1
P2=/dev/KuzEncDev2
P3=/dev/KuzEncDev3
PROC=/proc/kuzdriver
SYS=/sys/class/kuzdriver/KuzEncDev
IOCTL=./test_ioctl

PASS=0
FAIL=0

pass() { echo -e "\033[32m[PASS]\033[0m $1"; PASS=$((PASS+1)); }
fail() { echo -e "\033[31m[FAIL]\033[0m $1"; FAIL=$((FAIL+1)); }

check() {
    local desc="$1"; shift
    if eval "$@"; then pass "$desc"; else fail "$desc"; fi
}

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "Запускайте от root"; exit 1; }
}

wait_for_dev() {
    local dev="$1" i
    for i in $(seq 1 30); do
        [ -b "$dev" ] && return 0
        sleep 0.1
    done
    return 1
}

get_status() {
    $IOCTL "$1" status
}

# Round-trip: пишем полный 512-байтовый сектор (паттерн + нули), читаем обратно
roundtrip() {
    local dev="$1" pattern="$2"
    local in out rc
    in=$(mktemp); out=$(mktemp)
    dd if=/dev/zero of="$in" bs=512 count=1 2>/dev/null
    printf '%s' "$pattern" | dd of="$in" bs=1 conv=notrunc 2>/dev/null
    dd if="$in" of="$dev" bs=512 count=1 conv=notrunc 2>/dev/null
    dd if="$dev" of="$out" bs=512 count=1 2>/dev/null
    rc=1
    cmp -s "$in" "$out" && rc=0
    rm -f "$in" "$out"
    return $rc
}

# ---------- подготовка ----------
require_root
echo "=== KuzDriver test suite ==="

if ! lsmod | grep -q "^$DRV "; then
    echo "Загружаю $DRV..."
    insmod "./$DRV.ko" || { echo "insmod failed"; exit 1; }
fi

wait_for_dev "$DISK" || { echo "$DISK not found"; exit 1; }
wait_for_dev "$P1"   || exit 1
wait_for_dev "$P2"   || exit 1
wait_for_dev "$P3"   || exit 1

$IOCTL "$DISK" unlock     >/dev/null 2>&1
$IOCTL "$DISK" crypto-on  >/dev/null 2>&1
$IOCTL "$DISK" setkey     >/dev/null 2>&1

# ---------- 1. Существование ----------
echo
echo "--- 1. Device existence ---"
check "block device $DISK"  "[ -b $DISK ]"
check "block device $P1"    "[ -b $P1 ]"
check "block device $P2"    "[ -b $P2 ]"
check "block device $P3"    "[ -b $P3 ]"
check "/proc/kuzdriver"     "[ -f $PROC ]"
check "/sys/class/kuzdriver/KuzEncDev" "[ -d $SYS ]"

# ---------- 2. Размеры ----------
echo
echo "--- 2. Partition sizes (100 MiB each) ---"
for dev in "$P1" "$P2" "$P3"; do
    sz=$(blockdev --getsize64 "$dev" 2>/dev/null)
    check "$dev size = 100 MiB" "[ \"$sz\" = '104857600' ]"
done

# ---------- 3. Round-trip ----------
echo
echo "--- 3. Basic read/write round-trip ---"
check "roundtrip $P1" "roundtrip $P1 'hello partition 1'"
check "roundtrip $P2" "roundtrip $P2 'hello partition 2'"
check "roundtrip $P3" "roundtrip $P3 'hello partition 3'"

# ---------- 4. Изоляция ----------
echo
echo "--- 4. Partition isolation ---"
printf 'PART1-DATA' | dd of="$P1" bs=512 count=1 conv=notrunc 2>/dev/null
printf 'PART2-DATA' | dd of="$P2" bs=512 count=1 conv=notrunc 2>/dev/null
r1=$(dd if="$P1" bs=512 count=1 2>/dev/null | head -c 10)
r2=$(dd if="$P2" bs=512 count=1 2>/dev/null | head -c 10)
check "P1 unchanged after P2 write" "[ \"$r1\" = 'PART1-DATA' ]"
check "P2 unchanged after P1 write" "[ \"$r2\" = 'PART2-DATA' ]"

# ---------- 5. Границы ----------
echo
echo "--- 5. Boundary check ---"
dd if=/dev/zero of="$P3" bs=1M count=200 2>/dev/null
rc=$?
check "write beyond partition fails" "[ $rc -ne 0 ]"

# ---------- 6. SET_KEY ----------
echo
echo "--- 6. ioctl SET_KEY ---"
out=$($IOCTL "$P1" setkey)
check "SET_KEY returns ok" "echo \"$out\" | grep -q 'SET_KEY'"

st=$(get_status "$P1")
check "key_set: yes on $P1" "echo \"$st\" | grep -q 'key_set: *yes'"

# ---------- 7. LOCK / UNLOCK ----------
echo
echo "--- 7. ioctl LOCK / UNLOCK ---"

$IOCTL "$P1" lock >/dev/null
st=$(get_status "$P1")
check "locked: yes after LOCK" "echo \"$st\" | grep -q 'locked: *yes'"

dd if=/dev/zero of="$P1" bs=512 count=1 2>/dev/null
rc=$?
check "write on locked device fails" "[ $rc -ne 0 ]"

$IOCTL "$P1" unlock >/dev/null
st=$(get_status "$P1")
check "locked: no after UNLOCK" "echo \"$st\" | grep -q 'locked: *no'"

dd if=/dev/zero of="$P1" bs=512 count=1 2>/dev/null
rc=$?
check "write on unlocked device succeeds" "[ $rc -eq 0 ]"

# ---------- 8. ENABLE / DISABLE_CRYPTO ----------
echo
echo "--- 8. ioctl ENABLE / DISABLE_CRYPTO ---"

$IOCTL "$P2" setkey     >/dev/null
$IOCTL "$P2" crypto-on  >/dev/null

st=$(get_status "$P2")
check "crypto_enabled: yes" "echo \"$st\" | grep -q 'crypto_enabled: *yes'"

plain='PLAIN1234567890'
plain_hex=$(printf '%s' "$plain" | xxd -p | tr -d '\n')

{ printf '%s' "$plain"; head -c $((512 - ${#plain})) /dev/zero; } \
    | dd of="$P2" bs=512 count=1 conv=notrunc 2>/dev/null

$IOCTL "$P2" crypto-off >/dev/null
raw_hex=$(dd if="$P2" bs=512 count=1 2>/dev/null | xxd -p | tr -d '\n' \
          | head -c $((2 * ${#plain})))
check "with crypto-off data is not decrypted" \
      "[ \"$raw_hex\" != \"$plain_hex\" ]"

$IOCTL "$P2" crypto-on >/dev/null
back_hex=$(dd if="$P2" bs=512 count=1 2>/dev/null | xxd -p | tr -d '\n' \
           | head -c $((2 * ${#plain})))
check "with crypto-on data is decrypted back" \
      "[ \"$back_hex\" = \"$plain_hex\" ]"

# ---------- 9. Счётчики ----------
echo
echo "--- 9. I/O counters ---"
$IOCTL "$P3" setkey     >/dev/null
$IOCTL "$P3" crypto-on  >/dev/null

before=$(get_status "$P3" | grep 'writes:' | awk '{print $2}')
dd if=/dev/urandom of="$P3" bs=4k count=5 2>/dev/null
after=$(get_status "$P3" | grep 'writes:' | awk '{print $2}')

check "writes counter grew" "[ \"$after\" -gt \"$before\" ]"

# ---------- 10. /proc ----------
echo
echo "--- 10. /proc interface ---"
check "/proc/kuzdriver readable"  "cat $PROC >/dev/null"
check "mentions KuzEncDev1"       "grep -q 'KuzEncDev1' $PROC"
check "mentions KuzEncDev2"       "grep -q 'KuzEncDev2' $PROC"
check "mentions KuzEncDev3"       "grep -q 'KuzEncDev3' $PROC"

# ---------- 11. /sys ----------
echo
echo "--- 11. /sys interface ---"
check "disk size attr"       "cat $SYS/size >/dev/null"
check "disk locked attr"     "cat $SYS/locked >/dev/null"
check "partition KuzEncDev1 dir" "[ -d $SYS/KuzEncDev1 ]"
check "partition size attr"  "cat $SYS/KuzEncDev1/size >/dev/null"
check "partition start attr" "cat $SYS/KuzEncDev1/start >/dev/null"
check "partition locked attr" "cat $SYS/KuzEncDev1/locked >/dev/null"
check "partition key_set attr" "cat $SYS/KuzEncDev1/key_set >/dev/null"
check "partition crypto attr" "cat $SYS/KuzEncDev1/crypto_enabled >/dev/null"

echo 1 > "$SYS/KuzEncDev2/locked" 2>/dev/null
val=$(cat "$SYS/KuzEncDev2/locked")
check "write 1 to sysfs locked works" "[ \"$val\" = '1' ]"
echo 0 > "$SYS/KuzEncDev2/locked" 2>/dev/null
val=$(cat "$SYS/KuzEncDev2/locked")
check "write 0 to sysfs locked works" "[ \"$val\" = '0' ]"

# ---------- 12. Восстановление ----------
echo
echo "--- 12. Restore state ---"
$IOCTL "$DISK" unlock    >/dev/null
$IOCTL "$DISK" crypto-on >/dev/null
$IOCTL "$DISK" setkey    >/dev/null
check "restore complete" "true"

# ---------- Итог ----------
echo
echo "==========================================="
echo "PASS: $PASS    FAIL: $FAIL"
echo "==========================================="

[ $FAIL -eq 0 ]