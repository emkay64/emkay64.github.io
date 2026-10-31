---
title:  "Getting a Root Shell on the TP-Link Archer AX18 via UART"
categories: iot
classes: wide
---

## The Device

The TP-Link Archer AX18 V1.0 (sold as the Archer AX12 in Europe) is a budget WiFi 6 router built around a Realtek RTL8197F-VG SoC. It has 128MB of RAM, 16MB of SPI NOR flash (Winbond W25Q128JVSQ), and runs Linux 4.4.176 on a MIPS 24Kc core.

The board has an unpopulated and login restricted UART header. The console identifies itself as "Akronite."

## Why UART Login Is Impossible on Stock Firmware

The UART console is configured in `/etc/inittab`:

```
ttyS0::askfirst:/bin/login
```

Busybox `login` authenticates against `/etc/shadow`, which lives in the read-only squashfs rootfs. The stock entry is:

```
root:x:0:0:99999:7:::
```

The `x` in the password field means the account is locked. No password will ever match.

TP-Link's firmware *does* have a password sync mechanism: when you set an admin password through the web UI, `accountmgnt.lua` calls `shadow_renew` to write the password hash into `/etc/shadow` on the tmpfs overlay. But `shadow_renew` is only triggered by the web UI , no boot script ever calls it. The overlay is plain tmpfs, so even if the password were synced once, it would be lost on the next reboot.

The admin password stored in the UCI config is encrypted with AES-256-CBC using a key derived from `/etc/secretkey` , a file that only exists in RAM and is generated at runtime by `crypto.lua`. It is never written to flash. Even with full access to the SPI flash dump, the admin password cannot be recovered.

In short: UART login is locked by design. The only way in is to modify the firmware.

## The Approach

The goal is simple: change one line in `/etc/inittab` from `/bin/login` to `/bin/ash`, so the UART drops straight into a root shell instead of asking for a password.

The firmware lives on a 16MB SPI NOR flash chip. The relevant partitions are:

| Partition | Offset | Size | Contents |
|-----------|--------|------|----------|
| fs-uboot | 0x00000 | 256K | Realtek bootloader |
| os-image | 0x40000 | 4M | LZMA-compressed kernel |
| file-system | 0x440000 | ~11M | SquashFS rootfs |

The rootfs is a SquashFS 4.0 image with xz (LZMA2) compression, 256KB blocks, and 256KB dictionary size.

## Reading the Flash

The flash chip is a standard SOIC-8 SPI NOR. With the router powered off, connect a CH341A USB programmer to the chip , either with a clip, test hooks, or PCBite probes on the pads. The router must be powered off; with the SoC running, it holds the SPI bus and all reads return 0xFF.

```bash
sudo flashrom -p ch341a_spi -r ax18_full_dump.bin
sudo flashrom -p ch341a_spi -r ax18_full_dump2.bin
md5sum ax18_full_dump.bin ax18_full_dump2.bin  # must match
```

Always take two reads and verify they match.

## Why You Can't Just Rebuild the SquashFS

The obvious approach is to extract the squashfs with `unsquashfs`, edit `inittab`, and rebuild with `mksquashfs`. This does not work.

The host system's `mksquashfs` (even with identical compression settings) produces a subtly different squashfs that the kernel refuses to mount. The Realtek SDK's squashfs tools produce output with specific LZMA2 encoder parameters that the kernel's decompressor expects. A rebuild from scratch is a dead end.

## Binary Patching the SquashFS

Instead of rebuilding, we patch the compressed data in place. SquashFS stores small files in "fragment blocks" , compressed chunks shared by multiple files. The process is:

### 1. Find the target fragment

Parse the squashfs superblock to locate the fragment table, then find which fragment contains `/etc/inittab`. In this firmware, it's fragment #2, stored at squashfs offset `0x1B32C`, 41,952 bytes compressed.

### 2. Decompress, patch, recompress

```python
import lzma, struct

# Read the fragment from the flash dump
with open('ax18_full_dump.bin', 'rb') as f:
    f.seek(0x440000 + 0x1B32C)  # squashfs partition + fragment offset
    fragment = f.read(41952)

# Decompress
data = bytearray(lzma.decompress(fragment, format=lzma.FORMAT_XZ))

# Patch: replace /bin/login with /bin/ash, NUL-padded to same length
pos = data.find(b'askfirst:/bin/login')
data[pos:pos+18] = b'askfirst:/bin/ash\x00\x00'

# Recompress , MUST use CRC32, not CRC64
recompressed = lzma.compress(
    bytes(data),
    format=lzma.FORMAT_XZ,
    check=lzma.CHECK_CRC32,
    filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 256*1024, 'preset': 9}]
)
```

The recompressed fragment must fit within the original 41,952 bytes. With these parameters it compresses to exactly 41,952 bytes , a perfect fit. If it were larger, you'd need `preset: 9 | lzma.PRESET_EXTREME` to squeeze it down.

### 3. Update the fragment table

The squashfs fragment table records the compressed size of each fragment. Since we changed the compressed data, we need to update fragment #2's size entry. The fragment table is itself a compressed metadata block (at squashfs offset `0x9A5DC6` in this image). Decompress it, update the 4-byte size field for entry #2, and recompress , again with `CHECK_CRC32`.

### 4. Write it back

Copy the original flash dump, overwrite the fragment data and fragment table metadata in the copy, zero-padding any leftover space.

## The CRC32 Trap

Python's `lzma.compress()` defaults to CRC64 integrity checks in the xz stream. The Linux 4.4 kernel's squashfs xz decompressor does not support CRC64 , only CRC32.

If you forget `check=lzma.CHECK_CRC32`, the firmware will boot, the kernel will find the squashfs, and then:

```
SQUASHFS error: xz decompression failed, data probably corrupt
Kernel panic - not syncing: Requested init /etc/preinit failed (error -5).
```

The xz header byte at offset 7 tells the story: `0x01` = CRC32 (works), `0x04` = CRC64 (kernel panic). This cost a full debug cycle to figure out.

## The Realtek Bootloader Checksum

The Realtek bootloader validates the squashfs before booting. If you flash a modified squashfs without updating the checksum, the bootloader prints:

```
rootfs checksum error at 00440000!
```

...and refuses to boot. The checksum algorithm, found by reverse engineering:

- Read all `bytes_used` bytes of the squashfs as big-endian 16-bit words
- Sum them modulo 65536
- The checksum is the two's complement: `(0x10000 - sum) & 0xFFFF`
- Stored as 2 bytes at the squashfs partition start + `bytes_used` padded up to the next `0x8000` boundary

In this firmware, that's flash offset `0xDE8000`. When you add the data sum and the checksum, the result is zero , a classic "sum to zero" integrity check.

```python
# Compute checksum over the modified squashfs
sqfs = image[0x440000 : 0x440000 + 0x9A73C4]  # bytes_used
word_sum = 0
for i in range(0, len(sqfs), 2):
    word_sum = (word_sum + struct.unpack('>H', sqfs[i:i+2])[0]) & 0xFFFF
checksum = (0x10000 - word_sum) & 0xFFFF

# Write at flash offset 0xDE8000
image[0xDE8000] = (checksum >> 8) & 0xFF
image[0xDE8001] = checksum & 0xFF
```

## Flashing

With the router powered off and the CH341A connected to the SPI chip:

```bash
sudo flashrom -p ch341a_spi -w ax18_patched.bin
```

Wait for `Verifying flash... VERIFIED.` , if verification fails, the probe connections are flaky. Reseat and retry. Never flash with the router powered on; the SoC and programmer will fight over the SPI bus and corrupt the write.

## The Result

Power on, connect UART at 115200 8N1, and:

```
...
Freeing unused kernel memory: 196K
/ # id
uid=0(root) gid=0(root)
```

A root shell, no password required. 

## Summary of Pitfalls

| Attempt | Result | Root Cause |
|---------|--------|------------|
| Rebuild squashfs with host mksquashfs | Kernel can't mount rootfs | Encoder incompatibility with Realtek SDK |
| Binary patch with Python default xz | Kernel panic on decompression | CRC64 check type; kernel only supports CRC32 |
| Binary patch with CRC32, no checksum fix | Bootloader rejects image | Realtek bootloader validates 16-bit rootfs checksum |
| Binary patch with CRC32 + checksum fix | Root shell achieved | All three requirements met |

## Tools Used

- **flashrom** with CH341A adapter , SPI flash read/write
- **Python 3** with `lzma` and `struct` , squashfs binary patching
- **picocom** , UART serial terminal
- **PCBite probes** , in-circuit SPI flash access (no desoldering)
