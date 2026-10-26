# KVM/QEMU isolation backend

A real virtual machine: its own kernel, so a guest bugcheck, panic or crash loop
cannot touch the host. This is the strongest boundary the sandbox offers, and the
cheapest one to reset - every run gets a fresh disk that is deleted when the VM
exits, so "reset" is not an action you perform, it is the default.

Measured on a KVM host with a Debian 12 guest (4 GB / 4 vCPU): **8.3 s** for a trivial
payload, ~25-35 s for a Windows PE under wine (the first `wine` run builds its prefix).

## Install

```bash
sudo apt-get install -y qemu-system-x86 qemu-utils genisoimage
```

`/dev/kvm` must exist and be readable/writable by your user. Check:

```bash
python3 -m sandbox.capabilities
```

## Build the guest (one time)

```bash
./sandbox/kvm/provision-guest.sh ~/bobbypin-vm
python3 -c "from sandbox.config import set_value; set_value('kvm.base_image', \
  '$HOME/bobbypin-vm/base.qcow2')"
```

The script downloads the Debian cloud image (~330 MB), resizes it to 12 GB virtual,
and boots it once to install `qemu-guest-agent`, wine and `wine32` over cloud-init
(`cloud-init-user-data.yaml`), then powers the guest off. Result: a ~2 GB frozen
template.

`wine32` matters: most licence-guarded Windows targets are still win32, and a
64-bit-only wine cannot run them at all. It needs `dpkg --add-architecture i386`
first, which is why that step lives in `runcmd` rather than the `packages:` list.

The guest is deliberately **empty** - no user data, no credentials, no host
identity. Do not clone a working machine into this role: the whole point is that
nothing worth stealing is inside the boundary.

## What every run guarantees

| | |
|---|---|
| separate kernel | guest panic/bugcheck cannot reach the host |
| ephemeral disk | fresh qcow2 overlay per run on the base image; the base is **never** handed to QEMU - it is only ever the overlay's backing file - and the overlay is unlinked afterwards |
| `-no-reboot` | a bugcheck halts the VM instead of restarting into a crash loop |
| no egress | `-netdev user,id=n0,restrict=on` with zero port forwards: the guest cannot reach the host or the internet. Verified from *inside* the guest each run |
| headless | `-display none`, serial to `<workdir>/serial.log`, QEMU stderr to its own log |
| crash detection | `serial.log` + QEMU stderr are scanned by `sandbox.bsod`; a bugcheck/panic/halt sets `bsod_suspected` and lands in the record's warnings |
| read-only bait | honeypots shared in `readonly=on`, then copied inside the guest (manifest stripped) so the target meets them in a normal place |
| wall clock | the payload budget is enforced; an unresponsive guest is torn down after a short shutdown grace period |

## How execution works

The backend talks to `qemu-guest-agent` over the virtio-serial socket:

1. wait for `guest-ping` to answer
2. `mkdir` + mount the 9p shares: `target` -> `/in`, `honeypots` -> `/honeypots`,
   `out` -> `/out` (the payload path matches the container backend: `/in/<name>`)
3. stage the bait: copy `/honeypots/.` into `/root/`, dropping the manifest
4. run the payload with `guest-exec`, poll `guest-exec-status` for output and exit code
5. `guest-shutdown` (`mode: powerdown`) and wait out a short grace period
6. audit the honeypot root on the host for leaks into `/out`

Two pitfalls worth knowing, both hit in practice:

- **Use `guest-shutdown`, not `system_powerdown`.** The latter is a QMP monitor
  command; qemu-ga answers `CommandNotFound` and the VM keeps running until the
  grace period expires. That mistake cost 45 s per run until it was found.
- **The payload budget is not the shutdown budget.** Waiting `timeout_s` for the
  guest to power off makes every run as slow as its timeout. `shutdown_grace_s`
  (default 20 s) bounds the teardown; after that the VM is terminated.

## Guest-side notes

- The `linux` honeypot profile is the one that fits this guest. The `windows`
  profile is for a Windows guest (or wine's `drive_c`), and the paths still land
  under `/root/` here.
- The guest runs the payload as root, as qemu-ga does. That is deliberate: the
  target gets the run of a machine that is about to be deleted, and cannot reach
  anything that matters.
- The VM's filesystem is writable (it is an overlay, not a read-only rootfs).
  Container-style `rootfs_verified` does not apply here; the guarantee is the
  ephemeral disk, and `containment.disk` says so.

## Windows guest (native PE execution)

For targets that need real Windows — .NET, installers, anti-debug that trips on wine, and
anything whose failure mode is a bugcheck — there is a second, cleanly built template. It is
**not** an interactive workstation: no user profile, no credentials, no saved anything.

```bash
cd ~/bobbypin-vm/windows          # compose.yml + oem/install.bat live here
docker compose up -d              # unattended install, ~20 min, then it powers down
# when the log settles, stop it and point the backend at its disk:
docker compose down
python3 -c "from sandbox.config import set_value; \
  set_value('kvm.base_image', '$HOME/bobbypin-vm/windows/data/data.img')"
```

The guest needs the **QEMU guest agent**, and the usual way to get it — reading the MSI off
a virtio-win CD — does not work here: dockurr injects drivers from its own pack and never
attaches that CD. Ship the MSI in `./oem` instead (it is copied to `C:\OEM` too):

```bash
curl -fL -o virtio-win.iso \
  https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
7z x virtio-win.iso guest-agent/qemu-ga-x86_64.msi    # ~12 MB
cp guest-agent/qemu-ga-x86_64.msi oem/
```

What the compose does:

- `VERSION: "11l"` — Windows 11 Enterprise LTSC evaluation: lean, no Store/Cortana bloat,
  runs any Win32 PE, small attack surface.
- `DISK_SIZE: "40G"` — Windows 11 24H2+ refuses to install on less than 32 GB.
- `./oem:/oem` — copied to `C:\OEM` in the guest; `install.bat` runs during setup and does
  the three things an analysis guest needs:
  1. installs the QEMU guest agent (from the virtio CD) — this is how the backend drives it
  2. configures crash handling: `bcdedit /debug off`, `AutoReboot=1`,
     `CrashDumpEnabled=3` (small memory dump). Kernel debug over the serial port is the
     obvious way to capture a bugcheck and it **does not work here**: with no debugger
     attached at the other end, Windows waits for one forever, so the guest just goes quiet
     and never writes a dump you can reach. Measured that the hard way. A minidump plus an
     automatic restart gives the sandbox both the restart signal and the bugcheck code.
  3. disables boot recovery, so a crash is not swallowed by a repair screen
- `RAM_CHECK: "N"` — dockurr's allocator reads host availability and then decides it can only
  spare 1.9 GB (under Windows' 2 GB floor) and refuses to start. If you see that error and
  the host genuinely has the memory, this is the escape hatch; state `RAM_SIZE` explicitly.
  (In practice the install also wanted ~3 GB of headroom on this host — an idle 3 GB VM was
  stopped for the duration and restarted afterwards.)

### Crash evidence, measured

A fixture that bugchecks on debugger detection, run natively in this guest:

```
crashed: True | bsod_suspected: True | abnormal_exit: True
boot_cycles: 2 | guest_restarted: True
bugcheck: 0xef CRITICAL_PROCESS_DIED     <- read from the minidump
observed: the protection TRIPPED and the response was a bugcheck - the guest crashed and
          restarted itself mid-run; the host never noticed.
```

Two things make that work, and both are load-bearing:

- **Do not enable kernel debug.** It hides the crash (`-no-reboot` would then kill the VM at
  the moment of the bugcheck; without it the guest hangs waiting for a debugger that is not
  there). Let the guest write a dump and restart instead.
- **The restart is detected from the boot record, not from the guest.** `sandbox.bsod`
  counts UEFI/BIOS boot banners in `serial.log`: two cycles in one run means the machine
  went down and came back. That witness exists whether or not the agent survives, which
  matters because the agent is exactly what dies.

The bugcheck *code* comes from the dump. The human-readable `*** STOP:` banner is produced
by a debugger, not by the crashed machine, so the dump header is the only honest source:
`DUMP_HEADER64` carries the code at 0x38 and four parameters from 0x40.
`bsod.parse_minidump()` reads it, and the dump itself is kept in `<workdir>/crash/`.

Then the backend boots that disk per run, exactly like the Debian guest: fresh qcow2 overlay
on a base that is only ever opened read-only, no network, no shared folders, disk discarded at
the end. Two things differ and are handled automatically: the disk is **raw** (the overlay
records `-F raw`), and the firmware is **OVMF** (the `windows.vars` NVRAM is copied per run so
the template keeps its boot entries and no run inherits another's).

Overrides, if a future guest needs them: `kvm.firmware` (`bios`/`uefi`),
`kvm.firmware_code`, `kvm.firmware_vars`, `kvm.disk_bus` (`virtio-blk`/`virtio-scsi`).

## Notes on the Linux guest

Anything QEMU boots works, and a Windows guest is the right call when the target
needs native fidelity (wine struggles with .NET, installers, anti-debug tricks).
Build it **clean and dedicated** through dockurr/windows into its own data
directory, then use the resulting disk as `base.qcow2` - the same overlay machinery
applies unchanged.

Do not point the backend at your interactive RDP workstation VM: it holds your
profile and credentials, reverting it means copying a 25 GB image, and its egress
is open by design. That is the opposite of a throwaway analysis box.
