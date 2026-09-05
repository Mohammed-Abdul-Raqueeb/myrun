# Security model

What `myrun` protects against, how, and — just as important — what it does
not protect against.

## Threat model

The assumption is a **semi-trusted workload**: code you are willing to run
but not willing to give the host to. The container should not be able to
read host files, see or signal host processes, reconfigure host networking,
exhaust host resources, or escalate to host root through a setuid binary in
its own image.

The assumption is **not** a hostile kernel-exploit-grade adversary. A
container running as root in a shared kernel namespace is one kernel bug away
from the host. That is true of every runtime in this class; the mitigations
below raise the cost, they do not eliminate the risk. For untrusted code,
use a VM boundary.

## Layers

### 1. Namespaces

PID, mount, UTS, IPC, network and cgroup namespaces are created in a single
`clone3`. The container gets its own process table, mount tree, hostname,
IPC objects, network stack and cgroup root.

`CLONE_NEWCGROUP` matters more than it looks: without it `/sys/fs/cgroup`
inside the container exposes the host's full hierarchy, including the names
of every other container.

### 2. Filesystem

`pivot_root(".", ".")` followed by `umount2(".", MNT_DETACH)`. The host
filesystem is detached, not hidden. `chroot` is deliberately not used: it is
escapable by any process that holds a descriptor to a directory outside the
new root, and by `chroot`-ing again from a directory it still holds.

Before any of that, `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)`. Skip
it and every mount the container makes propagates to the host, because the
new namespace inherits shared propagation from systemd. This is the single
easiest way to write a container runtime that quietly modifies its host.

`/sys` is mounted read-only. `/proc` is a fresh procfs, so it reflects the new
PID namespace rather than the host's.

**Masked paths** (bind-mounted over with `/dev/null`, or an empty read-only
tmpfs for directories):

```
/proc/kcore              a readable image of kernel memory
/proc/keys               kernel keyring contents
/proc/timer_list         kernel addresses, useful for defeating KASLR
/proc/sched_debug        host process names and scheduling data
/proc/latency_stats
/proc/scsi
/sys/firmware            includes writable EFI variables on some hosts
/sys/devices/virtual/powercap    the PLATYPUS side channel
```

**Read-only paths** (`/proc/bus`, `/proc/fs`, `/proc/irq`, `/proc/sys`,
`/proc/sysrq-trigger`). `/proc/sysrq-trigger` alone is enough to reboot the
host from inside a container.

`--read-only` seals the rootfs while leaving `/tmp` and any tmpfs volumes
writable, so ordinary software still works.

### 3. Capabilities

The default set is Docker's, minus `CAP_NET_RAW`:

```
CHOWN DAC_OVERRIDE FSETID FOWNER MKNOD NET_BIND_SERVICE SETGID SETUID
SETFCAP SETPCAP NET_BIND_SERVICE SYS_CHROOT KILL AUDIT_WRITE
```

`CAP_NET_RAW` is dropped because it allows raw packet crafting and ARP
spoofing on the shared bridge — a container that can forge ARP replies can
intercept its neighbours' traffic. `ping` therefore does not work by default;
`--cap-add NET_RAW` restores it.

`CAP_SYS_ADMIN` is never in the default set. With it, a container can mount,
`setns`, and manipulate cgroups; it is close to being host root.

The drop order is: clear the ambient set, drop from the bounding set, then
`capset` the permitted/effective/inheritable sets. Dropping from the bounding
set is what makes the removal permanent — a capability absent from the
bounding set cannot be regained by any path, including a setuid-root binary
inside the container image.

### 4. no_new_privs

`PR_SET_NO_NEW_PRIVS` is set by default and cannot be unset once set. It
neutralises setuid and file-capability binaries in the rootfs, and it is what
allows a seccomp filter to be installed *without* `CAP_SYS_ADMIN`.

`--no-new-privs=false` is accepted but rejected in combination with seccomp,
because the kernel would then demand `CAP_SYS_ADMIN` — granting that to make
a sandbox work would defeat the sandbox.

### 5. Seccomp

A hand-assembled classic BPF filter (`src/sys/seccomp.rs`). Structure:

1. Load `arch`. If it is not the native architecture, `SECCOMP_RET_KILL_PROCESS`.
   On x86-64 this also rejects x32 syscall numbers (`0x40000000` and up),
   which is a well-known way to bypass a number-only filter.
2. Load `nr` and compare against the deny list.
3. Default `SECCOMP_RET_ALLOW`.

Denied by default (39 syscalls), grouped by what they would let a container
do:

- **Escape the mount namespace**: `mount`, `umount2`, `pivot_root`, `chroot`,
  `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `open_tree`
- **Cross namespaces**: `setns`, `unshare`
- **Load or modify kernel code**: `init_module`, `finit_module`,
  `delete_module`, `kexec_load`, `kexec_file_load`, `bpf`
- **Reboot or reconfigure the host**: `reboot`, `swapon`, `swapoff`,
  `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`,
  `sethostname`, `setdomainname`, `nfsservctl`, `vm86`
- **Read kernel or other processes' memory**: `kcmp`, `lookup_dcookie`,
  `perf_event_open`, `_sysctl`
- **Keyring access**: `keyctl`, `add_key`, `request_key`
- **Miscellaneous privilege**: `acct`, `ioperm`, `iopl`, `ptrace`,
  `mount_setattr`, `userfaultfd`

`--seccomp strict` additionally denies `process_vm_readv`,
`process_vm_writev` and `syslog`. `--seccomp unconfined` installs nothing.

The action for a denied syscall is `SECCOMP_RET_ERRNO(EPERM)` rather than
`KILL`, so a workload that probes for a syscall degrades gracefully instead
of dying with an unexplained `SIGSYS`.

### 6. Resource limits

cgroup v2 limits on memory, swap, CPU and process count. `pids.max` in
particular is what turns a fork bomb from a host outage into a container
that stops forking.

Processes are placed in the cgroup **at creation time** via
`CLONE_INTO_CGROUP`, not moved afterwards. The write-to-`cgroup.procs`
approach leaves a window in which the child exists outside its limits, and a
fork bomb started in that window escapes.

### 7. Binary sealing (CVE-2019-5736)

The classic runc escape: a container overwrites `/proc/self/exe` — which
points at the *host's* runtime binary — and waits for the next `exec` to run
its payload as host root.

`myrun` copies its own binary into a `memfd`, seals it with `F_SEAL_WRITE`,
`F_SEAL_SHRINK` and `F_SEAL_GROW`, and re-executes *that* descriptor with
`execveat(AT_EMPTY_PATH)`. The container can point at it all it likes; the
kernel will not let it be written. If sealing fails the runtime logs a
warning rather than silently running unprotected.

## Ordering

```
capabilities  →  no_new_privs  →  seccomp  →  setgid/setuid  →  execve
```

Every step needs the privileges the next one removes. `runtime/security.rs`
implements exactly this order, and `precheck()` runs in the CLI process so a
configuration that cannot work is rejected before anything has been created.

`verify()` re-reads `/proc/self/status` and asserts the post-conditions; the
integration suite parses `CapEff`, `NoNewPrivs` and `Seccomp` from inside a
real container rather than trusting the code path.

## What this does not protect against

- **Kernel exploits.** Shared kernel, shared attack surface.
- **The container being root.** Without user namespaces, uid 0 in the
  container is uid 0 on the host, restrained only by capabilities and
  seccomp. Use `--user` for anything that does not need root.
- **`--privileged`.** It disables capabilities, seccomp and path masking
  together. It exists for debugging the runtime itself.
- **Side channels.** Shared caches, shared CPU, timing.
- **Denial of service outside the cgroup's reach.** Inode exhaustion on a
  bind-mounted host filesystem, for example.
- **Bridge neighbours.** Containers on the same bridge can reach each other.
  There is no per-container firewall policy.

## What a user-namespace version would change

User namespaces are the significant missing layer. With them, container root
maps to an unprivileged host uid, so even a full capability set inside the
container is harmless outside it.

They were left out because they change the whole shape of the runtime rather
than adding a flag:

- Every bind mount source must be accessible to the mapped uid, or use idmapped mounts.
- `mknod` fails, so `/dev` must be built entirely from bind mounts.
- veth creation and `iptables` need privileges the mapped user does not have,
  so networking requires a setuid helper on the model of `slirp4netns` or
  `rootlesskit`.
- `/etc/subuid` and `/etc/subgid` need parsing, and `newuidmap`/`newgidmap`
  invoking, to get a usable range.

Implementing half of this would produce a runtime that looks rootless and is
not, which is worse than not offering it.
