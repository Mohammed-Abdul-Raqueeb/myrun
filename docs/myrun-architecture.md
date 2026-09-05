# `myrun` — A Mini Linux Container Runtime From Scratch

**Design document, architecture, and incremental implementation plan.**

This document covers everything you asked for before any code gets written: architecture, diagrams, lifecycles, state machine, repo layout, testing strategy, failure analysis, milestones, benchmarks, and interview prep. Implementation happens milestone by milestone after this.

---

## 0. Before anything: environment and language

### 0.1 Environment

Do **not** develop this on WSL2 or a Mac. You will waste days on kernel differences.

Use a real Linux VM you fully control:

```
Ubuntu 24.04 or Fedora 40+ VM (multipass, Vagrant+libvirt, or plain QEMU)
Kernel >= 5.19  (you want mount_setattr, clone3, pidfd, cgroup v2 by default)
Root access
Snapshot the VM before every milestone — you WILL wedge the mount table
```

Verify your baseline:

```bash
uname -r
stat -fc %T /sys/fs/cgroup/          # must print: cgroup2fs
cat /proc/self/uid_map
sysctl kernel.unprivileged_userns_clone
```

If `/sys/fs/cgroup` is `tmpfs`, you are on cgroup v1 hybrid. Boot with `systemd.unified_cgroup_hierarchy=1`. **Target cgroup v2 only.** v1 support doubles your cgroup code and teaches you a deprecated API.

### 0.2 Language: pick Rust

Both work, but they teach different things.

| | Rust | Go |
|---|---|---|
| `clone(2)` with namespace flags | Direct, you control the child | Blocked — Go runtime is multithreaded before `main()` |
| Standard workaround | None needed | Re-exec `/proc/self/exe` with `SysProcAttr.Cloneflags` |
| `setns()` for mount ns | Works | Needs `runtime.LockOSThread()`, and mount-ns setns from a threaded process is unreliable |
| Post-`fork` safety | You must obey async-signal-safety, but you can stay single-threaded | Cannot; runtime threads exist |
| Netlink ergonomics | `rtnetlink` crate, decent | `vishvananda/netlink`, excellent |
| What you learn | The actual kernel contract | How runtimes work around a runtime |

**Recommendation: Rust.** The Go workaround (re-exec) is exactly what runc does and is genuinely interesting, but it *hides* the `clone` flag semantics behind `os/exec`, and the whole point of project #6 is to not hide those. In Rust you call `clone3(2)` yourself and see `CLONE_NEWPID` do its thing.

Crate set (thin bindings only, no runtime wrapping):

```toml
nix          = "0.29"   # typed syscall wrappers: mount, pivot_root, clone, waitpid, signals
libc         = "0.2"    # raw syscalls where nix has no wrapper (clone3, mount_setattr)
rtnetlink    = "0.14"   # netlink; alternative: hand-rolled NETLINK_ROUTE sockets
tokio        = "1"      # ONLY if you go async for netlink; sync is fine
caps         = "0.5"    # capability set manipulation (or call capset yourself)
seccompiler  = "0.4"    # BPF program assembly for seccomp
serde/serde_json, clap, thiserror, tracing
```

Rule you should enforce on yourself: **a crate is allowed if it is a typed wrapper over a syscall you could have called directly, and forbidden if it implements the concept for you.** `nix::mount` — fine. A crate called `container-rs` — not fine.

---

## 1. Design principles

1. **Two binaries in one.** `myrun` is both the host-side runtime and the in-container `init`. The in-container side is reached via a hidden subcommand (`myrun __init`) or, better, via `clone()` from the parent so no re-exec of the runtime is needed at all.
2. **Explicit failure ordering.** Every setup step pushes an undo closure onto a rollback stack. Any error unwinds it. Half-created containers must leave zero host state.
3. **The kernel is the source of truth, the state file is a cache.** Never trust `state.json` about whether a container is alive. Verify against `/proc/<pid>` and the process start time.
4. **`create` and `start` are separate.** This is not bureaucracy — it is how you get a container that is fully set up (namespaces, cgroups, network) but has not yet executed user code. That window is where you attach, inspect, and configure. It also makes teardown testing sane.
5. **No shelling out in the final version.** You may shell out to `ip` in milestone 7a to get connectivity working, but milestone 7b replaces it with netlink. Same for `mount` — always the syscall, never the binary.

---

## 2. Complete architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              HOST USER SPACE                             │
│                                                                          │
│  ┌────────────┐                                                          │
│  │  CLI layer │  clap parsing, output formatting, exit codes             │
│  └─────┬──────┘                                                          │
│        │ Command objects (RunSpec, ContainerId, ...)                     │
│  ┌─────▼──────────────────────────────────────────────────────────────┐  │
│  │                          RUNTIME FACADE                            │  │
│  │  Orchestrates managers. Owns the rollback stack. Owns ordering.    │  │
│  └─┬────┬────┬────┬────┬────┬────┬────┬───────────────────────────────┘  │
│    │    │    │    │    │    │    │    │                                  │
│  ┌─▼──┐┌▼───┐┌▼──┐┌▼──┐┌▼──┐┌▼──┐┌▼──┐┌▼─────┐                           │
│  │Life││Name││FS ││Cgr││Net││Pro││Sec││Stats │                           │
│  │cycl││spac││Mgr││oup││Mgr││c  ││Mgr││Coll  │                           │
│  │ Mgr││e   ││   ││Mgr││   ││Mgr││   ││ector │                           │
│  └─┬──┘└─┬──┘└─┬─┘└─┬─┘└─┬─┘└─┬─┘└─┬─┘└──┬───┘                           │
│    │     │     │    │    │    │    │     │                               │
│  ┌─▼─────▼─────▼────▼────▼────▼────▼─────▼───┐                           │
│  │              STATE STORE                  │  /run/myrun/<id>/         │
│  │  flock + atomic rename + liveness probe   │                           │
│  └───────────────────────────────────────────┘                           │
└──────────┬────────────────────────────┬──────────────────────────────────┘
           │ syscalls                   │ sync socketpair (SOCK_SEQPACKET)
           │                            │
┌──────────▼────────────────────────────▼──────────────────────────────────┐
│                          LINUX KERNEL                                    │
│  clone3 · unshare · setns · mount · pivot_root · mount_setattr           │
│  cgroup2 fs · rtnetlink · capset · prctl · seccomp · pidfd · signalfd     │
└──────────┬───────────────────────────────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────────────────────────────┐
│                   CONTAINER (new PID/MNT/UTS/IPC/NET ns)                 │
│                                                                          │
│   PID 1: myrun-init  ── forks ──▶  PID 2: user command (/bin/sh)         │
│   · waits on sync socket           · full rootfs view via pivot_root     │
│   · reaps orphans (SIGCHLD loop)   · restricted caps, no_new_privs       │
│   · forwards signals               · eth0 from veth peer                 │
│   · execs into fifo-gated start    · limited by cgroup /myrun/<id>       │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Component responsibilities

| Component | Owns | Does NOT own |
|---|---|---|
| **CLI** | Arg parsing, human/JSON output, process exit code mapping | Any syscall |
| **Runtime facade** | Step ordering, rollback stack, error → exit-code mapping | Any single mechanism |
| **Lifecycle manager** | State machine transitions, `create`/`start`/`stop`/`kill`/`delete` semantics, the start FIFO | How a namespace is made |
| **Namespace manager** | `clone3` flag assembly, `setns`, namespace fd persistence (bind-mounts of `/proc/<pid>/ns/*`) | Mounting anything inside |
| **Filesystem manager** | Propagation flags, bind mounts, `pivot_root`, `/proc` `/sys` `/dev`, read-only remount, masked paths | Namespace creation |
| **Cgroup manager** | Path allocation under `/sys/fs/cgroup/myrun/`, `subtree_control`, limit writes, freeze, delete | Reading stats (that's Stats) |
| **Network manager** | Bridge, veth pair, netns placement, addressing, routes, NAT, port maps | Netns creation |
| **Process manager** | `clone3`, sync protocol, `waitpid`/`pidfd`, signal delivery, exit-code decoding, zombie policy | Namespace flags |
| **Security manager** | Capability sets, `no_new_privs`, seccomp filter, masked/ro paths policy | Applying mounts (asks FS mgr) |
| **Stats collector** | `cpu.stat`, `memory.current`, `pids.current`, `/proc/net/dev` inside netns | Enforcing limits |
| **State store** | Serialization, locking, liveness verification, GC of dead entries | Any decision about lifecycle |

---

## 3. Repository structure

```
myrun/
├── Cargo.toml
├── README.md
├── docs/
│   ├── architecture.md            # this file, trimmed
│   ├── syscalls.md                # the syscall inventory table (section 12)
│   ├── security-model.md
│   ├── networking.md
│   └── diagrams/*.svg             # export the ASCII diagrams properly
├── src/
│   ├── main.rs                    # thin: parse, dispatch, map error->exit code
│   ├── cli/
│   │   ├── mod.rs
│   │   ├── args.rs                # clap definitions
│   │   └── output.rs              # table + JSON formatting
│   ├── config/
│   │   ├── mod.rs
│   │   ├── spec.rs                # ContainerSpec (the merged CLI + file config)
│   │   └── file.rs                # TOML/JSON config loading + validation
│   ├── runtime/
│   │   ├── mod.rs                 # the facade
│   │   └── rollback.rs            # Vec<Box<dyn FnOnce()>> unwind stack
│   ├── container/
│   │   ├── mod.rs
│   │   ├── state.rs               # State enum + legal transitions
│   │   ├── lifecycle.rs           # create/start/stop/kill/delete/inspect/list
│   │   └── init.rs                # THE IN-CONTAINER SIDE. runs as PID 1.
│   ├── namespaces/
│   │   ├── mod.rs
│   │   ├── flags.rs               # CLONE_* assembly + validation
│   │   └── persist.rs             # bind-mount /proc/<pid>/ns/net etc.
│   ├── fs/
│   │   ├── mod.rs
│   │   ├── pivot.rs               # the pivot_root dance
│   │   ├── mounts.rs              # /proc /sys /dev /dev/pts /dev/shm
│   │   ├── readonly.rs            # mount_setattr AT_RECURSIVE
│   │   └── masked.rs              # /proc/kcore etc.
│   ├── cgroups/
│   │   ├── mod.rs
│   │   ├── v2.rs                  # path mgmt, subtree_control, writes
│   │   └── limits.rs              # "256m" -> 268435456, "1.5" -> "150000 100000"
│   ├── network/
│   │   ├── mod.rs
│   │   ├── bridge.rs
│   │   ├── veth.rs
│   │   ├── addr.rs                # IPAM: allocate from 172.18.0.0/16
│   │   ├── routes.rs
│   │   └── nat.rs                 # nftables rules for MASQUERADE + DNAT
│   ├── process/
│   │   ├── mod.rs
│   │   ├── spawn.rs               # clone3 wrapper
│   │   ├── sync.rs                # parent<->init SOCK_SEQPACKET protocol
│   │   ├── reaper.rs              # SIGCHLD loop for PID 1
│   │   └── signals.rs             # signalfd, forwarding, exit-code decode
│   ├── security/
│   │   ├── mod.rs
│   │   ├── caps.rs
│   │   ├── seccomp.rs
│   │   └── prctl.rs               # no_new_privs, PDEATHSIG
│   ├── stats/
│   │   ├── mod.rs
│   │   └── collect.rs
│   ├── state/
│   │   ├── mod.rs
│   │   ├── store.rs               # /run/myrun/<id>/state.json
│   │   └── lock.rs                # flock wrapper
│   └── error.rs                   # thiserror enum -> stable exit codes
├── tests/
│   ├── common/mod.rs              # fixtures, root guard, rootfs setup
│   ├── it_pid_isolation.rs
│   ├── it_mount_isolation.rs
│   ├── it_uts_ipc.rs
│   ├── it_network.rs
│   ├── it_cgroups.rs
│   ├── it_lifecycle.rs
│   ├── it_signals.rs
│   ├── it_security.rs
│   └── it_failures.rs
├── scripts/
│   ├── make-rootfs.sh             # busybox static + alpine minirootfs
│   ├── bench.sh
│   └── leakcheck.sh               # asserts zero leaked netns/veth/cgroup/mounts
└── examples/
    ├── minimal.toml
    └── full.toml
```

**Anti-monolith rule:** no file over ~400 lines. If `lifecycle.rs` grows, the state machine wants to move out. If `init.rs` grows, the setup sequence wants to become a list of `Step` objects.

### 3.1 Getting a rootfs (without Docker as a runtime)

You need a root filesystem. Three legitimate options:

```bash
# A. busybox static — smallest, best for milestones 1-4
mkdir -p rootfs/{bin,proc,sys,dev,tmp,etc}
curl -Lo rootfs/bin/busybox https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
chmod +x rootfs/bin/busybox
for a in sh ls cat ps mount hostname sleep ping ip; do ln -s busybox rootfs/bin/$a; done

# B. alpine minirootfs tarball — real distro, apk works
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz
mkdir alpine && tar -xzf alpine-minirootfs-*.tar.gz -C alpine

# C. debootstrap — heavyweight, closest to a real distro
sudo debootstrap --variant=minbase noble ./ubuntu-rootfs
```

Option B for most work. Note that using `docker export` to *obtain a tarball* is not "using Docker as the runtime" — but avoid it anyway so nobody in an interview raises an eyebrow.

---

## 4. Namespace architecture

### 4.1 The five namespaces and what each actually does

| Namespace | Flag | Isolates | Applies to caller on `unshare`? | Gotcha |
|---|---|---|---|---|
| PID | `CLONE_NEWPID` | PID number space, process visibility | **No** — only future children | The first process in the ns is PID 1 and gets special signal semantics. If it dies, kernel `SIGKILL`s the whole namespace. |
| Mount | `CLONE_NEWNS` | Mount table | Yes | Inherits a *copy* of the parent table, and mounts may be **shared** (propagate back to host). You must set `MS_REC\|MS_PRIVATE` on `/` first. |
| UTS | `CLONE_NEWUTS` | hostname, domainname | Yes | Trivial. Good first milestone. |
| IPC | `CLONE_NEWIPC` | SysV IPC, POSIX msg queues | Yes | Hard to demo without `ipcmk`/`ipcs`. |
| Network | `CLONE_NEWNET` | Interfaces, routes, netfilter, sockets, `/proc/net` | Yes | Starts with only `lo`, and `lo` is **DOWN**. Container has zero connectivity until you build a veth. |
| (User) | `CLONE_NEWUSER` | UID/GID mapping, capabilities | Yes | Stretch goal. Enables rootless. Must be created **first** if used. |

### 4.2 Creation order

```
                        parent (myrun, running as root)
                             │
                             │ socketpair(AF_UNIX, SOCK_SEQPACKET)  ── sync channel
                             │ pidfd requested via CLONE_PIDFD
                             ▼
        clone3(flags = CLONE_NEWUSER?          ← if rootless: FIRST, alone
                     | CLONE_NEWNS
                     | CLONE_NEWPID
                     | CLONE_NEWUTS
                     | CLONE_NEWIPC
                     | CLONE_NEWNET
                     | CLONE_PIDFD
                     | CLONE_INTO_CGROUP,      ← kernel >= 5.7, cgroup fd
               cgroup = fd of /sys/fs/cgroup/myrun/<id>)
                             │
             ┌───────────────┴───────────────┐
             │                               │
        parent continues              child = container PID 1
             │                               │
   1. write uid_map/gid_map ────────────▶ (blocked on sync socket)
   2. cgroup already applied by
      CLONE_INTO_CGROUP (atomic!)
   3. create veth, move peer
      into child's netns by pid
   4. persist ns fds (bind-mount)
   5. send SYNC_PARENT_READY ───────────▶ wakes
             │                               │
             │                          6. sethostname()
             │                          7. mount setup + pivot_root
             │                          8. mount /proc /sys /dev
             │                          9. bring up lo, eth0, routes
             │                         10. read-only remount if asked
             │                         11. drop caps, no_new_privs, seccomp
             │                         12. write state=created
             │                         13. open exec.fifo O_RDONLY  ← BLOCKS
   6. wait for SYNC_INIT_READY ◀─────────────┘
   7. write state.json, return
             │
        `myrun start <id>`:
        open exec.fifo O_WRONLY, write 1 byte ─────▶ fifo read returns
                                                   14. execve(user command)
```

**Why `CLONE_INTO_CGROUP` matters:** the classic approach is `clone()` then parent writes the child PID into `cgroup.procs`. Between those two events the child is unconstrained — it can allocate past the memory limit or fork past the pids limit. `clone3` with `CLONE_INTO_CGROUP` makes the child *born* in the cgroup. This is a genuinely good thing to be able to explain.

**Why a sync socket and not just "child does everything":** three setup steps can only be done by the parent (uid maps, moving a veth into the child's netns, persisting ns fds), and the child must not proceed past them. `SOCK_SEQPACKET` gives you message boundaries and detects parent death via EOF.

### 4.3 Namespace persistence

A namespace lives as long as (a) a process is in it, or (b) an fd/bind-mount references it. For `create` → `start` (where nothing runs yet, but PID 1 exists and blocks on the FIFO) you're fine. But for the network namespace you often want a stable handle:

```
mkdir -p /run/myrun/netns
touch /run/myrun/netns/<id>
mount("/proc/<pid>/ns/net", "/run/myrun/netns/<id>", NULL, MS_BIND, NULL)
```

Now `ip netns exec <id> ...` works for debugging, and `setns()` from the host works even during transient states. **This is also a leak source** — teardown must `umount2(path, MNT_DETACH)` and `unlink`.

---

## 5. Filesystem setup sequence

### 5.1 Why `chroot` is not enough

`chroot(2)` changes the process's root directory. It does **not**:
- change the mount table (the container sees every host mount)
- prevent escape (the classic escape: keep an fd to a directory outside the new root, `chroot` again, then `fchdir(fd)` and `cd ..` until you hit real `/`)
- unmount the old root

`pivot_root(2)` changes the root of the **mount namespace** and detaches the old root entirely. After `umount2(old, MNT_DETACH)`, the old root is not reachable through any path — there is no `..` to climb.

### 5.2 The exact sequence (runs in the child, after `CLONE_NEWNS`)

```
 1. mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)
       ↑ CRITICAL. Without this, your new mount namespace's mounts are
         MS_SHARED with the host (systemd sets / shared) and everything you
         mount inside leaks into the host mount table. pivot_root also
         refuses if new_root's parent is shared.

 2. mount(rootfs, rootfs, NULL, MS_BIND|MS_REC, NULL)
       ↑ pivot_root requires new_root to BE a mount point. Bind it to itself.

 3. old_root_fd = open("/", O_PATH|O_DIRECTORY|O_CLOEXEC)
    new_root_fd = open(rootfs, O_PATH|O_DIRECTORY|O_CLOEXEC)

 4. fchdir(new_root_fd)
    pivot_root(".", ".")        ← the "same path twice" trick
       ↑ Legal because pivot_root stacks the old root ON TOP of the new root
         at the same location. Avoids needing a /.pivot_old directory inside
         the rootfs (which you'd otherwise have to create and delete).

 5. fchdir(old_root_fd)
    mount(NULL, ".", NULL, MS_REC|MS_PRIVATE, NULL)   ← belt and braces
    umount2(".", MNT_DETACH)     ← old root gone. Lazy unmount because
                                   things may still reference it.

 6. chdir("/")

 7. Now mount the pseudo-filesystems INSIDE:
      mount("proc",  "/proc",     "proc",     MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)
      mount("sysfs", "/sys",      "sysfs",    MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RDONLY, NULL)
      mount("tmpfs", "/dev",      "tmpfs",    MS_NOSUID|MS_STRICTATIME, "mode=755,size=65536k")
      mkdir /dev/pts /dev/shm
      mount("devpts","/dev/pts",  "devpts",   MS_NOSUID|MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620")
      mount("tmpfs", "/dev/shm",  "tmpfs",    MS_NOSUID|MS_NODEV, "mode=1777,size=65536k")
      mount("mqueue","/dev/mqueue","mqueue",  MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)

 8. Device nodes (bind-mount from host /dev — safer than mknod, works without
    CAP_MKNOD and under user namespaces):
      for d in null zero full random urandom tty:
        touch /dev/$d ; mount("/host-dev/"+d, "/dev/"+d, NULL, MS_BIND, NULL)
      symlink /dev/ptmx -> pts/ptmx
      symlink /dev/fd -> /proc/self/fd, stdin->fd/0, stdout->fd/1, stderr->fd/2

 9. Masked paths (see security model):
      mount("/dev/null", "/proc/kcore", NULL, MS_BIND, NULL)
      ... same for /proc/keys, /proc/timer_list, /sys/firmware, /proc/sysrq-trigger

10. Read-only paths:
      mount(p, p, NULL, MS_BIND|MS_REC, NULL)
      mount(NULL, p, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL)
      for /proc/sys, /proc/sysrq-trigger, /proc/bus, /proc/fs, /proc/irq

11. If --read-only, make / read-only LAST (after all mounts):
      Modern:  mount_setattr(AT_FDCWD, "/", AT_RECURSIVE,
                 &{attr_set: MOUNT_ATTR_RDONLY}, sizeof)
      Legacy:  walk /proc/self/mountinfo and remount each mount RO individually.
      NOTE: MS_REMOUNT|MS_RDONLY does NOT apply recursively on old kernels.
            This is the #1 subtle bug in read-only rootfs implementations.
```

**Ordering constraint you must be able to justify:** `/proc` must be mounted *after* entering the new PID namespace, because a procfs instance is bound to the PID namespace of the mounting process. Mount it before, and you get the host's process list inside the container. This is the single most instructive bug in the whole project — you should deliberately introduce it once and observe it.

### 5.3 New mount API (worth knowing, optional to use)

Since 5.2 the kernel has `fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`. The advantage is that mount creation and attachment are split, so you can build a detached mount and only attach it if everything succeeded:

```
fd = fsopen("proc", 0)
fsconfig(fd, FSCONFIG_CMD_CREATE, ...)
mfd = fsmount(fd, 0, MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC)
move_mount(mfd, "", AT_FDCWD, "/proc", MOVE_MOUNT_F_EMPTY_PATH)
```

Implement the classic API first. Add the new API as a `--mount-api=new` flag in a later milestone and write up the difference — that is exactly the kind of detail that separates a portfolio project from a tutorial follow-along.

---

## 6. Process lifecycle and PID 1

### 6.1 The PID 1 problem

Inside a PID namespace, PID 1 has kernel-enforced special behaviour:

1. **Signals without handlers are discarded.** For signals sent by processes *inside* the namespace, the kernel skips the default action for PID 1. `SIGTERM` to a `/bin/sh` running as PID 1 does nothing. From an *ancestor* namespace, `SIGKILL` and `SIGSTOP` are always forced; other signals still require a handler.
   → Consequence: `myrun stop` cannot rely on `SIGTERM` reaching an unmodified user process. Either the user process installs handlers, or you supply an init.
2. **PID 1 must reap orphans.** When any process in the namespace is orphaned, it is reparented to PID 1. If PID 1 never calls `wait()`, zombies accumulate and eventually exhaust `pids.max`.
3. **If PID 1 exits, the kernel `SIGKILL`s every other process in the namespace.** This is your cleanup guarantee, and it is free.

### 6.2 Two execution models — support both

```
--init=false (default for simple demos)          --init=true (default for real use)

  PID 1 = /bin/sh (execve'd directly)              PID 1 = myrun-init
    · simplest                                       │ installs signalfd for all catchable signals
    · no reaping                                     │ forwards them to the child's process group
    · SIGTERM ignored → stop falls back to KILL      │ SIGCHLD loop: waitpid(-1, WNOHANG) until ECHILD
    · exit code = shell's exit code                  │ remembers the direct child's status
                                                     ▼
                                                   PID 2 = /bin/sh
                                                   exit code propagated: init exits with
                                                   the child's code, or 128+signo
```

The `--init` implementation is ~80 lines and is worth every one of them. It is also the answer to "how does `docker run --init` work and why does it exist".

### 6.3 Host-side process management

```
Attached mode (`myrun run`):
   parent stays alive, holds pidfd, blocks in poll(pidfd) or waitpid()
   on child exit → collect status → teardown → exit with mapped code

Detached mode (`myrun run -d` / `create`+`start`):
   the runtime process must NOT be the one waiting, because it exits.
   Options:
     (a) double-fork: reparent init to PID 1 (host). Simple, but nobody
         collects the exit code and cleanup never runs.
     (b) shim process: a small `myrun __shim` that stays alive, holds the
         pidfd, waits, writes the exit status into state.json, runs teardown.
         This is what containerd-shim does. ← DO THIS.
```

The shim also solves "runtime crashes" — because the runtime is not load-bearing after `start`.

### 6.4 Exit code mapping

```
WIFEXITED(status)   → exit code = WEXITSTATUS(status)
WIFSIGNALED(status) → exit code = 128 + WTERMSIG(status)     (137 = SIGKILL, i.e. OOM)
container never started (runtime error) → 125
command found but not executable       → 126
command not found                      → 127
```

Match these to Docker's conventions and say so in your README. Consistency with prior art is a signal of care.

### 6.5 `PR_SET_PDEATHSIG` caveat

`prctl(PR_SET_PDEATHSIG, SIGKILL)` in the child makes the kernel kill it when its parent **thread** dies — not the parent process. In a multithreaded parent (or if the parent re-execs), this fires unexpectedly. It's also cleared across a `setuid` exec. Use it, but document the caveat; the shim is your real guarantee.

---

## 7. cgroup v2 architecture

### 7.1 Layout

```
/sys/fs/cgroup/                      root, delegated by systemd
├── cgroup.controllers               "cpuset cpu io memory hugetlb pids rdma misc"
├── cgroup.subtree_control           must contain +cpu +memory +pids for children
└── myrun/                           ← your parent cgroup, created once
    ├── cgroup.subtree_control       "+cpu +memory +pids"
    ├── <container-id-1>/
    │   ├── cgroup.procs             ← PID 1 written here (or CLONE_INTO_CGROUP)
    │   ├── cgroup.freeze            0/1  → pause/unpause
    │   ├── cgroup.kill              write "1" → SIGKILL every member atomically
    │   ├── memory.max               268435456
    │   ├── memory.swap.max          0
    │   ├── memory.high              (soft, optional — throttles before OOM)
    │   ├── memory.current           read
    │   ├── memory.peak              read
    │   ├── memory.events            read: low/high/max/oom/oom_kill counters
    │   ├── cpu.max                  "100000 100000"  = 1.0 CPU
    │   ├── cpu.weight               1..10000, default 100  (relative shares)
    │   ├── cpu.stat                 usage_usec, user_usec, system_usec, nr_throttled
    │   ├── pids.max                 100
    │   ├── pids.current             read
    │   └── io.stat                  read
    └── <container-id-2>/
```

### 7.2 Rules you must encode

1. **No internal processes.** A cgroup with an enabled controller cannot have both processes and child cgroups (except the root). So `myrun/` is a pure parent — never put a PID in it.
2. **Controllers must be enabled top-down.** Writing `+memory` to `/sys/fs/cgroup/myrun/cgroup.subtree_control` fails unless `memory` is already in `/sys/fs/cgroup/cgroup.controllers` *and* enabled in the root's `subtree_control`. Under systemd, ask for delegation instead of fighting it: create your cgroup under a delegated slice, or run `systemd-run --unit=myrun.slice`.
3. **Deletion is `rmdir`,** and it only succeeds when the cgroup is empty. If it returns `EBUSY`, something is still in it — write `1` to `cgroup.kill` first, then `rmdir` with a short retry loop.
4. **Unit conversion is your bug farm.** Write and unit-test it:
   ```
   "256m"  → 268435456        (m = MiB, not MB — pick one and document it)
   "1g"    → 1073741824
   "1"     → cpu.max "100000 100000"
   "0.5"   → cpu.max "50000 100000"
   "2.5"   → cpu.max "250000 100000"
   "max"   → cpu.max "max 100000"
   ```

### 7.3 Detecting OOM correctly

Do not infer OOM from exit code 137 alone (that's just SIGKILL, which `myrun kill` also produces). Read `memory.events`:

```
oom 1          ← the cgroup hit memory.max and had to reclaim/kill
oom_kill 1     ← a process was actually killed
```

Better: `open("memory.events")` and register it with `epoll` for `EPOLLPRI` — cgroup v2 files support poll notification on change. That's a nice detail for the stats collector.

---

## 8. Networking architecture

### 8.1 Topology

```
                    HOST NETWORK NAMESPACE
   ┌─────────────────────────────────────────────────────────────┐
   │                                                             │
   │   eth0 (192.168.1.50/24) ── default route ──▶ internet      │
   │     ▲                                                       │
   │     │ nftables: postrouting masquerade                      │
   │     │           oifname eth0 ip saddr 172.18.0.0/16         │
   │     │                                                       │
   │   ┌─┴──────────────────────────┐                            │
   │   │  bridge myrun0             │  172.18.0.1/16             │
   │   │  (created once, on demand) │  forwarding=1              │
   │   └──┬──────────────┬──────────┘                            │
   │      │              │                                       │
   │   veth-a1b2      veth-c3d4     ← host-side peers, enslaved  │
   │      │              │                                       │
   └──────┼──────────────┼───────────────────────────────────────┘
          │              │
   ┌──────┼─────┐  ┌─────┼──────┐
   │    eth0    │  │   eth0     │   ← container-side peers, renamed
   │ 172.18.0.2 │  │ 172.18.0.3 │
   │ lo UP      │  │ lo UP      │
   │ default via│  │ default via│
   │ 172.18.0.1 │  │ 172.18.0.1 │
   │            │  │            │
   │ netns A    │  │ netns B    │
   └────────────┘  └────────────┘
```

### 8.2 Setup order (all rtnetlink, from the host side)

```
 1. Ensure bridge exists:
      RTM_NEWLINK, IFLA_INFO_KIND="bridge", ifname="myrun0"
      RTM_NEWADDR  172.18.0.1/16 on myrun0
      RTM_NEWLINK  set IFF_UP
      sysctl net.ipv4.ip_forward=1
      sysctl net.bridge.bridge-nf-call-iptables=0   (avoid surprising filtering)

 2. IPAM: allocate a free /32 from 172.18.0.0/16.
      Persist allocations in /run/myrun/ipam.json under flock.
      Reserve .0 and .1. Release on delete. Handle exhaustion explicitly.

 3. Create veth pair (both ends land in the current netns first):
      RTM_NEWLINK kind="veth", ifname="veth<id8>",
                  IFLA_INFO_DATA{VETH_INFO_PEER{ifname="tmp<id8>"}}

 4. Enslave host side to bridge:
      RTM_SETLINK ifindex=veth<id8>, IFLA_MASTER=<bridge ifindex>
      RTM_SETLINK set IFF_UP

 5. Move peer into container netns:
      RTM_SETLINK ifindex=tmp<id8>, IFLA_NET_NS_FD = fd of /proc/<pid>/ns/net
      (or IFLA_NET_NS_PID = <pid>)
      ← this is the magic step. The interface DISAPPEARS from the host.

 6. Configure inside the container netns. Two ways:
      (a) parent does setns(netns_fd, CLONE_NEWNET) in a forked helper,
          configures, exits.  ← keeps the child simple
      (b) child does it after the sync barrier.  ← keeps the parent simple
      Do (a): the parent already has netlink code and the child should be
      doing as little privileged work as possible.

      · rename tmp<id8> → eth0     (RTM_SETLINK IFLA_IFNAME)
      · RTM_NEWADDR 172.18.0.2/16 on eth0
      · set eth0 UP, set lo UP
      · RTM_NEWROUTE default via 172.18.0.1 dev eth0

 7. NAT (once, idempotent) — prefer nftables over iptables:
      table ip myrun {
        chain postrouting { type nat hook postrouting priority srcnat;
          ip saddr 172.18.0.0/16 oifname != "myrun0" masquerade }
        chain prerouting  { type nat hook prerouting  priority dstnat; }
      }

 8. Port forwarding  -p 8080:80:
      add to prerouting: tcp dport 8080 dnat to 172.18.0.2:80
      plus a hairpin rule in output for host-local access.
      Store the rule handle in state.json so delete can remove exactly it.
```

### 8.3 Modes to support

| Mode | Behaviour |
|---|---|
| `--network none` | New netns, only `lo` (brought up). Default for security tests. |
| `--network host` | No `CLONE_NEWNET`. Container shares host stack. One flag, big security note. |
| `--network bridge` | The full setup above. Default. |

### 8.4 Network statistics

Inside the container netns, read `/sys/class/net/eth0/statistics/{rx,tx}_{bytes,packets,errors,dropped}`. From the host, you can read the *host-side peer's* counters — but note rx/tx are **inverted** relative to the container's view. Easiest correct approach: `setns` into the netns in a short-lived thread and read `/proc/net/dev`.

---

## 9. Security model

### 9.1 Threat model — state it explicitly in your README

> `myrun` isolates **cooperating** workloads. It reduces accidental interference and limits resource consumption. It is **not** a sandbox for hostile code. A container process that gains `CAP_SYS_ADMIN`, or exploits a kernel bug, escapes to the host. There is no user namespace by default, no LSM policy, and the seccomp filter is a deny-list, not an allow-list.

Stating limits precisely is worth more in an interview than overclaiming.

### 9.2 Layers implemented

**1. Capabilities.** Linux splits root into ~41 capabilities across 5 sets (Permitted, Effective, Inheritable, Bounding, Ambient). Dropping means:

```
for cap in ALL_CAPS - KEEP_SET:
    prctl(PR_CAPBSET_DROP, cap)      ← bounding set: can never be regained,
                                       not even via a setuid-root binary
capset(): clear Permitted/Effective/Inheritable except KEEP_SET
clear the Ambient set entirely (PR_CAP_AMBIENT_CLEAR_ALL)
```

Default keep-set (mirror Docker's, then justify each):
```
CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID,
SETPCAP, NET_BIND_SERVICE, NET_RAW, SYS_CHROOT, MKNOD, AUDIT_WRITE, SETFCAP
```
Explicitly dropped and why:
```
SYS_ADMIN     — mount, pivot_root, setns. Grants effective root. Never keep.
SYS_MODULE    — load kernel modules = instant host compromise
SYS_PTRACE    — inspect other processes (in-namespace only, but still)
SYS_BOOT      — reboot the HOST
SYS_TIME      — set the HOST clock (time is not namespaced by default)
NET_ADMIN     — reconfigure the netns, delete routes, sniff
DAC_READ_SEARCH — enables the open_by_handle_at escape (CVE-2014-9357 class)
```

Ordering matters: drop capabilities **after** all privileged setup (mounts need `CAP_SYS_ADMIN`), **before** `execve`.

**2. `no_new_privs`.** `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. Once set, it is inherited and cannot be unset. It makes `execve` never grant privileges — setuid bits and file capabilities are ignored. It is also a prerequisite for installing a seccomp filter without `CAP_SYS_ADMIN`.

**3. Seccomp-BPF.** Start with a deny-list of the obviously dangerous:
```
DENY: init_module, finit_module, delete_module, kexec_load, kexec_file_load,
      reboot, swapon, swapoff, mount, umount2, pivot_root, open_by_handle_at,
      name_to_handle_at, bpf, perf_event_open, ptrace, process_vm_readv/writev,
      keyctl, add_key, request_key, userfaultfd, clock_settime, settimeofday
Action: SCMP_ACT_ERRNO(EPERM)   (not KILL — EPERM produces debuggable failures)
```
Note honestly in your docs that an allow-list is strictly stronger, and that a deny-list is defeated by any syscall you forgot.

**4. Filesystem hardening.**
```
Masked (bind /dev/null over, so reads return nothing):
  /proc/kcore          — raw physical memory image
  /proc/keys, /proc/key-users
  /proc/timer_list, /proc/sched_debug   — host process names/PIDs leak
  /proc/sysrq-trigger  — write "b" = reboot the host
  /sys/firmware, /sys/devices/virtual/powercap
Read-only:
  /proc/sys, /proc/bus, /proc/fs, /proc/irq, /sys
Mount flags everywhere: MS_NOSUID | MS_NODEV | MS_NOEXEC where compatible
```

**5. Miscellaneous.**
```
· rlimits: RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_CORE=0
· umask 0022
· close all fds > 2 before execve (or set CLOEXEC on everything; verify with
  a test that counts /proc/self/fd inside the container)
· never pass the sync socket or the cgroup fd through execve
```

### 9.3 Documented remaining limitations

```
1. Shared kernel — a kernel LPE is a full escape.
2. No user namespace by default — root in container == UID 0 on host.
3. Deny-list seccomp, not allow-list.
4. No AppArmor/SELinux profile.
5. No device cgroup restrictions (v2 requires an eBPF program on
   BPF_CGROUP_DEVICE — noted as future work).
6. No image verification, no signature checking; rootfs is trusted input.
7. Host network mode disables all network isolation.
8. Time namespace not used; container sees host uptime and can be affected
   by host clock changes.
```

### 9.4 Stretch: user namespaces

```
clone(CLONE_NEWUSER) FIRST and ALONE, then the child has full caps in the new ns
parent writes:
  /proc/<pid>/uid_map   "0 100000 65536"    (container 0 → host 100000)
  /proc/<pid>/setgroups "deny"              MUST be written before gid_map
  /proc/<pid>/gid_map   "0 100000 65536"
```
Ranges beyond a single ID require `CAP_SETUID` on the host or the setuid helpers `newuidmap`/`newgidmap` reading `/etc/subuid`. This unlocks rootless containers and is the single biggest real security improvement available to you. Treat it as milestone 11.

---

## 10. Container state machine

```
                        ┌─────────────┐
          myrun create  │             │
        ─────────────▶  │  CREATING   │
                        │             │
                        └──────┬──────┘
                    setup ok   │   setup failed
              ┌────────────────┴────────────────┐
              ▼                                 ▼
        ┌───────────┐                    ┌─────────────┐
        │  CREATED  │                    │   FAILED    │──▶ rollback ──▶ (gone)
        │ PID1 alive│                    └─────────────┘
        │ blocked on│
        │ exec.fifo │
        └─────┬─────┘
              │ myrun start  (write to fifo → execve)
              ▼
        ┌───────────┐  myrun pause (cgroup.freeze=1)   ┌──────────┐
        │  RUNNING  │ ───────────────────────────────▶ │  PAUSED  │
        │           │ ◀─────────────────────────────── │          │
        └──┬─────┬──┘        myrun resume              └──────────┘
           │     │
           │     │ myrun stop  (SIGTERM → grace period)
           │     ▼
           │  ┌───────────┐  timeout expires
           │  │ STOPPING  │ ─────────────▶ SIGKILL / cgroup.kill
           │  └─────┬─────┘
           │        │
           │ process exits on its own, or is killed, or OOM-killed
           ▼        ▼
        ┌────────────────┐
        │     EXITED     │   exit_code recorded by the shim
        │  (resources    │   cgroup/netns/mounts torn down
        │   released)    │   state.json retained for `inspect`
        └───────┬────────┘
                │ myrun delete   (or `run --rm` implicitly)
                ▼
            (removed from store)
```

**Legal transitions only.** Encode this as a Rust `enum` + a `fn can_transition(from, to) -> bool` and unit-test the matrix. Illegal transitions return a specific error (`myrun start` on a RUNNING container → `ErrAlreadyStarted`, exit 125).

**Liveness verification** (never trust the file):
```rust
fn is_alive(state: &State) -> bool {
    // PID reuse defence: compare field 22 of /proc/<pid>/stat (starttime)
    // against the value recorded at create time.
    read_starttime(state.pid) == Some(state.pid_start_time)
}
```
On every `list`/`inspect`, reconcile: if the state says RUNNING but the process is gone, transition to EXITED and run teardown. This makes your runtime self-healing after a crash.

---

## 11. State store design

```
/run/myrun/
├── myrun.lock                    global lock for IPAM + bridge creation
├── ipam.json                     { "172.18.0.2": "<id>", ... }
├── netns/<id>                    bind-mounted netns handle
└── <id>/
    ├── state.json                the record below
    ├── state.lock                per-container flock
    ├── exec.fifo                 the create→start gate
    ├── config.json               the resolved ContainerSpec
    ├── shim.pid
    └── log/{stdout,stderr}
```

```json
{
  "id": "a1b2c3d4",
  "name": "web",
  "status": "running",
  "pid": 48213,
  "pid_start_time": 902341,
  "shim_pid": 48210,
  "created_at": "2026-09-05T10:14:22Z",
  "started_at": "2026-09-05T10:14:22Z",
  "finished_at": null,
  "exit_code": null,
  "oom_killed": false,
  "bundle": "/home/raqueeb/rootfs",
  "cgroup_path": "/sys/fs/cgroup/myrun/a1b2c3d4",
  "netns_path": "/run/myrun/netns/a1b2c3d4",
  "network": { "mode": "bridge", "ip": "172.18.0.2/16", "gateway": "172.18.0.1",
               "veth_host": "veth-a1b2c3d4", "mac": "02:42:ac:12:00:02",
               "ports": [{"host": 8080, "container": 80, "proto": "tcp",
                          "nft_handle": 17}] },
  "resources": { "memory_max": 268435456, "cpu_max": "100000 100000",
                 "pids_max": 100 },
  "namespaces": ["pid","mnt","uts","ipc","net"]
}
```

Write protocol: `open(tmp)` → write → `fsync` → `rename(tmp, state.json)` → `fsync(dir)`. Atomic, crash-safe, no torn reads.

`/run` is a tmpfs — state does not survive reboot, which is correct. Containers do not survive reboot either.

---

## 12. Syscall / kernel API inventory

Keep this table in `docs/syscalls.md` and fill in the "where used" column as you go. Interviewers love this artifact.

| API | Purpose in `myrun` | Notes / traps |
|---|---|---|
| `clone3(2)` | Create container PID 1 with namespace flags, `CLONE_PIDFD`, `CLONE_INTO_CGROUP` | Struct-based; `libc` has no wrapper, use `syscall()` |
| `unshare(2)` | Alternative for non-PID namespaces on the current process | Does **not** move caller into a new PID ns |
| `setns(2)` | Enter an existing namespace (network config helper, `myrun exec`) | Mount-ns setns requires single-threaded process |
| `pidfd_open(2)`, `pidfd_send_signal(2)` | Race-free signalling and exit notification | Poll a pidfd with `epoll` for `EPOLLIN` on exit |
| `mount(2)` | Everything filesystem | `MS_REC\|MS_PRIVATE` on `/` is mandatory first step |
| `umount2(2)` | Detach old root, teardown | `MNT_DETACH` for lazy unmount |
| `pivot_root(2)` | Replace the mount-namespace root | new_root must be a mount point, not shared |
| `mount_setattr(2)` | Recursive read-only with `AT_RECURSIVE` | Kernel ≥ 5.12 |
| `open_tree`/`move_mount`/`fsopen`/`fsmount` | New mount API (optional milestone) | Detached mounts, better error handling |
| `statfs(2)` | Detect cgroup v2 (`CGROUP2_SUPER_MAGIC`) | |
| `sethostname(2)` | UTS namespace demo | Needs `CAP_SYS_ADMIN` in the UTS ns |
| `prctl(2)` | `PR_SET_NO_NEW_PRIVS`, `PR_CAPBSET_DROP`, `PR_SET_PDEATHSIG`, `PR_CAP_AMBIENT` | PDEATHSIG is thread-scoped |
| `capset(2)`/`capget(2)` | Capability sets | 5 sets, get the ordering right |
| `seccomp(2)` | Install BPF filter | Requires `no_new_privs` or `CAP_SYS_ADMIN` |
| `waitpid(2)`/`waitid(2)` | Reap children, decode exit status | `WNOHANG` loop until `ECHILD` |
| `signalfd(2)` | Signal handling as fd events in the init loop | Must block signals with `sigprocmask` first |
| `epoll(7)` | Multiplex signalfd + pidfd + cgroup event fd | |
| `socketpair(2)` | Parent↔init sync channel | `SOCK_SEQPACKET` for message framing |
| `mkfifo(3)` | The create→start gate | `open(O_WRONLY)` blocks until a reader exists |
| `flock(2)` | State store locking | Advisory; fine within one program |
| `execve(2)` | Finally run the user command | Point of no return; everything must be set up |
| rtnetlink (`AF_NETLINK`) | Bridge, veth, addresses, routes, netns move | `IFLA_NET_NS_FD` is the interesting attribute |
| cgroup v2 filesystem | Limits and stats | Not syscalls — plain file I/O, but with strict semantics |

---

## 13. Testing strategy

### 13.1 Test pyramid

```
                    ┌──────────────────────┐
                    │  Failure / chaos (9) │  kill the runtime mid-setup,
                    │                      │  corrupt state, exhaust IPAM
                    ├──────────────────────┤
                    │  Integration (~35)   │  real containers, needs root,
                    │                      │  needs a rootfs fixture
                    ├──────────────────────┤
                    │  Leak assertions     │  after EVERY integration test
                    ├──────────────────────┤
                    │     Unit (~60)       │  pure logic, no root, fast:
                    │                      │  parsing, state machine, IPAM,
                    │                      │  unit conversion, cgroup value
                    │                      │  formatting, config validation
                    └──────────────────────┘
```

### 13.2 The leak assertion — write this first

Every integration test ends with the same check. Make it a `Drop` guard so it runs even on panic.

```bash
# scripts/leakcheck.sh — snapshot before, compare after
ip link show | grep -c veth                    # must return to baseline
ls /run/myrun/netns/ | wc -l                   # must be 0
ls /sys/fs/cgroup/myrun/ | wc -l               # must be 0
grep -c myrun /proc/self/mountinfo             # must be 0 (host mount leak!)
nft list table ip myrun | grep -c dnat         # must return to baseline
ls /run/myrun/ | grep -v -E 'lock|ipam|netns'  # must be empty
pgrep -f 'myrun __' | wc -l                    # no orphan shims
```

The mountinfo check is the one that will catch your `MS_PRIVATE` mistake.

### 13.3 Isolation tests — what each asserts

| Test | Setup | Assertion |
|---|---|---|
| PID isolation | run `sh -c 'echo $$'` | prints `1` |
| PID visibility | run `ps aux \| wc -l` | ≤ 3 lines; host has hundreds |
| PID ns separate | host `ps -eo pid,comm \| grep <cmd>` | host PID ≠ 1, and container's PID 1 ≠ host PID 1 |
| /proc correctness | `ls /proc \| grep -c '^[0-9]'` inside | small number, matches `pids.current` |
| UTS isolation | `--hostname box1`, run `hostname`; then host `hostname` | `box1` inside, unchanged outside |
| Mount isolation | mount a tmpfs inside; check host `/proc/mounts` | absent on host |
| Mount table size | `wc -l /proc/self/mountinfo` inside vs host | inside is ~8, host is ~40+ |
| Rootfs isolation | `ls /` inside | matches rootfs contents, not host `/` |
| No old root | `ls /.pivot_old` | ENOENT |
| chroot escape attempt | run the classic fd-escape program | fails |
| Read-only root | `touch /foo` with `--read-only` | EROFS |
| Read-only recursive | `touch /usr/foo`, `touch /etc/foo` | both EROFS (catches non-recursive bug) |
| /tmp writable | `--read-only` + tmpfs `/tmp` | write succeeds |
| Net isolation | `ip link` inside with `--network none` | only `lo` |
| Net connectivity | `--network bridge`, `ping -c1 172.18.0.1` | 0% loss |
| Net egress | `ping -c1 8.8.8.8` | works (NAT) |
| Container↔container | two containers, ping each other | works |
| Port forward | `-p 8080:80` + `nc -l` inside | host `curl localhost:8080` succeeds |
| Memory limit | `--memory 64m`, allocate 128 MB | OOM-killed, exit 137, `memory.events` oom_kill ≥ 1 |
| Memory under limit | `--memory 64m`, allocate 32 MB | succeeds |
| CPU limit | `--cpus 0.5`, busy loop 10 s | `cpu.stat` usage_usec ≈ 5 000 000 ± 10% |
| PID limit | `--pids 20`, fork bomb | fork fails with EAGAIN, host unaffected |
| Cap dropped | `capsh --print` inside | no `cap_sys_admin` in bounding set |
| no_new_privs | `cat /proc/self/status \| grep NoNewPrivs` | `NoNewPrivs: 1` |
| Masked path | `cat /proc/kcore` inside | empty (0 bytes) |
| Signal: TERM w/ init | `--init`, send SIGTERM | exits 143 within grace period |
| Signal: TERM w/o init | plain `sleep 1000` as PID 1, SIGTERM | ignored → falls back to KILL, exit 137 |
| Zombie reaping | `--init`, spawn orphans | zombie count inside stays 0 |
| Exit code passthrough | `sh -c 'exit 42'` | runtime exits 42 |
| Cleanup on exit | any container, then leakcheck | all clean |

### 13.4 Failure tests

| Scenario | How to induce | Required behaviour |
|---|---|---|
| Invalid rootfs path | `./does-not-exist` | exit 125, clear error, no cgroup/netns created |
| rootfs is a file, not dir | pass a file | exit 125, ENOTDIR surfaced clearly |
| Command not found | `/bin/nope` | exit 127, container reaches EXITED, full cleanup |
| Command not executable | non-`+x` file | exit 126 |
| Container crashes (SIGSEGV) | `sh -c 'kill -SEGV $$'` | exit 139, cleanup runs |
| Runtime killed mid-setup | `SIGKILL` the runtime between clone and sync | init dies (PDEATHSIG/EOF on sync socket), no leaks after next `myrun list` reconcile |
| Runtime killed while running | `SIGKILL` runtime after `start` | container keeps running (shim owns it); `list` still correct |
| Shim killed | `SIGKILL` the shim | container is orphaned; next `list` reconciles and reports EXITED with unknown code |
| Network setup fails halfway | inject: succeed on veth create, fail before bridge enslave | veth removed, netns removed, cgroup removed, exit 125 |
| IPAM exhausted | fake a full pool | clear error, no partial container |
| cgroup write fails (EPERM) | run as non-root | exit 125, error explains root requirement |
| Duplicate container name | create twice | second fails, first untouched |
| Delete a running container | `myrun delete` on RUNNING | refuses without `--force`; with `--force`, `cgroup.kill` then teardown |
| Double start | `start` twice | second fails cleanly, fifo not corrupted |
| Concurrent creates | 20 parallel `myrun run` | no IPAM collisions, no cgroup races, all succeed or fail cleanly |
| OOM at exactly the limit | allocate exactly `memory.max` | documented behaviour, `oom_killed: true` in inspect |
| Disk full in /run | fill tmpfs | state write fails atomically, no corrupt state.json |

**Fault injection mechanism:** compile-time feature `fault-injection` plus an env var `MYRUN_FAIL_AT=network.enslave_bridge`. Every rollback-relevant step checks it. This is how you test rollback paths without a debugger, and it's a strong thing to show in a repo.

### 13.5 Harness practicalities

```rust
// tests/common/mod.rs
pub fn require_root() { if !nix::unistd::Uid::effective().is_root() {
    eprintln!("SKIP: needs root"); std::process::exit(0); } }
```
Run with `sudo -E cargo test -- --test-threads=1` (parallel tests fight over the bridge and IPAM until you make those properly locked — then re-enable parallelism as a test in itself).

CI: GitHub Actions `ubuntu-24.04` runners have cgroup v2, `sudo`, and allow namespace creation. Add a nightly job that runs the full suite under `sudo`, plus a `cargo test` job for unit tests only.

---

## 14. Development milestones

Fifteen milestones, ordered so that each one is testable on its own and nothing is thrown away later. Estimated effort assumes you're learning the concept as you go.

---

### M0 — Skeleton: fork, exec, wait (½ day)

**Concept.** Before any isolation, get the process plumbing right. A container runtime is, at its core, `fork` + setup + `execve` + `waitpid`. Everything else is setup.

**Design.** `myrun run <cmd> [args...]`. No namespaces. Parent forks, child execs, parent waits and exits with the mapped code.

**Tasks.**
- `clap` CLI with `run`, and a stub for `list`/`inspect`.
- `process/spawn.rs`: `fork()`, in child `execvp`, in parent `waitpid`.
- `error.rs`: error enum → exit codes 125/126/127.
- Exit status decoding (`WIFEXITED`/`WIFSIGNALED` → 128+n).

**Tests.** `myrun run /bin/echo hi` → prints `hi`, exit 0. `myrun run /bin/false` → exit 1. `myrun run /bin/nope` → exit 127. `myrun run sh -c 'kill -9 $$'` → exit 137.

**Expected output.**
```
$ myrun run /bin/echo hello
hello
$ echo $?
0
```

**What goes wrong.** Forgetting that `execvp` needs a NULL-terminated `argv`. Not handling `EINTR` from `waitpid`. Printing errors from the child *after* a failed exec without `_exit()` (you'll get duplicated buffered stdout from both processes — a classic).

**Debug.** `strace -f ./myrun run /bin/echo hi`. You should see exactly one `clone`, one `execve`, one `wait4`.

---

### M1 — UTS + IPC namespaces (½ day)

**Concept.** The cheapest namespaces. `CLONE_NEWUTS` gives an independent hostname; `CLONE_NEWIPC` an independent SysV IPC space. Neither needs any teardown, which makes them the perfect first taste.

**Design.** Replace `fork()` with `clone()` carrying flags. Add `--hostname`. The child calls `sethostname()` before exec.

**Tasks.** `namespaces/flags.rs`; `clone` wrapper with a manually allocated child stack (or `clone3`, which doesn't need one — prefer `clone3`); `sethostname` in the child.

**Tests.**
```
$ myrun run --hostname box1 /bin/hostname
box1
$ hostname
your-vm            ← unchanged
$ myrun run /bin/sh -c 'ipcs -q'    # empty, even if host has queues
```

**What goes wrong.** `clone()` requires the child stack pointer to be the *top* of the buffer and correctly aligned — get this wrong and you get an immediate `SIGSEGV` with no useful message. This alone is a good reason to use `clone3`, which takes no stack argument when `CLONE_VM` is unset.

**Debug.** `readlink /proc/<pid>/ns/uts` on host vs container — the inode numbers must differ. This `readlink` trick is your namespace debugger for the whole project.

---

### M2 — PID namespace and the `/proc` lesson (1 day)

**Concept.** `CLONE_NEWPID` makes the child PID 1 in a fresh number space. But process *visibility* comes from `/proc`, which is a filesystem — so PID isolation without a mount namespace is only half-real.

**Design.** Add `CLONE_NEWPID`. Deliberately do **not** add `CLONE_NEWNS` yet. Observe the broken state, then fix it in M3.

**Tasks.** Add the flag. Print `getpid()` in the child. Run `ps` inside.

**Tests / expected output.**
```
$ myrun run /bin/sh -c 'echo $$'
1                                  ← correct!
$ myrun run /bin/ps aux | wc -l
312                                ← WRONG. Still the host's /proc.
```

**Explain to yourself in writing why.** A procfs mount is bound to the PID namespace of whoever mounted it. Your container is reading the host's `/proc` mount because you share the host's mount namespace. This is the moment the relationship between namespaces clicks.

**What goes wrong.** `unshare(CLONE_NEWPID)` instead of `clone(CLONE_NEWPID)` — the caller is *not* moved, only its future children. If you use `unshare`, you must fork afterwards.

**Debug.** `ls -l /proc/<pid>/ns/pid` on both sides.

---

### M3 — Mount namespace, `pivot_root`, real rootfs (2–3 days) ⚠️ hardest early milestone

**Concept.** Section 5 in full.

**Design.** Add `CLONE_NEWNS`. Implement `fs/pivot.rs` and `fs/mounts.rs` exactly in the order given in 5.2.

**Tasks.**
1. `scripts/make-rootfs.sh` (alpine minirootfs).
2. `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` — first, always.
3. Self-bind the rootfs.
4. `pivot_root(".", ".")` with the two `O_PATH` fds.
5. `umount2(".", MNT_DETACH)`, `chdir("/")`.
6. Mount `/proc`, `/sys`, `/dev` (tmpfs), `/dev/pts`, `/dev/shm`.
7. Bind device nodes from a pre-`pivot_root` `/dev` fd.

**Tests.**
```
$ myrun run ./alpine /bin/ps aux
PID   USER  TIME  COMMAND
    1 root  0:00  /bin/ps aux           ← finally correct
$ myrun run ./alpine /bin/ls /
bin dev etc home lib proc root sbin sys tmp usr var
$ myrun run ./alpine /bin/ls /.pivot_old
ls: /.pivot_old: No such file or directory
$ grep -c alpine /proc/self/mountinfo   # on the HOST, after exit
0                                        ← no leak
```

**What goes wrong — this list will save you days.**
- **`pivot_root` returns `EINVAL`.** Causes, in order of likelihood: (a) you skipped `MS_REC|MS_PRIVATE` on `/`; (b) `new_root` is not a mount point (you skipped the self-bind); (c) `new_root` or its parent is shared; (d) you're still in the host mount namespace.
- **`/proc` shows host processes.** You mounted `/proc` before `pivot_root`, or the bind of the old `/proc` survived.
- **Host mount table grows every run.** Missing `MS_PRIVATE`. Check with `wc -l /proc/self/mountinfo` before and after. Reboot to clean up if it gets bad — this is why you snapshot the VM.
- **`execve` fails with `ENOENT` but the file exists.** The binary is dynamically linked and `/lib/ld-musl-x86_64.so.1` isn't in the rootfs. `ENOENT` from `execve` means the *interpreter* is missing, not the binary. Test with a static busybox first.
- **`/dev/null` missing → weird failures.** Many programs open `/dev/null` unconditionally.

**Debug.**
```bash
cat /proc/<pid>/mountinfo                    # container's view; field 7 shows shared/master
findmnt -o TARGET,PROPAGATION                # host propagation flags
strace -f -e trace=mount,umount2,pivot_root,chdir ./myrun run ...
nsenter -t <pid> -m -p ls /                  # step inside a live container
```

---

### M4 — State store, `create`/`start`, `list`/`inspect`/`delete` (2 days)

**Concept.** Turning a one-shot `run` into a managed lifecycle. The FIFO gate is the key idea.

**Design.** Section 11. `create` does all setup and blocks PID 1 on `open("exec.fifo", O_RDONLY)`. `start` opens it `O_WRONLY` and writes a byte.

**Tasks.** ID generation; `state/store.rs` with atomic write + flock; `mkfifo`; the shim process; liveness reconcile in `list`; `delete` with and without `--force`; `run` = `create` + `start` + attach.

**Tests.**
```
$ myrun create --name web ./alpine sleep 100
web
$ myrun list
ID        NAME  STATUS   PID    CREATED
a1b2c3d4  web   created  48213  2s ago
$ myrun start web && myrun list
a1b2c3d4  web   running  48213  5s ago
$ myrun inspect web | jq .status
"running"
$ myrun stop web && myrun list
a1b2c3d4  web   exited(137)  -   12s ago
$ myrun delete web && myrun list       # empty
```

**What goes wrong.** Opening a FIFO for reading blocks until a writer appears — if `create` fails after `mkfifo`, `start` will block forever on a container that doesn't exist; guard with a state check first. Non-atomic state writes produce half-JSON that crashes `list` for every container. PID reuse gives you a "running" container that is actually someone's `vim`.

**Debug.** `ls -l /proc/<pid>/fd` — you should see the fifo fd. `cat /run/myrun/<id>/state.json | jq`.

---

### M5 — cgroup v2: memory, CPU, pids (2 days)

**Concept.** Section 7.

**Design.** Create `/sys/fs/cgroup/myrun/<id>` before `clone3`, pass its fd with `CLONE_INTO_CGROUP`.

**Tasks.** cgroup v2 detection via `statfs`; `subtree_control` bootstrap with a clear error if delegation is missing; `limits.rs` unit conversion with unit tests; `cgroup.kill` and `cgroup.freeze`; `rmdir` with retry.

**Tests.**
```
$ myrun run --memory 64m ./alpine sh -c 'dd if=/dev/zero of=/dev/null bs=1M count=200'
Killed
$ echo $?
137
$ myrun inspect <id> | jq .oom_killed
true

$ myrun run --pids 20 ./alpine sh -c ':(){ :|:& };:'
sh: can't fork
# host remains responsive ← this is the whole point

$ time myrun run --cpus 0.5 ./alpine sh -c 'timeout 10 sh -c "while :; do :; done"'
# cpu.stat usage_usec ≈ 5000000 (50% of 10 s)
```

**What goes wrong.** `EBUSY` on `rmdir` because a process lingers. Writing `+memory` to `subtree_control` fails with `ENOENT`/`EINVAL` under systemd — you need delegation. `memory.max` alone doesn't stop a process that swaps; set `memory.swap.max = 0`. MB vs MiB confusion makes your tests off by 4.8%.

**Debug.**
```bash
cat /sys/fs/cgroup/myrun/<id>/{memory.max,memory.current,memory.events,pids.current}
cat /proc/<pid>/cgroup                    # should show /myrun/<id>
systemd-cgls                              # visualize the whole tree
dmesg | tail                              # kernel OOM killer messages
```

---

### M6 — Signals, PID 1 init, reaping, exit codes (1–2 days)

**Concept.** Section 6.

**Design.** `--init` flag → PID 1 becomes `myrun-init`, which forks the user command, blocks signals, installs a `signalfd`, and loops on `epoll`.

**Tasks.** `signals.rs` (`sigprocmask` all, `signalfd`); `reaper.rs` (`waitpid(-1, WNOHANG)` until `ECHILD`, remember the direct child's status); signal forwarding to the child's process group; `stop` = SIGTERM → grace timeout → `cgroup.kill`; `kill --signal`.

**Tests.**
```
$ myrun run -d --init ./alpine sleep 1000 && myrun stop <id>
# exits 143 (128+15) within grace period

$ myrun run -d ./alpine sleep 1000 && myrun stop --timeout 2 <id>
# SIGTERM ignored (PID 1 semantics), SIGKILL after 2 s, exit 137

$ myrun run --init ./alpine sh -c '(sleep 0.1 &) ; sleep 1; ps aux | grep -c defunct'
0                                  ← zombies reaped
```

**What goes wrong.** Forgetting `sigprocmask` before `signalfd` (signals get their default action instead). Forwarding SIGCHLD to the child (don't). Reaping the direct child in the generic loop and losing its exit code. Sending signals to a PID instead of a process group, missing grandchildren.

**Debug.** `cat /proc/<pid>/status | grep -E 'SigBlk|SigIgn|SigCgt'` — decode the hex mask. `ps -eo pid,stat,comm` looking for `Z`.

---

### M7a — Network namespace + veth via `ip` (1 day)

**Concept.** Get connectivity working with a tool you can trust before writing netlink.

**Design.** Add `CLONE_NEWNET` and `--network {none,bridge,host}`. Shell out to `ip`/`nft` temporarily. Persist the netns bind-mount.

**Tests.**
```
$ myrun run --network none ./alpine ip link
1: lo: <LOOPBACK,UP> ...              ← only lo
$ myrun run --network bridge ./alpine ping -c1 172.18.0.1
1 packets transmitted, 1 received, 0% packet loss
$ myrun run --network bridge ./alpine ping -c1 8.8.8.8
0% packet loss                        ← NAT works
```

**What goes wrong.** `lo` is DOWN by default — even `ping 127.0.0.1` fails until you bring it up. Forgetting `net.ipv4.ip_forward=1`. `br_netfilter` silently dropping bridged traffic. Moving the veth peer before the bridge is up.

**Debug.** `ip netns exec <id> ip a`; `tcpdump -i myrun0`; `nft list ruleset`; `ip -d link show veth-xxx` (shows master and peer index).

---

### M7b — Replace `ip` with rtnetlink (2 days)

**Concept.** Netlink is a socket protocol: you send `RTM_NEWLINK`/`RTM_NEWADDR`/`RTM_NEWROUTE` messages with nested TLV attributes and read `NLMSG_ERROR` responses.

**Design.** `network/*.rs` using `rtnetlink`. The interesting call is `RTM_SETLINK` with `IFLA_NET_NS_FD`.

**Tests.** All M7a tests pass unchanged, plus: `strace` shows zero `execve` of `/sbin/ip`.

**What goes wrong.** Attribute alignment (`NLA_ALIGN` to 4 bytes). Forgetting to read the ack — the next call then reads the previous error. Wrong ifindex after the netns move (indices are per-namespace).

**Debug.** `strace -e trace=sendto,recvmsg -s 2000`; compare against `ip -d monitor link`.

---

### M8 — Port forwarding and NAT rule lifecycle (1 day)

**Design.** `-p host:container[/proto]`. Add a DNAT rule to the `myrun` nftables table, store the rule handle in state, delete exactly that handle on teardown.

**Tests.**
```
$ myrun run -d -p 8080:80 ./alpine sh -c 'nc -lk -p 80 -e /bin/echo hi'
$ curl -s localhost:8080     # hi
$ myrun delete <id> && nft list table ip myrun | grep -c 8080
0
```

**What goes wrong.** Deleting rules by matching text instead of by handle removes the wrong rule when two containers use similar ports. Host-local access needs a hairpin/output-chain rule. Port already in use must fail at create time, not silently.

---

### M9 — Security layer (2 days)

**Design.** Section 9. Order: all privileged setup → masked/ro paths → capability drop → `no_new_privs` → seccomp → `execve`.

**Tests.**
```
$ myrun run ./alpine capsh --print | grep Bounding
# no cap_sys_admin, no cap_sys_module

$ myrun run ./alpine grep NoNewPrivs /proc/self/status
NoNewPrivs:	1

$ myrun run ./alpine wc -c /proc/kcore
0 /proc/kcore

$ myrun run ./alpine mount -t tmpfs none /mnt
mount: permission denied           ← seccomp EPERM

$ myrun run ./alpine sh -c 'echo b > /proc/sysrq-trigger'
sh: can't create /proc/sysrq-trigger: Read-only file system
# (and the host did NOT reboot)
```

**What goes wrong.** Dropping `CAP_SYS_ADMIN` before mounting → everything after fails with `EPERM`. Seccomp `SCMP_ACT_KILL` on a syscall your shell's startup uses → the container dies instantly with no message; use `ERRNO(EPERM)` while developing. Forgetting the ambient set — capabilities can be reacquired.

**Debug.** `getpcaps <pid>`; `grep Cap /proc/<pid>/status` then `capsh --decode=<hex>`; `dmesg | grep -i seccomp` shows the offending syscall number for `KILL` actions; `seccomp-tools dump`.

---

### M10 — Configuration file (½ day)

```toml
# examples/full.toml
[container]
name     = "web"
rootfs   = "/srv/rootfs/alpine"
command  = ["/bin/sh", "-c", "httpd -f -p 80"]
hostname = "web01"
init     = true
readonly = true
env      = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TZ=Asia/Kolkata"]
workdir  = "/"

[resources]
memory = "256m"
cpus   = 1.0
pids   = 100

[network]
mode  = "bridge"
ports = ["8080:80/tcp"]

[security]
drop_capabilities = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
no_new_privs      = true
seccomp           = "default"

[mounts]
bind = [ { source = "/srv/data", target = "/data", readonly = true } ]
tmpfs = [ { target = "/tmp", size = "64m" } ]
```

Precedence: CLI flag > config file > built-in default. Validate everything up front and report **all** errors at once, not the first one.

---

### M11 — Stats (1 day)

```
$ myrun stats web
CONTAINER  CPU %   MEM USAGE / LIMIT   MEM %   PIDS  NET I/O
web        23.4%   48.2MiB / 256MiB    18.8%   7     1.2MB / 340KB
```

CPU % over an interval: `(Δusage_usec / Δwall_usec) * 100`. Report per-CPU-normalized too, since `--cpus 0.5` caps you at 50%. `--stream` mode redraws every second. Read network counters by `setns`-ing into the netns from a short-lived thread.

**What goes wrong.** A single-sample CPU reading is meaningless — you must diff two samples. `memory.current` includes page cache; report `memory.stat`'s `anon` separately or people will think you leak.

---

### M12 — Failure hardening and rollback (2 days)

Implement the fault-injection framework (13.4) and make every failure test in section 13 pass. This is the milestone that converts "it works on my machine" into "it's a runtime". Budget real time for it; it is also the most interview-relevant work in the project.

---

### M13 — Tests, docs, diagrams, benchmarks (2–3 days)

Full suite green. `docs/` written. Diagrams exported (draw the ASCII ones properly in Excalidraw or D2). Benchmark results in the README with a methodology section. CI green.

---

### M14 — Stretch goals (pick one or two)

| Goal | Value |
|---|---|
| **User namespaces / rootless** | Highest security payoff; hardest. `uid_map`, `setgroups=deny`, `/etc/subuid` |
| `myrun exec <id> <cmd>` | `setns` into all namespaces of PID 1, join the cgroup. Teaches `setns` ordering (mount ns last) |
| Terminal/TTY support | `openpty`, `TIOCSCTTY`, terminal size propagation, raw mode. Fiddly but very visible |
| OCI runtime-spec compatibility | Read `config.json`; try running your runtime under `crun`'s test suite |
| New mount API | `fsopen`/`fsmount`/`move_mount` path behind a flag |
| Time namespace | `CLONE_NEWTIME` + `/proc/<pid>/timens_offsets` |
| Overlayfs layers | `mount -t overlay` with lower/upper/work dirs — the last big "how do images work" piece |
| eBPF device cgroup | `BPF_CGROUP_DEVICE` program to restrict `mknod`/device access |

---

## 15. Performance measurements to collect

Put these in the README with a stated methodology (kernel version, CPU, 100 iterations, p50/p99). Numbers with error bars beat numbers without.

### 15.1 Startup latency, broken down

Instrument each phase with `CLOCK_MONOTONIC` and emit a trace:

```
Phase                          p50      p99
─────────────────────────────────────────────
config parse + validate       0.4 ms   0.9 ms
cgroup create + limits        1.1 ms   2.4 ms
clone3                        0.3 ms   0.8 ms
mount setup + pivot_root      3.8 ms   7.2 ms
network (veth + bridge + ip) 12.6 ms  28.1 ms   ← dominates
security (caps + seccomp)     0.7 ms   1.5 ms
fifo wait → execve            0.2 ms   0.5 ms
─────────────────────────────────────────────
TOTAL                        19.1 ms  41.4 ms
```

Then compare:
```
bare fork+exec                ~1 ms      (floor)
myrun --network none          ~7 ms
myrun --network bridge        ~19 ms
docker run alpine true        ~400 ms    (for context, not competition)
```
The interesting conclusion — "networking is 65% of container startup" — is exactly the kind of finding that makes a portfolio project memorable.

### 15.2 Other measurements

| Metric | Method | Why it's interesting |
|---|---|---|
| Teardown latency | time from `stop` to leakcheck-clean | Usually dominated by netlink deletes |
| Memory overhead per container | shim RSS + init RSS, `smaps_rollup` PSS | Should be < 2 MB; compare to Docker's ~10 MB |
| Max concurrent containers | ramp until failure; record what fails first | Usually IPAM, `pids.max` on the host, or veth ifindex limits |
| CPU limit accuracy | busy loop 30 s at `--cpus {0.25,0.5,1,2}`; compare `cpu.stat` to expectation | Should be within 2%; if not, your period is wrong |
| CPU throttling | `cpu.stat` `nr_throttled`, `throttled_usec` | Shows the CFS bandwidth mechanism in action |
| Memory limit precision | binary-search the allocation size that triggers OOM | Reveals page-cache accounting |
| Network throughput | `iperf3` host↔container, container↔container | veth costs ~10-20% vs loopback; quantify it |
| Network latency | `ping -c 1000 -i 0.01`, report p50/p99 | ~0.05 ms overhead |
| Syscall count | `strace -c -f myrun run alpine true` | Tracks bloat across milestones |
| Isolation overhead | run the same CPU benchmark in and out of the container | Should be ≈ 0% — namespaces are free at runtime, which surprises people |

---

## 16. Interview questions you must be able to answer

Rehearse these out loud. If you can answer all of them, this project is doing its job.

### Namespaces
1. Name the Linux namespace types and what each isolates.
2. Why does `unshare(CLONE_NEWPID)` not move the calling process into the new PID namespace?
3. What is special about PID 1 in a PID namespace? Give three distinct behaviours.
4. What happens to the other processes when PID 1 in a namespace exits?
5. What's the difference between `clone`, `unshare`, and `setns`?
6. How do you check, from the shell, whether two processes are in the same namespace?
7. Why must you create a user namespace before the others when using one?
8. Are namespaces hierarchical? (PID and user are; the rest are flat.)

### Filesystem
9. Why is `chroot` insufficient for isolation? Describe the escape.
10. What exactly does `pivot_root` do that `chroot` doesn't?
11. Why must `/` be made `MS_PRIVATE` before setting up container mounts?
12. Explain mount propagation: shared, slave, private, unbindable.
13. Why must `/proc` be mounted after entering the PID namespace?
14. Why doesn't `MS_REMOUNT|MS_RDONLY` on `/` make the whole tree read-only?
15. What does `MNT_DETACH` mean and when do you need it?
16. What is `/proc/self/mountinfo` field 7 and why do you care?

### cgroups
17. Differences between cgroup v1 and v2. What is the unified hierarchy?
18. What is the "no internal processes" rule?
19. How does `cpu.max` express a CPU limit, and how does it differ from `cpu.weight`?
20. What is the race between `clone()` and writing to `cgroup.procs`, and how does `CLONE_INTO_CGROUP` fix it?
21. How do you tell an OOM kill apart from a `SIGKILL` you sent?
22. Why does `memory.current` include more than your process's heap?
23. How do you kill everything in a cgroup atomically?

### Process and signals
24. Walk through what happens between `myrun run` and the user's `main()`.
25. Why won't `SIGTERM` stop `sleep 1000` running as PID 1?
26. What is a zombie process and whose responsibility is reaping?
27. Why does `docker run --init` exist?
28. How do you encode "killed by signal N" in an exit code, and why 128+N?
29. What is a pidfd and what race does it eliminate?
30. What is the flaw in `PR_SET_PDEATHSIG`?

### Networking
31. What does a veth pair actually do at the kernel level?
32. How do you move a network interface into another namespace?
33. Why does a container need NAT to reach the internet?
34. What does a Linux bridge do, and how is it different from a router?
35. Trace a packet from `curl` inside the container to a public IP and back.
36. Why is `lo` down by default in a new netns, and what breaks because of it?

### Security
37. Name the five capability sets and how they interact on `execve`.
38. What does `no_new_privs` prevent, and why is it a seccomp prerequisite?
39. Why is `CAP_SYS_ADMIN` considered "the new root"?
40. Allow-list vs deny-list seccomp: which is stronger and why?
41. Why mask `/proc/kcore` and `/proc/sysrq-trigger`?
42. What does a user namespace buy you that capability dropping doesn't?
43. What can a container escape *not* be prevented by your runtime? (Answer honestly.)

### Design
44. Why separate `create` and `start`? What does the FIFO accomplish?
45. Why does a shim process exist, and what breaks without it?
46. How do you guarantee no resource leaks when setup fails at step 7 of 12?
47. How do you handle PID reuse in your state store?
48. What would you do differently if you rewrote this?
49. Where is your runtime slowest, and what would you fix first?
50. What's the hardest bug you hit and how did you find it?

Question 50 is the one that actually gets asked. Keep a `docs/bugs.md` while you build — a short log of each real bug, the symptom, the wrong hypothesis, and the fix. It becomes the best story you have.

---

## 17. Where this project sits next to your other five

You now have: a network protocol project (LAN transfer), an indexing/IR project (search engine), a `/proc` observability project (monitor), a distributed-consistency project (CRDT notes), and a storage/durability project (KV store).

This one is the **kernel-interface** project, and it's the one that ties the others together — it uses `/proc` like #3, sockets like #1 and #5, crash-recovery reasoning like #5, and process lifecycle management none of them needed. In your README, say that explicitly. A portfolio that shows a deliberate progression reads very differently from six unrelated repos.

---

## Next step

Tell me when you're ready and I'll go deep on **M0 + M1** together — full Rust code, the `clone3` binding (since `libc` doesn't ship one), the error-to-exit-code plumbing, and the first two integration tests. After that we do one milestone per session, and I'll review your code before we move on rather than handing you the next chunk blind.

If you'd rather start somewhere else, M3 (`pivot_root`) is the milestone that teaches the most per hour — but it's much harder to debug without M0–M2 in place first.
