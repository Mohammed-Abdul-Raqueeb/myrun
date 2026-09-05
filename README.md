# myrun

A container runtime for Linux, written in Rust with **no external crates** —
every syscall, every netlink message, and the JSON and TOML parsers are
hand-written against the kernel ABI.

It creates real containers: separate PID, mount, UTS, IPC, network and cgroup
namespaces; a pivoted root filesystem; cgroup v2 resource limits; a bridged
network with NAT and port publishing; capability dropping, `no_new_privs` and
a seccomp filter.

```
$ myrun run --network bridge -m 256m --cpus 1.5 ./rootfs /bin/sh
/ # hostname
a3f21c9b04e7
/ # ip -4 -o addr show eth0
2: eth0    inet 10.87.0.2/24 brd 10.87.0.255 scope global eth0
/ # grep -E 'CapEff|NoNewPrivs|Seccomp:' /proc/self/status
CapEff:  00000000280405fb
NoNewPrivs:      1
Seccomp: 2
```

---

## Contents

- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Container startup, step by step](#container-startup-step-by-step)
- [Commands](#commands)
- [Configuration files](#configuration-files)
- [Failure handling](#failure-handling)
- [Building and testing](#building-and-testing)
- [Known limitations](#known-limitations)
- [Further reading](#further-reading)

---

## Quick start

```sh
cargo build --release
sudo ./scripts/setup-rootfs.sh /tmp/myrun-rootfs      # minimal busybox rootfs
sudo ./target/release/myrun run /tmp/myrun-rootfs /bin/sh
```

Everything needs root. Namespace creation, cgroup manipulation, `pivot_root`
and veth creation are all privileged operations; `myrun` says so plainly
rather than failing with a bare `EPERM`.

Check what the host supports before you start:

```sh
sudo ./target/release/myrun info
```

---

## Architecture

Three processes cooperate to run one container.

```
   ┌──────────────────────────────────────────────────────────────────┐
   │ myrun (CLI)                                          host netns  │
   │  parse -> validate -> create state dir                           │
   │      │                                                           │
   │      │ fork + setsid                    (only for `run -d`)      │
   │      ▼                                                           │
   │  ┌───────────────────────────────────────────────────────┐       │
   │  │ myrun-shim                                            │       │
   │  │  owns the container, captures stdout/stderr to        │       │
   │  │  container.log, records the exit status, tears down   │       │
   │  │      │                                                │       │
   │  │      │ clone3(CLONE_NEWPID|NEWNS|NEWUTS|NEWIPC|       │       │
   │  │      │        NEWNET|NEWCGROUP|PIDFD|INTO_CGROUP)     │       │
   │  │      ▼                                                │       │
   │  │  ╔═════════════════════════════════════════════════╗  │       │
   │  │  ║ myrun-init  (PID 1 in the container)            ║  │       │
   │  │  ║   sethostname -> mounts -> pivot_root ->        ║  │       │
   │  │  ║   network -> caps -> no_new_privs -> seccomp    ║  │       │
   │  │  ║       │ fork + execve                           ║  │       │
   │  │  ║       ▼                                         ║  │       │
   │  │  ║   workload (PID 2)                              ║  │       │
   │  │  ║                                                 ║  │       │
   │  │  ║   init also: reaps orphans, forwards signals,   ║  │       │
   │  │  ║   exits with the workload's status              ║  │       │
   │  │  ╚═════════════════════════════════════════════════╝  │       │
   │  └───────────────────────────────────────────────────────┘       │
   └──────────────────────────────────────────────────────────────────┘
```

For `myrun run` without `-d` there is no shim: the CLI itself supervises.

### Why a shim at all?

A detached container needs *something* to outlive the CLI: to reap init, to
record the exit code, and to remove the cgroup, veth and iptables rules. A
`run -d` that simply forked and exited would leak all of those the moment the
workload finished. The shim also makes startup failures reportable — it tells
the CLI over a pipe whether the container actually came up, so `run -d`
returns a real error instead of "detached fine, died a millisecond later".

### Source layout

```
src/
  main.rs             CLI entry point and command dispatch
  cli.rs              hand-written argument parser and help
  config.rs           ContainerConfig: defaults, file loading, validation
  error.rs            error type and exit-code mapping
  fault.rs            named fault-injection points (MYRUN_FAULT)
  logging.rs          levelled stderr logger with a role prefix
  rollback.rs         LIFO undo stack for transactional setup
  sys/                the kernel ABI, hand-written
    ffi.rs            syscall numbers, structs, constants, externs
    mod.rs            small syscall wrappers, FileLock, namespace helpers
    mount.rs          mount/umount/pivot_root, /proc/*/mountinfo parser
    process.rs        clone3, sealed-memfd exec, pidfd, waitpid, /proc/*/stat
    caps.rs           capability table, capget/capset, bounding set
    seccomp.rs        BPF filter assembly and installation
    signal.rs         sigprocmask, signalfd, poll
    netlink.rs        rtnetlink: links, veth, bridge, addresses, routes
  runtime/
    mod.rs            runtime paths and naming
    state.rs          state machine and the on-disk store
    supervisor.rs     the launch sequence and its rollback
    shim.rs           the detached-container owner
    init.rs           container PID 1
    ipc.rs            the parent <-> init handshake protocol
    cgroup.rs         cgroup v2: limits, freeze, kill, stats
    filesystem.rs     mounts, devices, masking, pivot_root
    security.rs       capabilities, no_new_privs, seccomp, ordering
    network.rs        bridge and veth setup, in-namespace configuration
    ipam.rs           file-backed IP allocator with flock
    nat.rs            iptables rules for NAT and port publishing
    lifecycle.rs      start/stop/kill/pause/delete/wait/logs
    stats.rs          resource statistics
```

---

## Container startup, step by step

```
 CLI / shim                                 init (in the new namespaces)
 ──────────                                 ────────────────────────────
 1  validate config
 2  create state dir, write config.json
 3  create cgroup <mount>/myrun/<id>
 4  seal a copy of the binary into a memfd     (CVE-2019-5736 mitigation)
 5  socketpair()  ──── child end becomes fd 3 ────────►
 6  clone3(CLONE_NEW*, CLONE_INTO_CGROUP) ───────────►  starts, reads config
 7                        ◄──────── R (ready) ───────  namespaces exist
 8  create veth pair, enslave to bridge
 9  move the peer into the container's netns
10  allocate an IP, install iptables rules
11  write netstate.json
12  ──────────────── G (go) ───────────────────────►  sethostname
13                                                    mount proc/sys/dev/tmp
14                                                    mknod devices
15                                                    pivot_root(".", ".")
16                                                    configure eth0, routes
17                                                    mask /proc paths
18                                                    drop capabilities
19                                                    PR_SET_NO_NEW_PRIVS
20                                                    install seccomp filter
21                                                    block signals, signalfd
22                                                    fork -> execve(workload)
23                      ◄──────── S (started) ──────
24  mark Running, save state
25  ... container runs ...
26                      ◄──────── X (exit code) ─────  workload exited
27  record exit, tear down cgroup + network
```

Steps 3–10 are all registered with a rollback stack. A failure at step 10
removes the iptables rules, the IP lease, the veth pair and the cgroup, in
that order, before returning the error.

### Why the handshake

Without the **ready** message the parent would race the child's `execve`
while trying to move a network interface into a namespace that may not exist
yet. Without the **go** message init would mount and pivot before it has an
`eth0` to configure. Without the **started**/**error** reply a failed
`pivot_root` would surface as an opaque exit code instead of
`pivot_root failed: Invalid argument`.

### Why `pivot_root(".", ".")`

The usual form needs a `put_old` directory inside the new root, which has to
exist and be writable. The self-referential form stacks the old root on top
of the new one at `/` and then lazily unmounts it, leaving nothing behind and
working on a read-only rootfs. After the `umount2(".", MNT_DETACH)` the host
filesystem is genuinely unreachable, not merely hidden.

---

## Commands

| Command | What it does |
|---|---|
| `run <rootfs> <cmd>...` | Create and start; `-d` detaches |
| `create <rootfs> <cmd>...` | Create without starting |
| `start <container>` | Start a created container (`-a` to attach) |
| `stop <container>...` | SIGTERM, then SIGKILL the cgroup after `-t` seconds |
| `kill -s SIG <container>...` | Send one signal |
| `pause` / `unpause` | `cgroup.freeze` |
| `rm [-f] <container>...` | Delete state and release resources |
| `ls [-a] [--json] [-q]` | List containers |
| `inspect <container>...` | Full JSON state |
| `stats [-f] [--json]` | CPU, memory, pids, network counters |
| `logs [-f] [-n N]` | Captured output (detached containers) |
| `wait <container>...` | Block until exit; prints the code |
| `gc` | Reconcile state, remove orphans |
| `info` | Host capability report |

Containers can be named (`--name web`), referred to by name, by full id, or
by any unambiguous id prefix.

### Frequently used flags

```
-m, --memory 256m      --cpus 1.5        --pids 64        --read-only
-v /host:/ctr[:ro]     -e KEY=VALUE      -w /workdir      --hostname name
--network none|bridge|host               -p 8080:80[/udp]
--cap-add NET_RAW      --cap-drop all    --seccomp strict --user 1000:1000
```

---

## Configuration files

`--config container.toml` (JSON works too, and the same schema is what
`inspect` prints). [`examples/full.toml`](examples/full.toml) documents every
available option; a realistic one is shorter:

```toml
rootfs   = "/tmp/myrun-rootfs"
command  = ["/bin/sh", "-c", "exec /srv/app"]
hostname = "api"
read_only = true

[resources]
memory = "512m"
cpus   = 2
pids   = 128

[network]
mode = "bridge"
ip   = "10.87.0.10"

[[network.publish]]
host = 8080
container = 80

[security]
seccomp  = "strict"
cap_drop = ["all"]
```

Command line flags override the file.

---

## Failure handling

Anything the runtime creates on the way up is undone on the way down, in
reverse order. To prove that rather than assert it, the runtime has named
fault-injection points:

```sh
myrun info                                   # lists all 19 points
MYRUN_FAULT=after_veth_create myrun run --network bridge ./rootfs /bin/true
./scripts/check-leaks.sh                     # should report "Clean."
```

The integration suite fires every point in turn and then checks that the veth
count, cgroup count and IP lease count are all back where they started.

Exit codes follow `sysexits.h` conventions where they apply:

| Code | Meaning |
|---|---|
| 64 | usage error |
| 65 | invalid configuration |
| 66 | no such container |
| 67 | wrong state for the operation |
| 70 | syscall failure |
| 71 | unsupported on this host |
| 72 | injected fault |
| *n* | otherwise, the container's own exit code (128+*n* if signalled) |

---

## Building and testing

```sh
cargo build --release
cargo test                       # 155 unit + 9 CLI tests, no privileges needed

sudo ./scripts/setup-rootfs.sh /tmp/myrun-rootfs
sudo env MYRUN_PRIVILEGED_TESTS=1 MYRUN_TEST_ROOTFS=/tmp/myrun-rootfs \
     cargo test -- --test-threads=1        # + 41 privileged tests

./scripts/bench.sh 20                      # startup/teardown timings
./scripts/check-leaks.sh                   # host resource audit
```

Privileged tests print a `SKIP` line and pass when they cannot run, so
`cargo test` is still useful without root. See `docs/testing.md`.

Rust 1.70 or newer. No dependencies, so there is no `Cargo.lock` to audit and
nothing to vendor.

---

## Known limitations

These are deliberate scope decisions, not oversights:

- **Root only.** Rootless containers need user namespaces plus a setuid
  helper for networking. `docs/security.md` explains what would change.
- **No `exec` into a running container.** It needs `setns` into five
  namespaces plus PTY handling; the spec did not ask for it.
- **No image handling.** `myrun` takes a directory, not an OCI image. There is
  no registry client, no layer unpacking and no overlayfs.
- **Packet filtering shells out to `iptables`.** Everything else in this
  codebase talks to the kernel directly; nftables' netlink expression
  encoding is a serialisation project of its own. See `docs/networking.md`.
- **cgroup v2 only.** On a v1 or hybrid host, limits cannot be enforced and
  `myrun` refuses to pretend otherwise (override with
  `MYRUN_ALLOW_MISSING_CONTROLLERS=1`).
- **Attached `run` has a smaller crash window than `run -d`.** If the CLI is
  `SIGKILL`ed, init dies with it via `PDEATHSIG`, but the cgroup and network
  survive until the next `myrun gc`.

---

## Further reading

- [`docs/syscalls.md`](docs/syscalls.md) — every syscall used and why
- [`docs/security.md`](docs/security.md) — the sandbox, its ordering, and what it does not stop
- [`docs/networking.md`](docs/networking.md) — bridge, veth, IPAM, NAT, iptables
- [`docs/testing.md`](docs/testing.md) — what is tested, what needs a VM
- [`docs/bugs.md`](docs/bugs.md) — every real bug found during development, and its fix
- [`docs/myrun-architecture.md`](docs/myrun-architecture.md) — the original
  requirements document, preserved verbatim. A few file names it proposes
  (`make-rootfs.sh`, `leakcheck.sh`) ship under clearer names
  (`setup-rootfs.sh`, `check-leaks.sh`).
