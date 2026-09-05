# Syscalls used by myrun

Every kernel call the runtime makes, what it is for, and why it is the one
chosen. `myrun` links against libc for the thin wrappers but uses the
variadic `syscall(2)` entry point for anything glibc does not expose
portably (`clone3`, `pivot_root`, `setns` on older glibc, `seccomp`,
`memfd_create`, `execveat`, `capget`/`capset`, `pidfd_open`, `close_range`).

Source of truth: `src/sys/ffi.rs` holds the numbers and structures;
`src/sys/*.rs` holds the wrappers.

---

## Process creation and execution

| Syscall | Where | Why |
|---|---|---|
| `clone3` | `sys/process.rs` | Creates the container's init process with all `CLONE_NEW*` flags in one call. Chosen over `clone(2)` for `CLONE_INTO_CGROUP` (places the child in its cgroup atomically at creation, closing the window in which a fork bomb could escape the limit) and `CLONE_PIDFD` (a race-free handle on the child). |
| `clone` | `sys/process.rs` | Fallback when `clone3` returns `ENOSYS`/`EINVAL` (pre-5.3 kernels). Loses atomic cgroup placement, so the process is moved by writing `cgroup.procs` instead. |
| `fork` | `sys/process.rs`, `runtime/init.rs`, `runtime/shim.rs` | Init forks the workload; the CLI forks the shim. No namespace changes are wanted at these points, so plain `fork` is right. |
| `execveat` | `sys/process.rs` | Executes the sealed memfd copy of the runtime binary via `AT_EMPTY_PATH`. Executing an fd rather than a path is what makes the CVE-2019-5736 mitigation work. |
| `execve` | `runtime/init.rs` | Executes the workload itself, by path, inside the container. |
| `memfd_create` + `fcntl(F_ADD_SEALS)` | `sys/process.rs` | Copies the runtime binary into an anonymous file sealed with `F_SEAL_WRITE`/`F_SEAL_SHRINK`/`F_SEAL_GROW`. A malicious image cannot rewrite `/proc/self/exe` and take over the host runtime. |
| `waitpid` | `sys/process.rs` | Reaps children. Init calls it in a loop with `WNOHANG` to drain every orphan the PID namespace hands it. |
| `_exit` | init, shim | Terminates without running destructors — correct in a process whose filesystem has been pivoted away, and in a forked child that must not flush the parent's buffers. |
| `close_range` | `sys/process.rs` | Closes every descriptor above the two the child needs, so nothing from the parent leaks into the container. |
| `fcntl(F_DUPFD_CLOEXEC)` | `sys/process.rs` | Moves the sync and exe descriptors above the low range before the child `dup2`s onto fds 3 and 4, so the source cannot be clobbered. |
| `prctl(PR_SET_PDEATHSIG)` | `sys/mod.rs` | Init receives `SIGKILL` if its parent dies, so a killed CLI cannot leave an untracked container running. |
| `prctl(PR_SET_NAME)` | `sys/mod.rs` | Labels the shim and init in `ps`, which matters when three myrun processes are involved in one container. |

---

## Namespaces

| Syscall / flag | Where | Why |
|---|---|---|
| `CLONE_NEWPID` | `config.rs` → `clone3` | The container's init becomes PID 1 of a new namespace and inherits every orphan in it. |
| `CLONE_NEWNS` | same | Mount namespace; without it every mount the container makes would appear on the host. |
| `CLONE_NEWUTS` | same | Lets the container set its own hostname without touching the host's. |
| `CLONE_NEWIPC` | same | Separate System V IPC and POSIX message queues. |
| `CLONE_NEWNET` | same | Fresh network stack with only a down `lo`; the veth peer is moved in afterwards. |
| `CLONE_NEWCGROUP` | same | The container sees its own cgroup as `/`, so `/sys/fs/cgroup` does not reveal the host's hierarchy. |
| `setns` | `sys/mod.rs` | Enter another process's namespace. Used by helper paths and available for future `exec`. |
| `unshare` | `sys/mod.rs` | Namespace changes outside of a clone; used in tests and helpers. |
| `/proc/<pid>/ns/<kind>` (`stat`) | `sys/mod.rs` | Namespace identity by inode number — the reliable way to assert "these two processes are/are not in the same namespace". |

User namespaces are deliberately **not** used; see `docs/security.md`.

---

## Filesystem

| Syscall | Where | Why |
|---|---|---|
| `mount` | `sys/mount.rs` | Every mount, remount, bind and propagation change. The first call is `mount(NULL, "/", NULL, MS_REC\|MS_PRIVATE, NULL)` — without it the namespace inherits shared propagation from systemd and every subsequent mount leaks to the host. |
| `mount(MS_BIND)` | `runtime/filesystem.rs` | Binds the rootfs onto itself (`pivot_root` requires a mount point, not a directory), and provides user volumes. |
| `mount(MS_REMOUNT\|MS_RDONLY)` | same | A read-only bind needs a second call: `MS_RDONLY` is ignored in the initial `MS_BIND`. |
| `pivot_root` | `runtime/filesystem.rs` | Replaces the root. Used in the `pivot_root(".", ".")` form so no `put_old` directory is needed and the rootfs may be read-only. Preferred over `chroot`, which is escapable by any process holding a descriptor outside the new root. |
| `umount2(MNT_DETACH)` | same | Lazily detaches the old root stacked at `/` after the pivot. This is the step that makes the host filesystem genuinely unreachable. |
| `chdir` | same | Into the rootfs before pivoting, into `/` after, then into the configured working directory. |
| `mkdir` | same | Mount points inside the rootfs. |
| `mknod` | same | `/dev/null`, `zero`, `full`, `random`, `urandom`, `tty` as real character devices. Falls back to bind-mounting the host node when `mknod` is denied. |
| `symlink` | same | `/dev/fd`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`, `/dev/ptmx`. |
| `open`/`openat` | throughout | Files, cgroup directories (`O_DIRECTORY` for `CLONE_INTO_CGROUP`), the container log. |
| `read`, `write`, `close` | throughout | The sync channel, cgroup control files, `/proc` files. |
| `dup2` | shim, `clone3` child | Redirect stdio to the container log; place the sync and exe fds at 3 and 4. |
| `readlink` | `sys/mount.rs` | `/proc/self/exe` and namespace links. |
| `flock` | `sys/mod.rs` | Serialises read-modify-write on the state files and the IP lease file. Two concurrent `myrun run` invocations must never be handed the same address. |
| `rename` + `fsync` | `util/mod.rs` | Atomic state writes: write a temp file, fsync, rename. A crash mid-write must not leave a truncated `state.json`. |
| `/proc/self/mountinfo` (read) | `sys/mount.rs` | Parsed to check propagation, verify the pivot, and find the cgroup2 mount. |

---

## cgroups (v2)

Not syscalls, but the kernel interface the runtime depends on most.

| File | Use |
|---|---|
| `cgroup.controllers` | What the parent can delegate. |
| `cgroup.subtree_control` | Written as `+memory`, `+cpu`, `+pids`, one at a time so one missing controller does not discard the rest. |
| `cgroup.procs` | Fallback process placement when `CLONE_INTO_CGROUP` is unavailable. |
| `memory.max`, `memory.swap.max` | Memory limit. `--memory-swap` is the combined total, so the swap value written is the difference — v2 counts swap separately, unlike v1's `memsw`. |
| `memory.current`, `memory.peak`, `memory.events` | Statistics and OOM detection (`oom_kill`). |
| `cpu.max` | `"<quota> 100000"`; `--cpus 1.5` becomes `150000 100000`. |
| `cpu.weight`, `cpu.stat` | Relative shares; usage and throttling counters. |
| `pids.max`, `pids.current` | Process count limit. |
| `cgroup.freeze` | `pause`/`unpause`. Better than `SIGSTOP`: the workload cannot observe or block it, and it applies to the whole subtree atomically. |
| `cgroup.kill` | `stop` escalation and forced removal. Nothing can fork away from it, which a `kill(-pid)` loop cannot promise. |
| `cgroup.events` | `populated` tells us whether anything is still alive in the subtree. |

---

## Signals

| Syscall | Where | Why |
|---|---|---|
| `sigprocmask` | `sys/signal.rs` | Blocks the forwarded set before the fork so no signal is lost in the window between fork and the supervision loop. |
| `signalfd4` | same | Turns signals into readable events. PID 1 does **not** get default signal dispositions, so an unhandled `SIGTERM` is silently discarded — a `signalfd` avoids relying on handlers entirely and keeps the loop async-signal-safe. |
| `poll` | same | Waits on the signalfd and the sync channel together, with a timeout so a missed `SIGCHLD` cannot wedge init. |
| `kill` | `sys/process.rs` | Signal forwarding and the stop sequence. |
| `tgkill` | tests | Thread-directed delivery — needed because the test binary is multi-threaded and a process-directed signal could be handled by the wrong thread. |
| `pidfd_open`, `pidfd_send_signal` | `sys/process.rs` | Signal a process without the PID-reuse race. |
| `rt_sigaction` | `sys/signal.rs` | Resets handlers to default in the workload child, so it behaves exactly as if a shell had started it. |

---

## Security

| Syscall | Where | Why |
|---|---|---|
| `capget` / `capset` (v3) | `sys/caps.rs` | Reads and sets the permitted, effective and inheritable sets. |
| `prctl(PR_CAPBSET_DROP)` | same | Removes capabilities from the bounding set so they cannot be regained by any means, including a setuid binary. |
| `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)` | same | Clears the ambient set, which would otherwise survive `execve`. |
| `prctl(PR_SET_NO_NEW_PRIVS)` | `sys/mod.rs` | Makes setuid binaries inside the rootfs harmless. Irreversible once set, and required before a seccomp filter can be installed without `CAP_SYS_ADMIN` — which is exactly the trade we want. |
| `seccomp(SECCOMP_SET_MODE_FILTER)` | `sys/seccomp.rs` | Installs a hand-assembled classic BPF program. The filter checks `arch` first (a mismatched architecture is killed, closing the x32 bypass), then compares `nr` against the deny list. |
| `setgid`, `setgroups`, `setuid` | `sys/caps.rs` | `--user`. Group changes must come first: after `setuid` the privilege to make them is gone. |
| `prctl(PR_GET_NO_NEW_PRIVS)` | `sys/mod.rs` | Post-condition verification in tests. |

**Ordering is load-bearing:** capabilities → `no_new_privs` → seccomp →
`setgid`/`setuid` → `execve`. Any other order either fails outright or fails
open. `runtime/security.rs` enforces it and `precheck` rejects combinations
that cannot work (for example `--no-new-privs=false` with seccomp).

---

## Networking (rtnetlink)

All hand-built `AF_NETLINK`/`NETLINK_ROUTE` messages in `sys/netlink.rs`; no
`ip` command is involved.

| Message | Use |
|---|---|
| `RTM_NEWLINK` + `IFLA_INFO_KIND="veth"` + `VETH_INFO_PEER` | Create the veth pair in one request. |
| `RTM_NEWLINK` + `IFLA_INFO_KIND="bridge"` | Create `myrun0` on demand. |
| `RTM_SETLINK` + `IFLA_MASTER` | Enslave the host end to the bridge. |
| `RTM_SETLINK` + `IFF_UP` | Bring interfaces up. |
| `RTM_SETLINK` + `IFLA_MTU` | Apply `--mtu` to both ends. |
| `RTM_NEWLINK` + `IFLA_NET_NS_PID` + `IFLA_IFNAME` | Move the peer into the container's netns and rename it `eth0` in one operation. |
| `RTM_NEWADDR` | Assign the container address and the bridge gateway. |
| `RTM_NEWROUTE` | Default route via the gateway; on-link subnet route. |
| `RTM_DELLINK` | Teardown. |
| `RTM_GETLINK` (dump) + `IFLA_STATS64` | Interface enumeration and `stats` counters. |

`socket`, `bind`, `sendto`, `recvfrom` back all of the above; `socketpair`
creates the parent↔init sync channel.

---

## Miscellaneous

| Syscall | Why |
|---|---|
| `sethostname` | Inside the UTS namespace. |
| `setsid` | The shim leaves the caller's session so a Ctrl-C in the shell does not kill the container. |
| `setrlimit` | `RLIMIT_NOFILE` for the container. |
| `sysconf` (`_SC_CLK_TCK`, `_SC_NPROCESSORS_ONLN`, `_SC_PAGESIZE`) | Converting `/proc` jiffies to time, CPU counts, page accounting. |
| `clock_gettime` | Timestamps in state files. |
| `getpid`, `getppid`, `geteuid` | Identity checks and logging. |
| `/proc/<pid>/stat` (read) | Field 22 (`starttime`) is recorded with every PID so a recycled PID is never mistaken for a live container. |
| `/dev/urandom` (read) | 16 bytes for the container id. Read with an explicit length — reading the whole "file" never terminates. |
