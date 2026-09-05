# Testing

## Layers

| Layer | Location | Count | Needs |
|---|---|---|---|
| Unit | `#[cfg(test)]` in `src/**` | 155 | nothing |
| CLI integration | `tests/cli.rs` | 9 | nothing |
| Lifecycle & isolation | `tests/lifecycle.rs` | 21 | root + opt-in |
| Security, network, cgroups, faults | `tests/isolation.rs` | 20 | root + opt-in |

## Running them

```sh
# Everything that works unprivileged.
cargo test

# Real containers.
sudo ./scripts/setup-rootfs.sh /tmp/myrun-rootfs
sudo env MYRUN_PRIVILEGED_TESTS=1 MYRUN_TEST_ROOTFS=/tmp/myrun-rootfs \
     cargo test -- --test-threads=1
```

`--test-threads=1` for the privileged suites: they create bridges and
iptables rules on the shared host, and the leak-detection assertions compare
global interface and cgroup counts, which parallel tests would corrupt.

## Gating

Privileged tests are **opt-in twice over** — they need root *and*
`MYRUN_PRIVILEGED_TESTS=1`. They create real network interfaces and firewall
rules on the machine running them, which would be rude to do to a developer
who typed `cargo test` expecting unit tests.

When a test cannot run it prints a reason and passes:

```
test cpu_limit_is_applied ... SKIP cpu_limit_is_applied: cgroup v2 controller
  "cpu" is not delegated on this host (hybrid or v1 cgroups); boot with
  systemd.unified_cgroup_hierarchy=1
```

A silent skip would be worse than a failure — it hides the fact that nothing
was verified. Three guards exist:

- `require_privileged!` — root, opt-in, and a test rootfs
- `require_controllers!` — a specific cgroup v2 controller is delegated
- explicit checks inside tests, e.g. the non-root error-message test skips
  when running *as* root

## Isolation between tests

Each test gets a `Sandbox`: a unique `MYRUN_ROOT` under `/tmp`, torn down on
`Drop` with a `gc`, a forced removal of every container, and a second `gc`.
Sharing `/run/myrun` would mean one test's `gc` deleting another's container.

Unit tests that manipulate process-global state (`MYRUN_ROOT`) serialise on
a shared mutex in `src/testutil.rs`. Cargo runs unit tests in parallel
threads inside one process, so an environment variable set by one test is
visible to all of them; the resulting failures look like phantom bugs in the
IP allocator. This cost real debugging time and the lock is the fix.

## What the privileged suites actually check

Isolation is verified from **inside** a real container, not by inspecting the
code path:

- PID namespace — the workload is PID 2, and `/proc` shows fewer than ten processes
- Mount namespace — a host marker file is invisible, and exactly one entry in
  `/proc/self/mountinfo` has `/` as its *mount point* (field 5, not a grep for
  `" / "` — field 4 is `/` for nearly every entry, a mistake the first version
  of this test made)
- UTS — the container hostname is set and the host's is unchanged
- Devices — all six nodes exist, and `/dev/zero` and `/dev/null` behave
- Security — `CapEff`, `NoNewPrivs` and `Seccomp` are parsed from
  `/proc/self/status`; `CAP_SYS_ADMIN` and `CAP_NET_RAW` bits are asserted
  absent; `mount` is denied; `--cap-drop all` yields `CapEff: 0`
- Masked paths — `/proc/kcore` reads zero bytes, `/proc/sysrq-trigger` is unwritable
- Networking — address, default route, gateway reachable by ping, unique
  addresses across three concurrent containers, a payload delivered through a
  published port over a real TCP connection
- Signals — a workload that traps `SIGTERM` and exits 17 must exit 17, which
  is only possible if init forwarded the signal rather than the container
  being killed after the grace period
- Reaping — five orphaned children leave zero zombies
- Freezing — output stops while paused and resumes after unpause

## Fault injection

Nineteen named points (`myrun info` lists them). Setting
`MYRUN_FAULT=<point>` makes the runtime fail there.

```sh
MYRUN_FAULT=after_veth_create myrun run --network bridge ./rootfs /bin/true
./scripts/check-leaks.sh
```

`every_fault_point_rolls_back_cleanly` fires all seventeen reachable-at-start
points in turn and then asserts the veth count, cgroup count and IP lease
count are back where they started, and that nothing panicked.
`repeated_failures_do_not_accumulate_state` runs the same failure five times
and checks for drift.

This found a real bug: a fault at `after_cgroup_create` leaked the cgroup
directory, because the failure happened *inside* `Cgroup::create()` before
the `Cgroup` was returned, so the caller had nothing to register with its
rollback stack. `create()` now cleans up its own directory on failure.

Every bug the tests and the code audit turned up is written down in
[`bugs.md`](bugs.md), with the symptom, the hypothesis that turned out to be
wrong, and the fix.

## Crash recovery

`gc_reclaims_a_crashed_containers_resources` SIGKILLs both the shim and init
without letting either record an exit status, leaving a `state.json` that
claims the container is running. `myrun gc` must then notice the process is
gone, reconcile the state to `stopped`, and remove the iptables rules.

PID reuse is handled by recording `/proc/<pid>/stat` field 22 (`starttime`)
alongside every PID; a recycled PID has a different start time and is not
mistaken for the container.

## Benchmarks

```sh
./scripts/bench.sh 20
```

Measured in this development environment (Linux 6.18, single CPU,
debug build, hybrid cgroups):

```
run /bin/true (no network)         n=10   avg=66     min=22     max=231 (ms)
run /bin/true (bridge network)     n=10   avg=117    min=70     max=278 (ms)
run --rm /bin/true                 n=10   avg=66     min=23     max=232 (ms)
create (no start)                  n=10   avg=3      min=3      max=4   (ms)
```

Roughly 22 ms of floor for a container, about 50 ms more for bridge
networking (bridge creation, veth pair, the netns move and four `iptables`
invocations). The wide max is a single-CPU sandbox under load; a release
build on a real machine is faster.

## Leak checking

```sh
./scripts/check-leaks.sh          # audit; exits 1 if anything is outstanding
./scripts/check-leaks.sh --fix    # audit, then run myrun gc
```

Audits container state directories, `mrv*` interfaces, the bridge, container
cgroups, `myrun:`-tagged iptables rules and IP leases.

## What cannot be tested here

**cgroup limit enforcement.** This environment runs hybrid cgroups: cgroup v2
is mounted but only `hugetlb` is delegated to it; `memory`, `cpu` and `pids`
live on the v1 hierarchies. The three tests that check real enforcement
(`memory_limit_is_enforced`, `cpu_limit_is_applied`, `pids_limit_is_enforced`)
skip with an explicit message.

They need a host or VM booted with:

```
systemd.unified_cgroup_hierarchy=1
```

or any environment where `cat /sys/fs/cgroup/cgroup.controllers` includes
`memory cpu pids`. The CI workflow runs the full suite on a GitHub-hosted
Ubuntu runner, which is unified.

What *was* verified here: the cgroup is created, the correct values are
written to the correct files, `cgroup.freeze` genuinely stops the workload,
`cgroup.kill` genuinely kills it, statistics are read back correctly, and the
runtime refuses to run with an unenforceable limit unless
`MYRUN_ALLOW_MISSING_CONTROLLERS=1` is set.
