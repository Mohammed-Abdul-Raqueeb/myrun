# Bug log

The specification (`docs/myrun-architecture.md`) suggests keeping a record of
each real bug: the symptom, the wrong hypothesis, and the fix. This is that
record. Every entry is a bug that actually happened during development, not
a hypothetical.

---

## 1. Reading `/dev/urandom` hung, then OOM-killed the test binary

**Symptom.** `cargo test` froze and the process was killed. No panic, no
output.

**Wrong hypothesis.** A deadlock in the new `FileLock` code, since the tests
that hung all touched the state store.

**Cause.** `util::generate_id()` used `fs::read("/dev/urandom")`. That reads
until EOF, and a character device that never returns EOF produces an
infinite read. The allocator kept growing the buffer until the kernel
stepped in.

**Fix.** Open the device and read exactly 16 bytes. Character devices are not
files; anything that assumes a length is wrong.

---

## 2. Allocation in the post-`clone3` child

**Symptom.** Intermittent hangs between `clone3` and `execveat`, roughly one
run in twenty.

**Cause.** The child path formatted an error string before `execveat`. After
`clone`, the child is running in a copy of a process that may hold the
allocator lock; `malloc` there is not async-signal-safe and can deadlock.

**Fix.** `ExecPlan` pre-computes every `CString`, the argv/envp pointer
arrays and the exe descriptor in the parent. The child does nothing but
`prctl`, two `dup2`s, `close_range` and `execveat` — no allocation, no
formatting, and `_exit(127)` if the exec fails.

---

## 3. The signalfd test failed under cargo's parallel runner

**Symptom.** `sys::signal` tests passed alone and failed in the full suite.

**Wrong hypothesis.** A race in the `signalfd` wrapper.

**Cause.** The test sent a signal with `kill(getpid(), ...)`. A
process-directed signal is delivered to *any* thread that has it unblocked,
and the test binary is multi-threaded, so it was frequently handled by an
unrelated cargo thread instead of the one polling the descriptor.

**Fix.** The test uses `tgkill(getpid(), gettid(), sig)` for thread-directed
delivery.

---

## 4. Unit tests raced on `MYRUN_ROOT`

**Symptom.** `ipam::tests::allocation_lifecycle` failed with addresses it
should never have seen — leases that belonged to a different test.

**Wrong hypothesis.** A bug in the allocator's free-address scan.

**Cause.** Several test modules set the `MYRUN_ROOT` environment variable to
point at their own temporary directory. Cargo runs unit tests as parallel
threads *inside one process*, so the variable is shared: one test's root
silently became another's.

**Fix.** `src/testutil.rs` provides a `TempRoot` that holds a process-wide
mutex for as long as the variable is set. The lock recovers from poisoning,
so one failing test does not cascade into all the others.

---

## 5. A fault at `after_cgroup_create` leaked the cgroup directory

**Symptom.** `MYRUN_FAULT=after_cgroup_create myrun run ...` left a directory
under `<cgroup2 mount>/myrun/` behind. The leak detector caught it; nothing
else would have.

**Cause.** The fault fires *inside* `Cgroup::create()`, after `mkdir` but
before the `Cgroup` value is returned. The caller therefore never received
anything to register with its rollback stack, so there was nothing to undo.

**Fix.** `Cgroup::create()` cleans up its own directory if anything between
the `mkdir` and the return fails. A constructor owns what it creates until it
hands it over.

---

## 6. `gc` never removed the shared iptables rules

**Symptom.** `scripts/check-leaks.sh` reported six `myrun:base` rules
outstanding after every container had been removed.

**Cause.** `gc` removed per-container rules, orphaned interfaces and the
bridge, but the shared `MASQUERADE`/`FORWARD` rules and the three custom
chains were only ever created, never torn down.

**Fix.** When no containers remain, `gc` calls `nat::teardown_base()`. The
host's packet filter is left exactly as it was found.

---

## 7. Publishing a port to `127.0.0.1` timed out

**Symptom.** `-p 18080:9000` worked when connecting to the host's real
address and hung when connecting to `127.0.0.1`.

**Wrong hypothesis (first).** The DNAT rule was missing from the `OUTPUT`
chain, so host-originated traffic was never translated. It was there, and the
packet counters proved the SYN was being translated.

**Wrong hypothesis (second).** Missing `net.ipv4.conf.all.route_localnet`.
That *was* missing and did need setting — but enabling it did not fix the
hang, and adding a loopback `MASQUERADE` did not either.

**Cause.** The guard rule added alongside `route_localnet`:

```
-A INPUT ! -i lo -d 127.0.0.0/8 -j DROP
```

The reply from the container comes back on the bridge and is un-NATed to a
`127.0.0.1` destination *before* it reaches `INPUT`. The guard was dropping
the return traffic of the very feature it was protecting. The `INPUT` chain's
packet counter showed five drops — the retransmitted SYN-ACKs.

**Fix.** `-m conntrack --ctstate NEW` on the guard. It still blocks spoofed
inbound `127/8` traffic; it no longer blocks established replies. Found by
reading packet counters, not by reading code.

---

## 8. `pivot_root` verification test matched the wrong field

**Symptom.** `mount_namespace_and_pivot_root_detach_the_host` failed with
"old root still mounted", but the container was demonstrably isolated.

**Cause.** The test ran `grep -c ' / ' /proc/self/mountinfo`. Field 4 of a
mountinfo line is the *root within the filesystem*, which is `/` for nearly
every entry. The grep counted nine matches when there was exactly one mount
whose *mount point* was `/`.

**Fix.** `awk '$5 == "/"'`. A test that checks the wrong thing is worse than
no test: this one would have passed a genuinely broken pivot just as readily.

---

## 9. `myrun wait` exited with the container's exit code

**Symptom.** `wait_returns_the_exit_code` failed: the command printed the
right number but the test's success assertion tripped.

**Cause.** A design mistake, not a coding one. `cmd_wait` returned the
container's exit code as its own. That makes "the container exited 1"
indistinguishable from "wait itself failed".

**Fix.** `wait` prints the code and exits 0, the convention `docker wait`
uses. It exits non-zero only when the wait genuinely fails — unknown
container, or timeout.

---

## 10. An unreadable start time made a live container look dead

**Symptom.** None observed — found by audit rather than by failure.

**Cause.** `launch()` recorded `init_start_time` as `0` when
`/proc/<pid>/stat` could not be read, and `init_is_alive()` passed that
straight to `process_alive(pid, Some(0))`. No process has a start time of
zero, so the comparison could never match: a perfectly healthy container
would be reported dead and `gc` would tear it down underneath itself.

**Fix.** A recorded start time of `0` means "unknown" and falls back to a
pid-only liveness check. `launch()` now logs a warning when this happens,
because it also means PID reuse is no longer detectable for that container.

---

## 11. Descriptors leaked on the launch failure path

**Symptom.** None observed — found by audit.

**Cause.** `launch()` created the sealed-memfd descriptor and the cgroup
directory descriptor, then performed several fallible steps before closing
them. Any `?` in between leaked both — and the memfd holds a full copy of the
binary in memory.

**Fix.** A small `sys::OwnedFd` RAII wrapper. The descriptors close on scope
exit whichever way the function leaves.

---

## 12. Two panic paths in the TOML parser

**Symptom.** None observed — found by audit, then covered with tests.

**Cause.** `table_at()` did `node.get_mut(seg).unwrap()` immediately after a
`set()` that is a no-op on a non-object, and the string scanner did
`s[i..].chars().next().unwrap()` where `i` is a byte index — slicing a `&str`
at a non-boundary panics. Neither was reachable through the current call
graph, but both are on the path that parses a **user-supplied config file**,
where a panic is never an acceptable outcome.

**Fix.** Both return errors or step over the byte. Added
`malformed_input_never_panics` regression tests to both the TOML and JSON
parsers, covering truncated escapes, unterminated strings, unbalanced
brackets and multi-byte UTF-8.

---

## 13. `--config` precedence depended on argument order

**Symptom.** `myrun run -d --name fullex --config examples/full.toml`
created a container called `example` — the name from the file — and
`myrun inspect fullex` then reported "not found".

**Cause.** The argument parser applied the config file *at the point where
`--config` appeared*, replacing everything parsed so far. So
`--name a --config f.toml` and `--config f.toml --name a` meant different
things, and only the second did what the documentation promised.

**Fix.** `parse_run` now makes two passes over the same tokens. The first
discovers `--config` and discards everything else; the file is loaded; the
second pass applies every flag on top of it. Flags override the file
wherever they sit. Two regression tests assert both orderings produce the
same result, and that a positional command still overrides the file's while
leaving the file's `rootfs` intact.

**Found by** writing `examples/full.toml` and trying to use it — which is
the argument for shipping a worked example rather than only documenting the
options.

---

## 14. Multi-line arrays were rejected (limitation, then lifted)

**Symptom.** `examples/full.toml` failed to parse:
`multi-line arrays are not supported; keep the array on one line`.

**Assessment.** Not a bug — a documented limit of the TOML subset. But it
forced `masked_paths` to be written as a single 200-column line, which is
exactly the kind of thing that stops people using a config file at all.

**Fix.** A `logical_lines()` pre-pass folds continuation lines into one
logical line, tracking bracket depth while ignoring brackets inside quoted
strings, and stripping comments per physical line first so a `#` inside an
array does not swallow the rest of it. An unbalanced array at end of input is
now a clear "unterminated array starting on line N". Three tests cover
comments inside arrays, brackets inside strings, and the unterminated case.
