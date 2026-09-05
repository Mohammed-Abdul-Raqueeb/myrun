# Networking

## Modes

| Mode | What the container gets |
|---|---|
| `none` (default) | Its own network namespace with only a loopback interface, brought up. No route off the box. |
| `bridge` | A veth pair into a host bridge, an address from the runtime's IPAM, a default route, NAT to the outside world, optional published ports. |
| `host` | No network namespace at all. Full access to the host's interfaces. No isolation. |

`none` is the default because a container that unexpectedly has network
access is a worse surprise than one that unexpectedly does not.

## Topology

```
   host namespace                                 container namespace
   ┌────────────────────────────────┐             ┌────────────────────┐
   │                                │             │                    │
   │  eth0 (host uplink)            │             │   lo    127.0.0.1  │
   │    │                           │             │                    │
   │    │  MASQUERADE               │             │   eth0  10.87.0.2  │
   │    │  (MYRUN-POST)             │             │      /24           │
   │    │                           │             │   default via      │
   │  myrun0  10.87.0.1/24  ────────┼── veth ─────┼──   10.87.0.1      │
   │  (bridge)                      │    pair     │                    │
   │    ├── mrv1a2b3c4d ────────────┘             └────────────────────┘
   │    └── mrv5e6f7a8b  (another container)
   └────────────────────────────────┘
```

Interface names are `mrv` + eight hex digits of an FNV-1a hash of the
container id. Linux caps interface names at 15 characters (`IFNAMSIZ - 1`),
so the 32-character id cannot be used directly. The hash is deterministic,
which is what lets `gc` recognise an orphaned interface by name alone.

## How a container is wired up

Host side, in `runtime/network.rs`:

1. Create `myrun0` if it does not exist, give it the gateway address, bring it up.
2. Lease an address from the IPAM file.
3. Create the veth pair (`RTM_NEWLINK` with `IFLA_INFO_KIND="veth"` and a
   nested `VETH_INFO_PEER`) — one netlink message creates both ends.
4. Set the MTU on both ends, enslave the host end to the bridge (`IFLA_MASTER`),
   bring it up.
5. Move the peer into the container's network namespace **by pid**, renaming
   it to `eth0` in the same message (`IFLA_NET_NS_PID` + `IFLA_IFNAME`).
6. Install the NAT and forwarding rules.

Container side, run by init after the go signal:

7. Bring up `lo` — it is down in a fresh namespace and a surprising amount of
   software assumes otherwise.
8. Add the address to `eth0` (the on-link subnet route comes with it).
9. Add the default route via the gateway.

Addressing is done **from inside** the namespace by the process that is
already there, rather than by `setns`-ing in from outside. There is no window
in which a half-configured interface is visible, and no namespace juggling in
the parent.

All of this is hand-built rtnetlink (`src/sys/netlink.rs`). The `ip` command
is never invoked.

## IPAM

Leases live in `<runtime root>/ipam.json`:

```json
{ "subnet": "10.87.0.0/24",
  "leases": [ { "ip": "10.87.0.2", "id": "a3f2..." } ] }
```

Every read-modify-write holds an `flock` on `<runtime root>/ipam.lock`.
Without it, two `myrun run` invocations racing each other will both read the
same file, both pick `.2`, and both write it back — and the second container
silently gets a duplicate address. The lock is not optional.

Behaviour worth knowing:

- The gateway, network and broadcast addresses are never handed out.
- Re-running an existing container id keeps its address.
- `--ip` is honoured if free and inside the subnet, rejected otherwise.
- Changing `--subnet` invalidates every lease from the old one.
- A corrupt lease file logs a warning and starts fresh rather than wedging
  the runtime forever.
- `myrun gc` releases leases whose container no longer exists.

## Packet filtering

**This is the one place `myrun` shells out to an external tool.** Everything
else talks to the kernel directly. nftables is the modern interface, and
building its netlink messages means encoding expression bytecode —
immediate, cmp, payload, meta and nat expressions, set descriptors, batch
transactions — which is a serialisation project in its own right and well
outside the scope of a container runtime exercise. Emitting `iptables`
commands is the honest, reviewable choice. It is recorded here as known
technical debt.

Rules live in three chains of our own, so nothing we flush can disturb
another tool's rules:

| Chain | Table | Hooked from | Contents |
|---|---|---|---|
| `MYRUN-PRE` | nat | `PREROUTING`, `OUTPUT` | DNAT rules for published ports |
| `MYRUN-POST` | nat | `POSTROUTING` | MASQUERADE rules |
| `MYRUN-FWD` | filter | `FORWARD` | ACCEPT rules for container traffic |

Every rule carries an iptables comment of the form `myrun:<container id>`, or
`myrun:base` for the shared ones. Teardown parses `iptables -S`, finds the
tagged rules and deletes exactly those. No line-number arithmetic, no
guessing, and rules belonging to Docker or a firewall manager are never
touched.

### The rules, and why each exists

```
# outbound NAT: container subnet leaving via anything but the bridge
-A MYRUN-POST -s 10.87.0.0/24 ! -o myrun0 -j MASQUERADE

# loopback publishing: rewrite the 127.0.0.1 source so the container can reply
-A MYRUN-POST -s 127.0.0.0/8 -o myrun0 -j MASQUERADE

# hairpin: a container reaching its own published port via the host address
-A MYRUN-POST -s <ip> -d <ip> -p tcp --dport <cport> -j MASQUERADE

# published port
-A MYRUN-PRE -p tcp --dport <hport> -j DNAT --to-destination <ip>:<cport>

# container -> world, and the replies back
-A MYRUN-FWD -i myrun0 ! -o myrun0 -j ACCEPT
-A MYRUN-FWD -o myrun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MYRUN-FWD -i myrun0 -o myrun0 -j ACCEPT
-A MYRUN-FWD -o myrun0 -d <ip> -p tcp --dport <cport> -j ACCEPT
```

`! -o myrun0` on the outbound rule keeps container-to-container traffic
un-NATed, which matters if you ever want to see real source addresses in a
container's logs.

### Sysctls

Bridge networking sets two kernel knobs:

- `net.ipv4.ip_forward=1` — without it a container reaches the host and
  nothing beyond it.
- `net.ipv4.conf.all.route_localnet=1` — required for
  `-p 8080:80` to be reachable at `127.0.0.1:8080`. A DNAT from a loopback
  source to a non-loopback destination is otherwise dropped by the martian
  source check. Docker sets the same knob for the same reason.

`route_localnet` has a cost: with it enabled, a packet arriving from outside
claiming a `127/8` destination would be routed. So the runtime also installs
a guard:

```
-A INPUT ! -i lo -d 127.0.0.0/8 -m conntrack --ctstate NEW -j DROP
```

**The `--ctstate NEW` match is load-bearing.** Without it this rule also drops
the *return* traffic of our own published ports: a connection to
`127.0.0.1:<published>` is DNATed out to the container, and the reply comes
back on the bridge and is un-NATed to a `127.0.0.1` destination before it
reaches `INPUT`. Dropping that breaks exactly the feature `route_localnet`
was enabled for. This was found by testing, not by reading.

## DNS and `/etc/hosts`

Init writes `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf` inside the
new root, best effort. A rootfs may legitimately have no `/etc`, and a
container that cannot resolve names is still a working container, so a
failure here is logged rather than fatal. Nameservers come from `--dns`
(default `1.1.1.1`, `8.8.8.8`).

## Teardown

When a container exits:

1. Delete every iptables rule tagged with its id.
2. Delete the host veth if it still exists — usually it does not, because a
   veth pair is destroyed when either end's namespace goes away.
3. Release the IP lease.

`myrun gc` handles what a crash left behind: it deletes `mrv*` interfaces no
live container owns, releases stale leases, and — once no containers remain —
removes the shared rules, the chains and the bridge itself, leaving the host's
packet filter as it was found.

Verify with `./scripts/check-leaks.sh`, which audits veths, bridges, cgroups,
iptables rules and leases and exits non-zero if anything is outstanding.

## Limitations

- IPv4 only.
- One bridge and one subnet per host by default; `--bridge`/`--subnet` allow
  others but there is no network object to manage them.
- No container-to-container name resolution. Containers reach each other by
  address.
- No bandwidth shaping.
- No per-container firewall policy: anything on the bridge can reach anything
  else on it.
