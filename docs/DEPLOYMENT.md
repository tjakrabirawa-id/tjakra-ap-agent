# Deploying the tjakra-satria patrol agent

Supported patterns:

0. One-command Docker, the easiest path: a bare `docker run` enrolls on first boot
   and runs. No repo to clone, no binary to build.
1. systemd native, for a dedicated host where the agent runs directly on the OS.
2. Shared network-namespace container, for a shared host where the agent must
   enforce firewall rules that scope only to one target, not the whole host.

Platform URLs (the `SERVER` / `--server` value is the platform BACKEND API base
URL: the agent ships logs to it and polls signed commands from it):

- Production: `https://satria-api.tjakrabirawa.id`
- Dev: `https://satria-api-dev.tjakrabirawa.id`
- Local: `http://localhost:4000` (or `http://host.docker.internal:4000` from a
  container reaching a host-published backend)

The enroll token comes from the platform console (Patrol, "Enroll agent"). It is
single-use. Do not paste it into a file, a chat, or a shell history you keep. Pass
it once, as `ENROLL_TOKEN` to `docker run`, or to `enroll` / `install.sh`.

## Pattern 0: one-command Docker (easiest)

The published image enrolls itself on first boot from two environment variables,
then runs. The token is read from the environment only at run time; it is never
baked into an image layer and is written nowhere but the 0600 config on the data
volume.

```sh
docker run -d \
  --name patrol-agent \
  --cap-add NET_ADMIN \
  --restart unless-stopped \
  -e SERVER=https://satria-api.tjakrabirawa.id \
  -e ENROLL_TOKEN=<ENROLL_TOKEN> \
  -v patrol-agent:/data \
  tjakradev/tjakra-satria-agent:latest
```

The `-v patrol-agent:/data` named volume holds the enrolled `agent.json`, so the
container can be replaced without re-enrolling (the token is single-use). Extra
behavior is env-driven: `-e ENFORCE=1` to apply blocks (needs `NET_ADMIN`, above),
`-e CONSOLE=1` for the remote console, `-e LOG_FILE=/logs/access.log` (mount the
log with `-v /var/log/app:/logs:ro`) to tail and ship a log, `-e BLOCK_CONTAINER=<name>`
to scope blocks to a target container's netns, `-e INSECURE=1` for a dev backend
with a self-signed cert. To scope blocks to a target container instead of the host,
add `--network container:<target>` (see Pattern 2).

Confirm it enrolled: `docker logs patrol-agent` shows `enrolled agent <id> ...` then
`agent <id> polling <server> every 5s`, and the agent appears on the Patrol Agents
tab, online, within seconds.

An explicit `enroll` or `run` subcommand after the image name still runs the binary
directly, so the manual two-step flow in Pattern 2 keeps working.

## Pattern 1: systemd native

For a dedicated host, clone the public agent repo and run the installer: it does
everything, resolve or build the binary, install it, enroll, write the config, and
install and start the service.

```sh
git clone https://github.com/tjakrabirawa-id/tjakra-satria-agent.git
cd tjakra-satria-agent
sudo ./install.sh \
  --token <ENROLL_TOKEN> \
  --server https://satria-api.tjakrabirawa.id \
  --log-file /var/log/app/access.log \
  --enforce
```

What it does:

- Installs the binary to `/usr/local/bin/tjakra-satria-agent`.
- Creates `/etc/tjakra-satria-agent/` (0700) and writes the enrolled config to
  `/etc/tjakra-satria-agent/agent.json` (0600).
- Writes `/etc/systemd/system/tjakra-satria-agent.service` with the chosen flags baked
  into `ExecStart`.
- Runs `systemctl daemon-reload`, `enable`, and `restart`.

Re-running the installer updates the unit and restarts the service. Enroll tokens
are single-use, so a plain re-run keeps the existing enrollment; pass
`--re-enroll` with a fresh token to replace it. A re-run also rewrites the unit's
run flags from that run's arguments alone, so read "Upgrading" below before using
it to update a host that is already running.

### The enforce and user tradeoff

`-enforce` lets the agent change the host. It needs privileges:

- `block_ip` and `revert_block` run `iptables`, which needs `NET_ADMIN` (root or
  `CAP_NET_ADMIN`).
- `disable_user` runs `usermod -L`, which needs root.

The installer defaults the service to `User=root`, which covers both. If you do
not use `-enforce`, or you never expect `disable_user`, you can run as a dedicated
non-login system user with only `CAP_NET_ADMIN`. The
`tjakra-satria-agent.service` template shows that variant, commented, along with the
caveat that `disable_user` still needs root under it.

### Manual systemd install

If you prefer to install by hand, build and place the binary, enroll, then copy
the `tjakra-satria-agent.service` template and substitute the tokens:

```sh
go build -o tjakra-satria-agent .
sudo install -m 0755 tjakra-satria-agent /usr/local/bin/tjakra-satria-agent
sudo mkdir -p /etc/tjakra-satria-agent && sudo chmod 0700 /etc/tjakra-satria-agent
sudo /usr/local/bin/tjakra-satria-agent enroll \
  -server https://satria-api.tjakrabirawa.id \
  -token <ENROLL_TOKEN> \
  -config /etc/tjakra-satria-agent/agent.json
# edit the template: __BINARY__, __CONFIG__, __EXEC_FLAGS__
sudo cp tjakra-satria-agent.service /etc/systemd/system/tjakra-satria-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now tjakra-satria-agent.service
```

## Pattern 2: shared network-namespace container

On a shared host that already runs other services (for example Jenkins and
Infisical alongside a DVWA target), a host-level `iptables` DROP would block
traffic for the whole host. The proven-safe pattern runs the agent in a container
that shares the target's network namespace, so an `iptables -I INPUT` scopes only
to the target's namespace and never touches the host or its other services.

Build the image:

```sh
docker build -t tjakra-satria-agent:latest .
```

Enroll once to produce an `agent.json`, then bind-mount it into the container. You
can enroll with the image itself:

```sh
docker run --rm \
  -v "$PWD":/work \
  tjakra-satria-agent:latest \
  enroll -server https://satria-api.tjakrabirawa.id -token <ENROLL_TOKEN> -config /work/agent.json
```

Run the agent sharing the target container's netns (here the target is
`patrol-dvwa`):

```sh
docker run -d \
  --name patrol-agent \
  --network container:patrol-dvwa \
  --cap-add NET_ADMIN \
  --restart unless-stopped \
  -v "$PWD/agent.json":/agent.json:ro \
  -v /var/log/patrol-dvwa:/logs:ro \
  tjakra-satria-agent:latest \
  run -config /agent.json -log-file /logs/access.log -enforce
```

Notes:

- `--network container:patrol-dvwa` puts the agent in the DVWA container's network
  namespace. A block scopes to that namespace only. The host's Jenkins and
  Infisical are untouched.
- `--cap-add NET_ADMIN` lets the agent change iptables in that namespace without
  full privilege.
- Mount the target's access log read-only so the agent can tail and ship it.
- `disable_user` is not meaningful in this container pattern (no host accounts),
  so use it only in the native pattern.
- Tradeoff: the shared-netns container has only the tools baked into its image, so
  the remote console (`run_command`) sees that stripped container, not the host.
  `docker ps`, `sudo`, and host processes are not there. If you need the console to
  reach the host AND blocks to stay scoped to the target, use Pattern 3.

## Pattern 3: host agent with a container-scoped block (recommended for a shared host)

Network namespace (where a block lands) is independent of the PID and mount
namespaces and the installed tools (what the console reaches). So you can run the
agent natively on the host, where the console has full host reach, and still scope
every block to a target container's network namespace. `-block-container <name>`
does this: `block_ip` and `revert_block` run inside that container's netns via
`nsenter`, resolving the container's pid at apply time (it changes on restart), so a
DROP lands only in the target and never touches the host netfilter that carries the
host's other services.

The host needs `docker` and `nsenter` (util-linux), both standard. Run as root
(nsenter, iptables, and the console all need it). systemd unit ExecStart:

```
ExecStart=/usr/local/bin/tjakra-satria-agent run \
  -config /opt/tjakra-satria-agent-prod.json \
  -log-file /opt/patrol-dvwa-logs/access.log \
  -enforce -console -block-container patrol-dvwa
```

Notes:

- The agent process is on the host, so `run_command` reaches the whole host. Keep
  `-console` off on hosts that do not need it (it is host-root-equivalent), and rely
  on the platform audit trail and the kill switch.
- Blocks still scope to `patrol-dvwa`'s netns, so the host's Jenkins and Infisical
  are untouched, the same guarantee as Pattern 2.
- The target service's published port is where the agent reaches it. If the target
  binds to loopback only (a DVWA on `127.0.0.1:8085`), set the resource address to
  that loopback URL so a `run_probe` simulation fires there.
- Without `-block-container`, blocks run in the host netns, which is correct only on
  a single-purpose host that is itself the isolation boundary.

## Upgrading

An upgrade replaces the binary and restarts the agent. The enrollment lives in the
config file (or the `/data` volume), not in the binary, so it survives. Firewall
rules the agent installed live in the kernel, so restarting the agent does not lift
them. Agent 1.2.0 is the first build with target validation: after an upgrade, check
that the console shows `v1.2.0` or later for the host once it has polled, and that
the startup log still matches what you intended. It prints `running in dry-run mode`
only when `-enforce` is missing, so that line must not appear on a host that should
enforce, and it prints `remote console enabled` only with `-console`.

Before replacing an agent that runs a build older than 1.2.0, let its active blocks
reach their TTL (at most 24 h) or revert them from the console, then confirm
`iptables -S INPUT` and `ip6tables -S INPUT` are clean, run in the namespace the agent
enforces in: the host's, the block container's for Pattern 3, or the target's for
Pattern 2. Pattern 0 has nothing to lift, since removing its container discards the
rules. Anything left is a rule the new agent may not be able to lift: see the
`revert_block` notes under Target validation in the README.

### systemd hosts (Pattern 1 and Pattern 3)

Stop the unit, install the new binary, start the unit. This keeps the unit file,
every flag in its `ExecStart` (`-enforce`, `-console`, `-log-file`,
`-block-container`) and the enrollment:

```sh
sudo systemctl stop tjakra-satria-agent
sudo install -m 0755 <new-binary> /usr/local/bin/tjakra-satria-agent
sudo systemctl start tjakra-satria-agent
```

Stop first so the agent is not left running the old binary while the file is
replaced. `install` replaces the file, so it does not fail on a running binary the
way a plain `cp` over one does ("text file busy"). Build
`<new-binary>` with `go build -o tjakra-satria-agent .` from the updated checkout,
or on any machine that has Go with `GOOS=linux GOARCH=amd64`.

### Re-running install.sh

Re-running `install.sh` also installs the new binary, but it rewrites `ExecStart`
from the arguments of that run alone. It does not read the flags off the existing
unit, so:

- Repeat every run flag the host had: `--log-file`, `--enforce`, `--console` and
  `--insecure`. A re-run without `--enforce` leaves the agent in dry-run mode, where
  a block is reported done with a dry-run note and nothing is applied. A re-run
  without `--log-file` stops the log shipping.
- The script still requires `--token` and `--server`. With an enrolled config in
  place the token is not used or spent, and the existing enrollment is kept.
- `install.sh` cannot express `-block-container` (nor `-log-allow` or `-poll`). A
  host started with any of them, such as Pattern 3, must use the systemd path above.
  Re-running the installer there would overwrite the unit without the flag, and with
  `-block-container` gone, blocks would land in the host's network namespace instead
  of the target container's.

### Docker (Pattern 0 and Pattern 2)

Pull (or rebuild) the image, then recreate the container with exactly the options
the old one had: the same `-e` set, `--cap-add`, `--network` and volumes. The run
flags come from those options, so any that are left off are dropped.

```sh
docker pull tjakradev/tjakra-satria-agent:latest
docker stop patrol-agent && docker rm patrol-agent
docker run -d --name patrol-agent ...   # the original options
```

For a locally built image (Pattern 2), run `docker build -t tjakra-satria-agent:latest .`
from the updated checkout instead of the pull. The named volume (or the mounted
`agent.json`) carries the enrollment, so the new container needs no token. With
Pattern 0 the container has its own network namespace and removing it discards the
rules it installed; with `--network container:<target>` the rules live in the
target's namespace and stay.

## RedTeam simulation note (run_probe)

The platform's RedTeam simulation fires benign attack-signature requests at a
target so the detection rules light up in the access log. When a target is bound
to localhost for isolation, the platform cannot reach it directly. `run_probe`
solves that: the agent, which is local to the target, sends the plain GET requests
whose query strings carry the signature, so the simulation reaches a
localhost-bound target. Nothing is exploited.

`run_probe` is hard-restricted to a loopback or RFC1918 private target. A
`localhost` host or a loopback or private IP is allowed; any other hostname is
refused rather than resolved. So the platform can never turn an agent into a probe
against an arbitrary internet host. At most 20 paths are fired per command, each
with a 6 second timeout.

In the shared-netns container pattern, the agent shares the target's namespace, so
`http://127.0.0.1` from the agent reaches the target's own listener, which is
exactly what a localhost-bound DVWA needs.

## Remote console operational guide (run_command)

`run_command` runs an operator-typed shell command on the host and returns the
output. It exists for hands-on incident work where the fixed actions are not
enough. It is the one action outside the deterministic allowlist model, so it is
handled carefully:

- Off by default. It is inert unless the agent is started with `-console`. Without
  that flag it returns "remote console is disabled" and runs nothing. Do not set
  `-console` unless you intend for an operator to drive this host interactively.
- Still signed and admin-gated. Even with `-console`, the command must be signed
  by the platform and is admin-gated on the platform side. `-console` is the local
  operator's own consent, not a bypass of platform controls.
- Audited. Every command and its output is recorded on the platform.
- Never automated. The platform keeps `run_command` out of every playbook path, so
  it can only be issued by a human operator, never by automation.
- Bounded. A run is capped at a 30 second timeout and 64 KiB of output. A non-zero
  exit is a normal result with an `exitCode`; only a command that could not start
  or that timed out is reported as failed.

The risk is real: an enabled, admin-issued remote console can run any command the
service account can. Keep `-console` off on hosts that do not need it. When you do
enable it, run the service as the least-privileged account that still meets your
enforcement needs, and rely on the platform audit trail.

## Verification checklist

After install, confirm the agent is live and the command path works:

- The service is active: `systemctl is-active tjakra-satria-agent.service` reports
  `active`. For the container pattern, `docker ps` shows `patrol-agent` up.
- The process is polling: `journalctl -u tjakra-satria-agent.service -f` (native) or
  `docker logs -f patrol-agent` (container) shows
  `agent <id> polling <server> every <interval>` and no repeated crash-restart.
- The config is protected: `/etc/tjakra-satria-agent/agent.json` is mode 0600 and
  owned by the service account.
- The platform shows the agent connected: in the NSOC / Patrol agent list, the
  agent's last check-in advances every poll interval.
- The signed command path works end to end: issue a `run_collector` command from
  the platform. It is non-destructive and needs no `-enforce`. The result returns
  the host's hostname, os, and arch.
- Enforcement is intended: only hosts that should change firewall or account state
  run with `-enforce`. Confirm the startup log line reports enforce mode, not
  dry-run, on those hosts and dry-run everywhere else.
- The remote console is intended: only hosts that should accept interactive
  operator commands run with `-console`. Confirm the startup log reports the
  remote console enabled only where you meant it (and note the allowlist caveat
  above).
