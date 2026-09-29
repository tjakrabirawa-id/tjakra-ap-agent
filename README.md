# tjakra-satria-agent

The customer-installed patrol agent for the tjakra-satria platform (Defence and
Response, Model B). It enrolls with a one-time token from the platform, ships log
lines up so the platform can detect attacks, and runs allowlisted,
platform-signed commands down (block an IP, revert a block, disable a user,
isolate a host, run a collector, run a RedTeam probe). It is a single static Go
binary that depends only on the standard library.

For deployment patterns (systemd native and the shared-netns container), the
RedTeam simulation note, the remote-console operational guide, and a verification
checklist, see `docs/DEPLOYMENT.md`. For a one-command install, see the
`install.sh` section below.

## What the agent does

```
  platform (satria-api.tjakrabirawa.id)
        |   ^                    ^
 enroll |   | logs              | command results
 token  |   | (tail -log-file)  |
        v   |                    |
   +-------------------------------------+
   |            tjakra-satria-agent          |
   |  enroll -> pin agentKey + pubKey    |
   |  run    -> ship logs                |
   |          -> poll GET /commands      |
   |          -> verify ed25519 sig      |
   |          -> run allowlisted action  |
   |          -> POST /commands/{id}/result
   +-------------------------------------+
        |
        v
   host actions: iptables, usermod, collector, probe
```

Two subcommands:

- `enroll` exchanges a one-time token for a scoped agent key and the platform
  signing key, and writes them to a config file.
- `run` ships logs and polls for signed commands, verifies each one, and runs
  only the actions on its fixed allowlist.

## Security model

This is effectively an EDR and command-and-control agent, so the trust rules are
strict.

- The enrollment token is single-use and is not the operating credential. On
  enroll the platform returns a separate scoped agent key and the platform
  signing public key. The agent pins both. After enrollment the token is spent
  and the agent authenticates every request with the scoped key.
- Every command is verified against the pinned platform key over a frozen signing
  payload that binds the command id, agent id, action, canonical params, a nonce,
  and an expiry. The payload prefix is `tjakra-satria-agent-cmd-v1` and the format
  must match the platform's signer byte for byte. A stolen agent key or a tampered
  command cannot make the agent act, because neither can produce a valid platform
  signature.
- The agent runs only the fixed allowlist of named actions. A command naming any
  other action is refused even if its signature verifies. Targets are validated to
  a strict character set and passed as argv, not through a shell, so a crafted
  target cannot inject.
- Destructive actions (`block_ip`, `revert_block`, `disable_user`) are a dry-run
  unless the agent is started with `-enforce`. Without `-enforce` the agent
  records what it would run and reports it, but changes nothing.
- `run_probe` is hard-restricted to a loopback or RFC1918 private target. The
  agent refuses any probe target that is not a loopback or private address, and it
  does not resolve arbitrary hostnames, so the platform can never turn an agent
  into a probe against a host on the public internet.
- `run_command` (the admin remote console) is inert unless the agent is started
  with `-console`. Without that flag it returns "remote console is disabled" and
  runs nothing. The flag is the local operator's own consent that the host may be
  driven interactively. Even with `-console`, run_command is still signed by the
  platform, admin-gated on the platform side, and every command plus its output is
  audited. The platform keeps run_command out of every automated playbook path, so
  it can only be issued by a human operator, never by automation.

### Signature verification order

`verifyCommand` refuses a command, with a reported reason, if any check fails, in
this order:

1. No pinned platform key.
2. Action not on the allowlist.
3. Command is unsigned.
4. Command has expired (`expiresAt` in the past).
5. Signature does not verify against the pinned platform key.

The agent posts the refusal reason back as a failed result, so a declined command
is visible on the platform rather than silently dropped.

## Allowlisted actions

The fixed action table lives in `protocol.go` (`allowedActions`) and the
implementations in `executor.go`.

| Action | Params | Behavior | Gate |
| --- | --- | --- | --- |
| `block_ip` | `target`: IP or CIDR | `iptables -I INPUT -s <target> -j DROP` in the agent's network namespace | dry-run unless `-enforce` |
| `revert_block` | `target`: IP or CIDR | `iptables -D INPUT -s <target> -j DROP` | dry-run unless `-enforce` |
| `disable_user` | `target`: username | `usermod -L <target>` | dry-run unless `-enforce` |
| `isolate_host` | none used | recorded only, not enforced in this build | none |
| `run_collector` | none | returns `hostname`, `os`, `arch` | none |
| `run_probe` | `target`: loopback or private http(s) URL (default `http://127.0.0.1`), `paths`: list of request paths | fires benign GET requests whose query strings carry RedTeam attack signatures, so a simulation reaches a target bound to localhost | loopback / RFC1918 only, max 20 paths, 6s per-request timeout |
| `run_command` | `command`: shell command string | remote console: runs the command through the OS shell and returns combined output | inert unless `-console`; see the note below |

Target validation:

- IP targets (`block_ip` and `revert_block` alike): non-empty, at most 64
  characters, only `0-9 a-f A-F . : /`, and then parsed as an address. The target
  must be a single unicast address, or a CIDR no wider than /24 (IPv4) or /64
  (IPv6). The unspecified, loopback, link-local, multicast and broadcast ranges,
  any CIDR that contains one of them, and their IPv4-mapped IPv6 forms are refused.
  A refusal is a failed result whose error names the reason, for example
  `invalid target: loopback address`.
- Usernames: non-empty, at most 64 characters, only `a-z A-Z 0-9 _ . -`.

On a non-Linux host, `block_ip`, `revert_block`, and `disable_user` are recorded
and report a note, but make no firewall or account change (the iptables and
usermod paths are Linux only).

### run_probe detail

`run_probe` lets a RedTeam simulation reach a target the platform cannot, for
example a DVWA bound to localhost for isolation. The agent sends plain GET
requests whose query strings carry the signature the detection rules match in the
access log. Nothing is exploited. The target host must be `localhost`, a loopback
address, or an RFC1918 private address; any other hostname is refused rather than
resolved. At most 20 paths are fired, each with a 6 second timeout. The result
reports how many requests fired and the resolved target base.

### run_command detail and its current-build status

`run_command` is the operator remote console. It runs an operator-typed command
through `sh -c` on Unix or `cmd /c` on Windows and returns the combined output,
capped at 64 KiB, bounded by a 30 second timeout. A non-zero exit is a normal
result (status `done` with an `exitCode`), not a dispatch failure; only a command
that could not start or that timed out is reported `failed`. It is inert unless
the agent is started with `-console`.

`run_command` is the one action outside the automated allowlist model: a human
operator drives it, not a playbook. Three controls stand between a signed command
and a shell: the platform issues it only to an admin over the session and never
from any automation path; the command is signed like every other and verified
against the pinned platform key; and the agent runs it only when it was started
with `-console`, which is the local operator's own consent that this host may be
driven interactively. Every command and its output is written to the platform
audit log. With `-console` off (the default) the executor returns a disabled
result rather than running anything.

## Run in Docker (easiest)

The published image enrolls itself on first boot from `SERVER` and `ENROLL_TOKEN`,
then runs. Nothing to clone or build. `SERVER` is the platform BACKEND API base URL
(the agent ships logs to it and polls signed commands from it): `https://satria-api.tjakrabirawa.id`
in production, or `http://localhost:4000` (`http://host.docker.internal:4000` from a
container) for a local backend.

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

The token is read from the environment only at run time; it is never baked into an
image layer and is written nowhere but the 0600 config on the `/data` volume. Extra
behavior is env-driven: `ENFORCE=1` (apply blocks, needs `NET_ADMIN`), `CONSOLE=1`
(remote console), `LOG_FILE=/logs/access.log` (with `-v /var/log/app:/logs:ro`),
`BLOCK_CONTAINER=<name>`, `INSECURE=1` (dev cert). See `docs/DEPLOYMENT.md` Pattern 0
for the full one-command guide and Patterns 2 and 3 for the container/host netns
variants. An explicit `enroll`/`run` subcommand after the image name runs the binary
directly.

## Build

```sh
go build -o tjakra-satria-agent .
```

That produces a single static binary. Cross-compile for a Linux target from any
host with, for example:

```sh
GOOS=linux GOARCH=amd64 go build -o tjakra-satria-agent .
```

## Enroll

The enroll token comes from the platform console (NSOC, Patrol, "Enroll agent").
It is single-use.

```sh
./tjakra-satria-agent enroll \
  -server https://satria-api.tjakrabirawa.id \
  -token <enroll-token> \
  -config /etc/tjakra-satria-agent/agent.json
```

Enroll posts the token to `POST <server>/api/v1/agent/enroll`, receives
`agentId`, `agentKey`, `resourceId`, and `platformPublicKey`, and writes them to
the config file with mode 0600. If the platform returns no signing key, enroll
prints a warning that the command channel is disabled on the platform side.

Dev platform: `https://satria-api-dev.tjakrabirawa.id`. Add `-insecure` only for a
dev target with an untrusted certificate; it skips TLS verification and must not
be used against production.

## Config file

`enroll` writes a JSON config, default path `tjakra-satria-agent.json`, mode 0600
(owner read and write only):

```json
{
  "server": "https://satria-api.tjakrabirawa.id",
  "agentId": "<agent id>",
  "agentKey": "<scoped bearer key>",
  "platformPublicKey": "<base64 ed25519 public key>",
  "resourceId": "<resource id>"
}
```

The `agentKey` is a live credential and `platformPublicKey` is the pin that makes
signature verification trustworthy. Keep the file at 0600 and readable only by the
account that runs the agent. The installer places it under
`/etc/tjakra-satria-agent/agent.json` in a 0700 directory.

## Run

```sh
./tjakra-satria-agent run \
  -config /etc/tjakra-satria-agent/agent.json \
  -log-file /var/log/app/access.log \
  -enforce \
  -poll 5s
```

At start the agent prints whether it is in dry-run or enforce mode, whether the
remote console is enabled, and that it is polling. If `-log-file` is set it tails
that file in the background and ships appended lines to
`POST /api/v1/agent/logs`. It then loops: `GET /api/v1/agent/commands`, verify
each command, run the allowlisted ones, and `POST /api/v1/agent/commands/{id}/result`.

## Flags

Enroll:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-server` | (required) | Platform API base URL. |
| `-token` | (required) | One-time enrollment token. |
| `-config` | `tjakra-satria-agent.json` | Where to write the config. |
| `-insecure` | off | Skip TLS verification (dev only). |

Run:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-config` | `tjakra-satria-agent.json` | Config written by enroll. |
| `-log-file` | (none) | Log file to tail and ship. Omit to ship no logs. |
| `-enforce` | off | Apply destructive actions instead of dry-run. |
| `-console` | off | Enable the admin remote console (`run_command`). |
| `-block-container` | (none) | Apply blocks inside this container's network namespace via `nsenter`, so a host-run agent keeps blocks scoped to the target instead of the host. See Pattern 3 in `docs/DEPLOYMENT.md`. |
| `-poll` | `5s` | Command poll interval. |
| `-insecure` | off | Skip TLS verification (dev only). |

## Verify it is connected

After `run` starts, the agent checks in on every poll. On the platform its
`last_seen` (or last check-in) updates each poll interval, and the agent moves to a
connected or online state in the NSOC / Patrol agent list. To confirm end to end:

- The agent process prints `agent <id> polling <server> every <interval>` and does
  not exit.
- On the platform, the agent's last check-in advances every poll interval.
- Issue a `run_collector` command from the platform. It is non-destructive and
  works without `-enforce`. The result returns the host's hostname, os, and arch,
  which confirms the signed command path end to end.

## Troubleshooting

- "could not read config, run enroll first": the `-config` path does not exist or
  is unreadable by the current user. Run `enroll` first, or point `-config` at the
  written file.
- "enroll rejected" with a status code: the token is wrong, already used, or
  expired. Enroll tokens are single-use. Get a fresh one from the platform.
- "enroll returned no agent key": the platform response did not carry an agent
  key. Check the `-server` URL and that the platform enroll endpoint is reachable.
- "warning: the platform returned no signing key": the platform did not send a
  signing key, so the command channel is disabled on the platform side. The agent
  will still ship logs, but every command will be refused with "no pinned platform
  key".
- Commands refused with "action not allowlisted": the action is not in
  `allowedActions`. This is expected for anything outside the table above, and it
  currently includes `run_command` (see the run_command note).
- Commands refused with "signature does not verify": the pinned key and the
  platform signer disagree, or the command was altered in transit. Re-enroll to
  re-pin the current platform key.
- Destructive actions report "dry-run: start the agent with -enforce to apply":
  the agent is running without `-enforce`. Add the flag to apply changes.
- `run_command` returns "remote console is disabled": the agent is running without
  `-console`. See the run_command note for the current-build allowlist caveat as
  well.
- iptables actions fail with a permission error: the agent needs `NET_ADMIN` (root
  or `CAP_NET_ADMIN`) to change the firewall. See `docs/DEPLOYMENT.md`.
- TLS verification errors against a dev target: add `-insecure` for dev only.
  Never use `-insecure` against production.

## Known limitations

- The log tailer follows appended bytes and resets on truncation, but it does not
  fully handle rename-based log rotation. After a rotate-by-rename it can miss
  lines until the next truncation or restart.
- `isolate_host` is recorded, not enforced, in this build.
- The transport authenticates with the scoped bearer key over TLS. Certificate
  pinned mTLS is a later hardening, not in this build.

## Install

For a one-command install on a Linux host, clone this public repo and run
`install.sh`. It resolves or builds the binary, installs it to `/usr/local/bin`,
enrolls, writes the config to `/etc/tjakra-satria-agent/agent.json`, and installs and
starts a systemd service.

```sh
git clone https://github.com/tjakrabirawa-id/tjakra-satria-agent.git
cd tjakra-satria-agent
sudo ./install.sh --token <ENROLL_TOKEN> --server https://satria-api.tjakrabirawa.id
```

See `docs/DEPLOYMENT.md` for the full install options, the shared-netns container
pattern, and verification.
