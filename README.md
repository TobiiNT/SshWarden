# SshWarden

An MCP server that bridges SSH, so an agent that can speak HTTP but cannot open a shell can run
commands on a host — through one place that records every one of them.

**Apache-2.0. Self-hosted, and only self-hosted.** This process holds SSH credentials into your
production machines and its logs contain the output of commands run there. Neither belongs in
somebody else's cloud, so there is no hosted tier and there is not going to be one.

---

## What is here today

All eight steps. Seven tools — `run`, `read_file`, `tail_log`, `list_changes`, `start_job`,
`poll_job`, `kill_job` — behind a grant table, over pooled SSH, with output bounded and masked
before it leaves the process, every call in an append-only log whether it was allowed, refused or
failed, and six metrics over the same records.

- MCP over Streamable HTTP, bearer-authenticated, deny-by-default: an endpoint is authenticated
  unless it says otherwise where it is mapped.
- **Two ways in behind one seam** — a static token in a file, or OAuth 2.1 access tokens from any
  authorization server. A deployment picks one in the config; nothing downstream knows which ran.
- Per-tool, per-host and per-argument authorization, filtering `tools/list` and gating `tools/call`.
- An SSH connection pool with mandatory host-key verification.
- An append-only JSONL audit record for every call, including every refusal, and `/metrics` in
  Prometheus text derived from those same records so the two cannot disagree.
- An output budget that cuts the middle and says what it dropped, a server-side `grep`, and
  best-effort secret masking in the response **and** in the audit log.
- `read_file` and `tail_log` gated on paths and units, with the path re-checked after the target
  resolves it.
- A background sweeper over watched paths, behind `list_changes`.
- Jobs that outlive the call, over a registry that survives a restart of this server.
- A TOML config that refuses unknown keys, weak credentials and loose file modes.

The reasoning behind every one of those lines is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Running it

Two commands, plus the one thing that is genuinely yours: make the key this process reaches your
hosts with, and find out what each host's key is.

```bash
ssh-keygen -t ed25519 -f /etc/sshwarden/id_ed25519 -N ''   # then authorize the public half
ssh-keyscan -t ed25519 prod-web-1 | ssh-keygen -lf -       # over a channel you trust

sshwarden init \
  --identity-file /etc/sshwarden/id_ed25519 \
  --host prod-web-1=SHA256:... \
  --ssh-user deploy

sshwarden --config /etc/sshwarden/sshwarden.toml
curl -s http://127.0.0.1:8760/health        # {"ok":true,"server":"sshwarden"}
```

The same command writes the other mode, and the difference is which credential exists. `--auth
oauth` takes the authorization server to trust and the audience this server answers to, and writes a
file with no credential in it at all:

```bash
sshwarden init --auth oauth \
  --issuer https://auth.example.com \
  --resource https://sshwarden.example.com/mcp \
  --subject someone \
  --identity-file /etc/sshwarden/id_ed25519 \
  --host prod-web-1=SHA256:... \
  --ssh-user deploy
```

`--subject` is what the grant table is keyed on, and in this mode it has to be the `sub` the
authorization server puts in its access tokens rather than a name a person recognises.

`init` makes the directories at 0700, writes the file at 0600 from the first byte, generates a token
and prints it once, and points the audit log and job registry somewhere writable. It refuses to
overwrite an existing config, because the token in one is in somebody's client configuration and
rotating it silently signs them out. Every problem is reported at once.

**It will not do two things for you, and both absences are the design.** It does not accept
`--token`: a credential passed as an argument is readable by every process on the machine through
`ps`, so it generates one instead. And it does not scan for host fingerprints — a fingerprint read
off the network is one verified by whoever answered, which is trust-on-first-use wearing a different
name.

For the server, `--config` is the only argument read and `SSHWARDEN_CONFIG` the only environment
variable, for that same reason. A bad config exits **78** (`EX_CONFIG`) and prints every problem; an
authorization server that does not answer exits **69** (`EX_UNAVAILABLE`) instead, because the two
want opposite responses from a supervisor — a typo fails identically on every restart, and an
authorization server that is still booting does not.

Or write the config by hand from
[`sshwarden.example.toml`](hosts/SshWarden.Server/sshwarden.example.toml), which is the same keys
with the reasoning beside each one. There is a `Dockerfile` under `hosts/SshWarden.Server/`; build
it from the repository root.

## Security, stated plainly

Read this before deciding where to run it. What counts as a vulnerability, and how to report one,
is in [`SECURITY.md`](SECURITY.md); the arguments behind these are in
[`docs/DESIGN.md`](docs/DESIGN.md).

- **The command is not filtered, permanently.** `run` takes a shell command and passes it through
  unchanged. Filtering by content is not a feature that has not been built — it is not answerable at
  the string level, and every attempt reduces to a list of program names somebody has already
  published four hundred ways around. The gate is the host and the account, not the string. For the
  same reason the working directory is recorded but is **not** a boundary: a command can `cd`
  anywhere.

- **The last boundary is the unix account, not this code.** The grant table refuses early and logs
  clearly, and all of it runs inside a process the target host does not trust and cannot verify.
  What cannot be worked around is what the `ssh_user` in the matching rule may actually do once
  logged in. Give it its own narrow account; a rule pointing at one with broad `sudo` is not
  restrained by anything written here.

- **A host key is verified or the connection does not happen.** Every `[[host]]` declares a
  `fingerprint`. There is no trust-on-first-use and no way to switch it off, because a connection
  made without checking hands the private key's authority — and every command — to whoever answered.

- **The listener is loopback by default.** A real deployment is publicly reachable through a reverse
  proxy terminating TLS in front of this, not by opening this socket; startup warns when the address
  is not loopback. Restricting to a client vendor's published egress range reduces surface and is
  not authentication, because such a range belongs to the whole vendor rather than to any session.

- **A static token does not expire and cannot be revoked except by editing the file and
  restarting.** That is the honest limit of the zero-dependency mode, and it is why the other mode
  exists: under `auth.mode = "oauth"` the credential is minted elsewhere, expires on its own, and
  never sits in this file. Generate it with `openssl rand -base64 32`; under 32 characters is
  refused at startup.

- **Secret masking is best-effort, and that is not a hedge.** Output is matched against patterns
  somebody thought of, and a credential shaped like none of them goes through untouched. It is the
  **second** line — the first is the `ssh_user` not being able to read the file at all. Masking runs
  on the tool result and on the audit record including the command line, because environment
  variables have to be inlined into the command and a token passed as one would otherwise be
  recorded verbatim.

- **A path is checked twice, and only the second check sees a symlink.** What a caller writes is
  checked here — absolute, no `..`, under an allowed prefix — then resolved **on the target** with
  `realpath -e` and checked again, because a symlink out of the allowed tree passes every test that
  can be made from this side. The gap between resolving and reading is not closeable from here.

- **A job's output is unredacted on the target, and cannot be otherwise.** A job leads its own
  process group and writes to a file on the target, and nothing of SshWarden's is on that machine to
  intercept the write. What bounds it is a directory created mode 0700 inside the home of the
  account the rule maps to; masking happens on the way back through `poll_job`. What stays exposed
  is exposed to whoever could already have run the command.

- **`/metrics` needs a credential.** The `host` label carries the names of your production
  machines, which is the same information the scope design goes out of its way never to publish.
  Give a scraper a token whose subject has no grants: reading aggregates needs no reach, and a
  scraper holding a token that can run commands is a credential in a config file for the sake of a
  counter.

- **The scopes this server advertises are published unauthenticated.** They go in the RFC 9728
  document, which is the one response that must answer without a credential — so a scope naming a
  host publishes that host to anyone who asks. The loader refuses a scope naming a host this file
  declares, warns on one carrying a path separator (a published directory layout and a scope that is
  simply a URL cannot be told apart from here), and refuses outright anything outside RFC 6749
  §3.3's character set.

- **The config refuses to be sloppy.** Mode other than 0600, an unknown key, a token under the
  minimum — each is a startup failure rather than a warning, because a misspelled key is a rule that
  silently does not apply, which costs an incident rather than a restart.

## Building on it

```bash
dotnet build SshWarden.slnx    # must be 0 warnings
dotnet test  SshWarden.slnx    # must be 0 failures
```

Warnings are errors. This process issues commands that run as somebody on a production host, so a
warning is a defect that has not been noticed yet.

`tests/SshWarden.Ssh.IntegrationTests` starts a real OpenSSH server on loopback, because everything
at that layer is a claim about somebody else's software — whether a quoted argument survives a real
shell, whether a remote timeout really kills the process, whether several commands share one
connection. It **fails rather than skips** without an `sshd` to run: a suite that skips is green in
exactly the situation where it measured nothing. `apt-get install openssh-server`.

Two rules the tests are held to, and they are why the suite is worth its size:

- **A new rule needs a test that goes red without it.** Every rule here was checked by breaking it
  and watching exactly the test named for it fail.
- **A refusal proves nothing without a control.** Every test asserting something is refused has a
  sibling proving the same path accepts what it should.
