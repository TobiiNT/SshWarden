# SshWarden

An MCP server that bridges SSH, so an agent that can speak HTTP but cannot open a shell can run
commands on a host — through one place that records every one of them.

**Apache-2.0. Self-hosted, and only self-hosted.** This process holds SSH credentials into your
production machines, and its logs contain the output of commands run there. Neither belongs in
somebody else's cloud. There is no hosted tier and there is not going to be one.

---

## What is here today

**All eight steps.** It runs commands, reads files, tells you what changed, starts work that outlives
the call, and reports on itself. All seven tools — `run`, `read_file`, `tail_log`, `list_changes`,
`start_job`, `poll_job`, `kill_job` — behind a grant table, over pooled SSH, with output that is
bounded and masked before it leaves the process, every call in an append-only log whether it was
allowed, refused or failed, and six metrics over the same records.

| | |
|---|---|
| ✅ | MCP over Streamable HTTP, bearer-authenticated |
| ✅ | An authenticator seam with a static-token implementation behind it |
| ✅ | A TOML config file that refuses unknown keys, weak credentials and loose file modes |
| ✅ | Deny-by-default routing: an endpoint is authenticated unless it says otherwise where it is mapped |
| ✅ | Per-tool and per-host authorization, filtering `tools/list` and gating `tools/call` |
| ✅ | An SSH connection pool with mandatory host-key verification, and `run` |
| ✅ | An append-only JSONL audit record for every call, including every refusal |
| ✅ | An output budget that cuts the middle and says what it dropped, and a server-side `grep` |
| ✅ | Best-effort secret masking, in the response **and** in the audit log |
| ✅ | `read_file` and `tail_log`, gated on paths and units, with the path re-checked after the target resolves it |
| ✅ | A background sweeper over watched paths, and `list_changes` |
| ✅ | `start_job`, `poll_job` and `kill_job`, over a job registry that survives a restart of this server |
| ✅ | `/metrics` in Prometheus text, six metrics, derived from the audit records so the two cannot disagree |
| ✅ | OAuth 2.1 access tokens from any authorization server, behind the same seam the static token uses |

Both authentication modes are real and a deployment picks one in the config file. Nothing downstream
of the seam knows which is running.

The full plan, and the reasoning behind each of those lines, is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Running it

Two commands, plus the one thing that is genuinely yours to do: make the key this process reaches
your hosts with, and find out what each host's key is.

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

`init` makes the directories at 0700, writes the file at 0600 from the first byte, generates a
token and prints it once, and points the audit log and the job registry somewhere writable. It
refuses to overwrite an existing config — the token in one is in somebody's client configuration,
and rotating it silently signs them out. `--help` is `sshwarden init` with a bad argument; every
problem is reported at once.

**It will not do two things for you, and both absences are the design.** It does not accept
`--token`: a credential passed as an argument is readable by every process on the machine through
`ps`, so it generates one instead. And it does not scan for host fingerprints — a fingerprint read
off the network is one verified by whoever answered, which is trust-on-first-use wearing a different
name, and the host-key check has no way to switch off for exactly that reason.

`init` loads the file it just wrote before reporting success. A generator that drifts from the
loader produces a config that fails at startup on somebody else's machine, long after whoever ran
the command has gone.

Or write the config by hand from [`sshwarden.example.toml`](hosts/SshWarden.Server/sshwarden.example.toml),
which is the same keys with the reasoning behind each one.

For the server itself, `--config` is the only argument read and `SSHWARDEN_CONFIG` the only
environment variable. Nothing else in the configuration can be supplied that way, for the same
reason `init` generates the token rather than taking it.

A bad config exits **78** (`EX_CONFIG`), so a supervisor can tell "fix the file" from "the process
crashed", and prints **every** problem rather than the first one. An authorization server that does
not answer exits **69** (`EX_UNAVAILABLE`) instead, because the two want opposite responses from a
supervisor: a typo fails identically on every restart, and an authorization server that is still
booting does not.

There is a `Dockerfile` under `hosts/SshWarden.Server/`; build it from the repository root.

## Security, stated plainly

Read this before deciding where to run it.

- **The listener is loopback by default.** Clients reach an MCP server from the internet, so a real
  deployment is publicly reachable — through a reverse proxy terminating TLS in front of this, not
  by opening this socket. Startup warns when the address is not loopback. Restricting to a client
  vendor's published egress range reduces surface; it is not authentication, because such a range
  belongs to the whole vendor rather than to any one session.

- **A static token does not expire, and cannot be revoked except by editing the file and
  restarting.** That is the honest limit of the zero-dependency mode, and it is why the other mode
  exists: with `auth.mode = "oauth"` the credential is minted by an authorization server, expires on
  its own, and never sits in this file.
  Generate it with `openssl rand -base64 32`; anything under 32 characters is refused at startup.

- **The config file must be mode 0600.** Readable by anyone else and the process refuses to start.
  On a platform without Unix file modes the check cannot run, and it says so rather than passing
  quietly — unmeasured is not the same as safe.

- **An unknown key in the config is a startup failure.** A misspelled key would otherwise be a rule
  that silently does not apply, which is the failure that costs an incident rather than a restart.

- **The last boundary is the unix account, not this code.** The grant table refuses early and logs
  clearly, and all of it runs inside a process the target host does not trust and cannot verify.
  What cannot be worked around is what the `ssh_user` in the matching rule is actually permitted to
  do once it is logged in. Give it its own narrow account. A rule pointing at an account with broad
  `sudo` is not restrained by anything written here.

- **The command is not filtered, permanently.** `run` takes a shell command and passes it through
  unchanged. Filtering it by content is not a feature that has not been built — it is not
  answerable at the string level, and every attempt reduces to a list of program names somebody has
  already published four hundred ways around. The gate is the host and the account, not the string.
  For the same reason the working directory is recorded but is **not** a boundary: a command can
  `cd` anywhere.

- **A host key is verified or the connection does not happen.** Every `[[host]]` declares a
  `fingerprint`. There is no trust-on-first-use and no way to switch it off, because a connection
  made without checking hands the private key's authority — and every command — to whoever answered.

- **A path is checked twice, and only the second check sees a symlink.** `read_file` and `tail_log`
  gate on the `paths` and `units` in the matching rule. The path a caller writes is checked here —
  absolute, no `..`, under an allowed prefix — and then resolved **on the target** with
  `realpath -e` and checked again, because a symlink out of the allowed tree passes every test that
  can be made from this side. What stays open is the gap between resolving and reading: that race
  is not closeable from here, and it is answered one layer down. Refusals are distinguishable —
  `path_not_granted`, `path_escapes_grant`, `path_not_found` — because a symlink pointing out of
  its tree and a typo want different responses.

- **Secret masking is best-effort, and that is not a hedge.** Output is matched against patterns
  somebody thought of — AWS keys, `sk-` and `gh*_` tokens, private-key blocks, passwords inside
  URLs, assignments whose name looks like a secret — and a credential shaped like none of them goes
  through untouched. It is the **second** line. The first is the `ssh_user` in the matching rule not
  being able to read the file at all; if a secret only survives because a regex caught it, the
  deployment is one unusual format away from leaking it. Masking runs on the tool result and on the
  audit record, including the command line — environment variables have to be inlined into the
  command, so a token passed as one would otherwise be recorded verbatim.

- **Output is bounded, and the caller is told.** Over the budget, the middle is cut and a marker
  names how many lines and bytes went. The order is fixed and is the reason the pipeline is one
  function rather than four: measure what the host produced, filter, mask, then cut. Cutting before
  masking would leave a secret lying across the cut as two fragments that no pattern matches.

- **Change detection is a periodic sweep, and its limits are real.** One sweeper per host, running
  only while that host already has a connection open, comparing inode, size and modification time
  under the paths in `[watch]`. Four things follow, and none of them is a bug to be fixed later:

  - **The resolution is the sweep interval.** A command shorter than one interval gets a window
    wider than itself. The record says how wide, in `changes_window_ms`, and a zero there means no
    sweep covered that command at all — which is not the same as nothing having changed.
  - **A change made and undone between two sweeps is invisible.** Comparing modification times
    misses that however often you do it; it is not a cost of sweeping periodically.
  - **A change that leaves size, modification time and inode alone is invisible**, for the same
    reason.
  - **Exact per-command attribution does not exist** when commands overlap — not "is hard", does
    not exist. So a record carries `changes_confidence`: `exclusive` means nothing else was running
    on that host during the window and the changes are attribution; `overlapping:N` means they are
    a list of candidates. The two alternatives are to serialize commands per host, which destroys
    the concurrency this design is built on, or to attribute anyway and report a guess as an
    observation.

  The timeline is in memory and per process: a restart loses it, and a second instance has its own.
  What survives is the audit log, which carries what was attributed to each command at the time.

- **`list_changes` shows which paths changed, to anyone allowed it on that host.** Not their
  contents — but the fact that `/etc/shadow` was written at 03:14 is information. Which paths are
  watched is the operator's choice in `[watch].paths`, and putting one there is that decision.

- **A job's output is unredacted on the target, and cannot be otherwise.** `start_job` runs a
  command that outlives the call: it leads its own process group and its own session, writes to a
  file on the target, and keeps going when this server restarts. Nothing of SshWarden's is on that
  machine to intercept the write, so what bounds the exposure is a directory created mode 0700 with
  the umask set first, inside the home of the unix account the rule maps to. Masking happens on the
  way back through `poll_job`, like every other output. What is left exposed is exposed to whoever
  can already read that account's files — the same set of people who could have run the command.

- **A job has four states, and "not running" is two of them.** `running`, `finished` with an exit
  code, `gone` — not running and left no exit status, which is what a killed job looks like — and
  `vanished`, its directory no longer on the target. A killed job reported as `finished` with an
  invented code would say the command completed when nobody knows whether it did.

- **The job registry is on disk, because the jobs outlive this process.** Started jobs are appended
  to a JSONL file and replayed at startup. In memory it would not survive a deploy, and every
  running job would then be unpollable, unkillable and — worse — unowned, leaving the check that
  stops one caller reaching another's job with nothing to compare against.

- **A job belongs to a subject, not to a session.** `poll_job` and `kill_job` are gated on the
  subject the job was started by, not on the token or the grant that started it: two sessions of one
  person share a grant and could read the job's output file with `run` anyway, so gating tighter
  would refuse something it cannot actually prevent. A job identifier carries no host, so this check
  is the only thing between one caller and another's production output — which is why it lives in
  the gate that runs for every call rather than in the tools, where somebody can forget it. A
  caller asking about a job that is not theirs is told **no such job**: which of the two it is is in
  the audit record, for the operator, who is not the one being refused.

- **`start_job` does not return until the job has a process group.** Otherwise a command the
  target's shell cannot even parse is accepted, an identifier comes back for a job that will never
  run, and the caller finds out at some later poll — as `gone`, with nothing saying why. Instead the
  shell's own complaint comes back from the call that caused it.

- **Two ways in, one seam, and nothing downstream can tell which ran.** `auth.mode` is
  `static-token` or `oauth`. Both fill the same five named values — subject, client id, grant id,
  token id, scope claim — so the grant table, the gate and the audit record read one shape and never
  ask where it came from. They are properties with names rather than a claims dictionary, because a
  misspelled string key does not fail to compile; it returns null.

- **Any authorization server that issues JWT access tokens.** `SshWarden.OAuth` is what the shipped
  host references: the framework's own bearer handler doing OpenID Connect discovery against the
  issuer you configure, plus the RFC 9728 document, which belongs to the resource server rather than
  to the authorization server. Keycloak, Entra, Auth0 and anything else conformant are a config
  file, not a fork.

  Which claims carry the client id, the token id and the session grouping are settings, defaulting
  to RFC 9068's `client_id` and `jti`. The third has no RFC, so `auth.oauth.grant_id_claim` names it
  and its documentation says what to do when your server emits nothing of the kind — the one thing
  it will not do is pick a grouping nobody chose and put it in the audit log looking like the
  authorization server said it.

- **Every 401 points at the metadata document, and that pointer is the whole of discovery.** A
  client meeting this server for the first time gets a `WWW-Authenticate` carrying
  `resource_metadata` — the URL of the RFC 9728 document — and the whole advertised scope list. The
  document being correct is not enough on its own, and that is the shape this got wrong: the
  document was served at both well-known forms and the challenge was a bare `Bearer`, so nothing
  told a client the document existed. Every unit test passed, because no unit was wrong. What found
  it is the RFC 9728 pipeline contract each OAuth mode now derives from
  [Boltway](https://github.com/TobiiNT/Boltway)'s `Boltway.ResourceServer.Testing` — eight
  assertions against a wired application rather than against a unit, and a test dependency only:
  `SshWarden.OAuth` references nothing from Boltway.

  The scope list in that challenge is the whole configured list, never an endpoint's own. A
  connector on the same authorization server narrowed it to what one route required, so every client
  asked for only that scope and the one it did not name was never granted to anybody; every
  operation needing it failed for six and a half hours.

- **OAuth lives in its own assembly, and a static-token install never loads it.** A deployment
  references `SshWarden.OAuth` — or `SshWarden.Boltway`, which fills the same seam with
  [Boltway](https://github.com/TobiiNT/Boltway)'s own reading of a token, or one you write — so
  nobody running a token in a file is made to carry an authorization server's client libraries
  behind the MCP package. If the config says `oauth` and nothing registered an authenticator,
  startup fails naming what to call, rather than serving the MCP endpoint and finding out when the
  first caller arrives.

- **A scope never decides which tool runs, and `RequireScope` is never on `/mcp`.** One MCP endpoint
  carries all seven tools, so a scope demanded at the route is the intersection of what they all
  need. Worse, the scope named in the resulting 401 is what a client asks the authorization server
  for — demanding a narrow one there stops a caller from ever requesting the wider one another tool
  needs. The per-tool decision is the grant table's; the token only says who is calling.

- **The subject is `sub`, not a display name.** An authorization server will happily hand you
  `preferred_username`, and it is the right thing for something a person reads. The grant table is
  an authorization boundary looked up by this key, and a display name is a string an authorization
  server may let its user change — so a rule granting production access would follow a rename, or
  stop matching one.

- **A token that validates and is missing what the record needs is refused, not filled in.** No
  `sub`, `client_id`, `gid` or `jti` means a refusal naming the claim. A placeholder would produce
  an audit record that looks complete and answers nothing: `client_id` is what two records of one
  client match on, `gid` is what groups a session across a refresh, `jti` is what ties a revocation
  to the calls the revoked token made.

- **The scopes this server advertises are published unauthenticated.** They go in the RFC 9728
  document, which is the one response that has to answer without a credential, so a scope naming a
  host would publish that host to anyone who asks. The config loader and `sshwarden init` refuse a
  scope that names a host this file declares — which is checkable, unlike the shape of a hostname:
  the first version of that rule refused any scope containing a dot, and `stories.read` carries a
  dot and names nothing. A scope carrying a path separator is a warning rather than a refusal,
  because a path published in that list and a scope that is simply a URL cannot be told apart from
  here, and more than one authorization server names its scopes the second way. What is refused
  outright is a scope that is not a scope: RFC 6749 §3.3 allows printable ASCII without the space,
  the quote or the backslash, and each of those breaks something specific — a space makes one scope
  read as two and publishes a name no authorization server will issue, and a quote ends the
  challenge parameter early, taking the `resource_metadata` pointer after it out of the challenge.

- **The authorization server must be reachable at startup, and a private one takes saying so.** With
  no signing keys this server answers 401 to every caller holding a perfectly good token, which
  reads as a credential problem and is a deployment ordering one — so it refuses to start and names
  what did not answer, exiting 69 rather than 78 because a restart is the fix. An authorization
  server on a loopback or private address is blocked by the RFC 6890 check until
  `auth.oauth.allow_private_issuer = true` says it is meant to be there, and that logs a warning on
  every start.

- **No token introspection in v0, and that is a choice about credentials.** The only introspection
  auth method the authorization server offers needs a long-lived client secret, and this project
  prefers a credential that expires. A signature and an expiry answer the threat model it has; a
  revocation takes effect at the token's expiry rather than immediately, which is worth knowing
  before deciding it is enough.

- **The metrics are derived from the audit records, and there are six of them.** Calls by host and
  outcome, command duration, output size, truncations, refusals by rule, and pool connections. Taken
  off the same records the log is written from, so "the dashboard says forty and the log has
  thirty-nine lines" cannot happen. Written as Prometheus text by hand: `System.Diagnostics.Metrics`
  is an instrument API and .NET has no exposition for it, the OpenTelemetry exporter has never had a
  stable release, and `prometheus-net` still targets `net6.0`. The instruments are standard, so a
  deployment already running OpenTelemetry can subscribe to the same meter and ignore the endpoint.

- **Every metric label comes from a closed set, and that is a security property rather than tidiness.**
  A caller names the host on every call, and a refused call names a host that does not exist — so a
  label taken from that string straight would let one caller mint one series per request, out of
  calls this server correctly refuses, until the process runs out of memory. Host labels are the
  declared hosts or `unknown`; rules are the refusal reasons this server defines; tools are the
  seven. Nothing derived from `sub`, `gid`, `jti`, the command or the working directory reaches a
  label at all — those stay in the JSON body, filtered at query time rather than indexed.

- **`/metrics` needs a credential.** The `host` label carries the names of your production machines,
  which is the same information the scope design goes out of its way never to publish. Give a
  scraper a token whose subject has no grants: reading aggregates needs no reach, and a scraper
  holding a token that can run commands is a credential in a config file for the sake of a counter.

- **The audit log is the source of truth, and it stays put.** One JSON line per call, appended,
  never rewritten, including every refusal. It contains output from your production hosts, which
  means it contains whatever those hosts printed. Nothing in this repository ships it anywhere; if
  the process cannot write it, the process does not start.

- **The operational log is not the audit log, and its event ids are allocated rather than chosen.**
  The audit log is the evidence; the operational log is what shows up in whatever is already tailing
  the service, and nothing in it repeats a command, a credential or a tool argument. Ids come from a
  range per assembly — core `1000`, MCP `2000`, Boltway `3000`, host `4000` — so the number alone
  says which half of the process spoke, and every message carries a stable `EventName` so a query
  never has to match on message text. `LogEventRuleTests` holds all three: in range, no duplicates,
  named.

- **Two things used to fail in silence and no longer do.** A sweep that could not run was recorded
  where only `list_changes` would show it, so a change detector broken for a week looked like a
  quiet week; and a job-registry line that could not be replayed was skipped without a word, so
  `poll_job` answered "no such job" for work still running on the target. Both are logged on the
  transition — the first failure and the recovery — rather than every round, because one identical
  warning per interval is how the line that matters stops being read.

- **When a refusal comes from missing authorization rather than a missing credential, it can only be
  words in a tool result.** MCP has no mechanism a client will act on for that — measured, and
  written up in `docs/DESIGN.md` §6.5.8 — so the client will not automatically ask for more access. A
  person has to re-authorize.

## Building on it

```bash
dotnet build SshWarden.slnx    # must be 0 warnings
dotnet test  SshWarden.slnx    # must be 0 failures
```

Warnings are errors. This process issues commands that run as somebody on a production host, so a
warning is a defect that has not been noticed yet.

`tests/SshWarden.Ssh.IntegrationTests` starts a real OpenSSH server on loopback and runs against it,
because everything at that layer is a claim about somebody else's software — whether a quoted
argument survives a real shell, whether a remote timeout really kills the process, whether several
commands can share one connection. It **fails rather than skips** when there is no `sshd` to run,
for the same reason a storage suite should not skip itself without a database: a suite that skips is
green in exactly the situation where it measured nothing. `apt-get install openssh-server`.

Two rules the tests are held to, and they are why the suite is worth its size:

- **A new rule needs a test that goes red without it.** Every rule here was checked by breaking it
  and watching exactly the test named for it fail — the fail-open on an unreadable scope claim, the
  normalized client id, the ignored unknown key, the unchecked file mode, the skipped
  authentication, the collapsed grant and token identifiers, the loader that stops at the first
  problem, the unquoted working directory, the ungated host, the unfiltered tool listing, the
  refusal that writes no record, the cut that runs before masking, the secret left in the recorded
  command line, the path checked only before the target resolved it, and the first sweep reporting
  a whole tree as newly created.
- **A refusal proves nothing without a control.** Every test that asserts something is refused has a
  sibling proving the same path accepts what it should.
