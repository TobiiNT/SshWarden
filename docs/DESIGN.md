# Design

Why SshWarden is shaped the way it is, and which alternatives were rejected for what reason.

The section numbers here are cited from the code - a comment saying `docs/DESIGN.md §6.5.4` means
the reasoning lives in that section rather than being repeated at every call site. **The numbers are
load-bearing.** Renumbering a section orphans every citation to it, so a section that stops being
true is corrected in place, and a new one takes the next free number.

This document is the design. What the code enforces is in the code; what a deployment configures is
in [`sshwarden.example.toml`](../hosts/SshWarden.Server/sshwarden.example.toml); what the project
promises an operator is in the [README](../README.md). Where any of those disagree with this file,
one of them is wrong and the disagreement is worth resolving rather than averaging.

---

## 2. The problem

Two problems, and the point is that one thing solves both.

**Transport.** An agent that runs in somebody's cloud can speak HTTP but cannot open an SSH session.
An agent that runs on a laptop can, and does not scale past that laptop. What is missing is a
**remote MCP server that bridges SSH**.

**Observability.** When an agent runs commands on a host, nothing says what it did or what changed.
What is missing is a **choke point that records every call** and can say **what changed on the
host**.

The same process answers both: the server that bridges SSH is the only place that sees everything.
This is one project, not two.

### 2.1 Threat model

> Guard against an agent being **wrong**, and let a person **see** what happened. Not against an
> agent being **controlled**.

There is no attacker in this model. No indirect prompt injection, no taint tracking, no dual-LLM
pattern, no capability sealing, no plan freezing. A design that starts reaching for those has left
the model this project was built for.

The per-tool authorization in §6.5 does not change that. It is still "guard against being wrong",
moved from *record it after the fact* to *refuse it first*. Every decision it makes is
deterministic: no heuristics, and nothing reads the content of a command.

---

## 3. Settled decisions

### 3.1 There is no session shell

| State | Decision |
|---|---|
| **Connection** (TCP + SSH handshake) | **Kept**, pooled. Purely performance |
| **Shell** (cwd, environment, sudo timestamp) | **Not kept** |
| **Process** (long-running) | Its own job model - §4.4 |

Three reasons, in order of weight:

1. **A log line has to mean something on its own.** With a persistent shell, a record saying
   `npm install` is unreadable: the working directory came from some earlier call, so understanding
   one line means replaying the session. Stateless calls with an explicit working directory make
   every record independently readable - which is the reason this project exists, and a persistent
   shell blurs exactly what it was built to show.
2. **Concurrency breaks it.** Several agents run at once. One shared shell means two agents `cd` over
   each other; one shell per agent needs a stable agent identity, and **MCP has no concept of agent
   identity that survives between tool calls**.
3. **Hidden state is a bug nobody can reproduce.** The thirty-seventh command fails because the
   twelfth changed an environment variable.

### 3.2 Parameters instead of shell state

```
run(host, cmd, workdir?, env?, timeoutSec?, grep?)
```

The server builds `cd <workdir> && <cmd>`. The agent states what it wants; hidden state is zero.

`sudo` is expected to be `NOPASSWD` for a specific set of commands rather than resting on the
timestamp cache - which also makes every privileged command visible in the log.

**Environment variables cannot travel over the SSH protocol.** `sshd`'s `AcceptEnv` default accepts
only `LANG` and `LC_*`, so sending them as an SSH environment request **silently does nothing**. They
are inlined as `KEY='value' cmd` and quoted exactly like the working directory. See §4.1.

### 3.3 Self-hosted, and only self-hosted

This process holds SSH credentials into production machines, and its logs contain the output of
commands run there - which means they contain whatever those hosts printed, secrets included.

A hosted tier would concentrate every user's SSH access in one place. Nobody sensible would use it,
and convincing them otherwise would take SOC 2 and 24/7 on-call. So: **Apache-2.0, self-hosted, no
billing, no hosted tier.** The patent grant is why Apache-2.0 rather than MIT - it is the licence
that matters to somebody deploying this inside a company.

---

## 4. Architecture

```
MCP client (cloud, desktop, mobile)
        │  HTTPS + bearer token
        ▼
   SshWarden                                  ← the only choke point
        ├─ authorization gate (§6.5)          ← every tool call passes here
        ├─ connection pool (per host)
        ├─ audit log  → JSONL on disk
        ├─ change detector (background sweeper)
        ├─ /metrics
        └─ SSH ──► target host

   JSONL + /metrics ──► log shipper ──► your stack   (outside this repository)
```

An MCP client connects **from its vendor's infrastructure**, not from the user's machine. Two
consequences:

- The server has to be publicly reachable, and §6.1 still binds `127.0.0.1` by default. These do not
  conflict: the deployment goes behind a reverse proxy terminating TLS. Saying so matters, because
  somebody implementing this meets the contradiction on day one.
- Restricting to a vendor's published egress range reduces surface. **It is not authentication** - a
  published range belongs to the whole vendor, not to any one session.

One server serves every client, so "the desktop one does not scale" stops being a problem.

### 4.1 Connection pool

An SSH library gives the right semantics; this does not need writing. The constraints:

- **Keep the client alive, pooled per host.** That is where the TCP connection and the authentication
  handshake get reused.
- **Every command opens a new channel.** A new channel carries none of the previous command's
  working directory or environment.
- **Never a shell stream.** It keeps state - the thing §3.1 forbids. This is the trap at this layer:
  a shell stream *looks* more convenient, and the library's own forum advice recommends it for
  running several commands. Do not take that advice.
- The working directory is prefixed as `cd` and **must be quoted**: it comes from the agent and is
  untrusted input.
- The pool needs idle eviction, a health check before handing a connection out, and thread safety.

Four constraints that were measured rather than assumed:

1. **Ten concurrent sessions per connection, from both ends.** SSH.NET's `ConnectionInfo.MaxSessions`
   defaults to 10 and is gated by a semaphore; `sshd` also defaults to `MaxSessions 10`. One client
   per host therefore means **a ceiling of ten in flight per host**, whatever limit §6.1 configures.
   More than that needs more than one connection per host.

2. **Opening several channels at once is the intended design, not a workaround.** The library
   serialises writes on the session and the semaphore exists precisely to allow parallel channels.
   Its README says "optimized for parallelism" and commits to nothing in writing, so this was
   recorded as *not measured* rather than as *not supported* - and then measured.

   **Measured 2026-08-26, and it works.** OpenSSH over loopback, SSH.NET `2026.0.0`, .NET 10:
   **sixteen** commands issued at once through **one** pooled client, all completing, each returning
   its own output. Sixteen is deliberately above the default ceiling of ten, so the semaphore has to
   do its job rather than the test passing underneath the limit. It lives in
   `tests/SshWarden.Ssh.IntegrationTests` and it **fails rather than skips** when the machine has no
   `sshd` - an SSH suite that skips itself is green in exactly the situation where it measured
   nothing.

3. **A timeout cannot kill a remote process.** Cancelling a command sends a signal channel request,
   and SSH.NET's own XML documentation says: *"When the server does not implement signals, it may
   send no response."* (Re-checked 2026-08-26 against `2026.0.0`: still there.) That sentence exists
   because OpenSSH historically did not implement the `signal` channel request - sources disagree
   about whether it does now, so this is **not measured, and neither half should be believed**.
   → **Wrap the remote side in `timeout <n>s <cmd>`.** Without it §4.2 records `exit_code = null`
   while the process keeps running, invisibly.

4. **Environment variables must be inlined**, per §3.2.

**One shared quoting helper, with tests.** Single-quote wrapping with `'` escaped as `'\''`, and
`--` end-of-options wherever a tool builds a command itself. `run`'s `cmd` is passed through raw -
that is the design (§8), and it is exactly why every *other* argument must be quoted without
exception.

The goal is losing the handshake cost without carrying state. An implementation that achieves that
differently is fine: the constraint is the outcome, not the API.

### 4.2 The audit record

**Every line has to mean something on its own.** The test for this design: read one record, look at
no other record, and say what happened. If you cannot, a field is missing.

| Field | Content |
|---|---|
| `id` | record identifier |
| `type` | `command` / `job` / `decision` |
| `started_at` | with a timezone |
| `sub` | who called, from §6.2 |
| `client_id` | which client |
| `gid` | **which session** - see below |
| `jti` | which token, kept so a revocation can be correlated |
| `tool` | which tool |
| `decision` | `allow` / `deny` - §6.5 |
| `denied_by` | the id of the rule that refused, never free text |
| `allowed_by` | the id of the grant that permitted it |
| `host` | the target |
| `ssh_user` | the unix account the command ran as |
| `selector` | the path or unit the caller named, verbatim |
| `resolved_path` | where that actually pointed |
| `workdir` | always a value, never null |
| `command` | after redaction |
| `exit_code` | null on timeout or when unfinished |
| `duration_ms` | |
| `stdout_bytes` | the original size, before truncation **and** before redaction |
| `output_truncated` | the agent has to know |
| `error` | why a call that was allowed did not finish |
| `job_id` | on a `job` record |
| `changes` | §4.3; an empty array when there were none |
| `changes_window_ms` | the window the sweeper actually covered |
| `changes_confidence` | `exclusive` or `overlapping:N` |

Several of those exist because of the one-record test, not because a schema wanted them:

- **`ssh_user`** - §6.5.2 says the real boundary is the unix account. A record saying a command ran
  without saying which account it ran as omits the only barrier that actually holds; everything else
  is an early refusal inside a process the target host does not trust.
- **`allowed_by`** - an earlier schema gave a refused call a rule id and gave a permitted call
  nothing. "Which rule allowed this" was answerable for things that did not happen and unanswerable
  for things that did.
- **`selector` and `resolved_path`** - the path a caller named and the file a host opened are **two
  different facts** whenever a symlink is involved, which is exactly the case the path gate exists to
  catch. Recording one of them makes `path_escapes_grant` a rule id nobody can act on.
- **`error`** - a call that was allowed and then failed looks identical to a call that had no exit
  code to report. Adding it surfaced that three of the seven tools recorded nothing on their failure
  path, so the README's claim that every call lands in the log was not true; each tool now records at
  its own SSH choke point.

**Why `gid` and not `jti`.** §3.1 removed the session shell, and what was lost with it was the
ability to group commands into a session. A token identifier does not restore that: authorization
servers mint a fresh one per token, so a three-hour session fragments into a new group at every
refresh - precisely the grouping it was reached for. The grant identifier is stable across a refresh
family, so **grouping is by `gid`**, and `jti` stays as token identity. Both are kept because they
answer different questions and are extremely easy to confuse. Which claim carries the grant
identifier is configuration; see §6.2.

With a static token all three are still present, derived at startup. Lower resolution, same schema.

**Every refusal produces a record too.** "An agent went for a production host and was stopped" is the
most useful line this log carries, and a schema written only for commands that ran has nowhere to put
it. `denied_by` is a **rule id** rather than a message: a message is localizable and grep over one is
not stable.

**JSONL, append-only, on disk.** One line per record. No database, nothing pushed anywhere. Appending
needs no lock, `tail -f` works immediately, and any log shipper can scrape it. This is the **source of
truth**; everything in §4.7 is a consumer.

### 4.3 Change detection

A command log is not enough. One line of `ansible-playbook deploy.yml` changes forty files.

The mechanism: stat the paths declared as watched, compare modification time, size and inode, and
diff. No eBPF, no auditd. Watched paths are configuration.

**The hard question is *when* to run it, not *what* to run.** Snapshotting before and after every
command has three holes:

1. **Concurrency misattributes.** Two agents on one host produce nested snapshots, and A's changes get
   attributed to B's command - while running concurrently is the whole reason §3.1 exists.
2. **`list_changes(sinceMinutes)` has no baseline.** Compared against what?
3. **It is expensive.** Walking a directory tree twice per command, on every command's latency.

**A background sweeper and a timeline.** One sweeper per host, every N seconds, **only while that
host has a live connection** - an idle host is not swept, so it costs no SSH and produces no noise. It
holds the current state and pushes changes onto a timestamped timeline.

- `list_changes(host, sinceMinutes)` queries the timeline. Hole 2 closed.
- The `changes` on a `run` record are the timeline entries overlapping `[started_at, ended_at + one
  sweep]`, with the two fields from §4.2 saying how wide the window really was and whether anything
  else was running at the same time.
- Cost falls rather than rises: one sweep per interval instead of two walks per command. Fifty short
  commands in thirty seconds go from a hundred walks to one. Hole 3 closed.

**Why this is the right answer rather than a third option.** The other two pretend: a per-host lock
kills concurrency to fake exact attribution, and accepting misattribution lies quietly. Exact
per-command attribution **does not exist** when commands overlap - not "is hard", does not exist. This
records what it knows together with how much to trust it.

Three limits, and the README states all three rather than letting a user discover them:

- Resolution is bounded by the sweep interval; a command shorter than one interval gets a window
  wider than itself.
- A change made and reverted inside one interval is invisible - though a modification-time comparison
  already misses that, so it is not a loss this design introduced.
- Modification time, size and inode miss a change that preserves all three.

### 4.4 Long-running work is a job, not a session

```
start_job(host, cmd, workdir)  → job_id
poll_job(job_id, sinceLine)    → new lines and a status
kill_job(job_id)
```

The agent polls. Job records go into the same audit log as everything else - §4.2 has `type` and
`job_id` to hold them.

**Written here rather than using MCP's `tasks`.** The protocol gained `tasks` for tracking durable
requests with polling, and it looks like exactly these three tools. It is not used, for two reasons:

1. **Clients do not implement it.** The request to support it in a major client was closed as not
   planned. A server that returns a task handle nobody polls has returned nothing. (Not to be
   confused with a harness backgrounding a slow tool call on its own: that does not survive leaving
   the session and offers no poll or kill.)
2. **Even with support, the lifetimes differ.** `tasks` makes a **request** outlive the call. A job
   here makes a **process on the target host** outlive the call - it survives a restart of SshWarden,
   and `kill_job` sends `SIGTERM` to a real unix process rather than cancelling a request. The two do
   not map onto each other; they are different problems wearing one name.

**The job store is separate from the tool surface**, so the day a client does support the protocol
mechanism, a second adapter goes on the same store.

Two things had to be settled before this could ship:

1. **Job output is plaintext on the target host, and that cannot be fixed - only the read path can be
   closed.** The command writes to a file and SshWarden runs nothing on that machine to intercept it.
   What is possible: the job directory is created `0700` with the umask set **first**, so it is
   private from the moment it exists rather than a moment later, and it lives in the home directory of
   the unix account the rule maps to. Redaction runs on the way back through `poll_job`, like all
   other output. What remains exposed is exposed to whoever could already read that account's files -
   the same people who could already run the command. Written down rather than left to be inferred.
2. **The registry is append-only JSONL, replayed at startup.** Written **before** the `job_id` is
   returned: a job whose owner was not recorded is a job nobody can poll or kill, including the person
   who started it. The newest record per `job_id` wins, and a truncated last line - a process that
   died mid-write - is skipped rather than corrupting the file.

**`start_job` does not return before the job has a process group.** Without that wait, a command the
remote shell cannot even parse is still accepted, a `job_id` is still returned for a job that never
ran, and the caller finds out at some later poll - as `gone`, with no reason attached. With it, the
remote shell's own complaint comes back from the call that caused it. Measured 2026-08-26: with no
wait, the pid file was absent at the moment the command printed `started` in 300 runs out of 300 -
not rarely wrong, wrong every time.

**`job_id` must be unguessable** - from a CSPRNG, never a counter. §6.5.3 says why.

### 4.5 Output budget

`journalctl -u x` returning 400,000 lines happens in the first week. So:

- A byte cap, defaulting to something small and adjusted once there are real numbers.
- Cut from **the middle**, keeping the head and the tail - errors are usually at the end.
- **Say so in the output**: `[... truncated 380k lines ...]`. Otherwise the agent draws conclusions
  from truncated data without knowing it.
- A `grep` parameter, filtering on the server before anything is returned.

**The order is fixed: measure `stdout_bytes` → redact → truncate.** Truncating first lets a secret
lying across the cut escape §4.6's patterns, and `stdout_bytes` is measured on the original bytes,
before both.

### 4.6 Secret redaction

An agent that runs `cat .env` puts the key into its context and from there into somebody's logs.
Redaction happens on the server, before anything is returned: known patterns, `KEY=value` lines
masked on their value, and **in the audit log as well as the response**.

**Redaction is best-effort and the README says so.** It catches known shapes; it is not a guarantee.
The real barrier for a secret is §6.5.2 - the SSH account cannot read that file in the first place.

### 4.7 Consumers, and a boundary not to cross

> **SshWarden must not know what your dashboard is.** It writes JSONL to disk and exposes
> `/metrics`. That is all.

Nothing is pushed anywhere. Pushing means owning retry, buffering and backpressure, and losing logs
when the far end is down; with a file, the far end being down costs nothing. It also means somebody
running no observability stack at all can still use the tool - which §3.3 requires.

**Label cardinality is where this breaks if done wrong.** Finite label sets only: the tool, the host,
the outcome. Never the session id, the token id, the subject, the command or the working directory -
those are unbounded. The session id is especially dangerous because it is the grouping field from
§4.2 and looks like a natural label; one new session is one new stream. Those fields live in the JSON
body and are filtered at query time. **Which fields become labels is the log shipper's configuration,
not this project's.**

Six metrics, and the surface is closed:

```
sshwarden_commands_total{host,outcome}      // outcome: ok | fail | deny
sshwarden_command_duration_seconds
sshwarden_output_bytes                      // histogram
sshwarden_pool_connections_active
sshwarden_output_truncated_total
sshwarden_denied_total{tool,rule}
```

`sshwarden_output_bytes` exists to answer the open question in §4.5 - whether the cap is right - from
p95 and p99 after two weeks of real use, and `output_truncated_total` says how often an agent is being
cut off.

**A `MeterListener` writing Prometheus text, written here.** `System.Diagnostics.Metrics` is an
instrument API; .NET ships no Prometheus text exposition. The alternatives were measured: the
OpenTelemetry Prometheus exporter has never had a stable release, and `prometheus-net` targets an old
framework with no release since early 2024. Six metrics is a closed and small surface - counters and
gauges are trivial and only the two histograms are fiddly - so it is about two hundred lines with
tests, and scraping keeps two things pushing does not: `curl localhost/metrics` works with no
collector present, which matters for a tool where a misconfiguration means exposed SSH; and somebody
with no stack at all can still read it.

> Do not reuse §4.7's opening argument to reject pushing metrics. "The file survives when the far end
> dies" is true of **logs**, because logs are the source of truth. Metrics are already an aggregate,
> and scraping loses data too when the scraper dies. The reasons above are the reasons.

Three things surfaced while building it, each a real trap:

1. **Cardinality is a memory budget somebody else spends.** The rule against unbounded labels misses
   the more dangerous case: **the host comes from the caller**, and on a refused call it is a string
   that does not exist. Using it directly lets a caller create one series per request - using exactly
   the calls this server correctly refuses - until memory runs out. The fix is at the point where a
   label is chosen, not a cap underneath: every label value comes from a closed set, and anything
   outside becomes `unknown`. A cap is the other design and it **drops series silently**, which reads
   as "nothing happened" at the moment something did.
2. **A three-valued outcome needed a new field**, which is where §4.2's `error` came from.
3. **Do not record at the gate.** Tried: the gate catching every exception and writing a record. Wrong
   - a tool refuses on its own *after* the gate passed it (`path_not_found` is only knowable once the
   host has resolved the path) and records that itself, so the gate wrote a second `allow` record over
   the top. Record where the code knows what it is doing.

**`/metrics` requires a credential.** The `host` label carries production machine names - the same
thing §6.5.4 goes out of its way not to publish. A scraper's token should be one whose subject has no
grants at all: reading aggregates needs no reach.

---

## 5. Tool surface

Exactly seven tools:

```
run(host, cmd, workdir?, env?, timeoutSec?, grep?)
read_file(host, path, maxBytes?)
tail_log(host, unitOrPath, lines?, grep?)
list_changes(host, sinceMinutes?)
start_job(host, cmd, workdir?)
poll_job(jobId, sinceLine?)
kill_job(jobId)
```

An eighth is a decision, not an addition. §4.4 says why the three job tools do not give way to the
protocol's own task mechanism.

**There is no `query_audit` tool, deliberately.** The log is a file; whatever already reads logs can
read it, and a tool that queries the audit log from inside the process being audited is a strange
thing to build.

---

## 6. Authentication and authorization

### 6.1 Defaults

This is a tool where a misconfiguration exposes SSH to the internet.

- **Bind `127.0.0.1` by default.** Public requires saying so, and the right way is a reverse proxy.
- **Refuse to start without authentication.** There is no "no auth for development" mode.
- Static tokens are compared in constant time.
- Hosts and credentials are read from a config file at mode `0600`, never from a command-line
  argument - an argument is visible to every process on the machine.
- The SSH key this process uses should be its own, narrowly scoped. Never one with unrestricted
  `sudo`.
- Rate limiting and a per-host concurrency limit. Remember the hard ceiling in §4.1: a limit above ten
  means nothing with one connection per host.

### 6.2 Authentication is an interface, not a hard dependency

Authentication sits behind **one abstraction**, with **more than one implementation from the start**.

- Every implementation returns the same five values: **subject, client id, grant id, token id, and the
  scope claim's state**. These flow straight into the audit record (§4.2).
- **They are named properties on the interface, never a lookup into a claims dictionary.** A
  misspelled string key does not fail to compile; it returns null.
- The implementation is chosen by configuration, not by a compile-time flag.
- **Nothing else in the codebase may know which one is running.**

Two implementations ship, and the seam takes any third:

- **Static token** - zero dependencies, enough for somebody running their own machine. The default.
  It derives stable values for the five, because it genuinely has no authorization server behind it.
- **`SshWarden.OAuth`** - the framework's bearer handler doing OpenID Connect discovery against any
  configured issuer, plus the RFC 9728 document. What the shipped host references.
- **Anything else filling the same seam**, written by a deployment that needs one.

**There was a third, and removing it is the point of this paragraph.** An adapter shipped that read
one particular authorization server's tokens using that server's own packages. Nothing it did was
outside the standards: an authorization server hands a resource server a JWT, a JWKS document and an
RFC 9728 resource identifier, `SshWarden.OAuth` already speaks all three, and pointing it at that
server took one line naming the claim it spells differently, which the example config had documented
the whole time. What the adapter cost was a second reader of the same standards to keep correct, and
another project's packages in the dependency graph of a server whose selling point is that it
validates somebody else's tokens. A deployment consumes an authorization server; it does not carry
one's code.

**A validated token missing `sub`, the client id, the grant id or the token id is refused, not filled
in.** The rule above about deriving values is right for a static token; for OAuth it is not. A
placeholder produces an audit record that looks complete and answers nothing, because each of those
values has one job and a placeholder destroys exactly that job.

**Which claim carries which value is configuration.** RFC 9068 names `client_id` and `jti` for a JWT
access token, so those are the defaults. Nothing names the claim that groups a session, so
`auth.oauth.grant_id_claim` names it - and if an authorization server emits nothing of the kind, the
operator sets it to `sub` deliberately and accepts the coarser grouping. What the library will not do
is pick that fallback quietly: a grouping nobody chose, sitting in the audit log looking like the
authorization server produced it, is worse than a configuration key somebody had to fill in.

**No token introspection.** Introspection typically requires the resource server to hold a long-lived
client secret, and §6.1 prefers a credential that expires. For this threat model - being wrong, not
being controlled - a signature and an expiry answer the question. The cost is that a revocation takes
effect at the token's expiry rather than immediately, which is worth knowing before deciding it is
enough.

**The authorization server must be reachable at startup.** A resource server that starts with no
signing keys answers 401 to every caller holding a perfectly good token, which reads as a credential
problem and is a deployment ordering problem. The process refuses to start, names what did not answer,
and exits `69` rather than `78` - because a restart is the fix for one and not for the other.

### 6.4 What OAuth does not solve

> A valid token answers **who is calling**. It does not answer **as which SSH identity**.

If there is one SSH key and every valid token uses it, OAuth is a gate that opens onto root
everywhere. What is needed is an explicit mapping in configuration, expressing:

> **(subject + scope) → which SSH user, on which hosts**

The requirement: reading the config file tells you who can touch what, without inference. §6.5.2
raises this from preparation to **the** real boundary.

### 6.5 Per-tool and per-argument authorization

#### 6.5.0 Why this exists, and one line that must never be written

It is tempting to believe that granting a read-only scope prevents `run`. It does not. Scope
enforcement at the route gates a **route**, and MCP puts **every tool through one route**. A required
scope there is the intersection of what all the tools need, so the widest scope a connector advertises
is enforced by nothing.

⇒ Per-tool authorization is **this project's job**, and it is real work.

**But requiring a scope on the MCP route is worse than not gating at all - it also blocks *asking* for
scopes.** This is the most expensive thing in §6.5.

A route-level scope requirement declares **two** things at once:

1. the route gate - useless here, as above;
2. **the `scope` parameter of the 401 challenge** - which nobody notices.

An MCP client's scope-selection strategy reads the challenge's `scope` **first**, falling back to the
resource's advertised list only when the challenge names nothing.

⇒ Requiring `ssh:read` on the route **tells every client to ask only for `ssh:read`**. The wider scope
never reaches a consent screen, no token ever carries it, and **every `run` is refused forever** - and
re-consenting does not help, because the client reads the same challenge again.

**This has happened.** A connector declared a read scope on its endpoint. Its write scope was declared
in the host, advertised in both metadata documents, shown on the consent page and enforced in the
tool - every piece correct in isolation. Nothing raised an alarm: reads worked, the health endpoint
was green, the deployment's own verification script printed that the scopes agreed. It surfaced only
when the write scope began to be enforced in the tool, at which point **every write failed at once**.
From that incident's own record: the last successful write at 09:19 UTC, enforcement at 10:01 UTC,
discovered **six and a half hours later** because a person said they had lost access.

**Requiring both scopes is not the answer either** - a route requiring every named scope refuses a
genuinely read-only grant even for reads.

**The correct wiring is one line**: require a bearer, never a scope. The endpoint is still
challenged - deny-by-default still holds - and the challenge carries the resource's **whole**
advertised set, so a client asks for what the tools actually need. What is lost is a route-level scope
check, and losing it is deliberate: it gated nothing. What replaces it is §6.5.1 to §6.5.4.

> The consequence here is more expensive than in that incident. There, losing writes lost writes. Here,
> losing the execute scope means every `run` fails - which is the entire reason the tool exists.

**The sentence above was true of the design and not of the code, until it was measured.** Between
step 8 landing and 2026-08-27 the challenge carried nothing at all: no `scope`, and - worse - no
`resource_metadata`, so a client meeting this server for the first time was told it needed a
credential and never told where to read about getting one. The metadata document was served
correctly at both well-known forms the whole time, which is exactly why nothing noticed; every unit
test passed, because no unit was wrong. It was found by writing the RFC 9728 contract as a suite
that asserts against a wired application rather than a unit, which went red on the one assertion
that ties the document to the challenge that should point at it.

The challenge now carries both, and the scope parameter is the configured list
whole - which is the same set a client would have reached by the fallback above, stated rather than
relied upon.

#### 6.5.1 Which arguments can be gated

> An argument can be gated **when it identifies a resource**: discrete values, exactly comparable, and
> **dereferenced by SshWarden itself**.
> It cannot be gated **when it carries behaviour**: content the target host interprets.

| Tool | Gateable | Not gateable |
|---|---|---|
| `run` | `host` | `cmd`, `env`, `timeoutSec`, `grep` |
| `start_job` | `host` | `cmd` |
| `read_file` | `host`, `path` | `maxBytes` |
| `tail_log` | `host`, `unitOrPath` | `lines`, `grep` |
| `list_changes` | `host` | `sinceMinutes` |
| `poll_job` | `jobId` → (owner, host) | `sinceLine` |
| `kill_job` | `jobId` → (owner, host) | - |

**`run.workdir` is not a security boundary.**

```
run(host="prod-web-1", workdir="/opt/app", cmd="cat /etc/shadow")
```

Gating the working directory stops nothing: the command is free by design (§8) and `cd` goes
anywhere. For `run` and `start_job`, **the only real gate is the host.**

The working directory is still declared as a selector - it catches mistakes and it keeps the log
clean - but **the README says plainly that it is audit metadata rather than a barrier.** Not saying so
lets the config file itself create the false confidence that §9 requires warning about.

**`read_file` and `tail_log` have a real path gate, and three traps.** Here SshWarden builds the
command, so the agent injects nothing. But:

- **`..` traversal** - normalize before comparing.
- **Symlinks on the target host.** A local prefix check passes while the remote read escapes. The path
  must be resolved **on the target** and the *result* prefix-checked.
- **Time-of-check to time-of-use** - the link can change between resolution and read. Not closeable
  from this side.

#### 6.5.2 The last boundary is the unix account, not this code

**This is the most important point in §6.5.**

§6.4 laid the ground: a mapping from subject and scope to an SSH user on a set of hosts. Path gating
inside SshWarden is **the first layer** - it catches mistakes, refuses early and logs clearly. **The
layer that cannot be worked around is the unix permissions of that account.**

If a read-only mapping points at an account for which `cat /etc/shadow` fails on file mode, then every
traversal, symlink and race is meaningless - they change the error message. If it points at an account
with `sudo`, no amount of C# saves anything.

→ Invest in the mapping table and in creating narrow accounts on the target hosts. The path selector is
defence in depth and the README describes it as exactly that.

#### 6.5.3 `poll_job` and `kill_job` are an IDOR waiting to happen

A job id is an **indirect** resource reference. Without resolving it to its owner and host and
comparing against the caller, one agent can poll another's job - reading production output - and kill
it. Both bypass every host allowlist, because the argument contains no host.

The id must be **unguessable**: from a CSPRNG, not a counter.

**The comparison is on the subject rather than the grant.** That is looser than it first appears it
should be, and deliberately: two sessions of one person share a grant, and both could `run` a command
that reads the job's output file directly. A stricter gate would refuse something it cannot actually
prevent, at the cost of a user losing their own jobs every time their token changes. The owning grant
is still **recorded** - not compared, but present for whoever reads the log.

A refused caller is told only **`no such job`**: somebody else's job, from where they stand, does not
exist. The real reason is in the audit record, for the operator - who is not the person being refused.

#### 6.5.4 Two layers, and never a host in a scope

```
effective authority = (scope in the token) ∩ (the subject's grant table)
```

**Scopes stay coarse: `ssh:read`, `ssh:exec`. Never `ssh:exec:prod-web-1:/opt/app`.**

Three reasons, the first being the real one:

1. A resource's advertised scope list is a **public document that needs no credential**. A scope
   naming a host publishes that hostname to anyone who asks.
2. A consent screen becomes unreadable.
3. Every new host means editing the authorization server's configuration and re-consenting everybody.

**The fallback has to distinguish three states, not two:**

| Token | What to do |
|---|---|
| **no** `scope` claim | fall back to the grant table - an authorization server that publishes no scopes issues tokens carrying none, and so does a static token |
| a `scope` claim granting nothing | **refuse** - the token was written to grant nothing |
| a `scope` claim that will not parse | **refuse**, and under no circumstances fall back |

The third state is not hypothetical. A scope parser rejects the **whole** claim on any character
outside RFC 6749's scope-token set, so one stray character produces an empty set - and falling back to
the grant table then turns a token that was written to restrict a caller into one that does not
restrict them at all. That is fail-open, in the dangerous direction.

**The grant table is deny-by-default.** No matching grant means refusal, and the refusal names **which
rule** refused.

```toml
[[grant]]
id       = "dev-exec"
subject  = "someone"
scopes   = ["ssh:exec"]
tools    = ["run", "start_job", "poll_job", "kill_job"]
hosts    = ["dev-*"]
ssh_user = "deploy"

[[grant]]
id       = "prod-read"
subject  = "someone"
scopes   = ["ssh:read"]
tools    = ["read_file", "tail_log", "list_changes", "poll_job"]
hosts    = ["prod-web-1.example.com", "prod-db-1.example.com"]
paths    = ["/var/log/**", "/etc/nginx/**"]
ssh_user = "auditor"          # an account that cannot read anything else
```

Host patterns are globs matched label by label, compared ordinal and case-insensitively. **Never
regex** - it is a denial-of-service surface, and somebody who writes an incorrect regex does not find
out. A glob's mistakes produce no match, and no match is refused.

#### 6.5.5 Where the decision hooks in

Not hand-rolled middleware. The MCP SDK provides a filter over **every** `tools/call` and a filter over
`tools/list`, with the caller's principal available without depending on HTTP context.

The policy answers two questions, and both must be wired together - filtering `tools/list` without
gating `tools/call` is a surface that *looks* gated while anybody who knows a tool's name still reaches
it:

| Question | Runs on | Used for |
|---|---|---|
| may this caller see this tool | `tools/list` **and** `tools/call` | scope→tool, plus the grant table's `tools` column. A refusal here hides the tool entirely |
| may this caller call it **with these arguments** | `tools/call` only | all of §6.5.1: `host`, `path`, `unitOrPath`, and `jobId` (§6.5.3) |

**The second can only refuse, never hide** - a listing has no arguments to judge. That is the right
shape of the question rather than a limitation: whether you may see `run` does not depend on which host
you were going to pass it.

**This is where §6.5.3's IDOR check lives.** The first question always passes for `poll_job` - it is the
same tool for everyone. Resolving the job id to its owner and comparing **must** happen in the second,
not in the tool body.

Arguments arrive as a read-only view of the JSON as it arrived, before binding.

#### 6.5.6 Three mandatory safeguards

The filter sees arguments as raw JSON, before binding, so the policy extracts `host` and `path` **by
name**. A misspelled argument name means **the gate silently disappears**. Three tests:

1. Every registered tool has an entry in the policy - missing one fails the build.
2. Every resource-argument name the policy declares **actually exists** in that tool's input schema -
   otherwise the build fails.
3. **Every scope this server advertises can be asked for in the 401 challenge.** This is the test that
   catches §6.5.0: a route-level scope requirement introduced in future goes red here, rather than red
   in a `run` refused six hours later.

The third asserts a **property rather than a line of code**, which is why it catches what every
isolated test missed. All three must be **red before the change they check**, with a control proving
the permitted path still passes.

#### 6.5.7 `tools/list` must be filtered

Without filtering, "a read-only token means `run` does not exist for it" is a lie: the agent sees
`run`, calls it, takes an error and retries in a loop.

With filtering, the tool list differs per token - so if a scope is raised mid-session, a
`tools/list_changed` notification has to follow or the client keeps the old list.

#### 6.5.8 What a refusal can say - measured, and the answer is: only words

When the gate refuses, the caller needs to know **which scope would fix it**. Both mechanisms that
could carry that are closed, and both were measured on 2026-08-25.

- **The tool-result field.** A draft proposal defines a `WWW-Authenticate` value inside a tool result's
  metadata. It is **Draft**, sponsored, **not adopted**, names no target revision, and claims no client
  implements it. The string `authenticat` - any casing, any position - appears **zero times** in the
  current schema and **zero times** in the draft. No schema defines any such metadata key.
- **The HTTP challenge.** Refusing per-tool cannot be a `401` or `403`. Streamable HTTP refuses a
  client that will not accept an event stream, and by the time a call-tool filter runs the response has
  already started - the `200` status line is on the wire. Not "hard": the status is sent before the
  tool is even chosen.

⇒ **A refusal reaches the caller as text in a tool result, and nothing else.** Worse than a challenge,
better than silence, and the thing to do is **say which of the two it is** rather than imply the other.

A refusal for a missing scope names **every** scope the operation needs, not the difference - a client
asks for the union of what it is told and what it holds, so naming only the delta re-authorizes the
person into a *narrower* grant than they started with.

**Consequence for the README:** the security section says that when SshWarden refuses for a missing
scope it can only say so in words, and the client will not automatically ask for more access. A person
has to re-authorize.

---

## 7. Build order

1. MCP server skeleton over HTTP, the authentication abstraction, the static-token implementation and
   config loading - the abstraction declaring **five named values** (§6.2), no magic strings.
2. **The authorization gate (§6.5), the connection pool, `run`, and the audit record.**
3. Output cap and redaction, in the fixed order: measure bytes → redact → truncate.
4. `read_file` and `tail_log` - path selectors and remote path resolution.
5. Change detector and `list_changes` - background sweeper and timeline, §4.3.
6. The job model, three tools, §4.4. The job store is separate from the tool surface.
7. `/metrics` (§4.7) - a `MeterListener` written here.
8. OAuth, replacing the static token as the default for a real deployment.

**Why the gate is step 2 rather than step 8.** Deferring it means five tools ship ungated and then get
retrofitted one at a time - exactly what a single call-tool filter exists to avoid. Step 2 only needs
the gate working against a static token and a grant table; it does not need OAuth.

**Why OAuth is last.** A static token lets the thing ship and be used immediately while the
abstraction holds the place open. Starting with OAuth would mean every SSH bug arriving mixed with a
token bug.

---

## 8. Non-goals

- ❌ No session shell, however convenient it looks.
- ❌ No taint tracking, dual-LLM patterns, plan freezing or capability sealing - §2.1.
- ❌ **No command allowlist or denylist by string content - permanently.** It is not answerable at the
  string level: a shell's `-c`, several hundred binaries that can spawn one, and environment expansion.
  §6.5 guards somewhere else.
- ❌ **No gating of `cmd`, and no regex over `cmd`.** §6.5.1 is the boundary. "We only need to block
  `rm -rf`" is the beginning of a list that has already been published four hundred ways around.
- ❌ **Never a host, path or tenant inside a scope string** - §6.5.4.
- ❌ No approval or blocking workflow.
- ❌ No billing, hosted tier, multi-tenancy or user management.
- ❌ **Nothing pushed directly to an observability backend.** JSONL on disk, scraped.
- ❌ No dashboard, no frontend, no HTML. (This is about a user interface. It does **not** mean
   disabling the event stream in Streamable HTTP - that is the transport.)
- ❌ No alerting logic in code; alert rules live where alerts are configured.
- ❌ No unbounded log labels - §4.7.
- ❌ No SSH certificate authority or certificate issuance.
- ❌ No performance work before there are real measurements.

If one of these starts to look necessary to do the job properly, the scope has grown. Stop and say so.

---

## 9. Deliberately deferred

Not decisions against, just not now: an approval workflow where a person confirms a command before it
runs; a second upstream identity provider; anything that needs real usage data to size, including
whether the output cap is set correctly - which is what `sshwarden_output_bytes` exists to answer.
