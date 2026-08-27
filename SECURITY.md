# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting:
[Security → Report a vulnerability](https://github.com/TobiiNT/SshWarden/security/advisories/new).

If that is unavailable to you, open a public issue saying *only* that you have a report and cannot
file it privately. Never put the detail there: this project runs shell commands on other people's
production hosts, and a working report is a working attack until the fix ships.

What helps, roughly in order:

- Which version, and whether you reproduced it against `main`.
- Which surface: a tool, the grant table, the SSH layer, an authentication mode, the audit record.
- A failing test. Red on `main`, green on your fix, is the fastest possible report.
- What an attacker gets and what they needed to start with. "A read-only grant reaches a host it
  does not name" and "no credential reaches anything" are different reports.

You will get an acknowledgement within a week. That is a real limit rather than a promise dressed
up as one — if a week passes in silence, send a reminder.

**Supported versions:** `main`, and nothing else. There is no release yet and no branch carrying
backports.

## In scope

Everything under `src/` and `hosts/`. Worth your time, roughly in order of what a defect costs:

- **The grant table** — `(subject + scope) → which SSH user, on which hosts, for which tools, with
  which arguments`. Reaching a host, path, unit or tool that no matching rule names is the sharpest
  report this project can get. So is a rule matching a subject it should not.
- **The arguments around `cmd`.** `cmd` is the caller's to write and is deliberately ungated.
  Everything else is gated, so if `env`, `grep`, `path`, `unitOrPath`, `lines`, `maxBytes`,
  `timeoutSec` or `sinceMinutes` can break the quoting and append a second command, that is a
  vulnerability.
- **The job identifier gate.** Polling or cancelling a job belonging to someone else. The refusal is
  deliberately indistinguishable from "no such job"; if it is distinguishable, say so.
- **Host key verification** — a connection completing against a fingerprint that does not match.
- **Both authentication modes** — static-token comparison; and on the OAuth path, token validation,
  the audience binding, the claims a refusal depends on, and the RFC 9728 document, which answers
  without a credential and so must disclose nothing beyond what it is for.
- **Secret redaction and the audit record.** A credential surviving redaction in either direction,
  or a call that happened and left no record.
- **The output budget** — making this process spend unbounded memory or time.

## Not a vulnerability

Not because they do not matter, but because a report about them is not a vulnerability report:

- **That there is no command allowlist.** The oldest deliberate decision here, argued in
  `docs/DESIGN.md` §8: it is not answerable at the string level, and "we only need to block
  `rm -rf`" begins a list already published four hundred ways around. **`run` running a destructive
  command is the tool working.** What restrains it is which host the rule reaches and which unix
  account it logs in as.
- **Anything a deployment configures wrong** — a grant pointing at an account with broad `sudo`,
  `allow_private_issuer` left on, a listener off loopback with no proxy. Found a way to
  misconfigure this that the README does not warn about? That is a documentation issue, and welcome.
- **A static token not expiring.** The documented limit of the zero-dependency mode. One *accepted
  when it should not be* is very much in scope.
- **The last boundary being the unix account.** All of this runs in a process the target does not
  trust and cannot verify.
- **Deferred capabilities** (`docs/DESIGN.md` §9). An absent feature is not a vulnerability; one
  this project *advertises* and does not have is.
- **Scanner findings with no reachability analysis.** Open an ordinary issue.

## Disclosure

Report privately and give a fix a reasonable chance to ship. If this project is unresponsive past
what you consider reasonable, publish — an unmaintained security-critical tool that nobody knows is
unmaintained is worse than a disclosed bug. Reporters are credited in the release carrying the fix
unless they ask not to be.

---

Everything SshWarden does is, by design, what you would otherwise call a compromise: an automated
caller opening a shell on a production machine. The only difference is whether the grant table said
so — which is why a defect here is not a crash but a command that ran on a host nobody authorised,
and why the audit record is the only place it shows up.
