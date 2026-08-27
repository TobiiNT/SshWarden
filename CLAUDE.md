# Working in this repository

SshWarden lets a model run shell commands on somebody's production hosts. Everything it does is, by
design, what you would otherwise call a compromise, and the only difference is whether the grant
table said so. That one fact is behind most of the rules below.

Read [`docs/DESIGN.md`](docs/DESIGN.md) before a first change. It carries the reasoning, with the
section numbers the code cites; this file carries how to work.

---

## Part 1: how to work

Adapted from [multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills),
whose own note says to merge it with project-specific instructions. Part 2 is that merge, and where
the two disagree Part 2 wins, because it was paid for.

**Tradeoff:** these bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think before coding

**Do not assume. Do not hide confusion. Surface tradeoffs.**

- State your assumptions. If uncertain, ask.
- If multiple interpretations exist, present them rather than picking silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what is confusing. Ask.

### 2. Simplicity first

**The minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No configurability that nobody requested. Note the exception in Part 2: a value a *deployment*
  could reasonably need to change is an option with a documented default, not a constant.
- No error handling for impossible scenarios. This is not a licence to swallow a possible one:
  every refusal here names what was refused and which rule refused it.
- If you write 200 lines and it could be 50, rewrite it.

Ask: would a senior engineer say this is overcomplicated? If yes, simplify.

### 3. Surgical changes

**Touch only what you must. Clean up only your own mess.**

- Do not improve adjacent code, comments or formatting.
- Do not refactor things that are not broken.
- Match existing style even where you would do it differently.
- Notice unrelated dead code? Mention it. Do not delete it.
- Remove the imports, variables and functions *your* change orphaned. Nothing else.

The test: every changed line traces to the request.

**The one carve-out, and it is narrow.** A comment, a citation or a document that has become false
is not adjacent code, it is a defect in what the next reader will believe. Fixing one in a file you
are already editing is in scope, and saying so in the diff is required. Everything else waits.

### 4. Goal-driven execution

**Define success criteria. Loop until verified.**

- "Add validation" becomes "write tests for invalid input, then make them pass".
- "Fix the bug" becomes "write a test that reproduces it, then make it pass".

For multi-step work, state the plan as steps with a check each:

```
1. [step] -> verify: [check]
2. [step] -> verify: [check]
```

Strong criteria let you loop without asking. Weak criteria ("make it work") do not.

---

## Part 2: what this repository already decided

### A measurement, or say you did not measure it

Every axis needs a third value: yes, no, and could not tell. "I could not find it" is not "it is not
there". Anything asserted about somebody else's system carries how it was measured and when, because
a fact with no date silently becomes a claim. This is not style; it is why `changes_confidence`
exists on the run record and why `list_changes` states its own resolution.

### A refusal names its boundary

An empty result where an error belongs produces a caller who concludes the system lost their data.
Every refusal says what was refused and which rule refused it. The config loader reports **all**
problems in one exception rather than one per restart, and distinguishes "not measured" from "pass".

### Comments carry the reason, not the mechanism

Comment density here is deliberate. A comment does not say what the code does; it says **why this
and not the obvious alternative**, and where possible names the incident that settled it. If you
cannot say why the obvious alternative is wrong, that is worth discovering before the change lands.

Keep the anecdote and lose the deployment: *what* went wrong is the reusable half, *who it happened
to* is not.

### Nothing about one deployment lands here

This is an open-source tool, and the reader is a stranger with none of your context.

- **No company, product or person names** in identifiers, comments, docs, log lines or fixtures.
- **Example values obey RFC 2606**: `example.com`, `.test`, `.invalid`, `.localhost`. Nothing else
  is guaranteed unregistrable, and this process dereferences URLs somebody else supplied.
- **A default is not a policy.** Anything a deployment could reasonably need to change is an option
  with a documented default. If it cannot be changed, the comment says why.

### The boundaries that are not negotiable

- **No command allowlist or denylist by string content, permanently.** `docs/DESIGN.md` section 8.
  It is not answerable at the string level. `run` running something destructive inside a grant that
  permitted it is the tool working.
- **Never a host, path or tenant inside a scope string.** That list is published unauthenticated.
- **A host key is verified or the connection does not happen.** No trust-on-first-use, no off switch.
- **No credentials, ever.** Not in code, not in a fixture, not in a commit message, not in a sample.
  Prefer a credential that expires; if a long-lived secret must exist, make it the one that derives
  short-lived ones. A secret is never a command-line argument, because `ps` is readable.
- **Masking is the second line, not the first.** The first is the `ssh_user` not being able to read
  the file at all.

### Tests

- A new rule needs a test that goes **red without the change**. A test that would pass against the
  old code is a promise rather than a check.
- **A refusal proves nothing without a control.** Every test asserting something is refused has a
  sibling proving the same path accepts what it should.
- Do not assert on timing. Wait on the work.
- **Never skip, disable or quarantine a test to get green.** If a test is wrong, fix it and say in
  the diff why it was wrong.
- `SshWarden.Ssh.IntegrationTests` fails rather than skips without a real `sshd`, deliberately: a
  suite that skips itself is green in exactly the situation where it measured nothing.

### After changing anything

```bash
dotnet build SshWarden.slnx    # must be 0 warnings
dotnet test  SshWarden.slnx    # must be 0 failures
```

**Warnings are errors here.** This process opens shells on production hosts, so a warning is a
defect nobody has noticed yet.

---

## Part 3: how to write

The audience is a stranger reading under time pressure, often during an incident.

- **No em-dashes (U+2014).** Use a comma, a colon, a full stop, or ` - `. It applies to strings as
  well as prose here, which is stricter than it sounds: this repository has never had one in a
  literal, and its messages are matched character for character by tests. `ci.yml`'s `prose` job
  runs the check, over tracked files so `bin/` and `obj/` cannot be scanned:

  ```bash
  git ls-files -z | xargs -0 env LC_ALL=C.UTF-8 grep -nIP '\x{2014}'   # finding one is the failure
  ```

  `LC_ALL` is not decoration: without it GNU grep reads the pattern as bytes and answers
  `character code point value in \x{} or \o{} is too large`, which looks like a broken command
  rather than a passing check.

- **English everywhere**, and not as a preference: identifiers, comments, commit messages, log lines,
  and anything compared character for character. Two implementations must not diverge on a
  translation.
- **State the thing, then the reason.** A bolded claim followed by why it is true reads faster than
  a paragraph that arrives at its point.
- **Name the incident where there was one**, with its date. "Measured 2026-08-26" outranks "should".
- **Say what you did not check.** A section that is silent about its limits reads as complete.
- No filler openers, no restating the request back, no summarising what the reader just read.
