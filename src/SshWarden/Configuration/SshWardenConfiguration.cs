namespace SshWarden.Configuration;

/// <summary>Everything SshWarden reads out of its config file.</summary>
/// <remarks>
/// This is the whole surface of the file as of step 1 of docs/DESIGN.md §7. The loader rejects any key
/// it does not find here, so the type and the accepted file stay the same thing.
/// </remarks>
public sealed class SshWardenConfiguration
{
    /// <summary>Where the process listens, and under what path.</summary>
    public required ServerSection Server { get; init; }

    /// <summary>How callers are authenticated. There is no mode that skips it.</summary>
    public required AuthSection Auth { get; init; }

    /// <summary>How SshWarden reaches a host.</summary>
    /// <remarks>
    /// <see langword="null" /> when no <c>[[host]]</c> is declared, because there is then nothing
    /// to reach and no key to reach it with.
    /// </remarks>
    public SshSection? Ssh { get; init; }

    /// <summary>The machines SshWarden can be asked to reach.</summary>
    public IReadOnlyList<HostEntry> Hosts { get; init; } = [];

    /// <summary>
    /// Who may run what, where, and as which unix account. Deny by default: a call not covered here
    /// is refused.
    /// </summary>
    public IReadOnlyList<Authorization.Grant> Grants { get; init; } = [];

    /// <summary>Where the audit log is written.</summary>
    public required AuditSection Audit { get; init; }

    /// <summary>How much output a caller gets back.</summary>
    public OutputSection Output { get; init; } = new();

    /// <summary>Which paths are watched for changes, and how often.</summary>
    public WatchSection Watch { get; init; } = new();

    /// <summary>Where jobs live, on both ends.</summary>
    /// <remarks>
    /// Required rather than defaulted, because its own default depends on where the audit log is
    /// and a type cannot work that out for itself. The loader resolves it.
    /// </remarks>
    public required JobsSection Jobs { get; init; }

    /// <summary>The <c>/metrics</c> endpoint.</summary>
    public required MetricsSection Metrics { get; init; }
}

/// <summary>The <c>[metrics]</c> table.</summary>
/// <remarks>
/// <para>
/// Scraped rather than pushed, and that decision is not the one made about the audit log. The log
/// is written to a file because it is the source of truth and a file survives the collector dying;
/// a metric is already an aggregate, and a scrape loses data when the scraper dies exactly as a push
/// loses data when the receiver does. The two reasons scraping wins here are different ones:
/// <c>curl</c> against this endpoint works before any collector exists, which matters for a server
/// whose misconfiguration means exposed SSH; and a deployment with no metrics stack at all can still
/// read it.
/// </para>
/// </remarks>
public sealed class MetricsSection
{
    /// <summary>Whether the endpoint is routed at all. Defaults to on.</summary>
    /// <remarks>
    /// Off means the route does not exist, rather than existing and answering 404 or an empty
    /// document. A capability that is advertised and hollow is worse than one that is absent,
    /// because a scraper believes it and reports zero.
    /// </remarks>
    public bool Enabled { get; init; } = true;

    /// <summary>Where it is served. Defaults to <c>/metrics</c>.</summary>
    public string Path { get; init; } = "/metrics";
}

/// <summary>The <c>[jobs]</c> table.</summary>
public sealed class JobsSection
{
    /// <summary>Where the registry of started jobs is kept, on this machine.</summary>
    /// <remarks>
    /// <para>
    /// On disk rather than in memory, and that is not an optimisation. The process runs on the
    /// target and outlives a restart of this server; an in-memory registry would not, so after a
    /// deploy every running job would be unpollable, unkillable and - worse - unowned, leaving the
    /// check that stops one caller reaching another's job with nothing to compare against.
    /// </para>
    /// <para>
    /// Defaults to sitting beside the audit log. Both are this deployment's own state on this
    /// machine, so one directory to choose and secure is better than two - and a deployment that
    /// has already answered "where does my state go" should not have to answer it twice.
    /// </para>
    /// </remarks>
    public required string Registry { get; init; }

    /// <summary>
    /// The directory on each target that job directories are created under, relative to the account's
    /// home.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Under the home of the unix account the rule maps to, because that is an account which
    /// already owns its own files. Each job's directory is created mode 0700 with a umask set
    /// first, so its output is private from the moment it exists.
    /// </para>
    /// <para>
    /// <strong>That output is unredacted on the target and cannot be otherwise</strong> - the
    /// command writes to the file directly, and nothing of SshWarden's is on that machine to
    /// intercept it. Masking happens on the way back through <c>poll_job</c>. What remains exposed
    /// is exposed to whoever can already read that account's files, which is the same set of people
    /// who could have run the command.
    /// </para>
    /// </remarks>
    public string RemoteDirectory { get; init; } = ".sshwarden/jobs";

    /// <summary>How many lines <c>poll_job</c> returns when the caller does not say. Defaults to 200.</summary>
    public int DefaultPollLines { get; init; } = 200;
}

/// <summary>The <c>[watch]</c> table.</summary>
/// <remarks>
/// <para>
/// A command log is not enough on its own. <c>ansible-playbook deploy.yml</c> is one line in the
/// audit record and forty changed files on the machine, and the second is what somebody actually
/// needs to see.
/// </para>
/// <para>
/// Empty <see cref="Paths" /> turns change detection off, and startup says so. It is off rather
/// than defaulting to something, because what is worth watching is a property of the deployment -
/// a default of <c>/etc</c> would be right for some machines and an expensive irrelevance on
/// others.
/// </para>
/// </remarks>
public sealed class WatchSection
{
    /// <summary>The directories swept for changes.</summary>
    /// <remarks>
    /// <para>
    /// One list for every host. A path that does not exist on a machine simply contributes nothing
    /// there, which is self-correcting; per-host lists would be a second place to keep in step for
    /// a problem the sweeper does not actually have.
    /// </para>
    /// <para>
    /// <strong>Everything under these is visible to anyone allowed <c>list_changes</c> on the
    /// host</strong> - which paths changed and when, though not their contents. That is what
    /// putting a path here decides, so choose them the way you would choose what to publish.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Paths { get; init; } = [];

    /// <summary>How often to sweep, in seconds. Defaults to 30.</summary>
    /// <remarks>
    /// This is the resolution limit of everything change detection reports. A command shorter than
    /// one interval gets a window wider than itself, and a change made and undone inside one
    /// interval is invisible. Both are in the README rather than left to be discovered.
    /// </remarks>
    public int IntervalSeconds { get; init; } = 30;

    /// <summary>How long to keep entries, in minutes. Defaults to 60.</summary>
    /// <remarks>
    /// The timeline is in memory, so this is also how much a restart loses.
    /// </remarks>
    public int RetentionMinutes { get; init; } = 60;

    /// <summary>The most files one sweep reports. Defaults to 20000.</summary>
    /// <remarks>
    /// A ceiling on what crosses the network every interval. Reaching it is reported rather than
    /// silently truncated: a sweep that saw part of the tree has not measured the rest, and the
    /// difference between that and "nothing changed" is the whole point.
    /// </remarks>
    public int MaxEntries { get; init; } = 20_000;
}

/// <summary>The <c>[output]</c> table.</summary>
public sealed class OutputSection
{
    /// <summary>The most output bytes handed back for one stream. Defaults to 64 KiB.</summary>
    /// <remarks>
    /// <para>
    /// Per stream, so a command that fails loudly on standard error still gets its standard output
    /// budget. Applied after masking, never before: a secret lying across the cut is two fragments
    /// and neither matches the pattern that would have caught the whole.
    /// </para>
    /// <para>
    /// 64 KiB is a starting point rather than a measured optimum, and the honest reason to write it
    /// down is that it is one number to move once there is real usage to move it against. Too small
    /// wastes calls on re-running with a filter; too large spends the caller's context on output it
    /// cannot use.
    /// </para>
    /// </remarks>
    public int MaxBytes { get; init; } = 64 * 1024;
}

/// <summary>The <c>[audit]</c> table.</summary>
public sealed class AuditSection
{
    /// <summary>The JSONL file records are appended to.</summary>
    /// <remarks>
    /// <para>
    /// Checked for writability at startup, and a failure there stops the process. That is not
    /// strictness for its own sake: a choke point whose whole purpose is that there is one place
    /// which knows what ran where, running without the ability to write that down, is worse than
    /// one that is not running - it does the work and produces no record, and nothing about it
    /// looks wrong.
    /// </para>
    /// <para>
    /// The default matches what the container image and a typical unit file mount. It is a real
    /// default rather than a placeholder: if the process cannot write there, it says so at startup
    /// rather than falling back to somewhere it can.
    /// </para>
    /// </remarks>
    public string Path { get; init; } = "/var/log/sshwarden/audit.jsonl";
}

/// <summary>The <c>[server]</c> table.</summary>
public sealed class ServerSection
{
    /// <summary>
    /// The address to bind, as <c>host:port</c>. Defaults to <c>127.0.0.1:8760</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Loopback by default because misconfiguring this one line publishes SSH access to production
    /// hosts on the internet, and a default that fails closed is the only kind worth having here
    /// (docs/DESIGN.md §6.1).
    /// </para>
    /// <para>
    /// Binding something else is allowed and is how a real deployment works - but the intended
    /// route to the internet is a reverse proxy terminating TLS in front of a loopback listener,
    /// not this line. Clients reach SshWarden from Anthropic's cloud rather than from the user's
    /// machine (docs/DESIGN.md §4), so it does have to be publicly reachable; that is a statement about
    /// the proxy, not about this socket. Startup says so out loud when this is not loopback.
    /// </para>
    /// </remarks>
    public string Listen { get; init; } = "127.0.0.1:8760";

    /// <summary>The path the MCP endpoint is mapped at. Defaults to <c>/mcp</c>.</summary>
    public string McpPath { get; init; } = "/mcp";
}

/// <summary>The <c>[auth]</c> table.</summary>
/// <remarks>
/// There is deliberately no value of <see cref="Mode" /> that disables authentication. A tool that
/// executes commands on production hosts has no development mode worth the line of code, and the
/// one thing a "just for now" switch reliably does is outlive the afternoon it was added for.
/// </remarks>
public sealed class AuthSection
{
    /// <summary>Which authenticator to load.</summary>
    /// <remarks>
    /// A config value rather than a compile-time flag, per docs/DESIGN.md §6.2, so one build serves a
    /// deployment with an authorization server and one without.
    /// </remarks>
    public required string Mode { get; init; }

    /// <summary>
    /// The <c>[[auth.static_token]]</c> blocks, when <see cref="Mode" /> is
    /// <see cref="AuthModes.StaticToken" />.
    /// </summary>
    public IReadOnlyList<StaticTokenEntry> StaticTokens { get; init; } = [];

    /// <summary>
    /// The <c>[auth.oauth]</c> table, when <see cref="Mode" /> is <see cref="AuthModes.OAuth" />.
    /// </summary>
    public OAuthSection? OAuth { get; init; }
}

/// <summary>The <c>[auth.oauth]</c> table.</summary>
/// <remarks>
/// <para>
/// Three values, and none of them a secret: the authorization server to trust, the identifier this
/// server answers to, and the scopes it tells a client to ask for. There is deliberately no client
/// secret here - docs/DESIGN.md §6.2 leaves token introspection out of v0 for exactly that
/// reason, because the only introspection auth method the authorization server offers needs a
/// long-lived one and a signature plus an expiry already answers the threat model.
/// </para>
/// </remarks>
public sealed class OAuthSection
{
    /// <summary>The authorization server, as its <c>issuer</c> spells it.</summary>
    /// <remarks>
    /// One, not a list, and the singular is the design rather than a limitation not yet lifted:
    /// advertising a second issuer whose tokens this server would then refuse presents to a person
    /// as a successful sign-in followed by a permanent 401.
    /// </remarks>
    public required string Issuer { get; init; }

    /// <summary>
    /// What this server is called in a token's <c>aud</c> - the URL a person would type, path
    /// included.
    /// </summary>
    /// <remarks>
    /// RFC 8707 resource indicators, which the authorization server enforces rather than accepts and
    /// ignores: a token minted for something else is refused here on its audience. Getting this
    /// wrong is a 401 that looks like a credential problem and is a configuration one.
    /// </remarks>
    public required string Resource { get; init; }

    /// <summary>What a client is told to ask for when a challenge carries no scope of its own.</summary>
    /// <remarks>
    /// <para>
    /// Advertised in the RFC 9728 document, which is unauthenticated and public. So these stay
    /// coarse - <c>ssh:read</c>, <c>ssh:exec</c> - and never name a host, a path or a tenant.
    /// docs/DESIGN.md §6.5.4: a scope string carrying a hostname publishes that hostname to
    /// anyone who asks for the metadata.
    /// </para>
    /// <para>
    /// What a scope does <em>not</em> do here is decide which tool runs. One MCP endpoint carries
    /// every tool, so a scope required at the route is the intersection of what all of them need;
    /// the per-tool decision is the grant table's, and this list only tells a client what to ask
    /// for.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> ScopesSupported { get; init; } = [];

    /// <summary>
    /// Lets the fetch of the authorization server's metadata and signing keys reach a loopback or
    /// otherwise private address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off, and the reason it exists is that the alternative is worse: an authorization server on
    /// the same private network as this one is a real deployment, and so is a local one during
    /// development. Without this, oauth mode can only ever be pointed at a public host, and the
    /// failure is a refusal to start that names an address rather than a rule.
    /// </para>
    /// <para>
    /// <strong>What it turns off is narrower than it looks, and that is worth being exact about.</strong>
    /// SshWarden makes no outbound HTTP request except this one, and the address it reaches is the
    /// issuer written in this file by the operator - not a value a caller supplies. That is a
    /// different exposure from the same switch on an authorization server, where the addresses come
    /// from client-supplied redirect and metadata URLs and turning the check off makes the server
    /// fetch on a stranger's behalf. Turn it on here only because the authorization server really is
    /// on a private address; it is not a way to make a fetch that is failing for another reason go
    /// through.
    /// </para>
    /// </remarks>
    public bool AllowPrivateIssuer { get; init; }

    /// <summary>Which claim carries the client identifier.</summary>
    /// <remarks>
    /// RFC 9068 §2.2 names <c>client_id</c> for a JWT access token, which is why that is the
    /// default. It is a SHOULD rather than a MUST, and an authorization server is free to put it
    /// somewhere else - so it is a setting rather than a constant.
    /// </remarks>
    public string ClientIdClaim { get; init; } = "client_id";

    /// <summary>Which claim carries the token identifier.</summary>
    /// <remarks>RFC 9068 §2.2 requires <c>jti</c> on an <c>at+jwt</c> token.</remarks>
    public string TokenIdClaim { get; init; } = "jti";

    /// <summary>Which claim groups a run of calls into one working session.</summary>
    /// <remarks>
    /// <para>
    /// <strong>No RFC defines this one, and that is why it is the setting that needs a decision
    /// rather than a default that quietly works.</strong> What the audit record needs from it is on
    /// <c>CallerIdentity.GrantId</c>: a value that survives a refresh, because grouping by the token
    /// id splits one three-hour session into a new group every time the client renews. Authorization
    /// servers spell that differently or not at all - <c>gid</c> here, <c>sid</c> on a server that
    /// exposes its session id - so the name is configured.
    /// </para>
    /// <para>
    /// <strong>If your authorization server emits nothing of the kind, set this to <c>sub</c>
    /// deliberately.</strong> That groups every session of one person together, which is coarser
    /// than the record was designed for and is a real answer; what this will not do is pick that
    /// fallback silently. A grouping the library invented and nobody chose is a column in the audit
    /// log that looks like it came from the authorization server and did not.
    /// </para>
    /// </remarks>
    public string GrantIdClaim { get; init; } = "gid";
}

/// <summary>The accepted values of <see cref="AuthSection.Mode" />.</summary>
/// <remarks>
/// Ordinal English, matched character-for-character against the config file.
/// </remarks>
public static class AuthModes
{
    /// <summary>Credentials listed in the config file. The default, and zero dependencies.</summary>
    public const string StaticToken = "static-token";

    /// <summary>Access tokens from an OAuth 2.1 authorization server, validated by Boltway.</summary>
    /// <remarks>
    /// Added in the same change as a working authenticator for it, never ahead of one - a mode that
    /// parses and loads nothing says the deployment is authenticating one way while it is not
    /// authenticating at all. What makes it work is <c>SshWarden.Boltway</c>, a separate assembly a
    /// deployment references on purpose, so a static-token install is not made to carry an
    /// authorization server's client libraries.
    /// </remarks>
    public const string OAuth = "oauth";

    /// <summary>
    /// Every mode this build can actually load.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One entry today. The list exists rather than a single equality check because it is what the
    /// loader's refusal enumerates, so an unrecognised mode is answered with what this build does
    /// support instead of just "no".
    /// </para>
    /// <para>
    /// A mode is added here in the same change that adds a working authenticator for it - never
    /// ahead of one. A config value that parses and then loads nothing is the same defect as an
    /// endpoint advertised in a metadata document with a 404 behind it: the file says the
    /// deployment is authenticating one way while it is not authenticating at all.
    /// </para>
    /// </remarks>
    public static readonly IReadOnlyList<string> All = [StaticToken, OAuth];
}
