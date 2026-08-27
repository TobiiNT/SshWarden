namespace SshWarden.Configuration;

/// <summary>The <c>[ssh]</c> table: how SshWarden reaches a host.</summary>
public sealed class SshSection
{
    /// <summary>Path to the private key SshWarden authenticates with.</summary>
    /// <remarks>
    /// <para>
    /// Required, and it should be a key made for this process and nothing else. A key that also
    /// opens an administrator's own sessions makes every grant in the table decorative: the account
    /// it lands in is the boundary that holds, and a key with broad reach chooses that account
    /// before the grant table gets a say.
    /// </para>
    /// <para>
    /// Checked at startup for the same mode rule as the config file - a private key any other
    /// account can read is a private key that account has.
    /// </para>
    /// </remarks>
    public required string IdentityFile { get; init; }

    /// <summary>How long to wait for a connection, in seconds. Defaults to 15.</summary>
    public int ConnectTimeoutSeconds { get; init; } = 15;

    /// <summary>
    /// How long a pooled connection may sit unused before it is closed, in seconds. Defaults to 300.
    /// </summary>
    /// <remarks>
    /// The pool exists to skip the TCP and SSH handshake, not to hold sessions open indefinitely.
    /// An idle connection is a session on the target host's sshd and counts against its limits.
    /// </remarks>
    public int IdleEvictionSeconds { get; init; } = 300;

    /// <summary>How long a command may run when the caller does not say. Defaults to 60 seconds.</summary>
    /// <remarks>
    /// There is always a timeout. A command with no limit is a channel held open forever against a
    /// session count the target host caps, and - because the limit is enforced on the remote side -
    /// no limit also means no exit status to record when it never finishes.
    /// </remarks>
    public int DefaultTimeoutSeconds { get; init; } = 60;

    /// <summary>The longest timeout a caller may ask for. Defaults to 900 seconds.</summary>
    /// <remarks>
    /// A ceiling rather than a suggestion, because the caller choosing it is an agent and the cost
    /// of an over-long one lands on the host. Something that genuinely needs longer is a job -
    /// a process that outlives the call - rather than a longer call.
    /// </remarks>
    public int MaxTimeoutSeconds { get; init; } = 900;
}

/// <summary>Finds a configured host by the name a caller used.</summary>
/// <remarks>
/// Separate from the grant table on purpose: the grant table answers whether somebody may reach a
/// host, and this answers whether SshWarden knows how to. Both have to be true, and conflating them
/// would mean a machine becomes reachable by being mentioned in a rule.
/// </remarks>
public sealed class HostRegistry
{
    private readonly Dictionary<string, HostEntry> _byName;

    /// <summary>Builds the registry.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="hosts" /> is null.</exception>
    public HostRegistry(IReadOnlyList<HostEntry> hosts)
    {
        ArgumentNullException.ThrowIfNull(hosts);

        // Case-insensitive, because host names are (RFC 4343) and a caller typing one in a
        // different case has named the same machine. Ordinal-ignore-case rather than culture-aware
        // for the usual reason: a culture-aware fold can disagree about which characters are the
        // same letter.
        _byName = hosts.ToDictionary(host => host.Name, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Finds a host by name.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="name" /> is null.</exception>
    public HostEntry? Find(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return _byName.TryGetValue(name, out var host) ? host : null;
    }
}

/// <summary>One <c>[[host]]</c> block: a machine SshWarden can be asked to reach.</summary>
/// <remarks>
/// Hosts are declared rather than inferred from the grant table, because two things have to be true
/// before a connection is made and only one of them is a permission: the caller must be allowed to
/// reach the host, and SshWarden must know how to verify it is talking to the right machine.
/// </remarks>
public sealed class HostEntry
{
    /// <summary>
    /// The name callers use, and what the grant table's globs match against.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>Where to connect. Defaults to <see cref="Name" />.</summary>
    public string? Address { get; init; }

    /// <summary>The port. Defaults to 22.</summary>
    public int Port { get; init; } = 22;

    /// <summary>
    /// The host key fingerprint SshWarden requires, as OpenSSH prints it -
    /// <c>SHA256:</c> followed by unpadded base64.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required, with no trust-on-first-use fallback and no way to turn it off. A connection made
    /// without checking the host key hands the private key's authority, and every command, to
    /// whoever answered - and the whole value of this process is that there is one place that knows
    /// what ran where. An unverified connection means it does not know.
    /// </para>
    /// <para>
    /// Read it off the machine with
    /// <c>ssh-keyscan -t ed25519 &lt;host&gt; | ssh-keygen -lf -</c>, over a channel you trust.
    /// </para>
    /// </remarks>
    public required string Fingerprint { get; init; }

    /// <summary>Where to connect, resolved.</summary>
    public string ResolvedAddress => string.IsNullOrWhiteSpace(Address) ? Name : Address;
}

/// <summary>The tools v0 has names for.</summary>
/// <remarks>
/// <para>
/// Exactly seven, and the list is closed: an eighth is a conversation, not an edit. It lives here
/// because the config file names tools in its grant rules, and a name that matches nothing is a
/// rule that silently does nothing - the same defect as a misspelled key, one level in.
/// </para>
/// <para>
/// All seven have handlers as of the release that completed v0. While that was not true there was a
/// second list here of the ones that did, and a rule naming one of the others loaded with a warning
/// saying it was inert - that list is gone rather than left as a branch nothing can take, which is
/// the same rule this project applies to config keys with nothing behind them.
/// </para>
/// </remarks>
public static class ToolNames
{
    /// <summary>Run a command and wait for it.</summary>
    public const string Run = "run";

    /// <summary>Read a file.</summary>
    public const string ReadFile = "read_file";

    /// <summary>Read the end of a log.</summary>
    public const string TailLog = "tail_log";

    /// <summary>List what changed recently.</summary>
    public const string ListChanges = "list_changes";

    /// <summary>Start a command that outlives the call.</summary>
    public const string StartJob = "start_job";

    /// <summary>Read new output from a running job.</summary>
    public const string PollJob = "poll_job";

    /// <summary>Signal a running job.</summary>
    public const string KillJob = "kill_job";

    /// <summary>Every name v0 will have.</summary>
    public static readonly IReadOnlyList<string> All =
        [Run, ReadFile, TailLog, ListChanges, StartJob, PollJob, KillJob];

}
