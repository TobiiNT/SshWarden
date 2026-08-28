using System.ComponentModel;
using System.Text.Json.Serialization;

using ModelContextProtocol;
using ModelContextProtocol.Server;

using SshWarden.Audit;
using SshWarden.Auth;
using SshWarden.Authorization;
using SshWarden.Configuration;
using SshWarden.Output;
using SshWarden.Ssh;

namespace SshWarden.Mcp.Tools;

/// <summary>The tools that read something on a host without running a command for the caller.</summary>
/// <remarks>
/// <para>
/// These are the two tools whose arguments name a <em>resource</em> rather than describing
/// behaviour, so unlike <c>run</c> they have a second thing to gate: which file, or which service.
/// SshWarden builds the whole command line here, so nothing the caller sends is interpreted as
/// shell - which is what makes gating the path meaningful in the first place.
/// </para>
/// <para>
/// A path is decided <strong>twice</strong>: once as the caller wrote it, and once as the target
/// resolved it. Only the second survives a symlink, and only the first can be made before touching
/// the machine. See <see cref="RemotePath" /> for what that closes and what it does not.
/// </para>
/// </remarks>
[McpServerToolType]
public sealed class ReadTools
{
    /// <summary>How many lines <c>tail_log</c> returns when the caller does not say.</summary>
    public const int DefaultLines = 100;

    /// <summary>The most lines <c>tail_log</c> will return.</summary>
    /// <remarks>
    /// A ceiling on the argument rather than the real bound - the output budget is that, and it is
    /// measured in bytes because that is what costs the caller. This just stops a line count so
    /// large that the target does the work of assembling output the budget then throws away.
    /// </remarks>
    public const int MaxLines = 10_000;

    private readonly CallerContext _caller;
    private readonly GrantTable _grants;
    private readonly HostRegistry _hosts;
    private readonly SshCommandRunner _runner;
    private readonly IAuditLog _audit;
    private readonly SshSection _ssh;
    private readonly OutputSection _output;

    /// <summary>Builds the tools.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public ReadTools(
        CallerContext caller,
        GrantTable grants,
        HostRegistry hosts,
        SshCommandRunner runner,
        IAuditLog audit,
        SshSection ssh,
        OutputSection output)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(ssh);
        ArgumentNullException.ThrowIfNull(output);

        _caller = caller;
        _grants = grants;
        _hosts = hosts;
        _runner = runner;
        _audit = audit;
        _ssh = ssh;
        _output = output;
    }

    /// <summary>Reads the beginning of a file on a host.</summary>
    /// <param name="host">Which machine.</param>
    /// <param name="path">Which file.</param>
    /// <param name="maxBytes">How much to read.</param>
    /// <param name="cancellationToken">Cancels waiting.</param>
    /// <exception cref="McpException">The call cannot be carried out.</exception>
    [McpServerTool(Name = "read_file")]
    [Description(
        "Read a file on a host. Which files are readable is decided by this deployment's "
        + "configuration and by what the unix account it maps you to can open. Every call is "
        + "recorded. Credential-shaped values are masked before the content is returned.")]
    public async Task<ReadFileResult> ReadFileAsync(
        [Description("The host, as named in this deployment's configuration.")]
        string host,
        [Description(
            "An absolute path. Paths containing '..' are refused rather than resolved; name the "
            + "file directly.")]
        string path,
        [Description("How many bytes to read from the start of the file.")]
        int? maxBytes = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var startedAt = DateTimeOffset.UtcNow;
        var caller = _caller.Require();

        var target = FindHost(host);
        var normalized = Normalize(caller, ToolNames.ReadFile, host, path, startedAt);
        var grant = Authorize(caller, ToolNames.ReadFile, host, normalized, path, startedAt);

        var resolved = await ResolveAsync(
            caller, ToolNames.ReadFile, target, grant, normalized, path, startedAt, cancellationToken)
            .ConfigureAwait(false);

        // The smaller of what the caller asked for and what this deployment allows. Bounded on the
        // target as well, so a huge file is not moved across the network to be discarded here.
        //
        // Clamped at the bottom too, the way tail_log has always clamped its line count. A zero or
        // negative budget reached the command builder, whose ArgumentOutOfRangeException is not an
        // McpException - so the SDK replaced the message and the caller was told only that
        // something went wrong, after a round trip to the host had already happened.
        var budget = Math.Clamp(maxBytes ?? _output.MaxBytes, 1, _output.MaxBytes);

        var outcome = await RunAsync(
            caller, ToolNames.ReadFile, startedAt, target, resolved.Grant, path,
            RemotePath.ReadCommand(resolved.Path, budget), cancellationToken).ConfigureAwait(false);

        var prepared = OutputPipeline.Prepare(outcome.Stdout, grep: null, _output.MaxBytes);

        Record(caller, ToolNames.ReadFile, startedAt, resolved.Grant, target, path, resolved.Path, outcome, prepared);

        return new ReadFileResult
        {
            Content = prepared.Text,
            Bytes = outcome.StdoutBytes,
            Truncated = prepared.Truncated,
            RedactedValues = prepared.RedactedCount,
            Notes = OutputNotes.For(prepared),
            Host = target.Name,
            SshUser = resolved.Grant.SshUser,
            Path = resolved.Path,
            RequestedPath = path,
        };
    }

    /// <summary>Reads the end of a log on a host.</summary>
    /// <param name="host">Which machine.</param>
    /// <param name="unitOrPath">Which service unit, or which file.</param>
    /// <param name="lines">How many lines.</param>
    /// <param name="grep">Keep only lines matching this pattern.</param>
    /// <param name="cancellationToken">Cancels waiting.</param>
    /// <exception cref="McpException">The call cannot be carried out.</exception>
    [McpServerTool(Name = "tail_log")]
    [Description(
        "Read the end of a log on a host - either a service unit's journal or a log file. An "
        + "argument beginning with '/' is read as a file path; anything else is read as a service "
        + "unit name. Every call is recorded, and credential-shaped values are masked.")]
    public async Task<TailLogResult> TailLogAsync(
        [Description("The host, as named in this deployment's configuration.")]
        string host,
        [Description(
            "A service unit name, or an absolute path to a log file. Beginning with '/' makes it a "
            + "path.")]
        string unitOrPath,
        [Description("How many lines from the end.")]
        int? lines = null,
        [Description(
            "A regular expression. Only matching lines are returned. Lookarounds and "
            + "backreferences are not supported.")]
        string? grep = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(unitOrPath);

        var startedAt = DateTimeOffset.UtcNow;
        var caller = _caller.Require();

        var target = FindHost(host);
        var count = Math.Clamp(lines ?? DefaultLines, 1, MaxLines);

        if (!ResourceArguments.NamesAPath(unitOrPath))
        {
            var unitDecision = _grants.AuthorizeUnit(caller, ToolNames.TailLog, host, unitOrPath);
            Refuse(caller, ToolNames.TailLog, unitDecision, startedAt, host, unitOrPath, resolved: null);

            // Refuse throws when the decision is a refusal, so past it the grant is there.
            var unitGrant = unitDecision.Grant!;

            var unitOutcome = await RunAsync(
                caller,
                ToolNames.TailLog,
                startedAt,
                target,
                unitGrant,
                unitOrPath,
                RemotePath.JournalCommand(unitOrPath, count),
                cancellationToken).ConfigureAwait(false);

            var unitPrepared = OutputPipeline.Prepare(unitOutcome.Stdout, grep, _output.MaxBytes);

            Record(
                caller, ToolNames.TailLog, startedAt, unitGrant, target,
                unitOrPath, resolvedPath: null, unitOutcome, unitPrepared);

            return Result(unitOrPath, resolvedPath: null, target, unitGrant, unitOutcome, unitPrepared);
        }

        var normalized = Normalize(caller, ToolNames.TailLog, host, unitOrPath, startedAt);
        var grant = Authorize(caller, ToolNames.TailLog, host, normalized, unitOrPath, startedAt);

        var resolvedPath = await ResolveAsync(
            caller, ToolNames.TailLog, target, grant, normalized, unitOrPath, startedAt, cancellationToken)
            .ConfigureAwait(false);

        var outcome = await RunAsync(
            caller, ToolNames.TailLog, startedAt, target, resolvedPath.Grant, unitOrPath,
            RemotePath.TailCommand(resolvedPath.Path, count), cancellationToken).ConfigureAwait(false);

        var prepared = OutputPipeline.Prepare(outcome.Stdout, grep, _output.MaxBytes);

        Record(
            caller, ToolNames.TailLog, startedAt, resolvedPath.Grant, target,
            unitOrPath, resolvedPath.Path, outcome, prepared);

        return Result(unitOrPath, resolvedPath.Path, target, resolvedPath.Grant, outcome, prepared);
    }

    private static TailLogResult Result(
        string selector,
        string? resolvedPath,
        HostEntry target,
        Grant grant,
        CommandOutcome outcome,
        PreparedOutput prepared)
        => new()
        {
            Lines = prepared.Text,
            Bytes = outcome.StdoutBytes,
            Truncated = prepared.Truncated,
            RedactedValues = prepared.RedactedCount,
            Notes = OutputNotes.For(prepared),
            Host = target.Name,
            SshUser = grant.SshUser,
            Source = resolvedPath ?? selector,
        };

    private HostEntry FindHost(string host)
        => _hosts.Find(host)
            ?? throw new McpException(
                $"SshWarden has no configuration for host '{host}', so it does not know how to "
                    + "reach it or how to verify it.");

    private string Normalize(
        CallerIdentity caller,
        string tool,
        string host,
        string path,
        DateTimeOffset startedAt)
    {
        if (PathPattern.TryNormalize(path, out var normalized, out var problem))
        {
            return normalized;
        }

        var decision = AuthorizationDecision.Refuse(AuthorizationRefusal.PathNotUsable, problem);
        _audit.Write(AuditRecordFactory.Refusal(caller, tool, decision, startedAt, host, path));
        throw new McpException(problem);
    }

    private Grant Authorize(
        CallerIdentity caller,
        string tool,
        string host,
        string normalized,
        string requested,
        DateTimeOffset startedAt)
    {
        // Re-derived rather than carried from the gate. Same inputs, same pure function, same
        // answer - and no shared per-request state for the two to drift apart in. Reaching here
        // with a refusal means something invoked the tool outside the gate, which is worth
        // recording rather than assuming cannot happen.
        var decision = _grants.AuthorizePath(caller, tool, host, normalized);
        Refuse(caller, tool, decision, startedAt, host, requested, resolved: null);
        return decision.Grant!;
    }

    private void Refuse(
        CallerIdentity caller,
        string tool,
        AuthorizationDecision decision,
        DateTimeOffset startedAt,
        string host,
        string selector,
        string? resolved)
    {
        if (decision.IsAllowed)
        {
            return;
        }

        _audit.Write(AuditRecordFactory.Refusal(caller, tool, decision, startedAt, host, selector, resolved));
        throw new McpException(decision.Detail!);
    }

    private async Task<(string Path, Grant Grant)> ResolveAsync(
        CallerIdentity caller,
        string tool,
        HostEntry target,
        Grant grant,
        string normalized,
        string requested,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken)
    {
        var outcome = await RunAsync(
            caller, tool, startedAt, target, grant, requested,
            RemotePath.ResolveCommand(normalized), cancellationToken).ConfigureAwait(false);

        if (outcome.ExitCode == RemotePath.NotFoundExitCode)
        {
            // Not a permission problem, and said so: reporting a missing file as a refusal sends
            // somebody to edit the grant table over a typo.
            var missing = AuthorizationDecision.Refuse(
                AuthorizationRefusal.PathNotFound,
                $"SshWarden found no such file on host '{target.Name}'.");

            _audit.Write(AuditRecordFactory.Refusal(caller, tool, missing, startedAt, target.Name, requested));
            throw new McpException(missing.Detail!);
        }

        if (outcome.ExitCode == RemotePath.NotRegularFileExitCode)
        {
            var notAFile = AuthorizationDecision.Refuse(
                AuthorizationRefusal.PathNotFound,
                $"That path on host '{target.Name}' is not a regular file.");

            _audit.Write(AuditRecordFactory.Refusal(caller, tool, notAFile, startedAt, target.Name, requested));
            throw new McpException(notAFile.Detail!);
        }

        if (outcome.ExitCode != 0)
        {
            throw new McpException(
                $"SshWarden could not resolve that path on host '{target.Name}'.");
        }

        var resolved = outcome.Stdout.Trim();

        // **The check the whole tool exists for.** The caller's string passed a rule; this asks
        // whether the file it actually points at does. A symlink out of the allowed tree fails
        // exactly here, and nowhere earlier could have seen it.
        var decision = _grants.AuthorizePath(caller, tool, target.Name, resolved);
        if (!decision.IsAllowed)
        {
            var escaped = AuthorizationDecision.Refuse(
                AuthorizationRefusal.PathEscapesGrant,
                $"SshWarden refused tool '{tool}' on host '{target.Name}': the path resolves to "
                    + "somewhere no configured grant covers (rule: "
                    + AuthorizationRefusal.PathEscapesGrant + ").");

            _audit.Write(AuditRecordFactory.Refusal(
                caller, tool, escaped, startedAt, target.Name, requested, resolved));

            throw new McpException(escaped.Detail!);
        }

        return (resolved, decision.Grant!);
    }

    /// <summary>Every SSH call these two tools make, and the one place a failure is recorded.</summary>
    /// <remarks>
    /// <para>
    /// A call that was allowed and then failed - the connection dropped, the target never answered -
    /// used to leave no record at all here, because the record was written after the work and the
    /// work is what did not happen. So the log said nothing about the calls most worth reading
    /// about, and the README's claim that every call lands in it whether it was allowed or refused
    /// was not true of these two tools.
    /// </para>
    /// <para>
    /// Recorded at this chokepoint rather than around each caller because there are three of them
    /// and one is inside the path resolution, which is the SSH call most likely to be the first to
    /// fail. It is not recorded in the gate, which was the other option and is wrong: a tool can
    /// refuse on its own after the gate passed it - <c>path_not_found</c> is only knowable once the
    /// target has resolved the path - and it records that itself, so a gate recording every
    /// exception wrote `allow` over the top of the tool's `deny`.
    /// </para>
    /// </remarks>
    private async Task<CommandOutcome> RunAsync(
        CallerIdentity caller,
        string tool,
        DateTimeOffset startedAt,
        HostEntry target,
        Grant grant,
        string selector,
        string command,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _runner.RunAsync(
                target, grant.SshUser, command, workdir: null, environment: null,
                _ssh.DefaultTimeoutSeconds, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure)
        {
            _audit.Write(AuditRecordFactory.Failure(
                caller,
                tool,
                startedAt,
                target.Name,
                failure.Message,
                allowedBy: grant.Id,
                sshUser: grant.SshUser,
                selector: selector));

            throw;
        }
    }

    private void Record(
        CallerIdentity caller,
        string tool,
        DateTimeOffset startedAt,
        Grant grant,
        HostEntry target,
        string selector,
        string? resolvedPath,
        CommandOutcome outcome,
        PreparedOutput prepared)
        => _audit.Write(new AuditRecord
        {
            Id = AuditRecordFactory.NewId(),
            Type = AuditRecordTypes.Command,
            StartedAt = startedAt,
            Subject = caller.Subject,
            ClientId = caller.ClientId,
            GrantId = caller.GrantId,
            TokenId = caller.TokenId,
            Tool = tool,
            Decision = AuditDecisions.Allow,
            AllowedBy = grant.Id,
            Host = target.Name,
            SshUser = grant.SshUser,
            Selector = selector,
            ResolvedPath = resolvedPath,
            Workdir = RemoteCommand.DefaultWorkdir,
            Command = SecretRedactor.Redact(outcome.CommandLine).Text,
            ExitCode = outcome.ExitCode,
            DurationMs = outcome.DurationMs,
            StdoutBytes = outcome.StdoutBytes,
            OutputTruncated = prepared.Truncated,
        });
}

/// <summary>What <c>read_file</c> returns.</summary>
public sealed class ReadFileResult
{
    /// <summary>The file's contents, masked and bounded.</summary>
    [JsonPropertyName("content")]
    public required string Content { get; init; }

    /// <summary>How many bytes the host produced.</summary>
    [JsonPropertyName("bytes")]
    public required long Bytes { get; init; }

    /// <summary>Whether what came back was cut short.</summary>
    [JsonPropertyName("truncated")]
    public required bool Truncated { get; init; }

    /// <summary>How many credential-shaped values were masked. Best-effort.</summary>
    [JsonPropertyName("redacted_values")]
    public required int RedactedValues { get; init; }

    /// <summary>
    /// Anything that happened to this output which the text itself does not say.
    /// </summary>
    /// <remarks>
    /// Empty in the ordinary case. It carries what a caller would otherwise silently misread:
    /// masking that ran out of time and so did not finish.
    /// </remarks>
    [JsonPropertyName("notes")]
    public required IReadOnlyList<string> Notes { get; init; }

    /// <summary>The host.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }

    /// <summary>The unix account that opened the file.</summary>
    [JsonPropertyName("ssh_user")]
    public required string SshUser { get; init; }

    /// <summary>The file that was actually opened, as the target resolved it.</summary>
    /// <remarks>
    /// Returned as well as recorded. When it differs from <see cref="RequestedPath" /> something on
    /// the target pointed elsewhere, and a caller reading a file it did not name should be able to
    /// tell.
    /// </remarks>
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    /// <summary>The path as it was asked for.</summary>
    [JsonPropertyName("requested_path")]
    public required string RequestedPath { get; init; }
}

/// <summary>What <c>tail_log</c> returns.</summary>
public sealed class TailLogResult
{
    /// <summary>The lines, masked and bounded.</summary>
    [JsonPropertyName("lines")]
    public required string Lines { get; init; }

    /// <summary>How many bytes the host produced.</summary>
    [JsonPropertyName("bytes")]
    public required long Bytes { get; init; }

    /// <summary>Whether what came back was cut short.</summary>
    [JsonPropertyName("truncated")]
    public required bool Truncated { get; init; }

    /// <summary>How many credential-shaped values were masked. Best-effort.</summary>
    [JsonPropertyName("redacted_values")]
    public required int RedactedValues { get; init; }

    /// <summary>
    /// Anything that happened to this output which the text itself does not say.
    /// </summary>
    /// <remarks>
    /// Empty in the ordinary case. It carries what a caller would otherwise silently misread: a
    /// grep pattern that did not compile and so filtered nothing, or masking that ran out of time
    /// and so did not finish.
    /// </remarks>
    [JsonPropertyName("notes")]
    public required IReadOnlyList<string> Notes { get; init; }

    /// <summary>The host.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }

    /// <summary>The unix account that read the log.</summary>
    [JsonPropertyName("ssh_user")]
    public required string SshUser { get; init; }

    /// <summary>The unit, or the file as the target resolved it.</summary>
    [JsonPropertyName("source")]
    public required string Source { get; init; }
}
