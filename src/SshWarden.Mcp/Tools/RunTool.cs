using System.ComponentModel;
using System.Text.Json.Serialization;

using ModelContextProtocol;
using ModelContextProtocol.Server;

using SshWarden.Audit;
using SshWarden.Authorization;
using SshWarden.Changes;
using SshWarden.Configuration;
using SshWarden.Output;
using SshWarden.Ssh;

namespace SshWarden.Mcp.Tools;

/// <summary>The <c>run</c> tool.</summary>
/// <remarks>
/// <para>
/// Everything a command needs is an argument, because there is no session to have put it there
/// earlier. That is what makes one line of the audit log readable on its own - a record saying
/// <c>npm install</c> is worth nothing if the directory it ran in came from a command twelve calls
/// ago.
/// </para>
/// <para>
/// Authorization has already happened by the time this runs: the tool gate refused, or it did not.
/// What this does is resolve the same grant again to find the unix account, which is pure and gives
/// the same answer - deliberately, rather than passing state from the gate, because a gate and the
/// thing it gates sharing mutable state is how they come to disagree.
/// </para>
/// </remarks>
[McpServerToolType]
public sealed class RunTool
{
    private readonly CallerContext _caller;
    private readonly GrantTable _grants;
    private readonly HostRegistry _hosts;
    private readonly SshCommandRunner _runner;
    private readonly IAuditLog _audit;
    private readonly SshSection _options;
    private readonly OutputSection _output;
    private readonly ChangeAttribution _changes;

    /// <summary>Builds the tool.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public RunTool(
        CallerContext caller,
        GrantTable grants,
        HostRegistry hosts,
        SshCommandRunner runner,
        IAuditLog audit,
        SshSection options,
        OutputSection output,
        ChangeAttribution changes)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(changes);

        _caller = caller;
        _grants = grants;
        _hosts = hosts;
        _runner = runner;
        _audit = audit;
        _options = options;
        _output = output;
        _changes = changes;
    }

    /// <summary>Runs a shell command on a host and waits for it to finish.</summary>
    /// <param name="host">Which machine to run on.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="workdir">Which directory to run in.</param>
    /// <param name="env">Environment variables to set for this command.</param>
    /// <param name="timeoutSec">How long to allow.</param>
    /// <param name="grep">Keep only lines matching this pattern.</param>
    /// <param name="cancellationToken">Cancels waiting.</param>
    /// <exception cref="McpException">The call cannot be carried out.</exception>
    [McpServerTool(Name = "run")]
    [Description(
        "Run a shell command on a host over SSH and wait for it to finish. Every call is "
        + "independent: nothing is remembered between calls, so the working directory and any "
        + "environment variables must be given each time. Every call is recorded.")]
    public async Task<RunResult> RunAsync(
        [Description("The host to run on, as named in this deployment's configuration.")]
        string host,
        [Description(
            "The command, interpreted by a POSIX shell on the target - pipes and redirection work. "
            + "It is passed through unchanged and is not filtered.")]
        string cmd,
        [Description(
            "The directory to run in. Defaults to the login directory of the account this "
            + "deployment maps you to. Recorded, but not a security boundary - a command can "
            + "change directory freely.")]
        string? workdir = null,
        [Description("Environment variables to set for this command only.")]
        IReadOnlyDictionary<string, string>? env = null,
        [Description(
            "Seconds to allow before the command is killed on the target. Killed commands report "
            + "exit code 124.")]
        int? timeoutSec = null,
        [Description(
            "A regular expression. Only matching lines are returned, filtered here rather than on "
            + "the target, so it does not change the command's exit code. Lookarounds and "
            + "backreferences are not supported.")]
        string? grep = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(cmd);

        var caller = _caller.Require();
        var startedAt = DateTimeOffset.UtcNow;

        // Resolved again rather than carried from the gate. Same inputs, same pure function, same
        // answer - and no shared per-request state for the two to drift apart in.
        var decision = _grants.AuthorizeHost(caller, ToolNames.Run, host);
        if (!decision.IsAllowed)
        {
            // Reached only if something invoked this outside the gate. Recorded and refused rather
            // than trusted, because "the gate must have run" is an assumption and this is the last
            // place it can be checked.
            _audit.Write(AuditRecordFactory.Refusal(caller, ToolNames.Run, decision, startedAt, host));
            throw new McpException(decision.Detail!);
        }

        var target = _hosts.Find(host)
            ?? throw new McpException(
                $"SshWarden has no configuration for host '{host}', so it does not know how to "
                    + "reach it or how to verify it.");

        var timeout = timeoutSec ?? _options.DefaultTimeoutSeconds;
        if (timeout < 1 || timeout > _options.MaxTimeoutSeconds)
        {
            throw new McpException(
                $"timeoutSec must be between 1 and {_options.MaxTimeoutSeconds}. Something that "
                    + "needs longer wants to be a job rather than a longer call.");
        }

        var grant = decision.Grant!;
        var recordedWorkdir = string.IsNullOrWhiteSpace(workdir) ? RemoteCommand.DefaultWorkdir : workdir;

        // Registered before the command runs and closed after, so a record can say whether anything
        // else was running on that host at the same time. A list of changes without that is a claim
        // about which command caused them, and when commands overlap nothing can support it.
        var overlapToken = _changes.Begin(target.Name, startedAt);

        CommandOutcome? outcome = null;
        PreparedOutput? stdout = null;

        // Kept so the record written below can say what went wrong. Without it a call that failed
        // in the SSH layer produced a record reading `allow` with a null exit code, a null duration
        // and a null error - which a reader has to infer a failure from, and cannot tell apart from
        // a record this process managed to write before it was killed.
        string? error = null;
        try
        {
            outcome = await _runner
                .RunAsync(target, grant.SshUser, cmd, workdir, env, timeout, cancellationToken)
                .ConfigureAwait(false);

            // Both streams through the same pipeline, and the pipeline fixes the order: measure,
            // filter, mask, cut. Standard error gets its own budget rather than sharing one, so a
            // command that fails loudly still returns whatever it managed to print.
            stdout = OutputPipeline.Prepare(outcome.Stdout, grep, _output.MaxBytes);
            var stderr = OutputPipeline.Prepare(outcome.Stderr, grep, _output.MaxBytes);

            return new RunResult
            {
                ExitCode = outcome.ExitCode,
                Stdout = stdout.Text,
                Stderr = stderr.Text,
                DurationMs = outcome.DurationMs,

                // The number the host produced, not the number handed back. An agent comparing this
                // with what it received can tell how much it is not seeing.
                StdoutBytes = outcome.StdoutBytes,
                OutputTruncated = stdout.Truncated || stderr.Truncated,
                RedactedValues = stdout.RedactedCount + stderr.RedactedCount,
                Notes = OutputNotes.For(stdout, stderr),
                Host = target.Name,
                SshUser = grant.SshUser,
                Workdir = recordedWorkdir,
            };
        }
        catch (Exception failure)
        {
            error = failure.Message;
            throw;
        }
        finally
        {
            var attributed = _changes.Finish(target.Name, overlapToken, startedAt, DateTimeOffset.UtcNow);

            // In a finally, so a connection that failed or a command that died mid-flight still
            // leaves a line. A choke point that records only what succeeded is a choke point with a
            // hole exactly where somebody will be looking.
            _audit.Write(new AuditRecord
            {
                Id = AuditRecordFactory.NewId(),
                Type = AuditRecordTypes.Command,
                StartedAt = startedAt,
                Subject = caller.Subject,
                ClientId = caller.ClientId,
                GrantId = caller.GrantId,
                TokenId = caller.TokenId,
                Tool = ToolNames.Run,
                Decision = AuditDecisions.Allow,
                AllowedBy = grant.Id,
                Host = target.Name,
                SshUser = grant.SshUser,
                Workdir = recordedWorkdir,

                // What the host was actually sent, not what the caller typed: a working directory,
                // an environment and a timeout wrapper are added, and the one worth reproducing is
                // the one that ran.
                //
                // **Masked, and that is a hole this closes rather than a precaution.** The builder
                // inlines environment values into the command string - it has to, because sshd
                // drops variables sent through the protocol - so a caller passing an API key as an
                // environment variable put it verbatim into this field. The audit log is the one
                // artefact of this project that gets shipped somewhere else.
                Command = outcome is null ? null : SecretRedactor.Redact(outcome.CommandLine).Text,
                ExitCode = outcome?.ExitCode,
                DurationMs = outcome?.DurationMs,
                StdoutBytes = outcome?.StdoutBytes,
                OutputTruncated = stdout?.Truncated,
                Error = error,
                Changes = attributed.Changes,
                ChangesWindowMs = attributed.WindowMs,
                ChangesConfidence = attributed.Confidence,
            });
        }
    }
}

/// <summary>What <c>run</c> returns.</summary>
public sealed class RunResult
{
    /// <summary>The exit status, or null if the command reported none.</summary>
    /// <remarks>
    /// 124 means the command was killed by the timeout on the target. Null means the channel ended
    /// without a status - never read either as success.
    /// </remarks>
    [JsonPropertyName("exit_code")]
    public int? ExitCode { get; init; }

    /// <summary>Standard output.</summary>
    [JsonPropertyName("stdout")]
    public required string Stdout { get; init; }

    /// <summary>Standard error.</summary>
    [JsonPropertyName("stderr")]
    public required string Stderr { get; init; }

    /// <summary>How long the call took.</summary>
    [JsonPropertyName("duration_ms")]
    public required long DurationMs { get; init; }

    /// <summary>How many bytes of standard output the host produced.</summary>
    [JsonPropertyName("stdout_bytes")]
    public required long StdoutBytes { get; init; }

    /// <summary>Whether the output handed back was cut short.</summary>
    /// <remarks>
    /// The text says so too, in place of what was dropped. Both, because one is for a person
    /// reading the output and the other is for a caller deciding whether to narrow the command.
    /// </remarks>
    [JsonPropertyName("output_truncated")]
    public required bool OutputTruncated { get; init; }

    /// <summary>How many credential-shaped values were masked before this was returned.</summary>
    /// <remarks>
    /// <para>
    /// Masking is best-effort: it matches patterns somebody thought of, and a credential shaped
    /// like none of them goes through. It is the second line of defence - the first is that the
    /// unix account this ran as should not have been able to read the secret at all.
    /// </para>
    /// </remarks>
    [JsonPropertyName("redacted_values")]
    public required int RedactedValues { get; init; }

    /// <summary>
    /// Anything that happened to this output which the text itself does not say.
    /// </summary>
    /// <remarks>
    /// Empty in the ordinary case. It carries the things a caller would otherwise silently
    /// misread - a grep pattern that did not compile and so filtered nothing, or masking that ran
    /// out of time and so did not finish.
    /// </remarks>
    [JsonPropertyName("notes")]
    public required IReadOnlyList<string> Notes { get; init; }

    /// <summary>The host, as this deployment names it.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }

    /// <summary>The unix account the command ran as.</summary>
    /// <remarks>
    /// Returned as well as recorded, so the caller can tell which account it is acting through
    /// rather than inferring it from what worked and what did not.
    /// </remarks>
    [JsonPropertyName("ssh_user")]
    public required string SshUser { get; init; }

    /// <summary>The directory the command ran in.</summary>
    [JsonPropertyName("workdir")]
    public required string Workdir { get; init; }
}
