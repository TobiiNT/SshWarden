using System.ComponentModel;
using System.Text.Json.Serialization;

using ModelContextProtocol;
using ModelContextProtocol.Server;

using SshWarden.Audit;
using SshWarden.Auth;
using SshWarden.Authorization;
using SshWarden.Configuration;
using SshWarden.Jobs;
using SshWarden.Output;
using SshWarden.Ssh;

namespace SshWarden.Mcp.Tools;

/// <summary>The three tools for work that outlives the call that started it.</summary>
/// <remarks>
/// <para>
/// A thin adapter over the job store, which is where the state and the decisions live. That
/// separation is deliberate: the protocol has its own long-running-request extension, and the day a
/// client supports it that is a second adapter over the same store rather than a rewrite. The two
/// are not the same thing wearing different names - a task makes a <em>request</em> outlive a call,
/// a job makes a <em>process on the target</em> outlive one, and killing a job is a signal to a
/// unix process group rather than the cancellation of a request.
/// </para>
/// <para>
/// <strong>Ownership is checked by the gate, not here.</strong> A job identifier carries no host,
/// so a tool that checked its own arguments would be the only thing standing between one caller and
/// another's production output - and a tool is something somebody can forget to write the check
/// into. The gate runs for every call whether or not the tool remembered.
/// </para>
/// </remarks>
[McpServerToolType]
public sealed class JobTools
{
    private readonly CallerContext _caller;
    private readonly GrantTable _grants;
    private readonly HostRegistry _hosts;
    private readonly SshCommandRunner _runner;
    private readonly IAuditLog _audit;
    private readonly JobStore _jobs;
    private readonly JobsSection _options;
    private readonly SshSection _ssh;
    private readonly OutputSection _output;

    /// <summary>Builds the tools.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public JobTools(
        CallerContext caller,
        GrantTable grants,
        HostRegistry hosts,
        SshCommandRunner runner,
        IAuditLog audit,
        JobStore jobs,
        JobsSection options,
        SshSection ssh,
        OutputSection output)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(jobs);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(ssh);
        ArgumentNullException.ThrowIfNull(output);

        _caller = caller;
        _grants = grants;
        _hosts = hosts;
        _runner = runner;
        _audit = audit;
        _jobs = jobs;
        _options = options;
        _ssh = ssh;
        _output = output;
    }

    /// <summary>Starts a command that keeps running after the call returns.</summary>
    /// <param name="host">Which machine.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="workdir">Which directory to run in.</param>
    /// <param name="cancellationToken">Cancels waiting for the start, not the job.</param>
    /// <exception cref="McpException">The call cannot be carried out.</exception>
    [McpServerTool(Name = "start_job")]
    [Description(
        "Start a command on a host and return immediately with a job id. The command keeps running "
        + "after this call returns and after this server restarts. Use poll_job to read its output "
        + "and kill_job to stop it. Its output is written to a private file on the target, and is "
        + "masked for credential-shaped values only on the way back through poll_job.")]
    public async Task<StartJobResult> StartJobAsync(
        [Description("The host, as named in this deployment's configuration.")]
        string host,
        [Description(
            "The command, interpreted by a POSIX shell on the target. Passed through unchanged and "
            + "not filtered.")]
        string cmd,
        [Description("The directory to run in. Defaults to the login directory of your mapped account.")]
        string? workdir = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(cmd);

        var startedAt = DateTimeOffset.UtcNow;
        var caller = _caller.Require();

        var decision = _grants.AuthorizeHost(caller, ToolNames.StartJob, host);
        Refuse(caller, ToolNames.StartJob, decision, startedAt, host, selector: null);

        var target = FindHost(host);
        var grant = decision.Grant!;

        var jobId = JobStore.NewJobId();

        // Relative to the home of the account the rule maps to, and stored that way: the commands
        // prepend the home themselves, because which account a rule maps to can be changed in
        // configuration and a job started before that change would otherwise be looked for under an
        // absolute path that is no longer the right one. The identifier is in the path so two jobs
        // never share a directory, and because it is unguessable the directory name is too.
        var directory = $"{_options.RemoteDirectory.Trim('/')}/{jobId}";

        var outcome = await RunAsync(
            caller, ToolNames.StartJob, startedAt, target, grant, jobId,
            JobCommands.Start(directory, cmd, workdir),
            _ssh.DefaultTimeoutSeconds,
            cancellationToken).ConfigureAwait(false);

        if (outcome.ExitCode != 0)
        {
            // Named rather than handed back as a bare number. The three the start command chooses
            // for itself are the three that are worth telling apart - a directory that could not be
            // made, a working directory that does not exist, and a job that never came up - and
            // anything else is the target's own, so its stderr goes with it.
            var why = outcome.ExitCode switch
            {
                JobCommands.DirectoryFailed =>
                    "the job directory could not be created under the account's home",
                JobCommands.WorkdirFailed =>
                    $"the working directory '{workdir}' could not be entered",
                JobCommands.NoProcessGroup =>
                    "the job never reported a process group, so it did not start",
                _ => $"the target answered with exit code {outcome.ExitCode}",
            };

            var detail = string.IsNullOrWhiteSpace(outcome.Stderr)
                ? string.Empty
                : $" The target said: {SecretRedactor.Redact(outcome.Stderr.Trim()).Text}";

            throw new McpException(
                $"SshWarden could not start the job on host '{target.Name}': {why}.{detail}");
        }

        var record = new JobRecord
        {
            JobId = jobId,
            Host = target.Name,
            OwnerSubject = caller.Subject,
            OwnerGrantId = caller.GrantId,
            AllowedBy = grant.Id,
            SshUser = grant.SshUser,

            // Masked before it is written down. The registry is a file on disk like the audit log,
            // and a command carrying a token would otherwise sit in it in plain text.
            Command = SecretRedactor.Redact(cmd).Text,
            Workdir = workdir ?? RemoteCommand.DefaultWorkdir,
            Directory = directory,
            StartedAt = startedAt,
        };

        // Recorded before the caller is told the identifier. A job whose owner was never written
        // down is a job nobody can poll or kill afterwards, including the person who started it.
        _jobs.Put(record);
        Record(caller, ToolNames.StartJob, startedAt, grant, target, jobId, outcome, null);

        return new StartJobResult
        {
            JobId = jobId,
            Host = target.Name,
            SshUser = grant.SshUser,
            Workdir = record.Workdir,
        };
    }

    /// <summary>Reads what a job has printed since the caller last looked.</summary>
    /// <param name="jobId">Which job.</param>
    /// <param name="sinceLine">How many lines have already been seen.</param>
    /// <param name="cancellationToken">Cancels waiting.</param>
    /// <exception cref="McpException">The call cannot be carried out.</exception>
    [McpServerTool(Name = "poll_job")]
    [Description(
        "Read a job's status and whatever it has printed since a given line. Status is one of "
        + "running, finished, gone (not running and left no exit status - signalled, or the machine "
        + "restarted) or vanished (its directory is no longer on the target).")]
    public async Task<PollJobResult> PollJobAsync(
        [Description("The job id start_job returned.")]
        string jobId,
        [Description("How many lines of output you have already seen. Pass 0 the first time.")]
        int? sinceLine = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        var startedAt = DateTimeOffset.UtcNow;
        var (caller, job, target, grant) = Resolve(jobId, ToolNames.PollJob, startedAt);

        var from = Math.Max(sinceLine ?? 0, 0);

        var outcome = await RunAsync(
            caller, ToolNames.PollJob, startedAt, target, grant, jobId,
            JobCommands.Poll(job.Directory, from),
            _ssh.DefaultTimeoutSeconds,
            cancellationToken).ConfigureAwait(false);

        var (status, exitCode, raw) = JobCommands.ParsePoll(outcome.Stdout);

        // Through the same pipeline as everything else. This is the only point at which the job's
        // output can be masked at all - on the target it is a plain file, and nothing of
        // SshWarden's is over there to intercept a write.
        var prepared = OutputPipeline.Prepare(raw, grep: null, _output.MaxBytes);

        var lines = raw.Length == 0 ? 0 : raw.TrimEnd('\n').Split('\n').Length;

        Record(caller, ToolNames.PollJob, startedAt, grant, target, jobId, outcome, exitCode);

        return new PollJobResult
        {
            JobId = jobId,
            Status = status,
            ExitCode = exitCode,
            Output = prepared.Text,
            NextLine = from + lines,
            Truncated = prepared.Truncated,
            RedactedValues = prepared.RedactedCount,
            Host = target.Name,
        };
    }

    /// <summary>Signals a job's process group.</summary>
    /// <param name="jobId">Which job.</param>
    /// <param name="cancellationToken">Cancels waiting.</param>
    /// <exception cref="McpException">The call cannot be carried out.</exception>
    [McpServerTool(Name = "kill_job")]
    [Description(
        "Stop a job. Sends SIGTERM to its whole process group, waits briefly, then SIGKILL. Its "
        + "output stays readable with poll_job afterwards.")]
    public async Task<KillJobResult> KillJobAsync(
        [Description("The job id start_job returned.")]
        string jobId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jobId);

        var startedAt = DateTimeOffset.UtcNow;
        var (caller, job, target, grant) = Resolve(jobId, ToolNames.KillJob, startedAt);

        var outcome = await RunAsync(
            caller, ToolNames.KillJob, startedAt, target, grant, jobId,
            JobCommands.Kill(job.Directory),

            // Long enough to cover the grace period the kill command waits out before escalating.
            _ssh.DefaultTimeoutSeconds + 15,
            cancellationToken).ConfigureAwait(false);

        // An appended record rather than an edit, so "the process is gone" and "somebody stopped it"
        // stay distinguishable - which the target cannot tell you after the fact.
        _jobs.Put(new JobRecord
        {
            JobId = job.JobId,
            Host = job.Host,
            OwnerSubject = job.OwnerSubject,
            OwnerGrantId = job.OwnerGrantId,
            AllowedBy = job.AllowedBy,
            SshUser = job.SshUser,
            Command = job.Command,
            Workdir = job.Workdir,
            Directory = job.Directory,
            StartedAt = job.StartedAt,
            KilledAt = DateTimeOffset.UtcNow,
        });

        Record(caller, ToolNames.KillJob, startedAt, grant, target, jobId, outcome, null);

        return new KillJobResult { JobId = jobId, Host = target.Name };
    }

    private (CallerIdentity Caller, JobRecord Job, HostEntry Target, Grant Grant) Resolve(
        string jobId,
        string tool,
        DateTimeOffset startedAt)
    {
        var caller = _caller.Require();

        // Re-derived rather than carried from the gate. Same inputs, same pure function, same
        // answer - and reaching here with a refusal means something invoked the tool outside the
        // gate, which is worth recording rather than assuming cannot happen.
        var job = _jobs.Find(jobId);
        if (job is null || !string.Equals(job.OwnerSubject, caller.Subject, StringComparison.Ordinal))
        {
            var refusal = AuthorizationDecision.Refuse(
                job is null ? AuthorizationRefusal.JobNotFound : AuthorizationRefusal.JobNotOwned,
                $"SshWarden refused tool '{tool}': no such job (rule: "
                    + AuthorizationRefusal.JobNotFound + ").");

            _audit.Write(AuditRecordFactory.Refusal(
                caller, tool, refusal, startedAt, job?.Host, jobId));

            throw new McpException(refusal.Detail!);
        }

        var decision = _grants.AuthorizeHost(caller, tool, job.Host);
        Refuse(caller, tool, decision, startedAt, job.Host, jobId);

        return (caller, job, FindHost(job.Host), decision.Grant!);
    }

    /// <summary>Every SSH call these three tools make, and the one place a failure is recorded.</summary>
    /// <remarks>
    /// The same reasoning as <c>ReadTools.RunAsync</c>: a call that was allowed and then failed used
    /// to leave no record at all, because the record was written after the work. Recorded here
    /// rather than in the gate, because these tools refuse on their own after the gate has passed
    /// them - <c>job_not_owned</c> is decided against the registry - and a gate recording every
    /// exception wrote a second record saying `allow` over the top of that `deny`.
    /// </remarks>
    private async Task<CommandOutcome> RunAsync(
        CallerIdentity caller,
        string tool,
        DateTimeOffset startedAt,
        HostEntry target,
        Grant grant,
        string jobId,
        string command,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _runner.RunAsync(
                target, grant.SshUser, command, workdir: null, environment: null,
                timeoutSeconds, cancellationToken).ConfigureAwait(false);
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
                jobId: jobId));

            throw;
        }
    }

    private HostEntry FindHost(string host)
        => _hosts.Find(host)
            ?? throw new McpException($"SshWarden has no configuration for host '{host}'.");

    private void Refuse(
        CallerIdentity caller,
        string tool,
        AuthorizationDecision decision,
        DateTimeOffset startedAt,
        string host,
        string? selector)
    {
        if (decision.IsAllowed)
        {
            return;
        }

        _audit.Write(AuditRecordFactory.Refusal(caller, tool, decision, startedAt, host, selector));
        throw new McpException(decision.Detail!);
    }

    private void Record(
        CallerIdentity caller,
        string tool,
        DateTimeOffset startedAt,
        Grant grant,
        HostEntry target,
        string jobId,
        CommandOutcome outcome,
        int? jobExitCode)
        => _audit.Write(new AuditRecord
        {
            Id = AuditRecordFactory.NewId(),
            Type = AuditRecordTypes.Job,
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
            JobId = jobId,
            Workdir = RemoteCommand.DefaultWorkdir,
            Command = SecretRedactor.Redact(outcome.CommandLine).Text,

            // The job's own status when there is one, not the status of the command that asked
            // about it - those are different questions and only one of them is interesting.
            ExitCode = jobExitCode,
            DurationMs = outcome.DurationMs,
        });
}

/// <summary>What <c>start_job</c> returns.</summary>
public sealed class StartJobResult
{
    /// <summary>The identifier for poll_job and kill_job.</summary>
    [JsonPropertyName("job_id")]
    public required string JobId { get; init; }

    /// <summary>The host.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }

    /// <summary>The unix account it runs as.</summary>
    [JsonPropertyName("ssh_user")]
    public required string SshUser { get; init; }

    /// <summary>The directory it runs in.</summary>
    [JsonPropertyName("workdir")]
    public required string Workdir { get; init; }
}

/// <summary>What <c>poll_job</c> returns.</summary>
public sealed class PollJobResult
{
    /// <summary>The job.</summary>
    [JsonPropertyName("job_id")]
    public required string JobId { get; init; }

    /// <summary>running, finished, gone or vanished.</summary>
    [JsonPropertyName("status")]
    public required string Status { get; init; }

    /// <summary>The exit status, when the job finished and left one.</summary>
    [JsonPropertyName("exit_code")]
    public int? ExitCode { get; init; }

    /// <summary>What it printed since the requested line, masked and bounded.</summary>
    [JsonPropertyName("output")]
    public required string Output { get; init; }

    /// <summary>The line to ask from next time.</summary>
    /// <remarks>
    /// Counted on what the target sent, before masking and truncation, so paging stays aligned with
    /// the file even when what came back was shortened.
    /// </remarks>
    [JsonPropertyName("next_line")]
    public required int NextLine { get; init; }

    /// <summary>Whether the returned output was cut short.</summary>
    [JsonPropertyName("truncated")]
    public required bool Truncated { get; init; }

    /// <summary>How many credential-shaped values were masked. Best-effort.</summary>
    [JsonPropertyName("redacted_values")]
    public required int RedactedValues { get; init; }

    /// <summary>The host.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }
}

/// <summary>What <c>kill_job</c> returns.</summary>
public sealed class KillJobResult
{
    /// <summary>The job.</summary>
    [JsonPropertyName("job_id")]
    public required string JobId { get; init; }

    /// <summary>The host.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }
}
