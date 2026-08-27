using System.Text.Json.Serialization;

namespace SshWarden.Jobs;

/// <summary>What SshWarden knows about one job.</summary>
/// <remarks>
/// <para>
/// The job itself is a process on the target that outlives the call that started it. This is the
/// index: enough to find it again, and enough to decide whether the caller asking about it is the
/// one who started it.
/// </para>
/// </remarks>
public sealed class JobRecord
{
    /// <summary>The identifier callers use.</summary>
    /// <remarks>
    /// From the cryptographic generator, never a counter. It is the only argument
    /// <c>poll_job</c> and <c>kill_job</c> take, so a guessable one is a way to reach other
    /// people's jobs by trying.
    /// </remarks>
    [JsonPropertyName("job_id")]
    public required string JobId { get; init; }

    /// <summary>The host it runs on.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }

    /// <summary>Who started it.</summary>
    /// <remarks>
    /// <para>
    /// <strong>This is what ownership is checked against</strong>, and it is the subject rather
    /// than the grant identifier - a deliberate departure from docs/DESIGN.md §6.5.3, recorded there
    /// too rather than left as a silent divergence.
    /// </para>
    /// <para>
    /// The reason: everything else in this system authorizes by subject. Two sessions of one
    /// subject already share a grant, so the one that did not start the job can reach its output
    /// with <c>run</c> anyway - the file is in the home directory of the account both of them map
    /// to. Gating jobs by grant id would refuse the second session a file it can read with one
    /// command, which is not a boundary, it is a speed bump with a security-shaped comment on it.
    /// Between <em>subjects</em> the gate is real, and that is the line every other gate here draws.
    /// </para>
    /// </remarks>
    [JsonPropertyName("owner_subject")]
    public required string OwnerSubject { get; init; }

    /// <summary>Which grant started it.</summary>
    /// <remarks>
    /// Recorded but not compared. It is what a stricter mode would key on if a deployment ever
    /// wanted one, and it is what makes the audit record of a job line up with the session that
    /// started it.
    /// </remarks>
    [JsonPropertyName("owner_grant_id")]
    public required string OwnerGrantId { get; init; }

    /// <summary>Which rule allowed it.</summary>
    [JsonPropertyName("allowed_by")]
    public required string AllowedBy { get; init; }

    /// <summary>The unix account it runs as.</summary>
    [JsonPropertyName("ssh_user")]
    public required string SshUser { get; init; }

    /// <summary>The command, as the caller wrote it.</summary>
    [JsonPropertyName("command")]
    public required string Command { get; init; }

    /// <summary>Where it runs.</summary>
    [JsonPropertyName("workdir")]
    public required string Workdir { get; init; }

    /// <summary>
    /// The directory on the target holding its output, pid and exit status, relative to the home of
    /// the account the job runs as.
    /// </summary>
    [JsonPropertyName("directory")]
    public required string Directory { get; init; }

    /// <summary>When it was started.</summary>
    [JsonPropertyName("started_at")]
    public required DateTimeOffset StartedAt { get; init; }

    /// <summary>When SshWarden was asked to signal it, if it was.</summary>
    /// <remarks>
    /// Recorded because "the process is gone" and "somebody killed it" are different facts and the
    /// target cannot tell them apart after the fact.
    /// </remarks>
    [JsonPropertyName("killed_at")]
    public DateTimeOffset? KilledAt { get; init; }
}

/// <summary>What a job is doing, as far as the target will say.</summary>
public static class JobStatuses
{
    /// <summary>The process is alive.</summary>
    public const string Running = "running";

    /// <summary>It finished and left an exit status.</summary>
    public const string Finished = "finished";

    /// <summary>
    /// It is not running and left no exit status.
    /// </summary>
    /// <remarks>
    /// The third value, and it is not a synonym for finished. A job that was signalled, or whose
    /// machine rebooted, ends this way - and reporting it as finished with an unknown exit code
    /// would say the command completed when nobody knows whether it did.
    /// </remarks>
    public const string Gone = "gone";

    /// <summary>The job directory is not on the target any more.</summary>
    /// <remarks>
    /// SshWarden's registry survives a restart; the target's <c>/tmp</c> may not survive a reboot.
    /// A job in the registry whose directory has vanished is answered as this rather than as an
    /// error, because nothing is wrong - the evidence is simply gone.
    /// </remarks>
    public const string Vanished = "vanished";
}
