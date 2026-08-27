using Microsoft.Extensions.Logging;

namespace SshWarden.Diagnostics;

/// <summary>
/// Everything <c>SshWarden</c> can say to an operator, in one file.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Collected rather than declared where they are called</strong>, which is the other half of
/// what <see cref="LogEvents" /> is for. Log declarations scattered through the classes that log
/// them answer "what does this class say" and never answer "what can this process say" - and the
/// second is the question somebody has when they are deciding what to alert on.
/// </para>
/// <para>
/// Source-generated, so a disabled level formats nothing and no argument is boxed into a
/// <c>params object?[]</c>. Every message carries an <c>EventName</c> as well as an id: the id is
/// what a query filters on, and the name is what makes the query readable six months later.
/// </para>
/// <para>
/// <strong>This is not the audit log.</strong> The audit record is the evidence - one line per call,
/// append-only, with the five identity values on it - and it goes to its own file whether anybody is
/// listening or not. What is here is what shows up in whatever is already tailing the service, and
/// none of it is a substitute for the record.
/// </para>
/// </remarks>
public static partial class CoreLog
{
    /// <summary>A sweep of one host and account could not be done.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="host">The host, or <c>*</c> when the whole round failed.</param>
    /// <param name="sshUser">The unix account, or <c>*</c> when the whole round failed.</param>
    /// <param name="problem">What went wrong, as the caller of <c>list_changes</c> would be told.</param>
    /// <remarks>
    /// <para>
    /// <strong>The defect this closes: nothing said this out loud.</strong> The sweeper catches
    /// every failure into <c>SweepProblems</c> so one bad round cannot end the loop - which is
    /// right - and the only way to find out was to call <c>list_changes</c> and read the note. A
    /// change detector that has been off for a week and an operator tailing the service saw
    /// nothing, in the project whose second reason to exist is knowing what changed.
    /// </para>
    /// <para>
    /// Warning rather than Error: the process is serving, the other tools work, and the loop will
    /// try again on the next tick. Error is for something nobody can wait out.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Core + 1,
        EventName = "SweepProblem",
        Level = LogLevel.Warning,
        Message = "The last sweep of {Host} as {SshUser} had a problem: {Problem}")]
    public static partial void SweepProblem(ILogger logger, string host, string sshUser, string problem);

    /// <summary>A sweep that had a problem is working again.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="host">The host.</param>
    /// <param name="sshUser">The unix account.</param>
    /// <remarks>
    /// Only on the transition, never on an ordinary successful sweep. A line per host per interval
    /// forever is how the one line that matters becomes unreadable - and it is the recovery, not the
    /// steady state, that closes the question the warning above opened.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Core + 2,
        EventName = "SweepRecovered",
        Level = LogLevel.Information,
        Message = "Sweeping {Host} as {SshUser} is working again.")]
    public static partial void SweepRecovered(ILogger logger, string host, string sshUser);

    /// <summary>A line of the job registry could not be read and was skipped.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="path">The registry file.</param>
    /// <param name="line">Which line, counting from one.</param>
    /// <remarks>
    /// <para>
    /// Skipping is deliberate: the likely cause is a crash partway through the last write, and
    /// refusing to start over one truncated line turns a lost job into a lost server. What was
    /// missing is anybody being told - a job that survived a restart and a job that was silently
    /// dropped look identical from outside, and the second means <c>poll_job</c> answers "no such
    /// job" for work that is still running on the target.
    /// </para>
    /// <para>
    /// The line's contents are not logged. It is a job record, so it carries a command, and a
    /// command carries whatever the caller put in it.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Core + 3,
        EventName = "JobRegistryLineSkipped",
        Level = LogLevel.Warning,
        Message = "Line {Line} of the job registry at {Path} could not be read and was skipped. "
            + "A job it described is not known to this process and will not answer poll_job.")]
    public static partial void JobRegistryLineSkipped(ILogger logger, string path, int line);
}
