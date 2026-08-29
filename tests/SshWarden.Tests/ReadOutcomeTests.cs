using SshWarden.Ssh;

using Xunit;

namespace SshWarden.Tests;

/// <summary>
/// That a read which did not happen is refused rather than returned as an empty file.
/// </summary>
/// <remarks>
/// Measured against the running deployment on 2026-08-29: `read_file` on a 72 MB
/// /var/log/syslog that the mapped account cannot open returned content "" and bytes 0, with
/// no note and no error - identical to reading an empty file. `tail_log` did the same for that
/// path and for a unit whose journal the account may not read. The three call sites took
/// CommandOutcome.Stdout and never looked at CommandOutcome.ExitCode, so "you may not read
/// this" and "this is empty" were the same answer.
///
/// The decision is a pure function so it can be proved here with a hand-built outcome. Reaching
/// it through a tool needs a real host and a real account that cannot read a real file, which
/// is what the integration suite is for and not what this one measures.
/// </remarks>
public sealed class ReadOutcomeTests
{
    private const string Host = "web-1";
    private const string User = "auditor";
    private const string Selector = "/var/log/syslog";

    [Fact]
    public void A_read_that_succeeded_says_nothing()
    {
        // The control, and every other case here is meaningless without it: a function that
        // objects whatever happened has not measured anything.
        Assert.Null(ReadOutcome.Problem(Outcome(exitCode: 0, stdout: "a line\n"), Host, User, Selector));
    }

    [Fact]
    public void A_read_that_succeeded_and_found_nothing_still_says_nothing()
    {
        // A genuinely empty file is exit 0 with no output, and it must stay distinguishable from
        // the refusal below. This is the case that makes an empty result honest.
        Assert.Null(ReadOutcome.Problem(Outcome(exitCode: 0, stdout: string.Empty), Host, User, Selector));
    }

    [Fact]
    public void A_file_the_account_cannot_open_names_the_boundary()
    {
        var problem = ReadOutcome.Problem(
            Outcome(exitCode: 1, stderr: "head: cannot open '/var/log/syslog' for reading: Permission denied"),
            Host,
            User,
            Selector);

        Assert.NotNull(problem);

        // Which file, which host, which account. The account is in it because that is the boundary
        // that refused: the grant table allowed this path, and the unix layer did not, and a reader
        // told only "could not read" goes and edits the wrong one of the two.
        Assert.Contains(Selector, problem, StringComparison.Ordinal);
        Assert.Contains(Host, problem, StringComparison.Ordinal);
        Assert.Contains(User, problem, StringComparison.Ordinal);

        // And not the target's stderr. Quoting it is the channel this change removed: on failure it
        // put host output into a caller-facing message held back only by best-effort masking. This
        // assertion is red against the version that quoted it; the boundary above is named without
        // the target's words.
        Assert.DoesNotContain("Permission denied", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_failure_the_target_did_not_explain_still_names_the_exit_code()
    {
        // Saying nothing here would put us back where we started, with a caller who cannot tell a
        // failed read from an empty one.
        var problem = ReadOutcome.Problem(Outcome(exitCode: 13, stderr: string.Empty), Host, User, Selector);

        Assert.NotNull(problem);
        Assert.Contains("13", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_command_that_reported_no_status_is_could_not_tell_rather_than_empty()
    {
        // CommandOutcome's own documentation: null means the channel ended without a status, and
        // it is never to be conflated with zero. That is the third value this codebase requires on
        // every axis, and it is a different sentence from a refusal because it is a different fact.
        var problem = ReadOutcome.Problem(Outcome(exitCode: null), Host, User, Selector);

        Assert.NotNull(problem);
        Assert.Contains("could not tell", problem, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_secret_in_the_target_error_never_reaches_the_caller()
    {
        // The red-before-change case, and the reason this is "do not quote stderr" rather than
        // "mask it harder". SecretRedactor is best-effort and anchored: a secret in a shape it does
        // not know - here a password that is neither part of a URL nor a KEY=value assignment - goes
        // through it untouched. The earlier version quoted the first line of stderr into this
        // message, so that secret reached the caller and its provider's transcript. Not quoting
        // stderr at all is what closes the channel, and this asserts the close, not the masking.
        var problem = ReadOutcome.Problem(
            Outcome(exitCode: 1, stderr: "tail: could not read config: db password is hunter2"),
            Host,
            User,
            Selector);

        Assert.NotNull(problem);
        Assert.DoesNotContain("hunter2", problem, StringComparison.Ordinal);
    }

    private static CommandOutcome Outcome(int? exitCode, string stdout = "", string stderr = "")
        => new()
        {
            CommandLine = "head -c 65536 -- /var/log/syslog",
            ExitCode = exitCode,
            Stdout = stdout,
            Stderr = stderr,
            StdoutBytes = stdout.Length,
            DurationMs = 1,
        };
}
