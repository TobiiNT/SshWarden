using SshWarden.Output;

namespace SshWarden.Ssh;

/// <summary>Whether a read command actually read the thing it was pointed at.</summary>
/// <remarks>
/// <para>
/// <b>An empty result where a refusal belongs is the failure this exists to stop.</b> The read
/// tools built their answer out of <see cref="CommandOutcome.Stdout" /> alone, so a file the
/// mapped account may not open - which produces no standard output and a non-zero status - came
/// back as a file with nothing in it. Measured against a running deployment on 2026-08-29: a
/// 72 MB <c>/var/log/syslog</c> owned <c>syslog:adm</c>, read by an account in neither group,
/// returned <c>content ""</c> and <c>bytes 0</c> with no note. A caller reads that as "the log is
/// empty" and goes looking for why nothing is being logged.
/// </para>
/// <para>
/// The missing-file case was already refused by name, in the resolve step, which is what makes
/// this a gap rather than a design: the tool knew how to say "that is not there" and had nothing
/// to say about "you may not read that".
/// </para>
/// <para>
/// <b>Three answers, not two.</b> A zero status is a read. A non-zero status is a refusal that
/// names the account and quotes the target. A null status is neither, and
/// <see cref="CommandOutcome.ExitCode" /> says why: the channel ended without one, which is not
/// to be conflated with zero. Reporting that as an empty file is a guess about what happened on a
/// machine we stopped hearing from.
/// </para>
/// </remarks>
public static class ReadOutcome
{
    /// <summary>
    /// How much of the target's own error is quoted back.
    /// </summary>
    /// <remarks>
    /// Nothing upstream bounds standard error, and this string reaches an exception message and an
    /// audit line. One line is what a reader acts on; the rest is what the target would have said
    /// to a shell, and the audit record already carries the command that produced it.
    /// </remarks>
    private const int MaxDetail = 300;

    /// <summary>The sentence to refuse with, or <see langword="null" /> when the read happened.</summary>
    /// <param name="outcome">What running the read command produced.</param>
    /// <param name="host">The host as this deployment names it.</param>
    /// <param name="sshUser">The unix account the caller was mapped to.</param>
    /// <param name="selector">The file or unit the caller asked for.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static string? Problem(CommandOutcome outcome, string host, string sshUser, string selector)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(sshUser);
        ArgumentNullException.ThrowIfNull(selector);

        if (outcome.ExitCode == 0)
        {
            return null;
        }

        var detail = Detail(outcome.Stderr);

        if (outcome.ExitCode is not { } code)
        {
            return $"SshWarden could not tell whether reading '{selector}' on host '{host}' as "
                + $"'{sshUser}' succeeded: the channel ended without an exit status, so returning "
                + $"an empty result here would be a guess.{detail}";
        }

        // The account is named because it is the boundary that refused. The grant table let this
        // path through - that check has already passed by the time a command runs - so a caller
        // told only "could not read" has two rules to suspect and edits the wrong one.
        return $"SshWarden could not read '{selector}' on host '{host}' as '{sshUser}': the command "
            + $"exited {code}.{detail}";
    }

    /// <summary>The first line the target said, masked, or an empty string when it said nothing.</summary>
    /// <remarks>
    /// Masked with the same redactor every other stream goes through. A failed read is exactly
    /// where a connection string turns up - the command that failed had one in it - and this
    /// message travels further than the output ever would have.
    /// </remarks>
    private static string Detail(string stderr)
    {
        var masked = SecretRedactor.Redact(stderr).Text;

        var line = masked
            .Split('\n')
            .Select(candidate => candidate.Trim())
            .FirstOrDefault(candidate => candidate.Length > 0);

        if (line is null)
        {
            return " The target said nothing on standard error.";
        }

        return line.Length > MaxDetail
            ? $" The target said: {line[..MaxDetail]}..."
            : $" The target said: {line}";
    }
}
