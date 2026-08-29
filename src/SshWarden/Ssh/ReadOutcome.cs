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
/// names the account and the exit code. A null status is neither, and
/// <see cref="CommandOutcome.ExitCode" /> says why: the channel ended without one, which is not
/// to be conflated with zero. Reporting that as an empty file is a guess about what happened on a
/// machine we stopped hearing from.
/// </para>
/// <para>
/// <b>The target's own error is not quoted back.</b> An earlier version put the first line of
/// <see cref="CommandOutcome.Stderr" /> into this message, masked. That opened a channel the read
/// tools never had: on failure, host output reached the caller and its provider's transcript, held
/// back only by the best-effort <c>SecretRedactor</c>. Masking is the second line of defence, and
/// the first - the account not being able to read the file - does not cover standard error, which a
/// failing command writes whether or not it could open anything. So a secret in a shape the
/// redactor does not know went through untouched, and a redactor timeout was dropped rather than
/// reported the way the output pipeline reports it. The boundary is named without any of that:
/// which file, which host, which account, and the exit code. Diagnosing <em>why</em> the account
/// was refused is what <c>run</c> is for, and its output goes back through the masking pipeline that
/// records when masking did not finish.
/// </para>
/// </remarks>
public static class ReadOutcome
{
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

        if (outcome.ExitCode is not { } code)
        {
            return $"SshWarden could not tell whether reading '{selector}' on host '{host}' as "
                + $"'{sshUser}' succeeded: the channel ended without an exit status, so returning "
                + "an empty result here would be a guess.";
        }

        // The account is named because it is the boundary that refused. The grant table let this
        // path through - that check has already passed by the time a command runs - so a caller
        // told only "could not read" has two rules to suspect and edits the wrong one. Most often
        // the account simply cannot open the file; the target's own error is not quoted, because
        // that stream can carry a credential and this message reaches the caller.
        return $"SshWarden could not read '{selector}' on host '{host}' as '{sshUser}': the command "
            + $"exited {code}. The grant table already allowed this path, so the account is the "
            + "boundary that refused, most often because it cannot open the file.";
    }
}
