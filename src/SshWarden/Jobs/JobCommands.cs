using SshWarden.Ssh;

namespace SshWarden.Jobs;

/// <summary>The commands that start, inspect and signal a job on the target.</summary>
/// <remarks>
/// <para>
/// A job is a real unix process that outlives the call that started it, so all three of these are
/// about a process group rather than about a request. That is the difference from the protocol's
/// own long-running-request extension, and the reason these are hand-written: cancelling a request
/// and sending <c>SIGTERM</c> to a process group are not the same operation wearing two names.
/// </para>
/// <para>
/// <strong>The output file sits unredacted on the target, and that is the second thing
/// docs/DESIGN.md §4.4 said had to be settled first.</strong> It cannot be otherwise - the command
/// writes to it directly and nothing of SshWarden's is on that machine to intercept it. What is
/// done instead: the job directory is created mode 0700 inside the home of the unix account the
/// rule maps to, so the file is readable by that account and root and nobody else; and everything
/// read back through <c>poll_job</c> goes through the same masking every other output does. The
/// residual exposure is to whoever can already read that account's files - which is the same set of
/// people who could have run the command in the first place, so it adds nothing new. That is worth
/// saying rather than leaving somebody to work out.
/// </para>
/// </remarks>
public static class JobCommands
{
    /// <summary>The file inside a job directory holding the process group's leader pid.</summary>
    public const string PidFile = "pid";

    /// <summary>The file holding everything the job printed.</summary>
    public const string OutputFile = "out";

    /// <summary>The file holding the exit status, written only when the job finishes.</summary>
    public const string ExitFile = "exit";

    /// <summary>The file holding whatever the wrapper itself complained about.</summary>
    /// <remarks>
    /// Separate from the output file so a job's own stderr and the reason a job never started are
    /// never confused for one another. It exists because the wrapper's stderr used to go to
    /// <c>/dev/null</c>: a job that could not start left no trace at all, and the only thing the
    /// caller was told was that it had not started.
    /// </remarks>
    public const string ErrorFile = "err";

    /// <summary>Exit status when the job directory could not be created.</summary>
    public const int DirectoryFailed = 71;

    /// <summary>Exit status when the working directory could not be entered.</summary>
    public const int WorkdirFailed = 72;

    /// <summary>Exit status when the job never reported a process group.</summary>
    public const int NoProcessGroup = 73;

    /// <summary>How many times a wait re-tests its condition before giving up.</summary>
    /// <remarks>
    /// A hundred at a twentieth of a second is five seconds, which is the same grace the remote
    /// command timeout gives a process between <c>SIGTERM</c> and <c>SIGKILL</c>. Deliberately the
    /// same number in both places: a job that will not start and a job that will not die are the
    /// same question about how long is long enough, and answering it twice differently would be two
    /// numbers to keep in step.
    /// </remarks>
    private const int WaitAttempts = 100;

    /// <summary>Builds the command that starts a job.</summary>
    /// <param name="directory">The job's directory, relative to the account's home.</param>
    /// <param name="command">The caller's command, passed through unchanged.</param>
    /// <param name="workdir">Where to run it, or null for the account's login directory.</param>
    /// <exception cref="ArgumentException">A required argument is null or whitespace.</exception>
    /// <remarks>
    /// <para>
    /// <c>setsid</c> so the job leads its own process group and its own session: leading a group is
    /// what makes killing it kill the pipeline rather than only its first stage, and leaving the
    /// session is what stops it dying when the SSH channel closes. <c>umask 077</c> before anything
    /// is created, so the output file is private from the moment it exists rather than a moment
    /// after.
    /// </para>
    /// <para>
    /// The inner shell writes its own pid rather than the outer one reporting it, because what is
    /// wanted is the group leader and <c>$!</c> would name whichever process the shell happened to
    /// fork. And the caller's command is inlined into a brace group rather than handed to a third
    /// <c>sh -c</c>: the two are equivalent, and every level of nesting doubles how much escaping a
    /// quote in the command has to survive.
    /// </para>
    /// <para>
    /// <strong>It does not return until the job has a process group.</strong> Without the wait,
    /// measured on 2026-08-26, the pid file was absent at the instant the command printed
    /// <c>started</c> on 300 starts out of 300, idle and under load alike - so the guarantee is not
    /// merely racy, it is false every time. What that costs is two things. A caller that acts on
    /// the identifier immediately acts on a job that does not exist yet, and more importantly a
    /// command the target's shell cannot even parse is <em>accepted</em>: an identifier comes back
    /// for a job that will never run, and the caller learns about it at some later poll, as
    /// <c>gone</c>, with nothing saying why.
    /// </para>
    /// <para>
    /// Honest about what the tests show: the suite does <strong>not</strong> go red for the first
    /// of those, because every way of observing a job costs an SSH round trip and the job wins that
    /// race on any machine tried. It goes red for the second, which is
    /// <c>A_job_that_cannot_start_is_refused_rather_than_accepted</c>. The wait is kept for the
    /// contract rather than for the failure that was seen.
    /// </para>
    /// <para>
    /// The alternative considered was a fifth status meaning <em>starting</em>, rejected because it
    /// moves the same race onto every caller and still leaves <c>kill_job</c> with nothing to
    /// signal. The other one considered was giving up as soon as <c>$!</c> is gone, which would
    /// refuse a failed start in milliseconds rather than in five seconds; it was rejected because
    /// <c>setsid</c> forks when it is already a process group leader, and in that case <c>$!</c>
    /// names a process that exits immediately on success too - a wrong refusal, which is worse than
    /// a slow correct one. It does not fork here (measured, util-linux 2.39.3, 2026-08-26), and
    /// that is a fact about this machine rather than about the target.
    /// </para>
    /// <para>
    /// The wait is bounded twice - by its own counter and by the remote timeout wrapping the whole
    /// command - and each way of failing exits with its own status so the caller is told which one
    /// happened rather than being handed a bare non-zero.
    /// </para>
    /// </remarks>
    public static string Start(string directory, string command, string? workdir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(command);

        var inner = $"echo $$ > {InHome(directory, PidFile)}; "
            + $"{{ {command}\n}} > {InHome(directory, OutputFile)} 2>&1; "
            + $"echo $? > {InHome(directory, ExitFile)}";

        var cd = string.IsNullOrWhiteSpace(workdir)
            ? "cd -- \"$HOME\""
            : "cd -- " + ShellQuoting.Quote(workdir);

        // Separated by `;` rather than `&&`, because `&` binds to a whole and-list: written as
        // `mkdir && cd && setsid ... &` the directory was created in the background too, so a
        // failure to create it was invisible and `echo started` still reported success.
        return $"umask 077; mkdir -p -m 700 -- {InHome(directory)} || exit {DirectoryFailed}; "
            + $"{cd} || exit {WorkdirFailed}; "
            + $"setsid sh -c {ShellQuoting.Quote(inner)} "
            + $"< /dev/null > /dev/null 2> {InHome(directory, ErrorFile)} & "
            + WaitFor(
                $"[ ! -s {InHome(directory, PidFile)} ]",
                $"cat {InHome(directory, ErrorFile)} >&2 2>/dev/null; exit {NoProcessGroup}")
            + "echo started";
    }

    /// <summary>Builds the command that reports a job's status and new output.</summary>
    /// <param name="directory">The job's directory, relative to the account's home.</param>
    /// <param name="sinceLine">How many lines of output the caller has already seen.</param>
    /// <exception cref="ArgumentException"><paramref name="directory" /> is null or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="sinceLine" /> is negative.</exception>
    /// <remarks>
    /// Status first and on its own line, then the output, so one round trip answers both and the
    /// parser never has to guess where one ends. The status has four values rather than two:
    /// a job that is not running and left no exit status is not the same as one that finished, and
    /// a job whose directory is gone is not an error.
    /// </remarks>
    public static string Poll(string directory, int sinceLine)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfNegative(sinceLine);

        var dir = InHome(directory);
        var pid = InHome(directory, PidFile);
        var output = InHome(directory, OutputFile);
        var exit = InHome(directory, ExitFile);

        return $"if [ ! -d {dir} ]; then echo '{JobStatuses.Vanished} '; else "
            + $"if [ -f {exit} ]; then echo \"{JobStatuses.Finished} $(cat {exit})\"; "
            + $"elif kill -0 \"$(cat {pid} 2>/dev/null)\" 2>/dev/null; then echo '{JobStatuses.Running} '; "
            + $"else echo '{JobStatuses.Gone} '; fi; "
            + $"tail -n +{sinceLine + 1} -- {output} 2>/dev/null; fi";
    }

    /// <summary>Builds the command that signals a job's process group.</summary>
    /// <param name="directory">The job's directory, relative to the account's home.</param>
    /// <exception cref="ArgumentException"><paramref name="directory" /> is null or whitespace.</exception>
    /// <remarks>
    /// <para>
    /// The negated pid signals the whole process group, which is why the job was given one: killing
    /// only the leader of <c>a | b | c</c> leaves the rest running and reports success.
    /// <c>SIGTERM</c> first with a grace period, then <c>SIGKILL</c> - the same shape the remote
    /// timeout uses, so a job gets the chance to clean up that a command does.
    /// </para>
    /// <para>
    /// <strong>No <c>--</c> before the negated pid.</strong> It reads as the careful spelling and it
    /// is the broken one: dash's builtin <c>kill</c> rejects the option terminator with
    /// <c>Illegal number: -</c>, so <c>kill -TERM -- "-$p"</c> signalled nothing and the job stayed
    /// running while the call reported success. Measured against dash 0.5.12 on 2026-08-26; bash and
    /// dash both accept the form without it. There is nothing to disambiguate here anyway - the
    /// argument is a signal target, not a filename.
    /// </para>
    /// <para>
    /// The grace is spent waiting for the group to actually go rather than sleeping through it, so
    /// a job that exits on <c>SIGTERM</c> - which is nearly all of them - does not hold the call
    /// open for the full window.
    /// </para>
    /// </remarks>
    public static string Kill(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        return $"p=$(cat {InHome(directory, PidFile)} 2>/dev/null) || exit 0; "
            + "[ -n \"$p\" ] || exit 0; "
            + "kill -TERM \"-$p\" 2>/dev/null; "
            + WaitFor("kill -0 \"-$p\" 2>/dev/null", onGiveUp: null)
            + "kill -KILL \"-$p\" 2>/dev/null; "
            + "exit 0";
    }

    /// <summary>Reads what <see cref="Poll" /> printed.</summary>
    /// <param name="output">The command's standard output.</param>
    /// <exception cref="ArgumentNullException"><paramref name="output" /> is null.</exception>
    public static (string Status, int? ExitCode, string Output) ParsePoll(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        var newline = output.IndexOf('\n', StringComparison.Ordinal);
        if (newline < 0)
        {
            // No status line at all means the command did not run as expected. Answered as gone
            // rather than guessed at: a job reported finished with an invented exit code would say
            // the command completed when nobody knows whether it did.
            return (JobStatuses.Gone, null, string.Empty);
        }

        var header = output[..newline].Split(' ', 2);
        var status = header[0];
        var exitCode = header.Length > 1 && int.TryParse(header[1].Trim(), out var parsed) ? parsed : (int?)null;

        return (status, exitCode, output[(newline + 1)..]);
    }

    /// <summary>A bounded wait for a shell condition to stop holding.</summary>
    /// <param name="keepWaiting">The condition, as a shell command whose success means not yet.</param>
    /// <param name="onGiveUp">What to run if it never stops holding, or null to carry on regardless.</param>
    /// <remarks>
    /// <para>
    /// A poll loop in shell is not pretty and it is what there is: the two things being waited for -
    /// a process writing a file, and a process group going away - are the state of processes this
    /// shell is not the parent of, so there is nothing to <c>wait</c> on. It is bounded by its own
    /// counter as well as by the remote timeout around the whole command, so the worst case is a
    /// named refusal rather than a hung call.
    /// </para>
    /// <para>
    /// <c>sleep 0.05 || sleep 1</c> because fractional sleeps are a GNU extension rather than
    /// POSIX. Where they work the wait is fine-grained; where they do not, the fallback keeps the
    /// loop from spinning a core. Neither case is a hang, which is the property worth having when
    /// the shell on the other end is somebody else's.
    /// </para>
    /// </remarks>
    private static string WaitFor(string keepWaiting, string? onGiveUp)
    {
        // Braced, because `A && B; C` runs C whether or not A held - so an unbraced give-up made of
        // more than one command would run its tail on every pass through the loop.
        var giveUp = onGiveUp is null ? "break" : $"{{ {onGiveUp}; }}";

        // Phrased as the condition for carrying on rather than the condition for stopping, so
        // neither caller has to negate it: dash rejects `! ! cmd` outright with a syntax error, so
        // a caller whose own condition is already a negation had no way to write it. Measured
        // against dash 0.5.12 on 2026-08-26.
        return $"n=0; while {keepWaiting}; do n=$((n+1)); "
            + $"[ \"$n\" -gt {WaitAttempts} ] && {giveUp}; "
            + "sleep 0.05 2>/dev/null || sleep 1; done; ";
    }

    /// <summary>A path under the account's home, as one shell word.</summary>
    /// <remarks>
    /// <para>
    /// <c>"$HOME"</c> in double quotes so the shell expands it, concatenated with a single-quoted
    /// relative path so nothing in the path is interpreted. Two quoting styles in one word is
    /// deliberate: the home directory is the shell's own variable and has to expand, and everything
    /// after it came from configuration and must not.
    /// </para>
    /// <para>
    /// It has to be built this way rather than resolved once and stored absolute, because the home
    /// differs per unix account and the account differs per rule - and asking the target for it
    /// would be a round trip before every job operation.
    /// </para>
    /// </remarks>
    private static string InHome(string directory, string? file = null)
    {
        var relative = directory.Trim('/');
        if (file is not null)
        {
            relative += "/" + file;
        }

        return "\"$HOME\"/" + ShellQuoting.Quote(relative);
    }

}
