namespace SshWarden.Ssh;

/// <summary>Builds the single command line SshWarden sends for one call.</summary>
/// <remarks>
/// <para>
/// Every command goes over its own channel, so there is no state from the previous one to inherit -
/// no working directory, no environment, no <c>sudo</c> timestamp. Everything a command needs has
/// to be in the string this builds, which is exactly why the audit record can be read on its own.
/// </para>
/// </remarks>
public static class RemoteCommand
{
    /// <summary>
    /// What <see cref="Build" /> records as the working directory when the caller names none.
    /// </summary>
    /// <remarks>
    /// The account's login directory, written as the shell writes it. docs/DESIGN.md §4.2 requires the
    /// working directory to always have a value, and "wherever the previous command left it" is the
    /// answer this project exists to avoid - so an unset one is still an explicit <c>cd</c>, to a
    /// place that depends only on which unix account the grant chose.
    /// </remarks>
    public const string DefaultWorkdir = "~";

    /// <summary>Builds the command line.</summary>
    /// <param name="command">The caller's command, passed through unchanged.</param>
    /// <param name="workdir">Where to run it, or null for the account's login directory.</param>
    /// <param name="environment">Variables to set, or null.</param>
    /// <param name="timeoutSeconds">How long the remote side should allow it.</param>
    /// <exception cref="ArgumentException"><paramref name="command" /> is null or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="timeoutSeconds" /> is not positive.</exception>
    /// <exception cref="ArgumentException">An environment variable name is not usable.</exception>
    public static string Build(
        string command,
        string? workdir,
        IReadOnlyDictionary<string, string>? environment,
        int timeoutSeconds)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutSeconds);

        var parts = new List<string>();

        if (string.IsNullOrWhiteSpace(workdir))
        {
            // Double quotes so the shell expands it, which is the one place in this builder where
            // expansion is wanted: the value is the shell's own variable, not anything a caller
            // supplied.
            parts.Add("cd -- \"$HOME\"");
        }
        else
        {
            // Quoted, and with `--`, because a directory the caller named beginning with a dash
            // would otherwise be read by cd as an option.
            parts.Add("cd -- " + ShellQuoting.Quote(workdir));
        }

        var run = new List<string>();

        if (environment is { Count: > 0 })
        {
            // `env --` rather than NAME=VALUE prefixes, so the assignments are ordinary arguments
            // and a name beginning with a dash cannot be read as an option to it.
            run.Add("env --");

            foreach (var (name, value) in environment)
            {
                if (!ShellQuoting.IsValidEnvironmentName(name))
                {
                    throw new ArgumentException(
                        $"'{name}' is not a usable environment variable name. Names are letters, "
                            + "digits and underscores, not starting with a digit - a name carrying "
                            + "an '=' would set a different variable than the one asked for, and no "
                            + "amount of quoting changes that.",
                        nameof(environment));
                }

                run.Add(ShellQuoting.Quote(name + "=" + value));
            }
        }

        // The timeout is enforced here rather than by cancelling the channel, and that is measured
        // rather than cautious: SSH.NET's own documentation says that when the server does not
        // implement signals it may send no response, so cancelling can complete on this side while
        // the process keeps running on the other - producing a record with no exit status for a
        // command that is still going, which is invisible.
        //
        // -k gives the process a window to exit on SIGTERM before SIGKILL. GNU timeout runs the
        // command in its own process group and signals the group, so a pipeline dies with it rather
        // than leaving the tail of it behind.
        run.Add($"timeout -k 5s {timeoutSeconds}s");

        // sh -c with the whole command as one argument, so the timeout wraps everything. Written as
        // `timeout ... sh -c '<cmd>'` rather than `timeout ... <cmd>`, because in the second form a
        // pipeline would put only its first stage under the timeout and leave the rest unbounded.
        run.Add("sh -c " + ShellQuoting.Quote(command));

        parts.Add(string.Join(' ', run));
        return string.Join(" && ", parts);
    }
}
