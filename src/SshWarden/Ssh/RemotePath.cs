namespace SshWarden.Ssh;

/// <summary>Resolving a path on the target, before anything reads it.</summary>
/// <remarks>
/// <para>
/// <strong>The trap this closes.</strong> A rule allows <c>/var/log/**</c>. On the target,
/// <c>/var/log/app</c> is a symlink to <c>/etc</c>. Every check that can be made from here passes -
/// the string is absolute, it has no <c>..</c> in it, and it sits under an allowed prefix - and the
/// read lands in <c>/etc</c>. Nothing on this side can see that, because the filesystem it is about
/// is somewhere else.
/// </para>
/// <para>
/// So the path is resolved <em>on the target</em> and the <strong>result</strong> is checked against
/// the rule again. The check the caller's string passed is layer zero; this is layer one.
/// </para>
/// <para>
/// <strong>What stays open, and is not closeable from here.</strong> Between resolving and reading,
/// the symlink can change - the classic time-of-check to time-of-use gap. Doing both in one round
/// trip would narrow it, and is not done, because it would mean writing the rule's globs a second
/// time as shell patterns: two matchers, which can disagree, deciding one thing. The single matcher
/// that is tested is worth more than a narrower window on a race the layer below already answers -
/// if the unix account cannot read <c>/etc/shadow</c>, winning this race changes the error message
/// and nothing else.
/// </para>
/// </remarks>
public static class RemotePath
{
    /// <summary>The exit status the resolve command uses for "no such file".</summary>
    public const int NotFoundExitCode = 66;

    /// <summary>The exit status the resolve command uses for "not a regular file".</summary>
    public const int NotRegularFileExitCode = 67;

    /// <summary>Builds the command that resolves <paramref name="path" /> and prints the result.</summary>
    /// <param name="path">The path the caller named, already normalized.</param>
    /// <exception cref="ArgumentException"><paramref name="path" /> is null or whitespace.</exception>
    /// <remarks>
    /// <para>
    /// <c>realpath -e</c> rather than <c>-m</c> or nothing: <c>-e</c> requires every component to
    /// exist, so a path that resolves to somewhere plausible but is not there fails here instead of
    /// being carried forward as if it were real.
    /// </para>
    /// <para>
    /// Distinct exit statuses rather than one, because "the file is not there" and "the caller is
    /// not allowed" want opposite responses and reporting the first as the second sends somebody to
    /// edit the grant table over a typo.
    /// </para>
    /// </remarks>
    public static string ResolveCommand(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var quoted = ShellQuoting.Quote(path);

        // `--` on every command that takes the value, so a path beginning with a dash is a path
        // rather than an option. printf rather than echo, which mangles a leading dash of its own.
        return $"p=$(realpath -e -- {quoted} 2>/dev/null) || exit {NotFoundExitCode}; "
            + $"[ -f \"$p\" ] || exit {NotRegularFileExitCode}; "
            + "printf '%s' \"$p\"";
    }

    /// <summary>Builds the command that reads the first <paramref name="maxBytes" /> of a file.</summary>
    /// <param name="resolvedPath">The path as the target resolved it.</param>
    /// <param name="maxBytes">How many bytes to read.</param>
    /// <exception cref="ArgumentException"><paramref name="resolvedPath" /> is null or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxBytes" /> is not positive.</exception>
    /// <remarks>
    /// Bounded on the target rather than after transfer, so a caller asking for a fifty-gigabyte
    /// file does not move fifty gigabytes to find that out. The output budget then applies to what
    /// arrives, and is the smaller of the two.
    /// </remarks>
    public static string ReadCommand(string resolvedPath, int maxBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resolvedPath);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

        return $"head -c {maxBytes} -- {ShellQuoting.Quote(resolvedPath)}";
    }

    /// <summary>Builds the command that reads the last <paramref name="lines" /> lines of a file.</summary>
    /// <param name="resolvedPath">The path as the target resolved it.</param>
    /// <param name="lines">How many lines to read.</param>
    /// <exception cref="ArgumentException"><paramref name="resolvedPath" /> is null or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="lines" /> is not positive.</exception>
    public static string TailCommand(string resolvedPath, int lines)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resolvedPath);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(lines);

        return $"tail -n {lines} -- {ShellQuoting.Quote(resolvedPath)}";
    }

    /// <summary>Builds the command that reads the last <paramref name="lines" /> of a unit's journal.</summary>
    /// <param name="unit">The unit name.</param>
    /// <param name="lines">How many lines to read.</param>
    /// <exception cref="ArgumentException"><paramref name="unit" /> is null or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="lines" /> is not positive.</exception>
    /// <remarks>
    /// <c>--no-pager</c> because there is no terminal on the other end and journalctl would
    /// otherwise wait for one. The unit name is quoted like every other value SshWarden splices in;
    /// it named a thing rather than describing one.
    /// </remarks>
    public static string JournalCommand(string unit, int lines)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(unit);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(lines);

        return $"journalctl --no-pager -n {lines} -u {ShellQuoting.Quote(unit)}";
    }
}
