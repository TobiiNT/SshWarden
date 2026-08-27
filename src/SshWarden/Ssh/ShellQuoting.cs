namespace SshWarden.Ssh;

/// <summary>Turns a value into one shell word.</summary>
/// <remarks>
/// <para>
/// One implementation, used everywhere SshWarden builds part of a command line. Two helpers that
/// quote almost the same way is how a value comes to be safe on one path and not on another, and
/// the difference only shows up on the input somebody chose specifically to find it.
/// </para>
/// <para>
/// <strong>The command a caller passes to <c>run</c> is deliberately not quoted.</strong> It is
/// meant to be a shell command, pipes and all, and that is the design rather than an oversight -
/// docs/DESIGN.md §8 rules out filtering it by content permanently, because deciding what a shell will
/// do with a string is not answerable at the string level. Precisely because of that, every
/// <em>other</em> value SshWarden splices in has to be quoted without exception: those are the ones
/// where the caller is naming a thing, not writing a program, and an unquoted one turns a name into
/// a program.
/// </para>
/// </remarks>
public static class ShellQuoting
{
    /// <summary>Wraps <paramref name="value" /> so a POSIX shell reads it as one literal word.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="value" /> is null.</exception>
    /// <remarks>
    /// Single quotes, because inside them a POSIX shell interprets nothing at all - no variable
    /// expansion, no command substitution, no backslash escapes. The single quote itself is the
    /// only character that needs handling, and it is done by closing the quote, emitting an escaped
    /// quote, and reopening: <c>'</c> becomes <c>'\''</c>. Double quotes would leave <c>$</c>,
    /// <c>`</c> and <c>\</c> live, which is three more things to be right about forever.
    /// </remarks>
    public static string Quote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    }

    /// <summary>Whether <paramref name="name" /> is a usable environment variable name.</summary>
    /// <param name="name">The candidate name.</param>
    /// <exception cref="ArgumentNullException"><paramref name="name" /> is null.</exception>
    /// <remarks>
    /// Checked rather than quoted, because quoting does not help here. A name is passed to
    /// <c>env</c> as part of a single <c>NAME=VALUE</c> word, and <c>env</c> splits that on the
    /// first <c>=</c> itself - so a name containing an <c>=</c> silently sets a different variable
    /// to a different value, no matter how well the word is quoted for the shell. Refusing is the
    /// only correct answer.
    /// </remarks>
    public static bool IsValidEnvironmentName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (name.Length == 0 || (!char.IsAsciiLetter(name[0]) && name[0] != '_'))
        {
            return false;
        }

        foreach (var character in name)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character != '_')
            {
                return false;
            }
        }

        return true;
    }
}
