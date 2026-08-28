namespace SshWarden.Output;

/// <summary>What happened to a piece of output that the output itself does not say.</summary>
/// <remarks>
/// <para>
/// One builder, shared by every tool that hands output back. <c>run</c> carried these two rules
/// alone: <c>read_file</c>, <c>tail_log</c> and <c>poll_job</c> ran the same pipeline, computed the
/// same two flags, and dropped them - so the tool whose whole job is reading a file was the one
/// with nowhere to say that masking had not finished, and <c>tail_log</c> returned a whole log to a
/// caller who had asked for a subset and was told nothing.
/// </para>
/// <para>
/// <strong>Shared rather than copied, for the reason <see cref="Ssh.ShellQuoting" /> is.</strong>
/// Two builders that say almost the same thing is how a caller comes to be warned on one path and
/// not on another, and the difference only shows up on the output somebody needed the warning for.
/// </para>
/// </remarks>
public static class OutputNotes
{
    /// <summary>What a caller is told when masking ran out of time.</summary>
    /// <remarks>
    /// A constant rather than a literal at each call site. This sentence is the whole of what a
    /// caller has to act on, and one that differs by a word between two tools is one nothing
    /// downstream can match on.
    /// </remarks>
    public const string RedactionIncomplete =
        "Secret masking did not finish on this output, so it may still contain credentials. "
            + "Treat it as unmasked.";

    /// <summary>Everything worth saying about <paramref name="outputs" />, or an empty list.</summary>
    /// <param name="outputs">The prepared outputs this result is built from.</param>
    /// <exception cref="ArgumentNullException"><paramref name="outputs" /> is null.</exception>
    /// <remarks>
    /// Empty in the ordinary case, and that matters as much as the notes do: a list that carries
    /// something whatever happened is not a signal.
    /// </remarks>
    public static IReadOnlyList<string> For(params PreparedOutput[] outputs)
    {
        ArgumentNullException.ThrowIfNull(outputs);

        var notes = new List<string>();

        // A filter that did not run is the case most worth saying out loud: the caller asked for a
        // subset, got everything, and would otherwise read the extra lines as matches.
        foreach (var output in outputs)
        {
            if (output.FilterProblem is { } problem && !notes.Contains(problem, StringComparer.Ordinal))
            {
                notes.Add(problem);
            }
        }

        // Once, however many streams it happened on. Two identical sentences read as two separate
        // problems, and the remedy for both is the same one.
        foreach (var output in outputs)
        {
            if (output.RedactionIncomplete)
            {
                notes.Add(RedactionIncomplete);
                break;
            }
        }

        return notes;
    }
}
