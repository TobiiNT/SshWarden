namespace SshWarden.Configuration;

/// <summary>
/// The config file could not be turned into a configuration this process will run under.
/// </summary>
/// <remarks>
/// <para>
/// Carries <strong>every</strong> problem found, not the first one. A loader that stops at the
/// first mistake turns fixing a config file into one restart per line, and the operator doing that
/// is usually the one who has just been paged. Boltway's startup validation was built the same way
/// for the same reason.
/// </para>
/// <para>
/// Nothing here quotes a credential. The problems name keys and rules, never values, because this
/// message is printed to a terminal, captured by an init system and shipped to whatever collects
/// the host's logs.
/// </para>
/// </remarks>
public sealed class SshWardenConfigurationException : Exception
{
    /// <summary>Builds the exception from the problems found.</summary>
    /// <param name="path">The config file that was read.</param>
    /// <param name="problems">Every problem, in the order they were found.</param>
    /// <exception cref="ArgumentException"><paramref name="problems" /> is empty.</exception>
    public SshWardenConfigurationException(string path, IReadOnlyList<string> problems)
        : base(Describe(path, problems))
    {
        Path = path;
        Problems = problems;
    }

    /// <summary>The config file that was read.</summary>
    public string Path { get; } = string.Empty;

    /// <summary>Every problem found, in the order they were found.</summary>
    public IReadOnlyList<string> Problems { get; } = [];

    private static string Describe(string path, IReadOnlyList<string> problems)
    {
        ArgumentNullException.ThrowIfNull(problems);

        if (problems.Count == 0)
        {
            throw new ArgumentException(
                "An empty problem list would produce a refusal that does not say what it refused.",
                nameof(problems));
        }

        var lines = problems.Select(problem => "  - " + problem);
        return $"SshWarden will not start: {problems.Count} problem(s) in '{path}'."
            + Environment.NewLine
            + string.Join(Environment.NewLine, lines);
    }
}
