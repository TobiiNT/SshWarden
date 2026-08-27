namespace SshWarden.Ssh;

/// <summary>What running one command produced.</summary>
public sealed class CommandOutcome
{
    /// <summary>The command line that was sent, after SshWarden built it.</summary>
    /// <remarks>
    /// What actually ran, not what the caller typed. The two differ - a working directory, an
    /// environment and a timeout wrapper are added - and the audit record needs the one the host
    /// saw, because that is the one somebody will be trying to reproduce.
    /// </remarks>
    public required string CommandLine { get; init; }

    /// <summary>The exit status, or <see langword="null" /> if the command reported none.</summary>
    /// <remarks>
    /// <para>
    /// A command stopped by the remote timeout reports <c>124</c>, which is a real answer and much
    /// better than null: it says the command was killed for running too long, and it distinguishes
    /// that from a command that failed on its own.
    /// </para>
    /// <para>
    /// Null means the channel ended without a status - the connection dropped, or the process was
    /// killed by a signal. Never conflate it with zero.
    /// </para>
    /// </remarks>
    public int? ExitCode { get; init; }

    /// <summary>Standard output.</summary>
    public required string Stdout { get; init; }

    /// <summary>Standard error.</summary>
    public required string Stderr { get; init; }

    /// <summary>How many bytes of standard output the host produced.</summary>
    /// <remarks>
    /// Measured on what arrived, before anything in SshWarden has touched it. The order is fixed -
    /// measure, then redact, then cut - and measuring anywhere later reports a number about
    /// SshWarden's own processing rather than about what ran.
    /// </remarks>
    public required long StdoutBytes { get; init; }

    /// <summary>How long the call took, end to end.</summary>
    public required long DurationMs { get; init; }
}
