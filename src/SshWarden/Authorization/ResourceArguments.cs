namespace SshWarden.Authorization;

/// <summary>Which argument of each tool names a resource the gate decides on.</summary>
/// <remarks>
/// <para>
/// The classification rule of docs/DESIGN.md §6.5.1: an argument can be gated when it
/// <strong>identifies a resource</strong> - a discrete value, comparable exactly, that SshWarden
/// dereferences itself. It cannot be gated when it <strong>carries behaviour</strong> - content the
/// target host interprets.
/// </para>
/// <para>
/// So <c>run</c> gates on <c>host</c> and on nothing else. Not <c>cmd</c>: deciding what a shell
/// will do with a string is not answerable at the string level, and every attempt reduces to a list
/// of program names somebody else has already published four hundred ways around. Not <c>workdir</c>
/// either, and that one is worth stating because it looks gateable - a command is free to
/// <c>cd</c> anywhere, so a directory selector catches mistakes and cleans up the log while
/// enforcing nothing. Describing it as a boundary would manufacture the false confidence this
/// design exists to avoid.
/// </para>
/// <para>
/// These names are matched against the raw JSON of a call, so a name here that is not in the tool's
/// input schema is a gate that never fires and never says so. That is checked at startup rather
/// than trusted - see the tool registry check.
/// </para>
/// </remarks>
public static class ResourceArguments
{
    /// <summary>The argument naming the host, for tools that take one.</summary>
    public const string Host = "host";

    /// <summary>The argument naming the file, on the tool that reads one.</summary>
    public const string Path = "path";

    /// <summary>The argument naming either a file or a service unit, on the tool that tails one.</summary>
    public const string UnitOrPath = "unitOrPath";

    /// <summary>The argument naming a job, on the two tools that act on one.</summary>
    public const string JobId = "jobId";

    /// <summary>
    /// For each tool, the argument that names the host it acts on - or absent when the tool takes
    /// no host.
    /// </summary>
    /// <remarks>
    /// <c>poll_job</c> and <c>kill_job</c> are absent here on purpose: their resource reference is a
    /// job id, which is <em>indirect</em>, and it is handled by
    /// <see cref="JobArgumentByTool" /> instead. They still end up gated on a host - the one the job
    /// runs on, which the identifier is resolved to first.
    /// </remarks>
    public static readonly IReadOnlyDictionary<string, string> HostArgumentByTool =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["run"] = Host,
            ["read_file"] = Host,
            ["tail_log"] = Host,
            ["list_changes"] = Host,
            ["start_job"] = Host,
        };

    /// <summary>
    /// For each tool, the argument naming the file or unit it acts on - or absent when the tool
    /// names no resource inside the host.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>run</c> and <c>start_job</c> are absent, and that is the classification rule rather than
    /// an omission: their command is behaviour, not a resource, and their working directory is not
    /// a boundary because a command can change directory freely. For those two the host is the
    /// whole of the gate.
    /// </para>
    /// <para>
    /// A path here is decided twice - once as the caller wrote it, and once as the target resolved
    /// it. Only the second means anything against a symlink, and only the first can be done before
    /// touching the machine.
    /// </para>
    /// </remarks>
    public static readonly IReadOnlyDictionary<string, string> PathArgumentByTool =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["read_file"] = Path,
            ["tail_log"] = UnitOrPath,
        };

    /// <summary>
    /// For each tool, the argument naming a job - which stands for a host and an owner rather than
    /// carrying either.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The most dangerous argument shape in the whole surface, because it looks like the least. A
    /// job identifier contains no host, so a gate that only knows how to check hosts sees nothing
    /// to check and lets everything through - and what goes through is one caller reading another's
    /// production output and signalling their processes.
    /// </para>
    /// <para>
    /// Resolving it happens in the policy rather than in the tool body. A tool that checks its own
    /// arguments is a tool somebody can forget to write the check into; the gate runs for every
    /// call whether or not the tool remembered.
    /// </para>
    /// </remarks>
    public static readonly IReadOnlyDictionary<string, string> JobArgumentByTool =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["poll_job"] = JobId,
            ["kill_job"] = JobId,
        };

    /// <summary>Whether a caller's selector names a path rather than a service unit.</summary>
    /// <param name="value">The argument as the caller wrote it.</param>
    /// <exception cref="ArgumentNullException"><paramref name="value" /> is null.</exception>
    /// <remarks>
    /// A leading slash and nothing else. It is a rule somebody can hold in their head while reading
    /// a config file, which matters more here than cleverness: the alternative - guessing from a
    /// <c>.service</c> suffix, or trying both - would make which selector applies depend on
    /// something the reader has to work out.
    /// </remarks>
    public static bool NamesAPath(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.StartsWith('/');
    }
}
