using System.Text.Json.Serialization;

namespace SshWarden.Audit;

/// <summary>One line of the audit log.</summary>
/// <remarks>
/// <para>
/// The schema of docs/DESIGN.md §4.2, and its design test is the thing to keep in mind when changing
/// it: <em>read one record, look at nothing else, and understand what happened.</em> A field that
/// only makes sense next to another record is a field that fails it.
/// </para>
/// <para>
/// <strong>Four fields are here that §4.2's table does not list</strong>, each added under that same
/// test rather than silently. <see cref="SshUser" />, because a record saying a command ran without
/// saying which unix account ran it leaves out the only boundary that actually held - everything
/// else is a refusal inside a process the target host does not trust. <see cref="AllowedBy" />,
/// because §4.2 gives a refused call a rule id and gives an allowed one nothing, so "which rule let
/// this through" was answerable for the calls that did not happen and not for the calls that did.
/// And <see cref="Selector" /> with <see cref="ResolvedPath" />, because a path the caller named and
/// the file the target actually opened are two different facts whenever a symlink is involved -
/// which is the case the path gate exists for, and the one where a record carrying only one of them
/// says nothing useful.
/// </para>
/// <para>
/// JSON names are snake_case and matched character-for-character by whatever ships these lines. They
/// are part of the wire, not a style choice: renaming one silently empties every dashboard panel
/// built on it.
/// </para>
/// </remarks>
public sealed class AuditRecord
{
    /// <summary>This record's identifier.</summary>
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>What kind of record this is.</summary>
    /// <remarks>
    /// Jobs share this log with commands rather than getting their own channel, and a refused call
    /// is a record too - "an agent went for production and was stopped" is the most valuable line
    /// on the dashboard, and an earlier schema had nowhere to put it.
    /// </remarks>
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    /// <summary>When the operation started, with an offset.</summary>
    [JsonPropertyName("started_at")]
    public required DateTimeOffset StartedAt { get; init; }

    /// <summary>Who called. From the authenticator, never inferred.</summary>
    [JsonPropertyName("sub")]
    public required string Subject { get; init; }

    /// <summary>Which client called, verbatim as the token gave it.</summary>
    [JsonPropertyName("client_id")]
    public required string ClientId { get; init; }

    /// <summary>Which grant - what groups a run of calls into one working session.</summary>
    /// <remarks>
    /// Stable across a refresh, which is why this and not the token identifier: grouping by the
    /// token would split one long session into a new group every time it renewed.
    /// </remarks>
    [JsonPropertyName("gid")]
    public required string GrantId { get; init; }

    /// <summary>Which token. Kept so a revocation can be traced to the calls that token made.</summary>
    [JsonPropertyName("jti")]
    public required string TokenId { get; init; }

    /// <summary>Which tool was called.</summary>
    [JsonPropertyName("tool")]
    public required string Tool { get; init; }

    /// <summary><c>allow</c> or <c>deny</c>.</summary>
    [JsonPropertyName("decision")]
    public required string Decision { get; init; }

    /// <summary>
    /// The identifier of the rule that refused, when <see cref="Decision" /> is <c>deny</c>.
    /// </summary>
    /// <remarks>
    /// An identifier, never a message. A message is prose somebody will improve, and every query
    /// built on it breaks silently when they do.
    /// </remarks>
    [JsonPropertyName("denied_by")]
    public string? DeniedBy { get; init; }

    /// <summary>
    /// The identifier of the grant that allowed the call, when <see cref="Decision" /> is
    /// <c>allow</c>.
    /// </summary>
    [JsonPropertyName("allowed_by")]
    public string? AllowedBy { get; init; }

    /// <summary>The target host.</summary>
    [JsonPropertyName("host")]
    public string? Host { get; init; }

    /// <summary>The unix account the command ran as.</summary>
    [JsonPropertyName("ssh_user")]
    public string? SshUser { get; init; }

    /// <summary>What the caller named - a file path, or a service unit.</summary>
    /// <remarks>
    /// Verbatim, as it was written, before normalizing and before the target resolved anything.
    /// Null for a tool that names no resource inside the host.
    /// </remarks>
    [JsonPropertyName("selector")]
    public string? Selector { get; init; }

    /// <summary>What <see cref="Selector" /> turned out to be on the target.</summary>
    /// <remarks>
    /// <para>
    /// Null for a unit, and null when resolution did not happen or did not succeed. When it differs
    /// from <see cref="Selector" />, something on the target pointed the caller elsewhere - which
    /// is either directories that are not what the rules assume, or somebody finding out what is
    /// reachable. Without both halves recorded, a refusal saying the path escaped its grant names a
    /// rule and gives nobody anything to act on.
    /// </para>
    /// </remarks>
    [JsonPropertyName("resolved_path")]
    public string? ResolvedPath { get; init; }

    /// <summary>The working directory. Always a value for a command, never null.</summary>
    /// <remarks>
    /// Explicit even when it is the account's default, because the whole reason there is no
    /// persistent shell is that a record has to be readable on its own. "Wherever the last command
    /// left it" is not readable on its own.
    /// </remarks>
    [JsonPropertyName("workdir")]
    public string? Workdir { get; init; }

    /// <summary>The command that ran.</summary>
    [JsonPropertyName("command")]
    public string? Command { get; init; }

    /// <summary>
    /// The exit status, or <see langword="null" /> when the command did not report one.
    /// </summary>
    /// <remarks>
    /// Null means it timed out or is still running - not zero. A timeout recorded as success is the
    /// single most misleading value this file could carry.
    /// </remarks>
    [JsonPropertyName("exit_code")]
    public int? ExitCode { get; init; }

    /// <summary>How long the operation took.</summary>
    [JsonPropertyName("duration_ms")]
    public long? DurationMs { get; init; }

    /// <summary>How many bytes of output the command produced.</summary>
    /// <remarks>
    /// Measured on what came off the wire, before anything else touches it. The order matters and
    /// is fixed: measure, then redact, then truncate. Truncating first lets a secret straddling the
    /// cut escape the patterns that would have caught it, and measuring after either one reports a
    /// number about SshWarden's processing rather than about what the host produced.
    /// </remarks>
    [JsonPropertyName("stdout_bytes")]
    public long? StdoutBytes { get; init; }

    /// <summary>Why the call did not complete, when it was allowed and then failed.</summary>
    /// <remarks>
    /// <para>
    /// Null when nothing went wrong, which is what makes it readable: an operator scanning for
    /// trouble greps for the field's presence rather than for the absence of something else.
    /// </para>
    /// <para>
    /// It exists because there was no way to tell two very different records apart. A
    /// <c>list_changes</c> that worked and a <c>run</c> whose connection dropped both wrote
    /// <c>decision: allow</c> with a null exit code, so the log said the same thing about a call
    /// that succeeded and a call that never reached the target - and the one number an operator
    /// alerts on could not be computed from it.
    /// </para>
    /// <para>
    /// Masked like every other free text here. A connection failure renders the target's address
    /// and, in some libraries, the credential it tried.
    /// </para>
    /// </remarks>
    [JsonPropertyName("error")]
    public string? Error { get; init; }

    /// <summary>Which job this record is about, for a record of type <c>job</c>.</summary>
    /// <remarks>
    /// Jobs share this log with commands rather than getting a channel of their own, so the
    /// identifier is what ties a start, its polls and its kill together into one story.
    /// </remarks>
    [JsonPropertyName("job_id")]
    public string? JobId { get; init; }

    /// <summary>What changed under the watched paths while this ran.</summary>
    /// <remarks>
    /// An empty array rather than null when nothing changed, so a consumer can tell "nothing
    /// changed" from a record that predates change detection.
    /// </remarks>
    [JsonPropertyName("changes")]
    public IReadOnlyList<Changes.FileChange> Changes { get; init; } = [];

    /// <summary>How much time the sweeper actually looked at, in milliseconds.</summary>
    /// <remarks>
    /// <para>
    /// Not the command's duration - the span between the sweep before it started and the last sweep
    /// since. A command that finished between two sweeps has a window narrower than itself, and
    /// zero means no sweep covered it at all. Saying so is the point: without this field, an empty
    /// <see cref="Changes" /> list would read as "nothing changed" when it means "nothing was
    /// looked at".
    /// </para>
    /// </remarks>
    [JsonPropertyName("changes_window_ms")]
    public long? ChangesWindowMs { get; init; }

    /// <summary>
    /// <c>exclusive</c> when nothing else was running on that host during the window, or
    /// <c>overlapping:N</c>.
    /// </summary>
    /// <remarks>
    /// Exact per-command attribution does not exist when commands overlap. An <c>exclusive</c>
    /// record's changes are attribution; an <c>overlapping</c> record's are a list of candidates.
    /// Both are useful and they are not the same claim.
    /// </remarks>
    [JsonPropertyName("changes_confidence")]
    public string? ChangesConfidence { get; init; }

    /// <summary>Whether the output the caller received was cut short.</summary>
    /// <remarks>
    /// The agent must be able to tell. Without it, a conclusion gets drawn from a partial answer
    /// with nothing marking it partial.
    /// </remarks>
    [JsonPropertyName("output_truncated")]
    public bool? OutputTruncated { get; init; }
}

/// <summary>The values of <see cref="AuditRecord.Type" />.</summary>
public static class AuditRecordTypes
{
    /// <summary>A command that ran to completion, or tried to.</summary>
    public const string Command = "command";

    /// <summary>A job on the target host that outlives the call.</summary>
    public const string Job = "job";

    /// <summary>An authorization decision with no operation behind it - a refusal.</summary>
    public const string Decision = "decision";
}

/// <summary>The values of <see cref="AuditRecord.Decision" />.</summary>
public static class AuditDecisions
{
    /// <summary>The call was authorized.</summary>
    public const string Allow = "allow";

    /// <summary>The call was refused.</summary>
    public const string Deny = "deny";
}
