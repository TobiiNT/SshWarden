using System.ComponentModel;
using System.Text.Json.Serialization;

using ModelContextProtocol;
using ModelContextProtocol.Server;

using SshWarden.Audit;
using SshWarden.Authorization;
using SshWarden.Changes;
using SshWarden.Configuration;

namespace SshWarden.Mcp.Tools;

/// <summary>The <c>list_changes</c> tool.</summary>
/// <remarks>
/// <para>
/// A query against the timeline the background sweeper fills, not a scan of its own. That is what
/// makes "what changed in the last ten minutes" answerable at all: a snapshot taken around each
/// command has no baseline for a question about a span of time.
/// </para>
/// <para>
/// Gated on the host and nothing else. Which paths are watched is the operator's choice in
/// <c>[watch]</c>, and putting a path there is a decision that its change events are visible to
/// anyone who may list changes on that host - the paths, not their contents.
/// </para>
/// </remarks>
[McpServerToolType]
public sealed class ChangesTool
{
    /// <summary>How far back <c>list_changes</c> looks when the caller does not say.</summary>
    public const int DefaultMinutes = 10;

    private readonly CallerContext _caller;
    private readonly GrantTable _grants;
    private readonly HostRegistry _hosts;
    private readonly ChangeTimeline _timeline;
    private readonly SweepProblems _problems;
    private readonly WatchSection _watch;
    private readonly IAuditLog _audit;

    /// <summary>Builds the tool.</summary>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public ChangesTool(
        CallerContext caller,
        GrantTable grants,
        HostRegistry hosts,
        ChangeTimeline timeline,
        SweepProblems problems,
        WatchSection watch,
        IAuditLog audit)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentNullException.ThrowIfNull(timeline);
        ArgumentNullException.ThrowIfNull(problems);
        ArgumentNullException.ThrowIfNull(watch);
        ArgumentNullException.ThrowIfNull(audit);

        _caller = caller;
        _grants = grants;
        _hosts = hosts;
        _timeline = timeline;
        _problems = problems;
        _watch = watch;
        _audit = audit;
    }

    /// <summary>Lists what changed under the watched paths of a host.</summary>
    /// <param name="host">Which machine.</param>
    /// <param name="sinceMinutes">How far back to look.</param>
    /// <exception cref="McpException">The call cannot be carried out.</exception>
    [McpServerTool(Name = "list_changes")]
    [Description(
        "List files under this deployment's watched paths that were created, modified or deleted "
        + "on a host recently. Changes are noticed by a periodic sweep, so the resolution is the "
        + "sweep interval: a change made and undone between two sweeps is not seen, and neither is "
        + "one that leaves size, modification time and inode alone.")]
    public ListChangesResult ListChanges(
        [Description("The host, as named in this deployment's configuration.")]
        string host,
        [Description("How many minutes back to look.")]
        int? sinceMinutes = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var startedAt = DateTimeOffset.UtcNow;
        var caller = _caller.Require();

        var decision = _grants.AuthorizeHost(caller, ToolNames.ListChanges, host);
        if (!decision.IsAllowed)
        {
            _audit.Write(AuditRecordFactory.Refusal(
                caller, ToolNames.ListChanges, decision, startedAt, host));

            throw new McpException(decision.Detail!);
        }

        var target = _hosts.Find(host)
            ?? throw new McpException(
                $"SshWarden has no configuration for host '{host}'.");

        var window = TimeSpan.FromMinutes(Math.Clamp(
            sinceMinutes ?? DefaultMinutes,
            1,
            _watch.RetentionMinutes));

        var changes = _timeline.Since(target.Name, window, startedAt);
        var lastSweep = _timeline.LastSweep(target.Name);

        _audit.Write(new AuditRecord
        {
            Id = AuditRecordFactory.NewId(),
            Type = AuditRecordTypes.Command,
            StartedAt = startedAt,
            Subject = caller.Subject,
            ClientId = caller.ClientId,
            GrantId = caller.GrantId,
            TokenId = caller.TokenId,
            Tool = ToolNames.ListChanges,
            Decision = AuditDecisions.Allow,
            AllowedBy = decision.Grant!.Id,
            Host = target.Name,
            SshUser = decision.Grant.SshUser,
            Changes = changes,
        });

        return new ListChangesResult
        {
            Changes = changes,
            Host = target.Name,
            SinceMinutes = (int)window.TotalMinutes,
            LastSweepAt = lastSweep,

            // The difference between "nothing changed" and "nothing was looked at", which an empty
            // list on its own cannot carry. A host nobody has connected to since this process
            // started has never been swept, and answering that with a confident empty list would be
            // the same lie the whole change-detection design is arranged to avoid.
            Notes = Notes(target.Name, lastSweep),
        };
    }

    private List<string> Notes(string host, DateTimeOffset? lastSweep)
    {
        var notes = new List<string>();

        if (_watch.Paths.Count == 0)
        {
            notes.Add(
                "Change detection is off in this deployment: no watched paths are configured, so "
                    + "this list is empty regardless of what happened.");
            return notes;
        }

        if (lastSweep is null)
        {
            notes.Add(
                "This host has not been swept yet. Sweeps only run while a connection to it is "
                    + "already open, so a host nothing has talked to has no history here - an empty "
                    + "list means nothing was looked at, not that nothing changed.");
        }

        notes.AddRange(_problems.For(host));

        return notes;
    }
}

/// <summary>What <c>list_changes</c> returns.</summary>
public sealed class ListChangesResult
{
    /// <summary>What changed, oldest first.</summary>
    [JsonPropertyName("changes")]
    public required IReadOnlyList<FileChange> Changes { get; init; }

    /// <summary>The host.</summary>
    [JsonPropertyName("host")]
    public required string Host { get; init; }

    /// <summary>How far back this looked, after clamping.</summary>
    [JsonPropertyName("since_minutes")]
    public required int SinceMinutes { get; init; }

    /// <summary>When this host was last swept, or null if it never has been.</summary>
    /// <remarks>
    /// Returned so a caller can tell how stale the answer is without being told. A list that ends
    /// four minutes ago and a list that ends now are different answers.
    /// </remarks>
    [JsonPropertyName("last_sweep_at")]
    public DateTimeOffset? LastSweepAt { get; init; }

    /// <summary>Anything about this answer the list itself does not say.</summary>
    [JsonPropertyName("notes")]
    public required IReadOnlyList<string> Notes { get; init; }
}
