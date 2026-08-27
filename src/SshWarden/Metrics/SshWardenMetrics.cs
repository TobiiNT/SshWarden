using System.Diagnostics.Metrics;

using SshWarden.Audit;
using SshWarden.Authorization;
using SshWarden.Configuration;

namespace SshWarden.Metrics;

/// <summary>The six instruments this server publishes, and the one place a measurement is taken.</summary>
/// <remarks>
/// <para>
/// Built on <c>System.Diagnostics.Metrics</c> rather than on a counter of our own, because that is
/// the seam: a deployment already running OpenTelemetry can subscribe a listener to this meter by
/// name and ship the same numbers somewhere else, without the endpoint in this repository being
/// involved at all. What this project hand-writes is the Prometheus exposition, which .NET does not
/// have - not the instruments, which it does.
/// </para>
/// <para>
/// <strong>The surface is exactly six and it is closed.</strong> That is what makes writing the
/// exposition by hand a reasonable amount of work rather than an open-ended one, and it is why the
/// bucket boundaries below can be chosen per instrument instead of configured.
/// </para>
/// </remarks>
public sealed class SshWardenMetrics : IDisposable
{
    /// <summary>The meter name, which is what a listener subscribes to.</summary>
    public const string MeterName = "SshWarden";

    /// <summary>The label value standing in for anything outside the known set.</summary>
    /// <remarks>
    /// <para>
    /// <strong>Cardinality is a memory budget somebody else can spend.</strong> A caller names the
    /// host on every call, and a refused call names a host that does not exist - so putting that
    /// string on a label straight would let one caller mint one series per request until the
    /// process runs out of memory, using nothing but calls this server correctly refuses.
    /// </para>
    /// <para>
    /// Answered by clamping at the point the label is chosen rather than by a cap downstream: every
    /// label value here comes from a closed set - the declared hosts, <see cref="ToolNames.All" />,
    /// <see cref="AuthorizationRefusal.All" />, three outcomes - and anything else becomes this.
    /// A cap would be the other design, and it drops series silently, which reads as "nothing
    /// happened" exactly when something did.
    /// </para>
    /// </remarks>
    public const string Unknown = "unknown";

    /// <summary>Bucket boundaries for command duration, in seconds.</summary>
    /// <remarks>
    /// The last finite boundary is 900, which is the default ceiling on
    /// <c>ssh.max_timeout_sec</c> - so anything falling in <c>+Inf</c> means a command outlived the
    /// ceiling that was supposed to stop it, which is worth seeing rather than worth bucketing.
    /// </remarks>
    public static readonly double[] DurationBuckets =
        [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900];

    /// <summary>Bucket boundaries for output size, in bytes.</summary>
    /// <remarks>
    /// 65536 is a boundary rather than a value between two, and that is the whole point of this
    /// instrument: docs/DESIGN.md §4.5 left "is the 64 KiB cap right" open, and it is answerable
    /// only by reading how much of the distribution sits above that exact line. Measured on what
    /// came off the wire, before the cut - measuring after it would report the cap back to itself.
    /// </remarks>
    public static readonly double[] OutputByteBuckets =
        [1024, 4096, 16384, 65536, 262144, 1048576, 4194304];

    private readonly Meter _meter;
    private readonly Counter<long> _commands;
    private readonly Histogram<double> _duration;
    private readonly Histogram<long> _outputBytes;
    private readonly Counter<long> _truncated;
    private readonly Counter<long> _denied;
    private readonly HostRegistry _hosts;

    /// <summary>Builds the instruments.</summary>
    /// <param name="hosts">The declared hosts, which bound the <c>host</c> label.</param>
    /// <param name="liveConnections">Reads the pool's current size at scrape time.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public SshWardenMetrics(HostRegistry hosts, Func<int> liveConnections)
    {
        ArgumentNullException.ThrowIfNull(hosts);
        ArgumentNullException.ThrowIfNull(liveConnections);

        _hosts = hosts;
        _meter = new Meter(MeterName);

        _commands = _meter.CreateCounter<long>(
            "sshwarden_commands_total",
            unit: null,
            description: "Calls this server handled, by host and outcome.");

        _duration = _meter.CreateHistogram<double>(
            "sshwarden_command_duration_seconds",
            unit: "s",
            description: "How long the command on the target took.");

        _outputBytes = _meter.CreateHistogram<long>(
            "sshwarden_output_bytes",
            unit: "By",
            description: "Bytes the target produced, measured before masking and before the cut.");

        _truncated = _meter.CreateCounter<long>(
            "sshwarden_output_truncated_total",
            unit: null,
            description: "Calls whose output was over the budget and had its middle cut.");

        _denied = _meter.CreateCounter<long>(
            "sshwarden_denied_total",
            unit: null,
            description: "Refusals, by tool and by the rule that refused.");

        // Observable, so the number is read when somebody asks rather than pushed on every change.
        // A gauge that is written from wherever a connection happens to open is a gauge that drifts
        // the first time a path forgets to decrement it.
        _meter.CreateObservableGauge(
            "sshwarden_pool_connections_active",
            liveConnections,
            unit: null,
            description: "SSH connections currently open in the pool.");
    }

    /// <summary>Takes every measurement one audit record carries.</summary>
    /// <param name="record">The record.</param>
    /// <exception cref="ArgumentNullException"><paramref name="record" /> is null.</exception>
    /// <remarks>
    /// <para>
    /// Driven off the audit record rather than off the tools, and that is deliberate: the audit log
    /// is already the thing that cannot miss a call, so metrics taken from the same object cannot
    /// disagree with it. A tool that forgets to increment a counter is a tool nobody notices; a tool
    /// that forgets to write a record is a hole somebody is already looking for.
    /// </para>
    /// <para>
    /// Nothing here reads <c>sub</c>, <c>gid</c>, <c>jti</c>, <c>command</c> or <c>workdir</c>, and
    /// that is a rule rather than an omission - docs/DESIGN.md §4.7 names those as the fields
    /// whose value sets are unbounded. They stay in the JSON body, where a query filters them
    /// without indexing them.
    /// </para>
    /// </remarks>
    public void Observe(AuditRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        _commands.Add(
            1,
            new KeyValuePair<string, object?>("host", HostLabel(record.Host)),
            new KeyValuePair<string, object?>("outcome", Outcome(record)));

        if (record.DurationMs is { } milliseconds)
        {
            _duration.Record(milliseconds / 1000.0);
        }

        if (record.StdoutBytes is { } bytes)
        {
            _outputBytes.Record(bytes);
        }

        if (record.OutputTruncated == true)
        {
            _truncated.Add(1);
        }

        if (record.Decision == AuditDecisions.Deny)
        {
            _denied.Add(
                1,
                new KeyValuePair<string, object?>("tool", ToolLabel(record.Tool)),
                new KeyValuePair<string, object?>("rule", RuleLabel(record.DeniedBy)));
        }
    }

    /// <summary>Which of the three outcomes a record describes.</summary>
    /// <remarks>
    /// Three values, and the third is why <see cref="AuditRecord.Error" /> exists. Without it a call
    /// that was allowed and then failed - the SSH connection dropped, the target never answered -
    /// looked exactly like a call with nothing to report an exit code about, so the one thing an
    /// operator sets an alert on was the one thing the numbers could not say.
    /// </remarks>
    public static string Outcome(AuditRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (record.Decision == AuditDecisions.Deny)
        {
            return "deny";
        }

        return record.Error is not null || record.ExitCode is not (null or 0) ? "fail" : "ok";
    }

    /// <summary>Disposes the meter.</summary>
    public void Dispose() => _meter.Dispose();

    private string HostLabel(string? host)
        => host is not null && _hosts.Find(host) is not null ? host : Unknown;

    private static string ToolLabel(string tool)
        => ToolNames.All.Contains(tool) ? tool : Unknown;

    private static string RuleLabel(string? rule)
        => rule is not null && AuthorizationRefusal.All.Contains(rule) ? rule : Unknown;
}
