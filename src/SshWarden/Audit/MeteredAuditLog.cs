using SshWarden.Metrics;

namespace SshWarden.Audit;

/// <summary>An audit log that takes this server's measurements on the way past.</summary>
/// <remarks>
/// <para>
/// A decorator rather than a call added to every tool, because the property worth having is that
/// the numbers and the log cannot disagree. Every call writes exactly one record - the tool when it
/// completes, the gate when it refuses or when something failed - so a metric derived from the
/// record stream is derived from the same stream an operator is reading, and "the dashboard says
/// forty and the log has thirty-nine lines" cannot happen.
/// </para>
/// <para>
/// It writes to the log first. If taking a measurement ever threw, the record would already be
/// durable; the other order would lose the evidence to protect the statistic.
/// </para>
/// </remarks>
public sealed class MeteredAuditLog : IAuditLog
{
    private readonly IAuditLog _inner;
    private readonly SshWardenMetrics _metrics;

    /// <summary>Wraps a log.</summary>
    /// <param name="inner">Where records actually go.</param>
    /// <param name="metrics">The instruments.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public MeteredAuditLog(IAuditLog inner, SshWardenMetrics metrics)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(metrics);

        _inner = inner;
        _metrics = metrics;
    }

    /// <inheritdoc />
    public void Write(AuditRecord record)
    {
        _inner.Write(record);
        _metrics.Observe(record);
    }
}
