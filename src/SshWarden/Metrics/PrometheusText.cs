using System.Globalization;
using System.Text;

namespace SshWarden.Metrics;

/// <summary>Writes a snapshot as Prometheus text exposition, version 0.0.4.</summary>
/// <remarks>
/// <para>
/// The one piece .NET does not have. <c>System.Diagnostics.Metrics</c> is an instrument API and
/// stops at delivering measurements; turning a distribution into <c>_bucket</c>, <c>_sum</c> and
/// <c>_count</c> lines is somebody's job and here it is this file's.
/// </para>
/// <para>
/// The format is small but it has three edges that bite. Buckets are <strong>cumulative</strong>,
/// so a value in the first bucket counts in every bucket after it - written as "at most this" rather
/// than "between these", and getting it wrong produces a histogram that looks plausible and answers
/// every quantile wrong. <c>le</c> is a label like any other and shares one set of braces with the
/// rest. And numbers are formatted invariantly, because a machine on a Vietnamese locale would
/// otherwise write <c>0,05</c> and no scraper would take it.
/// </para>
/// </remarks>
public static class PrometheusText
{
    /// <summary>The content type a scraper expects.</summary>
    public const string ContentType = "text/plain; version=0.0.4; charset=utf-8";

    /// <summary>Renders the snapshot.</summary>
    /// <param name="snapshot">What to render.</param>
    /// <exception cref="ArgumentNullException"><paramref name="snapshot" /> is null.</exception>
    public static string Write(MetricsSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var text = new StringBuilder();

        // Ordered by name so two scrapes of an unchanged process produce the same bytes. Nothing
        // requires it; it makes a diff of two scrapes readable, which is what somebody does when
        // they are trying to work out what moved.
        foreach (var instrument in snapshot.Instruments.OrderBy(i => i.Name, StringComparer.Ordinal))
        {
            var kind = instrument.Kind switch
            {
                InstrumentKind.Counter => "counter",
                InstrumentKind.Gauge => "gauge",
                _ => "histogram",
            };

            text.Append("# HELP ").Append(instrument.Name).Append(' ').Append(EscapeHelp(instrument.Help)).Append('\n');
            text.Append("# TYPE ").Append(instrument.Name).Append(' ').Append(kind).Append('\n');

            switch (instrument.Kind)
            {
                case InstrumentKind.Counter:
                    WriteSimple(text, instrument.Name, snapshot.Counters, value => Number(value));
                    break;

                case InstrumentKind.Gauge:
                    WriteSimple(text, instrument.Name, snapshot.Gauges, Number);
                    break;

                default:
                    WriteHistogram(text, instrument.Name, snapshot);
                    break;
            }
        }

        return text.ToString();
    }

    /// <summary>Escapes a value for a label, per the exposition format.</summary>
    /// <param name="value">The value.</param>
    /// <exception cref="ArgumentNullException"><paramref name="value" /> is null.</exception>
    /// <remarks>
    /// Three characters and no more: backslash, double quote, newline. Everything reaching a label
    /// here is already clamped to a closed set by <see cref="SshWardenMetrics" />, so this should
    /// never have anything to do - it is here because "should never" and "cannot" are different
    /// words, and an unescaped quote does not corrupt one line, it corrupts the parse from that
    /// point on.
    /// </remarks>
    public static string EscapeLabelValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }

    private static string EscapeHelp(string help)
        => help
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);

    private static void WriteSimple<T>(
        StringBuilder text,
        string name,
        IReadOnlyDictionary<SeriesKey, T> series,
        Func<T, string> render)
    {
        foreach (var pair in series
            .Where(pair => pair.Key.Instrument == name)
            .OrderBy(pair => pair.Key.Labels, StringComparer.Ordinal))
        {
            text.Append(name).Append(Braces(pair.Key.Labels)).Append(' ').Append(render(pair.Value)).Append('\n');
        }
    }

    private static void WriteHistogram(StringBuilder text, string name, MetricsSnapshot snapshot)
    {
        foreach (var pair in snapshot.Histograms
            .Where(pair => pair.Key.Instrument == name)
            .OrderBy(pair => pair.Key.Labels, StringComparer.Ordinal))
        {
            var state = pair.Value;
            var labels = pair.Key.Labels;
            var running = 0L;

            for (var i = 0; i < state.Bounds.Count; i++)
            {
                running += state.Counts[i];
                text.Append(name).Append("_bucket").Append(WithLe(labels, Number(state.Bounds[i])))
                    .Append(' ').Append(Number(running)).Append('\n');
            }

            // +Inf is required and its value is the total, not the overflow bucket alone: the
            // cumulative rule holds all the way to the end, and a scraper reads this line as the
            // count. Writing the overflow here instead is the classic way to produce a histogram
            // whose quantiles are quietly nonsense.
            text.Append(name).Append("_bucket").Append(WithLe(labels, "+Inf"))
                .Append(' ').Append(Number(state.Count)).Append('\n');

            text.Append(name).Append("_sum").Append(Braces(labels)).Append(' ').Append(Number(state.Sum)).Append('\n');
            text.Append(name).Append("_count").Append(Braces(labels)).Append(' ').Append(Number(state.Count)).Append('\n');
        }
    }

    private static string Braces(string labels) => labels.Length == 0 ? string.Empty : "{" + labels + "}";

    private static string WithLe(string labels, string le)
        => labels.Length == 0
            ? $"{{le=\"{le}\"}}"
            : $"{{{labels},le=\"{le}\"}}";

    private static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);

    // No format specifier, which on .NET means the shortest string that round-trips. "G17" also
    // round-trips and is the obvious choice, and it renders the 0.05 bucket boundary as
    // `0.050000000000000003` - a label value no dashboard query written by a human will ever match,
    // on every bucket line of every scrape.
    private static string Number(double value) => value.ToString(CultureInfo.InvariantCulture);
}
