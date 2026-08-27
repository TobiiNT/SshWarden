using System.Diagnostics.Metrics;
using System.Globalization;

namespace SshWarden.Metrics;

/// <summary>Aggregates this server's measurements so a scrape has something to read.</summary>
/// <remarks>
/// <para>
/// <c>System.Diagnostics.Metrics</c> is an instrument API: it delivers each measurement to whoever
/// is listening and keeps nothing. Prometheus is a pull model and wants a running total. This is the
/// piece between them, and it is the reason docs/DESIGN.md §4.7 answered Q2 with "hand-written"
/// - the alternatives measured there were an exporter that has never had a stable release and a
/// package that still targets <c>net6.0</c>.
/// </para>
/// <para>
/// Every value is kept in memory and per process, which is the same sentence as the change timeline
/// and the connection pool: a restart resets the counters, and two replicas each report their own.
/// A Prometheus counter reset is a thing the query language already understands, so this is a
/// property to state rather than a defect - but it is stated, because it belongs in the operator's
/// table beside the others.
/// </para>
/// </remarks>
public sealed class MetricsCollector : IDisposable
{
    private readonly MeterListener _listener;
    private readonly Lock _gate = new();

    private readonly Dictionary<SeriesKey, long> _counters = [];
    private readonly Dictionary<SeriesKey, double> _gauges = [];
    private readonly Dictionary<SeriesKey, HistogramState> _histograms = [];
    private readonly Dictionary<string, InstrumentInfo> _instruments = [];

    /// <summary>Starts listening to the meter this server publishes.</summary>
    public MetricsCollector()
    {
        _listener = new MeterListener
        {
            // By meter name rather than by instrument name, so an instrument added to the meter is
            // collected without a second edit here. The exposition still needs its type and its
            // help text, and both are read off the instrument itself.
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == SshWardenMetrics.MeterName)
                {
                    Remember(instrument);
                    listener.EnableMeasurementEvents(instrument);
                }
            },
        };

        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _)
            => Record(instrument, value, tags));

        _listener.SetMeasurementEventCallback<int>((instrument, value, tags, _)
            => Record(instrument, value, tags));

        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _)
            => Record(instrument, value, tags));

        _listener.Start();
    }

    /// <summary>Everything currently known, in one consistent read.</summary>
    /// <remarks>
    /// Observable instruments are polled first, so a gauge's value is the value at scrape time
    /// rather than whatever it was when something last happened to be recorded.
    /// </remarks>
    public MetricsSnapshot Snapshot()
    {
        _listener.RecordObservableInstruments();

        lock (_gate)
        {
            return new MetricsSnapshot(
                [.. _instruments.Values],
                new Dictionary<SeriesKey, long>(_counters),
                new Dictionary<SeriesKey, double>(_gauges),
                _histograms.ToDictionary(pair => pair.Key, pair => pair.Value.Copy()));
        }
    }

    /// <summary>Stops listening.</summary>
    public void Dispose() => _listener.Dispose();

    private void Remember(Instrument instrument)
    {
        var kind = instrument switch
        {
            Counter<long> or Counter<int> or Counter<double> => InstrumentKind.Counter,
            Histogram<long> or Histogram<int> or Histogram<double> => InstrumentKind.Histogram,
            _ => InstrumentKind.Gauge,
        };

        lock (_gate)
        {
            _instruments[instrument.Name] = new InstrumentInfo(
                instrument.Name,
                kind,
                instrument.Description ?? instrument.Name,
                Buckets(instrument.Name));
        }
    }

    private static double[] Buckets(string instrument) => instrument switch
    {
        "sshwarden_command_duration_seconds" => SshWardenMetrics.DurationBuckets,
        "sshwarden_output_bytes" => SshWardenMetrics.OutputByteBuckets,
        _ => [],
    };

    private void Record(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var key = new SeriesKey(instrument.Name, Labels(tags));

        lock (_gate)
        {
            if (!_instruments.TryGetValue(instrument.Name, out var info))
            {
                return;
            }

            switch (info.Kind)
            {
                case InstrumentKind.Counter:
                    _counters[key] = _counters.GetValueOrDefault(key) + (long)value;
                    break;

                case InstrumentKind.Histogram:
                    if (!_histograms.TryGetValue(key, out var histogram))
                    {
                        histogram = new HistogramState(info.Buckets);
                        _histograms[key] = histogram;
                    }

                    histogram.Observe(value);
                    break;

                default:
                    // Replaced rather than added: a gauge reports a level, and adding levels
                    // together produces a number that was never true at any moment.
                    _gauges[key] = value;
                    break;
            }
        }
    }

    /// <summary>The tags as an ordered, rendered label list.</summary>
    /// <remarks>
    /// Rendered here rather than at scrape time so two measurements carrying the same labels land on
    /// the same series whatever order the tags arrived in. Sorted for the same reason.
    /// </remarks>
    private static string Labels(ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        if (tags.Length == 0)
        {
            return string.Empty;
        }

        var pairs = new List<KeyValuePair<string, object?>>(tags.Length);
        foreach (var tag in tags)
        {
            pairs.Add(tag);
        }

        pairs.Sort(static (left, right) => string.CompareOrdinal(left.Key, right.Key));

        return string.Join(
            ',',
            pairs.Select(pair =>
                $"{pair.Key}=\"{PrometheusText.EscapeLabelValue(Convert.ToString(pair.Value, CultureInfo.InvariantCulture) ?? string.Empty)}\""));
    }
}

/// <summary>One series: an instrument and the labels that distinguish it.</summary>
/// <param name="Instrument">The instrument name.</param>
/// <param name="Labels">The rendered labels, without braces, or empty for none.</param>
public readonly record struct SeriesKey(string Instrument, string Labels);

/// <summary>What kind of thing an instrument reports, which decides how it is written out.</summary>
public enum InstrumentKind
{
    /// <summary>Only ever goes up.</summary>
    Counter,

    /// <summary>A level, read at scrape time.</summary>
    Gauge,

    /// <summary>A distribution, written as cumulative buckets plus a sum and a count.</summary>
    Histogram,
}

/// <summary>What the exposition needs to know about an instrument.</summary>
/// <param name="Name">Its name.</param>
/// <param name="Kind">Counter, gauge or histogram.</param>
/// <param name="Help">The description, for the <c>HELP</c> line.</param>
/// <param name="Buckets">Upper bounds, for a histogram; empty otherwise.</param>
public sealed record InstrumentInfo(string Name, InstrumentKind Kind, string Help, double[] Buckets);

/// <summary>One histogram series' running state.</summary>
public sealed class HistogramState
{
    private readonly double[] _bounds;
    private readonly long[] _counts;

    /// <summary>Starts an empty histogram over these upper bounds.</summary>
    /// <param name="bounds">Upper bounds, ascending. The implicit <c>+Inf</c> is not one of them.</param>
    /// <exception cref="ArgumentNullException"><paramref name="bounds" /> is null.</exception>
    public HistogramState(double[] bounds)
    {
        ArgumentNullException.ThrowIfNull(bounds);

        _bounds = bounds;
        _counts = new long[bounds.Length + 1];
    }

    /// <summary>How many observations fell in each bucket, the last being everything above.</summary>
    public IReadOnlyList<long> Counts => _counts;

    /// <summary>The upper bounds.</summary>
    public IReadOnlyList<double> Bounds => _bounds;

    /// <summary>Every observation added together.</summary>
    public double Sum { get; private set; }

    /// <summary>How many observations there were.</summary>
    public long Count { get; private set; }

    /// <summary>Adds one observation.</summary>
    /// <param name="value">The value.</param>
    public void Observe(double value)
    {
        Sum += value;
        Count++;

        for (var i = 0; i < _bounds.Length; i++)
        {
            if (value <= _bounds[i])
            {
                _counts[i]++;
                return;
            }
        }

        _counts[^1]++;
    }

    /// <summary>A copy, so a scrape reads a state nothing else is writing to.</summary>
    public HistogramState Copy()
    {
        var copy = new HistogramState(_bounds) { Sum = Sum, Count = Count };
        Array.Copy(_counts, copy._counts, _counts.Length);
        return copy;
    }
}

/// <summary>Everything known at one moment.</summary>
/// <param name="Instruments">The instruments, for their kind and help text.</param>
/// <param name="Counters">Counter series.</param>
/// <param name="Gauges">Gauge series.</param>
/// <param name="Histograms">Histogram series.</param>
public sealed record MetricsSnapshot(
    IReadOnlyList<InstrumentInfo> Instruments,
    IReadOnlyDictionary<SeriesKey, long> Counters,
    IReadOnlyDictionary<SeriesKey, double> Gauges,
    IReadOnlyDictionary<SeriesKey, HistogramState> Histograms);
