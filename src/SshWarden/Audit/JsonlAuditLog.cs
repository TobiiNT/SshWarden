using System.Text;
using System.Text.Json;

namespace SshWarden.Audit;

/// <summary>Appends records to a JSONL file.</summary>
/// <remarks>
/// <para>
/// One record per line, appended, never rewritten. docs/DESIGN.md §4.2 settles on this over a database
/// for reasons that are all about the day somebody needs it: <c>tail -f</c> works immediately,
/// <c>jq</c> works, every log shipper already knows how to scrape it, and an append-only file has
/// no schema migration to be halfway through during an incident.
/// </para>
/// <para>
/// <strong>This file is the source of truth.</strong> Whatever ships it onward - a scraper, a
/// dashboard, an alert rule - is a consumer, and none of them are in this repository. That
/// boundary is deliberate: this process writes the record and stops, so a broken pipeline
/// downstream loses a view rather than the evidence.
/// </para>
/// <para>
/// It also contains output from production hosts, which means it contains whatever those hosts
/// printed. It stays on the machine that wrote it.
/// </para>
/// </remarks>
public sealed class JsonlAuditLog : IAuditLog, IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        // Nulls are written rather than omitted. A consumer querying `exit_code` should find the
        // key present and null on a command that timed out, not absent - "the key is missing" and
        // "the command reported no status" are different facts, and a query cannot tell them apart
        // once the key stops being emitted.
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        WriteIndented = false,
    };

    private readonly Lock _writeLock = new();
    private readonly StreamWriter _writer;

    /// <summary>Opens the log for appending.</summary>
    /// <param name="path">The file to append to. Its directory must already exist.</param>
    /// <exception cref="ArgumentException"><paramref name="path" /> is null or whitespace.</exception>
    public JsonlAuditLog(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        Path = path;

        // Opened once and held, rather than opened per record: a record written during an incident
        // is exactly when the filesystem is least likely to cooperate, and the failure should have
        // happened at startup instead.
        var stream = new FileStream(
            path,
            FileMode.Append,
            FileAccess.Write,
            FileShare.Read);

        _writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            // Flushed per record. Buffering would trade the last few records for throughput, and
            // the records worth losing least are the ones written just before something went wrong.
            AutoFlush = true,
        };
    }

    /// <summary>The file being appended to.</summary>
    public string Path { get; }

    /// <inheritdoc />
    public void Write(AuditRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        var line = JsonSerializer.Serialize(record, SerializerOptions);

        // A lock rather than relying on the atomicity of an append: a record longer than the pipe
        // buffer can be split by the kernel, and a half-written line in a JSONL file is a line no
        // consumer can parse and no operator can recover.
        lock (_writeLock)
        {
            _writer.Write(line);
            _writer.Write('\n');
        }
    }

    /// <summary>Closes the file.</summary>
    public void Dispose()
    {
        lock (_writeLock)
        {
            _writer.Dispose();
        }
    }
}
