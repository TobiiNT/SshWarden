using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using SshWarden.Authorization;
using SshWarden.Diagnostics;

namespace SshWarden.Jobs;

/// <summary>Every job SshWarden has started, and which of them are still worth asking about.</summary>
/// <remarks>
/// <para>
/// <strong>Separate from the tool surface on purpose.</strong> The three tools are a thin adapter
/// over this. The day a client supports the protocol's own long-running-request extension, that is
/// a second adapter rather than a rewrite - and the two would be adapters over the same store,
/// because a job is a process on the target and a protocol task is a request that outlives a call.
/// Those are different lifetimes wearing the same word.
/// </para>
/// <para>
/// <strong>On disk, and this is one of the two things docs/DESIGN.md §4.4 said had to be settled before
/// jobs could ship.</strong> The process lives on the target and survives a restart of this server;
/// an in-memory index would not, so after a deploy every running job would be unpollable,
/// unkillable, and - worse - unowned, which means the check that stops one caller reaching
/// another's job would have nothing to check against.
/// </para>
/// <para>
/// Append-only, replayed at startup, latest entry per job wins. The same shape as the audit log and
/// for the same reasons: no schema to be halfway through migrating during an incident, and a file
/// anybody can read with <c>jq</c>. Mutation is an appended record rather than a rewrite, so a
/// crash mid-write costs the last line rather than the file.
/// </para>
/// </remarks>
public sealed class JobStore : IJobLookup, IDisposable
{
    private const string IdPrefix = "sw_job_";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        WriteIndented = false,
    };

    private readonly Lock _lock = new();
    private readonly Dictionary<string, JobRecord> _jobs = new(StringComparer.Ordinal);
    private readonly StreamWriter _writer;

    /// <summary>Opens the registry, replaying what is already in it.</summary>
    /// <param name="path">The registry file.</param>
    /// <param name="logger">
    /// Where a line that could not be replayed is reported. Optional and defaulting to the null
    /// logger, because this store is constructed directly in tests and a registry that replays
    /// cleanly says nothing at all.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="path" /> is null or whitespace.</exception>
    public JobStore(string path, ILogger<JobStore>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        Path = path;

        var log = logger ?? (ILogger)NullLogger.Instance;

        if (File.Exists(path))
        {
            var number = 0;

            foreach (var line in File.ReadLines(path))
            {
                number++;

                if (line.Length == 0)
                {
                    continue;
                }

                try
                {
                    if (JsonSerializer.Deserialize<JobRecord>(line, SerializerOptions) is { } record)
                    {
                        _jobs[record.JobId] = record;
                    }
                }
                catch (JsonException)
                {
                    // A line that will not parse is skipped rather than failing startup. The likely
                    // cause is a crash partway through the last write, and refusing to start over
                    // one truncated line would turn a lost job into a lost server.
                    //
                    // Said out loud, which it was not: a job that survived the restart and one that
                    // was silently dropped look identical from outside, and the second means
                    // poll_job answers "no such job" for work still running on the target.
                    CoreLog.JobRegistryLineSkipped(log, path, number);
                }
            }
        }

        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        _writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true,
        };
    }

    /// <summary>The registry file.</summary>
    public string Path { get; }

    /// <summary>A new, unguessable job identifier.</summary>
    /// <remarks>
    /// 128 bits from the cryptographic generator. Not a counter and not a timestamp: this is the
    /// only argument the polling and killing tools take, so a guessable one is a way to reach other
    /// people's jobs by trying rather than by being allowed.
    /// </remarks>
    public static string NewJobId() => IdPrefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

    /// <summary>Records a job.</summary>
    /// <param name="record">The job.</param>
    /// <exception cref="ArgumentNullException"><paramref name="record" /> is null.</exception>
    public void Put(JobRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        lock (_lock)
        {
            _jobs[record.JobId] = record;
            _writer.Write(JsonSerializer.Serialize(record, SerializerOptions));
            _writer.Write('\n');
        }
    }

    /// <summary>Finds a job.</summary>
    /// <param name="jobId">The identifier.</param>
    /// <exception cref="ArgumentNullException"><paramref name="jobId" /> is null.</exception>
    public JobRecord? Find(string jobId)
    {
        ArgumentNullException.ThrowIfNull(jobId);

        lock (_lock)
        {
            return _jobs.GetValueOrDefault(jobId);
        }
    }

    /// <summary>Every job started by <paramref name="subject" />.</summary>
    /// <param name="subject">The owner.</param>
    /// <exception cref="ArgumentNullException"><paramref name="subject" /> is null.</exception>
    public IReadOnlyList<JobRecord> ForSubject(string subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        lock (_lock)
        {
            return [.. _jobs.Values
                .Where(job => string.Equals(job.OwnerSubject, subject, StringComparison.Ordinal))
                .OrderByDescending(job => job.StartedAt)];
        }
    }

    /// <summary>The seam the gate uses.</summary>
    /// <remarks>
    /// Two values and no more. A gate that could see the command or the output path would be a gate
    /// that could start deciding on them, and the classification rule says those are not decidable.
    /// Implemented explicitly so it does not compete with <see cref="Find" />, which is what the
    /// tools use.
    /// </remarks>
    (string Host, string OwnerSubject)? IJobLookup.Find(string jobId)
    {
        ArgumentNullException.ThrowIfNull(jobId);

        var job = Find(jobId);
        return job is null ? null : (job.Host, job.OwnerSubject);
    }

    /// <summary>Closes the registry.</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            _writer.Dispose();
        }
    }
}
