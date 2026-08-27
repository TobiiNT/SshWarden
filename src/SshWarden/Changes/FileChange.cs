using System.Text.Json.Serialization;

namespace SshWarden.Changes;

/// <summary>Something that happened to a watched file.</summary>
public sealed class FileChange
{
    /// <summary>When the sweep that noticed it ran.</summary>
    /// <remarks>
    /// When it was <em>noticed</em>, not when it happened. The difference is bounded by the sweep
    /// interval and is the resolution limit of the whole mechanism - a limit the README states
    /// rather than leaving somebody to work out from a timestamp that is slightly wrong.
    /// </remarks>
    [JsonPropertyName("at")]
    public required DateTimeOffset At { get; init; }

    /// <summary>The file.</summary>
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    /// <summary>What happened to it.</summary>
    [JsonPropertyName("kind")]
    public required string Kind { get; init; }
}

/// <summary>The values of <see cref="FileChange.Kind" />.</summary>
/// <remarks>
/// Three, and no <c>renamed</c>: a rename looks exactly like a delete and a create to something
/// comparing two lists of paths, and reporting it as a rename would be a guess presented as an
/// observation. Two honest entries beat one invented one.
/// </remarks>
public static class FileChangeKinds
{
    /// <summary>The path was not there on the previous sweep.</summary>
    public const string Created = "created";

    /// <summary>The path is gone.</summary>
    public const string Deleted = "deleted";

    /// <summary>Size, modification time or inode differs from the previous sweep.</summary>
    public const string Modified = "modified";
}

/// <summary>What one sweep saw of one file.</summary>
/// <remarks>
/// <para>
/// Inode, size and modification time. Not a hash: hashing every watched file over SSH on every
/// interval costs more than the whole mechanism is worth, and this catches what an ordinary change
/// does.
/// </para>
/// <para>
/// <strong>What it misses is a change that leaves all three alone</strong> - a write of the same
/// number of bytes with the timestamp restored. That is a real limit and it goes in the README;
/// it is not a shortcoming of choosing a background sweep, because comparing modification times
/// misses it however often you do it.
/// </para>
/// </remarks>
/// <param name="Inode">The inode number, which changes when a file is replaced rather than edited.</param>
/// <param name="Size">The size in bytes.</param>
/// <param name="ModifiedAt">The modification time, as seconds since the epoch.</param>
public readonly record struct FileState(long Inode, long Size, double ModifiedAt);
