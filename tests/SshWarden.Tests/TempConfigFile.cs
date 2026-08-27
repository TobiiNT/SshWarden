namespace SshWarden.Tests;

/// <summary>A config file on disk for the length of one test, at the mode the test asks for.</summary>
/// <remarks>
/// The mode is part of what the loader checks, so a helper that wrote everything at the process
/// umask would make the permission test pass or fail depending on the machine running it.
/// </remarks>
internal sealed class TempConfigFile : IDisposable
{
    private TempConfigFile(string path) => Path = path;

    public string Path { get; }

    /// <summary>What a test config writes for <c>ssh.identity_file</c> to get a real one.</summary>
    /// <remarks>
    /// The loader refuses a key that is not there, so a fixture naming a path that does not exist
    /// is testing that refusal rather than whatever it meant to test. A placeholder rather than a
    /// path, because the real one is only known once the temporary directory exists.
    /// </remarks>
    public const string IdentityFilePlaceholder = "{identity_file}";

    public static TempConfigFile Write(string content, UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite)
    {
        var directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "sshwarden-tests",
            Guid.NewGuid().ToString("n"));

        Directory.CreateDirectory(directory);

        var path = System.IO.Path.Combine(directory, "sshwarden.toml");

        // Every config gets an [audit] block pointing inside its own temporary directory, unless it
        // declares one. The loader refuses a config whose audit log it cannot write, and the default
        // path is a system directory - so without this every test here would be testing whether the
        // machine running it happens to allow writing to /var/log.
        var withAudit = content.Contains("[audit]", StringComparison.Ordinal)
            ? content
            : content
                + Environment.NewLine
                + Environment.NewLine
                + "[audit]"
                + Environment.NewLine
                + "path = \"" + System.IO.Path.Combine(directory, "audit.jsonl").Replace("\\", "/", StringComparison.Ordinal) + "\"";

        // Not a key, and it does not have to be: what the loader checks is that the path exists and
        // that nobody else can read it. Whether the bytes parse is SSH.NET's question, asked at the
        // first connection.
        if (withAudit.Contains(IdentityFilePlaceholder, StringComparison.Ordinal))
        {
            var key = System.IO.Path.Combine(directory, "id_ed25519");
            File.WriteAllText(key, string.Empty);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(key, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            withAudit = withAudit.Replace(
                IdentityFilePlaceholder,
                key.Replace("\\", "/", StringComparison.Ordinal),
                StringComparison.Ordinal);
        }

        File.WriteAllText(path, withAudit);

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, mode);
        }

        return new TempConfigFile(path);
    }

    public void Dispose()
    {
        var directory = System.IO.Path.GetDirectoryName(Path);
        if (directory is not null && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
