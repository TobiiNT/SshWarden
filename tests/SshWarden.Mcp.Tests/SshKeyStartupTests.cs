using SshWarden.Configuration;

using Xunit;

namespace SshWarden.Mcp.Tests;

/// <summary>When an SSH private key that cannot be used is discovered.</summary>
/// <remarks>
/// <para>
/// At startup, and the alternative is not "later" but "invisibly". The connection pool reads the key
/// in its constructor, and while that constructor was left to the first tool call the failure
/// happened inside dependency injection - before the tool method ran, so before the record it
/// writes in a <c>finally</c> could be written. Measured on 2026-08-26 against a running server: an
/// authenticated call passed the grant table, reached the SSH layer, and left nothing in the audit
/// log; the caller was told "An error occurred invoking 'run'".
/// </para>
/// <para>
/// The loader cannot catch this. It checks that the file is there and that nobody else can read it,
/// which is all it can do without pulling an SSH library into the config layer - whether the bytes
/// are a key is SSH.NET's question, and this is the first moment it is asked.
/// </para>
/// </remarks>
public sealed class SshKeyStartupTests
{
    [Fact]
    public async Task A_key_that_cannot_be_parsed_stops_the_process_starting()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-key", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var path = Path.Combine(directory, "id_rsa");
        await File.WriteAllTextAsync(path, "this is not a private key");

        // A configuration problem and not the library's own exception, because that is what it is:
        // ssh.identity_file names something unusable, and it will name the same unusable thing on
        // every restart. SSH.NET says `Invalid private key file.` and does not say which file, so
        // an operator reading that in a crash trace has to guess.
        var failure = await Assert.ThrowsAsync<SshWardenConfigurationException>(
            async () => await AuthenticatedPipeline.StartAsync(identityFile: path));

        Assert.Contains(path, failure.Message, StringComparison.Ordinal);
        Assert.Contains("ssh.identity_file", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_key_it_can_parse_starts_and_serves()
    {
        // The control, and it carries most of the weight here. Without it the test above passes
        // against a pipeline that refuses to start with any key at all, which would be a far worse
        // defect than the one being fixed.
        await using var pipeline = await AuthenticatedPipeline.StartAsync();

        var response = await pipeline.Client.GetAsync(new Uri("/health", UriKind.Relative));

        response.EnsureSuccessStatusCode();
    }
}
