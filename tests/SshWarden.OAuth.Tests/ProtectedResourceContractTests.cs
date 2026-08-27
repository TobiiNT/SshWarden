using Boltway.ResourceServer.Testing;

using Xunit;

namespace SshWarden.OAuth.Tests;

/// <summary>
/// RFC 9728 conformance, run against the pipeline rather than against a unit.
/// </summary>
/// <remarks>
/// <para>
/// The suite is <c>Boltway.ResourceServer.Testing</c>'s, derived rather than copied. Nothing in its
/// surface is a Boltway type - an <c>HttpClient</c>, the resource identifier and one protected path
/// - and every assertion in it is a sentence out of the RFC, so it is as true of this assembly as of
/// the authorization server it was written beside. Deriving it means a defect that library learns
/// about arrives here as a failing test rather than as a paragraph somebody has to read.
/// </para>
/// <para>
/// <strong>A test dependency, and it stays one.</strong> <c>src/SshWarden.OAuth</c> references
/// nothing from Boltway and must not begin to: a deployment on some other authorization server is
/// the case that assembly exists for.
/// </para>
/// <para>
/// <strong>This is the suite that found the missing pointer.</strong> Before it ran, this server
/// published a correct metadata document at both well-known forms and refused every request with a
/// bare <c>Bearer</c> - so a client meeting it for the first time was told it needed a credential
/// and never told where to get one. Every unit test passed the whole time, because no unit is wrong:
/// the document is right, the refusal is right, and the thing missing is the link between them.
/// </para>
/// </remarks>
public sealed class ProtectedResourceContractTests : ProtectedResourceContract, IAsyncLifetime
{
    private OAuthPipeline _pipeline = null!;

    /// <inheritdoc />
    protected override HttpClient Client => _pipeline.Client;

    /// <inheritdoc />
    protected override string Resource => OAuthPipeline.Resource;

    /// <inheritdoc />
    protected override string ProtectedPath => OAuthPipeline.McpPath;

    /// <inheritdoc />
    public async Task InitializeAsync() => _pipeline = await OAuthPipeline.StartAsync();

    /// <inheritdoc />
    public async Task DisposeAsync() => await _pipeline.DisposeAsync();
}
