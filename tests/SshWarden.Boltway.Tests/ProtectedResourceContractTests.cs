using Boltway.ResourceServer.Testing;

using Xunit;

namespace SshWarden.Boltway.Tests;

/// <summary>
/// RFC 9728 conformance, run against the pipeline rather than against a unit.
/// </summary>
/// <remarks>
/// <para>
/// The same suite the generic OAuth mode derives, against the other wiring. Running it twice is the
/// point: the two modes publish the metadata document through different code - one maps its own
/// endpoints, the other maps Boltway's - and a contract run against only one of them says nothing
/// about the other. This is also the mode where the anonymous-marker defect was first measured, on
/// 2026-08-26, against a running process with everything else working.
/// </para>
/// <para>
/// Here the library that ships the contract is also the library under test, which is worth naming:
/// what is being checked is not Boltway's own conformance but this repository's wiring of it - the
/// route group that carries both anonymous vocabularies, the middleware order, and the resource
/// identifier reaching the document unchanged.
/// </para>
/// </remarks>
public sealed class ProtectedResourceContractTests : ProtectedResourceContract, IAsyncLifetime
{
    private BoltwayPipeline _pipeline = null!;

    /// <inheritdoc />
    protected override HttpClient Client => _pipeline.Client;

    /// <inheritdoc />
    protected override string Resource => BoltwayPipeline.Resource;

    /// <inheritdoc />
    protected override string ProtectedPath => BoltwayPipeline.McpPath;

    /// <inheritdoc />
    public async Task InitializeAsync() => _pipeline = await BoltwayPipeline.StartAsync();

    /// <inheritdoc />
    public async Task DisposeAsync() => await _pipeline.DisposeAsync();
}
