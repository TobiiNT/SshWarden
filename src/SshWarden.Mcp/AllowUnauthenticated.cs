namespace SshWarden.Mcp;

/// <summary>
/// Marks an endpoint as reachable without a credential.
/// </summary>
/// <remarks>
/// <para>
/// The authentication middleware runs over the whole application and refuses anything not carrying
/// this, so an endpoint added later is authenticated unless somebody says otherwise <em>at the
/// place they add it</em>. The alternative shape - running authentication only over the MCP path -
/// reads as equivalent and is not: under it, a route mapped outside that prefix is open, and
/// nothing about adding one says so.
/// </para>
/// <para>
/// A marker type rather than a path list for the same reason. A list lives in startup, away from
/// the route it exempts, and stays behind when the route moves.
/// </para>
/// </remarks>
public sealed class AllowUnauthenticated
{
    /// <summary>The single instance to attach as endpoint metadata.</summary>
    public static readonly AllowUnauthenticated Instance = new();

    private AllowUnauthenticated()
    {
    }
}
