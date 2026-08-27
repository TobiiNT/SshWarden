using System.Collections.ObjectModel;
using System.Text.Json;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using ModelContextProtocol.Protocol;

using SshWarden.Audit;
using SshWarden.Auth;
using SshWarden.Mcp.Diagnostics;
using SshWarden.Authorization;

namespace SshWarden.Mcp;

/// <summary>Puts the grant table in front of every tool listing and every tool call.</summary>
/// <remarks>
/// <para>
/// One call registers both filters, and that is the design rather than a convenience. Filtering
/// <c>tools/list</c> without gating <c>tools/call</c> produces a surface that looks authorized:
/// the tool is absent from the listing and still answers anybody who knows its name. Wiring them
/// separately makes it possible to do one and believe you have done both, so they are not
/// separable here.
/// </para>
/// <para>
/// A refusal from the call filter is <strong>text in a tool result</strong> and can be nothing
/// else. By the time this runs the transport has sent the <c>200</c>, so there is no status code
/// left to set; and the MCP field a client might read to know which scope would fix it is a draft
/// proposal that no schema revision defines. Both halves were measured on 2026-08-25 and written
/// up in docs/DESIGN.md §6.5.8. So the text says which rule refused, in as many words, because that is
/// the only channel there is.
/// </para>
/// </remarks>
public static class SshWardenToolGate
{
    /// <summary>Registers the listing filter and the call filter together.</summary>
    /// <param name="builder">The MCP server builder.</param>
    /// <exception cref="ArgumentNullException"><paramref name="builder" /> is null.</exception>
    public static IMcpServerBuilder WithSshWardenToolPolicy(this IMcpServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.WithRequestFilters(filters => filters
            .AddListToolsFilter(next => async (context, cancellationToken) =>
            {
                var result = await next(context, cancellationToken).ConfigureAwait(false);

                var (caller, policy, _, _) = Resolve(context.Services);

                // Filtered rather than annotated. An agent shown a tool it cannot use will call it,
                // read the refusal, and try again - docs/DESIGN.md §6.5.7 - so "this token cannot run
                // commands" has to mean the tool is not there, not that it is there and says no.
                result.Tools = [.. result.Tools.Where(tool => policy.Allows(caller, tool.Name).IsAllowed)];
                return result;
            })
            .AddCallToolFilter(next => async (context, cancellationToken) =>
            {
                var startedAt = DateTimeOffset.UtcNow;
                var (caller, policy, audit, logger) = Resolve(context.Services);
                var tool = context.Params?.Name ?? string.Empty;

                // Asked again here, not only in the listing. A client that knows a name can call it
                // whether or not the listing mentioned it, so the listing filter is a courtesy and
                // this is the gate.
                var arguments = context.Params?.Arguments?.AsReadOnly();

                var visible = policy.Allows(caller, tool);
                if (!visible.IsAllowed)
                {
                    return Refuse(caller, tool, visible, startedAt, arguments, audit, logger);
                }

                var allowed = policy.AllowsArguments(caller, tool, arguments);
                if (!allowed.IsAllowed)
                {
                    return Refuse(caller, tool, allowed, startedAt, arguments, audit, logger);
                }

                // Not wrapped in a catch that records the failure, and that was tried: a tool can
                // refuse on its own after the gate has passed it - `path_not_found` is only knowable
                // once the target has resolved the path - and it records that refusal itself before
                // throwing. A gate that recorded every exception wrote a second record for the same
                // call, saying `allow` over the top of the tool's `deny`. Failures are recorded
                // where the tool knows what it was doing; see RunTool's finally.
                return await next(context, cancellationToken).ConfigureAwait(false);
            }));
    }

    private static CallToolResult Refuse(
        CallerIdentity caller,
        string tool,
        AuthorizationDecision decision,
        DateTimeOffset startedAt,
        ReadOnlyDictionary<string, JsonElement>? arguments,
        IAuditLog audit,
        ILogger logger)
    {
        // Written before the result is returned, and written whether or not anybody is watching the
        // stream. "An agent went for a production host and was stopped" is the line this log exists
        // to carry, and an earlier draft of the schema had nowhere to put it.
        //
        // The host and the selector are pulled out for the record, because a refusal that names a
        // rule and nothing else gives whoever reads it nothing to act on - "a path was refused as
        // unusable" without the path is a line nobody can do anything with.
        audit.Write(AuditRecordFactory.Refusal(
            caller,
            tool,
            decision,
            startedAt,
            ReadArgument(arguments, ResourceArguments.HostArgumentByTool, tool),
            ReadArgument(arguments, ResourceArguments.PathArgumentByTool, tool)));

        McpLog.ToolRefused(logger, tool, caller.Subject, decision.RefusedBy!);

        return new CallToolResult
        {
            IsError = true,
            Content = [new TextContentBlock { Text = decision.Detail! }],
        };
    }

    private static string? ReadArgument(
        ReadOnlyDictionary<string, JsonElement>? arguments,
        IReadOnlyDictionary<string, string> namesByTool,
        string tool)
    {
        // Best effort, and only so the audit record can say where the caller was heading. An
        // argument that cannot be read leaves the field null and changes nothing else; this must
        // never become a second place that decides anything.
        if (arguments is null
            || !namesByTool.TryGetValue(tool, out var name)
            || !arguments.TryGetValue(name, out var element)
            || element.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return element.GetString();
    }

    private static (CallerIdentity Caller, ISshWardenToolPolicy Policy, IAuditLog Audit, ILogger Logger)
        Resolve(IServiceProvider? services)
    {
        // Null here means the MCP server was built without a request scope to resolve from, which
        // is a wiring mistake rather than a caller problem - and the difference matters, because
        // the alternative to throwing is a gate that quietly cannot find its policy.
        if (services is null)
        {
            throw new InvalidOperationException(
                "The MCP request carries no service provider, so the tool gate cannot resolve the "
                    + "caller or the grant table. Register SshWarden through AddSshWarden.");
        }

        var caller = services.GetRequiredService<CallerContext>().Require();
        var policy = services.GetRequiredService<ISshWardenToolPolicy>();
        var audit = services.GetRequiredService<IAuditLog>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(SshWardenToolGate));

        return (caller, policy, audit, logger);
    }

}
