using System.Text.Json;

using ModelContextProtocol.Server;

using SshWarden.Authorization;
using SshWarden.Configuration;

namespace SshWarden.Mcp;

/// <summary>
/// Checks at startup that the gate can actually see everything it is supposed to gate.
/// </summary>
/// <remarks>
/// <para>
/// The gate reads arguments out of raw JSON by name. A name that does not match the tool's schema
/// finds nothing, and finding nothing is indistinguishable, from inside the policy, from a caller
/// who did not send it - so a misspelling here silently removes a boundary and every test of the
/// happy path still passes. docs/DESIGN.md §6.5.6 asks for exactly these checks, and asks that they
/// fail the build rather than waiting for the call that would have been refused.
/// </para>
/// <para>
/// They run at startup because that is where the two halves are both present: the registered tools
/// with their schemas, and the policy's map of which argument each one is gated on.
/// </para>
/// </remarks>
public static class ToolPolicyCoverage
{
    /// <summary>Verifies the coverage, or throws describing every gap.</summary>
    /// <param name="tools">The registered tools.</param>
    /// <param name="expectTools">
    /// Whether this deployment should have tools at all - false for one with no SSH layer
    /// configured, where an empty surface is correct.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="tools" /> is null.</exception>
    /// <exception cref="InvalidOperationException">Something is not covered.</exception>
    public static void Verify(IEnumerable<McpServerTool> tools, bool expectTools = true)
    {
        ArgumentNullException.ThrowIfNull(tools);

        var problems = new List<string>();
        var registered = tools.ToList();

        // The check that a tool this build implements is actually registered, and it is here because
        // it was needed: one SDK registration overload compiles, runs and registers nothing, leaving
        // a server whose tool list is empty and whose tools/call answers "method not available".
        // Nothing else notices - the gate is happy to cover an empty set, every unit test of the
        // policy passes, and the surface is simply not there. Measured 2026-08-26.
        if (expectTools)
        {
            foreach (var expected in ToolNames.All)
            {
                if (!registered.Any(tool => string.Equals(tool.ProtocolTool.Name, expected, StringComparison.Ordinal)))
                {
                    problems.Add(
                        $"The tool '{expected}' is part of v0 but is not registered, so it is absent "
                            + "from every listing and every call answers that the method is not "
                            + "available.");
                }
            }
        }

        foreach (var tool in registered)
        {
            var name = tool.ProtocolTool.Name;

            // Every registered tool has to be a name the grant table can be written against.
            // A tool outside that vocabulary cannot appear in any rule, so deny-by-default makes it
            // permanently unreachable - which is safe, and confusing enough to be worth refusing.
            if (!ToolNames.All.Contains(name, StringComparer.Ordinal))
            {
                problems.Add(
                    $"The tool '{name}' is registered but is not one of the names a grant rule can "
                        + "name, so no rule could ever allow it. v0 has exactly seven: "
                        + string.Join(", ", ToolNames.All) + ".");
                continue;
            }

            var properties = ReadProperties(tool.ProtocolTool.InputSchema);

            if (ResourceArguments.HostArgumentByTool.TryGetValue(name, out var hostArgument))
            {
                // The name the policy reads must be a name the tool actually declares. Otherwise
                // the gate looks for an argument nobody sends and the host check never runs.
                if (!properties.Contains(hostArgument))
                {
                    problems.Add(
                        $"The policy gates '{name}' on an argument called '{hostArgument}', which "
                            + "is not in that tool's input schema. The gate would look for it, not "
                            + "find it, and refuse every call - or worse, be changed to allow them.");
                }
            }
            else if (properties.Contains(ResourceArguments.Host))
            {
                // The other direction, and the dangerous one: a tool that takes a host and is not
                // in the map is a tool whose host is not gated at all. Nothing else would say so.
                problems.Add(
                    $"The tool '{name}' takes a '{ResourceArguments.Host}' argument but the policy "
                        + "does not gate it on one, so any caller allowed the tool reaches every "
                        + "host. Add it to the resource-argument map, or say in a comment there why "
                        + "this one is different.");
            }

            CheckSelector(name, properties, problems);
        }

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "SshWarden will not start: the tool gate does not cover everything it is supposed "
                    + "to."
                    + Environment.NewLine
                    + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }
    }

    private static void CheckSelector(string name, HashSet<string> properties, List<string> problems)
    {
        // The job identifier first, because it is the argument shape where getting this wrong is
        // least visible: it names no host, so a gate that only knows how to check hosts sees nothing
        // to check and lets everything through - and what goes through is one caller reading
        // another's production output and signalling their processes.
        if (ResourceArguments.JobArgumentByTool.TryGetValue(name, out var jobArgument))
        {
            if (!properties.Contains(jobArgument))
            {
                problems.Add(
                    $"The policy gates '{name}' on an argument called '{jobArgument}', which is not "
                        + "in that tool's input schema. The gate would look for it and not find it.");
            }

            return;
        }

        if (properties.Contains(ResourceArguments.JobId))
        {
            problems.Add(
                $"The tool '{name}' takes a '{ResourceArguments.JobId}' argument but the policy does "
                    + "not resolve it to an owner and a host, so any caller allowed the tool reaches "
                    + "every job - including other people's. Add it to the job-argument map, or say "
                    + "in a comment there why this one is different.");
        }

        // The same pair of questions for the argument that names a file or a unit. A path is the
        // selector where getting this wrong is worst: an ungated one reaches every file the unix
        // account can open, which is the whole set the grant table was written to narrow.
        if (ResourceArguments.PathArgumentByTool.TryGetValue(name, out var pathArgument))
        {
            if (!properties.Contains(pathArgument))
            {
                problems.Add(
                    $"The policy gates '{name}' on an argument called '{pathArgument}', which is "
                        + "not in that tool's input schema. The gate would look for it and not find "
                        + "it.");
            }

            return;
        }

        foreach (var selector in new[] { ResourceArguments.Path, ResourceArguments.UnitOrPath })
        {
            if (properties.Contains(selector))
            {
                problems.Add(
                    $"The tool '{name}' takes a '{selector}' argument but the policy does not gate "
                        + "it on one, so any caller allowed the tool reaches every file the unix "
                        + "account can open. Add it to the resource-argument map, or say in a "
                        + "comment there why this one is different.");
            }
        }
    }

    private static HashSet<string> ReadProperties(JsonElement schema)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);

        if (schema.ValueKind == JsonValueKind.Object
            && schema.TryGetProperty("properties", out var properties)
            && properties.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in properties.EnumerateObject())
            {
                _ = names.Add(property.Name);
            }
        }

        return names;
    }
}
