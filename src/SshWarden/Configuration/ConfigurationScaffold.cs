using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using SshWarden.Authorization;

namespace SshWarden.Configuration;

/// <summary>What a deployment must supply before a config file can be written for it.</summary>
/// <remarks>
/// <para>
/// Every field here is something only the operator knows. Nothing is guessed and nothing is
/// fetched: the fingerprints in particular are supplied rather than scanned, because a fingerprint
/// this process read off the network is a fingerprint verified by whoever answered. That is
/// trust-on-first-use with an extra step, and the whole host-key design refuses it.
/// </para>
/// </remarks>
public sealed class ScaffoldRequest
{
    /// <summary>Which authentication mode.</summary>
    public string AuthMode { get; init; } = AuthModes.StaticToken;

    /// <summary>The authorization server to trust, for <see cref="AuthModes.OAuth" />.</summary>
    public string? Issuer { get; init; }

    /// <summary>What this server answers to in a token's audience.</summary>
    public string? Resource { get; init; }

    /// <summary>What a client is told to ask for. Published unauthenticated, so keep it coarse.</summary>
    public IReadOnlyList<string> ScopesSupported { get; init; } = [];

    /// <summary>Who the generated token belongs to. The grant table is keyed on it.</summary>
    public string Subject { get; init; } = "operator";

    /// <summary>What the operator calls this credential, in log lines and refusals.</summary>
    public string TokenName { get; init; } = "laptop";

    /// <summary>Where to listen.</summary>
    public string Listen { get; init; } = "127.0.0.1:8760";

    /// <summary>The private key this process reaches every host with.</summary>
    public required string IdentityFile { get; init; }

    /// <summary>Where the audit log and the job registry go.</summary>
    public required string StateDirectory { get; init; }

    /// <summary>The hosts, each with the fingerprint the operator verified out of band.</summary>
    public IReadOnlyList<ScaffoldHost> Hosts { get; init; } = [];

    /// <summary>The unix account commands run as.</summary>
    public string? SshUser { get; init; }

    /// <summary>Which tools the generated rule covers.</summary>
    /// <remarks>
    /// <para>
    /// Defaults to every tool that is gated on nothing but a host, which is not the same as every
    /// tool. <c>read_file</c> and <c>tail_log</c> are gated on a path or a unit as well, and a rule
    /// naming them with neither is one the loader refuses - it could never allow a read, so it is a
    /// rule that looks like it works and does not.
    /// </para>
    /// <para>
    /// Derived from <see cref="ResourceArguments.PathArgumentByTool" /> rather than written out, so
    /// a tool that grows a selector later leaves this default correct instead of quietly wrong.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Tools { get; init; } =
        [.. ToolNames.All.Where(tool => !ResourceArguments.PathArgumentByTool.ContainsKey(tool))];

    /// <summary>Absolute path globs the generated rule allows reading under.</summary>
    public IReadOnlyList<string> Paths { get; init; } = [];

    /// <summary>Service unit names the generated rule allows reading the journal of.</summary>
    public IReadOnlyList<string> Units { get; init; } = [];
}

/// <summary>One host, as the operator supplied it.</summary>
/// <param name="Name">Its name, which is what a caller passes as <c>host</c>.</param>
/// <param name="Fingerprint">The <c>SHA256:</c> fingerprint, verified over a channel they trust.</param>
public readonly record struct ScaffoldHost(string Name, string Fingerprint);

/// <summary>Writes a configuration file for a deployment that has none.</summary>
/// <remarks>
/// <para>
/// A pure function from a request to TOML text, deliberately: the thing worth testing is whether
/// what comes out loads, and a generator that also touched the filesystem could only be tested
/// against the filesystem. The host is what creates directories and sets modes.
/// </para>
/// <para>
/// <strong>The token is generated here rather than accepted as an argument.</strong> An argument is
/// readable by every process on the machine through <c>ps</c>, which is the same reason the server
/// takes nothing but <c>--config</c>. A one-command install that put the credential on the command
/// line would have moved the secret from a 0600 file to the process table.
/// </para>
/// </remarks>
public static class ConfigurationScaffold
{
    /// <summary>How many bytes of entropy the generated token carries.</summary>
    /// <remarks>
    /// 32 bytes, which is 43 characters unpadded - comfortably over the 32-character floor the
    /// loader enforces. The floor is a floor rather than the target: a static token does not expire,
    /// so being unguessable is the whole of its security.
    /// </remarks>
    public const int TokenBytes = 32;

    /// <summary>Generates a credential for the file this scaffold writes.</summary>
    public static string NewToken()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(TokenBytes))
            .Replace("+", "-", StringComparison.Ordinal)
            .Replace("/", "_", StringComparison.Ordinal)
            .TrimEnd('=');

    /// <summary>Everything wrong with a request, or empty when there is nothing.</summary>
    /// <param name="request">What the operator supplied.</param>
    /// <exception cref="ArgumentNullException"><paramref name="request" /> is null.</exception>
    /// <remarks>
    /// All of them at once, like the loader, and for the same reason: an operator who fixes one
    /// problem per run learns about the next one on the next run. Each names what it wants rather
    /// than only what is wrong - a refusal saying a fingerprint is required, without saying how to
    /// obtain one, sends somebody to search for it.
    /// </remarks>
    public static IReadOnlyList<string> Problems(ScaffoldRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var problems = new List<string>();

        if (!AuthModes.All.Contains(request.AuthMode))
        {
            problems.Add(
                $"--auth is '{request.AuthMode}', which this build cannot load. It supports: "
                    + $"{string.Join(", ", AuthModes.All)}.");
        }

        if (string.IsNullOrWhiteSpace(request.Subject))
        {
            problems.Add("--subject is required. It is what the grant table is keyed on.");
        }

        if (request.AuthMode == AuthModes.OAuth)
        {
            // Both, or neither works: the issuer decides whose tokens are trusted and the resource
            // decides which audience this server answers to. A token minted for something else is
            // refused on its audience, which reads as a credential problem and is a configuration
            // one - so it is worth being refused here instead.
            foreach (var (value, flag) in new[] { (request.Issuer, "--issuer"), (request.Resource, "--resource") })
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    problems.Add($"{flag} is required with --auth {AuthModes.OAuth}.");
                }
                else if (!value.StartsWith("https://", StringComparison.Ordinal))
                {
                    problems.Add($"{flag} is '{value}', which is not an https URL.");
                }
            }

            // The same rule the loader applies, and it has to be the same one: a scope this refuses
            // and the loader accepts is a tool that will not let somebody write a config that works.
            // What is refused is a scope naming a host this command was asked to declare - not a
            // shape, because `stories.read` carries a dot and names nothing. The loader warns about
            // a path separator when the file is read back, which happens a few lines below here.
            var declared = new HashSet<string>(
                request.Hosts.Select(host => host.Name),
                StringComparer.OrdinalIgnoreCase);

            foreach (var scope in request.ScopesSupported)
            {
                var named = scope
                    .Split([':', '/'], StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault(declared.Contains);

                if (named is not null)
                {
                    problems.Add(
                        $"--scopes has '{scope}', which names the host '{named}' from --host. That "
                            + "list is published unauthenticated, so a scope naming a host publishes "
                            + "it. Keep scopes coarse and let the grant table decide what a caller "
                            + "reaches.");
                }
            }
        }

        if (!File.Exists(request.IdentityFile))
        {
            // Refused rather than scaffolded around, because a config naming a key that is not
            // there does not start - and finding that out from a startup failure after `init`
            // reported success is worse than being told now.
            problems.Add(
                $"--identity-file is '{request.IdentityFile}', which does not exist. Make one for "
                    + $"this process alone with 'ssh-keygen -t ed25519 -f {request.IdentityFile} "
                    + "-N \"\"', and authorize its public half on the targets.");
        }

        foreach (var host in request.Hosts)
        {
            if (string.IsNullOrWhiteSpace(host.Name))
            {
                problems.Add("--host needs a name before the '='.");
                continue;
            }

            if (!HostFingerprint.IsValid(host.Fingerprint ?? string.Empty, out var problem))
            {
                // The validator's own sentence, with its <host> placeholder filled in rather than a
                // second sentence appended. Both carried the same ssh-keyscan command, so the
                // refusal told the operator twice how to read a fingerprint and once what was
                // wrong with theirs.
                problems.Add(
                    $"--host '{host.Name}' fingerprint "
                        + problem.Replace("<host>", host.Name, StringComparison.Ordinal)
                        + ".");
            }
        }

        if (request.Hosts.Count > 0 && string.IsNullOrWhiteSpace(request.SshUser))
        {
            problems.Add(
                "--ssh-user is required when a host is given. It is the unix account commands run "
                    + "as, and the boundary that cannot be worked around - give it its own narrow "
                    + "account rather than one that can already do everything.");
        }

        foreach (var tool in request.Tools.Where(tool => !ToolNames.All.Contains(tool)))
        {
            problems.Add($"--tools names '{tool}', which is not one of: {string.Join(", ", ToolNames.All)}.");
        }

        // The same rule the loader enforces, one step earlier and with the flag names rather than
        // the key names. A rule naming a read tool and no selector could never allow a read, so
        // writing the file and letting startup refuse it would be this command reporting success
        // for a configuration that does not start.
        var reads = request.Tools
            .Where(ResourceArguments.PathArgumentByTool.ContainsKey)
            .ToList();

        if (reads.Count > 0 && request.Paths.Count == 0 && request.Units.Count == 0)
        {
            problems.Add(
                $"--tools names {string.Join(" and ", reads)}, which read a path or a unit - so the "
                    + "rule needs --paths, --units, or both. Without one it could never allow a "
                    + "read, and that is a rule that looks like it works.");
        }

        foreach (var path in request.Paths.Where(path => !path.StartsWith('/')))
        {
            problems.Add($"--paths has '{path}', which is not absolute.");
        }

        return problems;
    }

    /// <summary>Renders the file.</summary>
    /// <param name="request">What the operator supplied. Assumed to have no problems.</param>
    /// <param name="token">The credential, from <see cref="NewToken" />.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <remarks>
    /// Deliberately shorter than the shipped example. The example teaches - it carries the reasoning
    /// behind every key, and reading it is worth an afternoon. This is what a deployment runs, so it
    /// says what was chosen and points at the example for why, rather than repeating six hundred
    /// words the operator has already decided about.
    /// </remarks>
    public static string Render(ScaffoldRequest request, string token)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(token);

        var text = new StringBuilder();

        text.Append("# Written by 'sshwarden init'. Every key here has a documented default and a\n");
        text.Append("# reason, both in hosts/SshWarden.Server/sshwarden.example.toml.\n");
        text.Append("#\n");

        // Two sentences, because one of them is false in the other mode. An oauth config carries no
        // credential at all - the token is minted by the authorization server - and a header saying
        // it does sends somebody looking for a secret that is not there, on the same reasoning that
        // stopped this command printing a generated token in that mode.
        text.Append(request.AuthMode == AuthModes.OAuth
            ? "# Nothing in this file is a credential - callers authenticate against the\n"
                + "# authorization server. It must still stay mode 0600 or the process refuses to\n"
                + "# start: it decides which hosts this server reaches and as which unix account.\n\n"
            : "# This file holds a credential. It must stay mode 0600 or the process refuses\n"
                + "# to start.\n\n");

        text.Append("[server]\n");
        text.Append(Quoted("listen", request.Listen));
        text.Append('\n');

        text.Append("[auth]\n");
        text.Append(Quoted("mode", request.AuthMode));
        text.Append('\n');

        if (request.AuthMode == AuthModes.OAuth)
        {
            text.Append("# The authorization server whose access tokens this trusts, and the name this\n");
            text.Append("# server answers to in a token's audience. Neither is a secret; there is no\n");
            text.Append("# client secret here because v0 does not introspect.\n");
            text.Append("[auth.oauth]\n");
            text.Append(Quoted("issuer", request.Issuer!));
            text.Append(Quoted("resource", request.Resource!));

            if (request.ScopesSupported.Count > 0)
            {
                text.Append("\n# Published unauthenticated in the RFC 9728 document, so never a host, a\n");
                text.Append("# path or a tenant. Which machine a caller reaches is [[grant]]'s decision.\n");
                text.Append(List("scopes_supported", request.ScopesSupported));
            }

            text.Append('\n');
        }
        else
        {
            text.Append("# A static token does not expire and cannot be revoked except by editing this\n");
            text.Append("# file and restarting.\n");
            text.Append("[[auth.static_token]]\n");
            text.Append(Quoted("name", request.TokenName));
            text.Append(Quoted("subject", request.Subject));
            text.Append(Quoted("token", token));
            text.Append('\n');
        }

        if (request.Hosts.Count > 0)
        {
            text.Append("[ssh]\n");
            text.Append(Quoted("identity_file", request.IdentityFile));
            text.Append('\n');

            foreach (var host in request.Hosts)
            {
                text.Append("# Verified out of band, not scanned: a fingerprint read off the network\n");
                text.Append("# is one verified by whoever answered.\n");
                text.Append("[[host]]\n");
                text.Append(Quoted("name", host.Name));
                text.Append(Quoted("fingerprint", host.Fingerprint));
                text.Append('\n');
            }

            text.Append("# Deny by default: a call no rule covers is refused, and the refusal says\n");
            text.Append("# which rule refused it. Narrow this before it reaches anything real.\n");
            text.Append("[[grant]]\n");
            text.Append(Quoted("id", "initial"));
            text.Append(Quoted("subject", request.Subject));
            text.Append(List("tools", request.Tools));
            text.Append(List("hosts", [.. request.Hosts.Select(host => host.Name)]));

            if (request.Paths.Count > 0)
            {
                text.Append(List("paths", request.Paths));
            }

            if (request.Units.Count > 0)
            {
                text.Append(List("units", request.Units));
            }

            text.Append(Quoted("ssh_user", request.SshUser!));
            text.Append('\n');
        }

        text.Append("# Every call - allowed, refused or failed - appends one JSON line here. It\n");
        text.Append("# contains output from your hosts, so it stays on the machine that wrote it.\n");
        text.Append("[audit]\n");
        text.Append(Quoted("path", Path.Combine(request.StateDirectory, "audit.jsonl").Replace("\\", "/", StringComparison.Ordinal)));
        text.Append('\n');

        text.Append("# On disk, because a job outlives a restart of this server and an in-memory\n");
        text.Append("# registry would leave every running job unowned after a deploy.\n");
        text.Append("[jobs]\n");
        text.Append(Quoted("registry", Path.Combine(request.StateDirectory, "jobs.jsonl").Replace("\\", "/", StringComparison.Ordinal)));

        return text.ToString();
    }

    private static string Quoted(string key, string value)
        => string.Create(CultureInfo.InvariantCulture, $"{key} = \"{Escape(value)}\"\n");

    private static string List(string key, IReadOnlyList<string> values)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"{key} = [{string.Join(", ", values.Select(value => $"\"{Escape(value)}\""))}]\n");

    /// <summary>Escapes a value for a TOML basic string.</summary>
    /// <remarks>
    /// Backslash and quote only, which is what the values here can contain: a Windows path and a
    /// name somebody chose. It is here rather than assumed away because a generator whose output
    /// does not parse produces a file that fails at startup on somebody else's machine.
    /// </remarks>
    private static string Escape(string value)
        => value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
