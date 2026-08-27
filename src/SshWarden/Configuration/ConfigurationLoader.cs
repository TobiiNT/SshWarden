using Tomlyn;
using Tomlyn.Model;

namespace SshWarden.Configuration;

/// <summary>Reads and validates the config file.</summary>
/// <remarks>
/// <para>
/// This file is the security surface of a SshWarden deployment: it holds the credentials that reach
/// the SSH layer, and from step 2 it will hold the grant table that decides who reaches which host.
/// docs/DESIGN.md §6.4 asks that reading it tells you immediately who can touch what. That puts two
/// obligations on the loader, and both are enforced here rather than documented:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <strong>Unknown keys are refused.</strong> A misspelled table is a rule that silently does
///       not apply - the config says one thing and the process does another, with nothing to see.
///       This is the direction that costs an incident rather than a restart.
///     </description>
///   </item>
///   <item>
///     <description>
///       <strong>Every problem is reported at once.</strong> One restart per typo is how a config
///       fix at 3am becomes an hour.
///     </description>
///   </item>
/// </list>
/// </remarks>
public static partial class ConfigurationLoader
{
    /// <summary>
    /// The shortest credential the loader accepts, in characters.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A static token never expires, so the only thing standing between the internet and SSH access
    /// to a production host is that the credential cannot be guessed. Thirty-two characters is
    /// below what the documented way of generating one produces and far above anything a person
    /// types, so the rule costs a correct deployment nothing.
    /// </para>
    /// <para>
    /// It is also what stops the example config from working. A file shipped with a placeholder
    /// where the credential goes is a file somebody will run unedited; the placeholder is short, so
    /// it is refused by a rule that exists anyway rather than by a list of forbidden strings that
    /// would have to guess what people write.
    /// </para>
    /// </remarks>
    public const int MinimumTokenLength = 32;

    /// <summary>Reads the config file at <paramref name="path" />.</summary>
    /// <param name="path">Path to the TOML config file.</param>
    /// <returns>The configuration, and anything worth saying about it that is not fatal.</returns>
    /// <exception cref="ArgumentException"><paramref name="path" /> is null or whitespace.</exception>
    /// <exception cref="SshWardenConfigurationException">
    /// The file is missing, unreadable, not valid TOML, or does not describe a configuration this
    /// process will run under. Carries every problem found.
    /// </exception>
    public static ConfigurationLoadResult Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var problems = new List<string>();
        var warnings = new List<string>();

        if (!File.Exists(path))
        {
            // Thrown on its own rather than collected: with no file there is nothing else to check,
            // and a list of consequential problems would bury the one that caused them.
            throw new SshWardenConfigurationException(path, [
                $"No config file at '{path}'. SshWarden reads its listen address and its "
                    + "credentials from a file rather than from command-line arguments, because an "
                    + "argument is visible to every process on the machine through 'ps'.",
            ]);
        }

        CheckFilePermissions(path, problems, warnings);

        var text = File.ReadAllText(path);

        TomlTable root;
        try
        {
            root = TomlSerializer.Deserialize<TomlTable>(text)!;
        }
        catch (TomlException syntax)
        {
            // Every diagnostic, not just the one that stopped the parse, and each keeps the line and
            // column Tomlyn reports so the operator can go straight there. The file name is prefixed
            // here because nothing in the parse call carries it.
            foreach (var diagnostic in syntax.Diagnostics)
            {
                problems.Add($"{path}{diagnostic}");
            }

            if (problems.Count == 0)
            {
                problems.Add($"{path} is not valid TOML: {syntax.Message}");
            }

            // A document that did not parse has no model to validate, so continuing would report
            // absences caused by the syntax error as if they were separate mistakes.
            throw new SshWardenConfigurationException(path, problems);
        }

        var server = ReadServer(root, problems);

        // Hosts before auth, because the scope check below needs to know which names this
        // deployment actually has before it can say a scope publishes one.
        var hosts = ReadHosts(root, problems);
        var auth = ReadAuth(root, hosts, problems, warnings);
        var ssh = ReadSsh(root, hosts.Count > 0, problems);
        var grants = ReadGrants(root, hosts, problems, warnings);
        var audit = ReadAudit(root, problems);
        var output = ReadOutput(root, problems);
        var watch = ReadWatch(root, problems, warnings);
        var jobs = ReadJobs(root, audit.Path, problems);
        var metrics = ReadMetrics(root, problems);

        RefuseUnknownKeys(
            root,
            ["server", "auth", "ssh", "host", "grant", "audit", "output", "watch", "jobs", "metrics"],
            keyPath: string.Empty,
            problems);

        if (problems.Count > 0)
        {
            throw new SshWardenConfigurationException(path, problems);
        }

        WarnAboutListenAddress(server!, warnings);
        WarnAboutAnEmptyReach(hosts, grants, warnings);

        return new ConfigurationLoadResult
        {
            Configuration = new SshWardenConfiguration
            {
                Server = server!,
                Auth = auth!,
                Ssh = ssh,
                Hosts = hosts,
                Grants = grants,
                Audit = audit,
                Output = output,
                Watch = watch,
                Jobs = jobs,
                Metrics = metrics,
            },
            Warnings = warnings,
        };
    }

    private static AuditSection ReadAudit(TomlTable root, List<string> problems)
    {
        var section = TryGetTable(root, "audit", problems, out var table)
            ? new AuditSection { Path = ReadString(table, "path", "audit.path", problems) ?? new AuditSection().Path }
            : new AuditSection();

        if (table.Count > 0)
        {
            RefuseUnknownKeys(table, ["path"], "audit", problems);
        }

        CheckAuditPathIsWritable(section.Path, problems);
        return section;
    }

    private static void CheckAuditPathIsWritable(string path, List<string> problems)
    {
        // Opened and closed here rather than trusted until the first tool call. The first tool call
        // is the worst moment to discover the log is unwritable: the command has already run on the
        // target host, so refusing then loses the record of something that happened, and proceeding
        // then produces the silent no-record case this check exists to prevent.
        try
        {
            var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var probe = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException
            or NotSupportedException or ArgumentException)
        {
            problems.Add(
                $"The audit log at '{path}' cannot be written: {failure.Message} SshWarden will not "
                    + "run commands it cannot record - that is the whole reason it sits between the "
                    + "caller and the host. Set audit.path somewhere this process can append.");
        }
    }

    private static void CheckPrivateKey(string path, List<string> problems)
    {
        if (!File.Exists(path))
        {
            // Absence used to be left to the SSH layer, on the reasoning that a key at a path that
            // does not exist yet is a deployment mid-setup and that saying "permissions" about a
            // file that is not there would be the wrong complaint. The first half still holds; the
            // second half assumed the SSH layer would report it, and it does not. It throws
            // DirectoryNotFoundException out of the container while the endpoints are being mapped,
            // so what an operator got for a key they had not generated yet was thirty lines of
            // stack trace naming Renci.SshNet - measured by starting the server against the example
            // config on 2026-08-26. Refused here instead, where it is one line among all the other
            // problems in the file rather than one per restart.
            problems.Add(
                $"ssh.identity_file is '{path}', which does not exist. Every host reached by this "
                    + "deployment is reached with that key, so nothing would work: generate one "
                    + $"with 'ssh-keygen -t ed25519 -f {path} -N \"\"' and authorize its public "
                    + "half on the targets.");

            return;
        }

        // The same rule as the config file, for the same reason and with a sharper edge: a private
        // key another account can read is a private key that account has.
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var offending = File.GetUnixFileMode(path) & ReachableByOthers;
        if (offending != UnixFileMode.None)
        {
            problems.Add(
                $"The private key at '{path}' is readable beyond its owner (mode grants "
                    + $"{offending}). Anyone who can read it can be SshWarden: 'chmod 600 {path}'.");
        }
    }

    private const UnixFileMode ReachableByOthers =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    private static bool TryGetTableArray(
        TomlTable parent,
        string key,
        List<string> problems,
        out TomlTableArray blocks)
    {
        blocks = [];

        if (!parent.TryGetValue(key, out var raw))
        {
            return false;
        }

        if (raw is not TomlTableArray found)
        {
            problems.Add(
                $"{key} must be written as repeated [[{key}]] blocks.");
            return false;
        }

        blocks = found;
        return true;
    }

    private static List<string>? ReadStringArray(
        TomlTable table,
        string key,
        string keyPath,
        List<string> problems)
    {
        if (!table.TryGetValue(key, out var raw))
        {
            return null;
        }

        if (raw is not TomlArray array)
        {
            problems.Add($"{keyPath} must be an array of strings.");
            return null;
        }

        var values = new List<string>(array.Count);
        foreach (var item in array)
        {
            if (item is not string text || string.IsNullOrWhiteSpace(text))
            {
                problems.Add($"{keyPath} must contain only non-empty strings.");
                return null;
            }

            values.Add(text);
        }

        return values;
    }

    private static int? ReadPositiveInteger(
        TomlTable table,
        string key,
        string keyPath,
        List<string> problems)
    {
        if (!table.TryGetValue(key, out var raw))
        {
            return null;
        }

        if (raw is not long value || value is < 1 or > int.MaxValue)
        {
            problems.Add($"{keyPath} must be a positive whole number.");
            return null;
        }

        return (int)value;
    }

    private static void WarnAboutAnEmptyReach(
        List<HostEntry> hosts,
        List<Authorization.Grant> grants,
        List<string> warnings)
    {
        // Neither is a reason to refuse to start - a deployment mid-setup is a real state, and the
        // refusals a caller gets in the meantime are correct and legible. But a server that cannot
        // do anything should say so once at startup rather than only in the tool result of whoever
        // tries first.
        if (hosts.Count == 0)
        {
            warnings.Add(
                "No [[host]] is declared, so there is nowhere to run a command. Every tool call "
                    + "will be refused.");
        }

        if (grants.Count == 0)
        {
            warnings.Add(
                "No [[grant]] is declared. The grant table is deny-by-default, so every tool call "
                    + "will be refused and every tool listing will be empty.");
        }
    }

    private static void CheckFilePermissions(string path, List<string> problems, List<string> warnings)
    {
        if (OperatingSystem.IsWindows())
        {
            // Windows has ACLs rather than a mode, and the shape of "is this file readable by
            // anybody else" is a different question there. Recorded as not measured rather than
            // passed: a check that quietly returns true where it cannot run is how a deployment
            // comes to believe a file is protected because nothing complained.
            warnings.Add(
                $"The permissions of '{path}' were not checked: this is not a Unix filesystem, "
                    + "so the mode-0600 rule does not apply as written. Whether the credentials in "
                    + "this file are readable by other accounts on this machine is unmeasured, not "
                    + "confirmed.");
            return;
        }

        var offending = File.GetUnixFileMode(path) & ReachableByOthers;
        if (offending != UnixFileMode.None)
        {
            problems.Add(
                $"'{path}' is readable beyond its owner (mode grants {offending}). It holds the "
                    + "credentials that reach the SSH layer, so it must be mode 0600: "
                    + $"'chmod 600 {path}'.");
        }
    }

    private static ServerSection? ReadServer(TomlTable root, List<string> problems)
    {
        if (!TryGetTable(root, "server", problems, out var table))
        {
            // Every key in [server] has a default, so an absent table is a complete answer rather
            // than a missing one. [auth] below is the opposite, and deliberately so.
            return new ServerSection();
        }

        var listen = ReadString(table, "listen", "server.listen", problems) ?? "127.0.0.1:8760";
        var mcpPath = ReadString(table, "mcp_path", "server.mcp_path", problems) ?? "/mcp";

        if (!TryParseListenAddress(listen, out _, out _))
        {
            problems.Add(
                $"server.listen is '{listen}', which is not 'host:port'. Use an address and a port, "
                    + "for example '127.0.0.1:8760' or '[::1]:8760'.");
        }

        if (!mcpPath.StartsWith('/'))
        {
            problems.Add($"server.mcp_path is '{mcpPath}', which must start with '/'.");
        }

        RefuseUnknownKeys(table, ["listen", "mcp_path"], "server", problems);

        return new ServerSection { Listen = listen, McpPath = mcpPath };
    }

    private static AuthSection? ReadAuth(
        TomlTable root,
        IReadOnlyList<HostEntry> hosts,
        List<string> problems,
        List<string> warnings)
    {
        if (!TryGetTable(root, "auth", problems, out var table))
        {
            problems.Add(
                "There is no [auth] table. SshWarden refuses to start without a way to "
                    + "authenticate a caller - there is no mode that skips it, because this "
                    + "process runs commands on other people's production hosts.");
            return null;
        }

        var mode = ReadString(table, "mode", "auth.mode", problems);
        if (mode is null)
        {
            problems.Add(
                "auth.mode is not set. Supported: " + string.Join(", ", AuthModes.All) + ".");
        }
        else if (!AuthModes.All.Contains(mode, StringComparer.Ordinal))
        {
            problems.Add(
                $"auth.mode is '{mode}', which this build does not support. Supported: "
                    + string.Join(", ", AuthModes.All) + ".");
        }

        var tokens = ReadStaticTokens(table, problems, out var declared);

        // Declared, not valid. A block that was written and then rejected for a missing subject is
        // a different problem from no block at all, and saying "add one" to somebody who wrote one
        // sends them to fix the wrong thing - on top of the problem that actually names their
        // mistake, which is already in this list.
        if (mode == AuthModes.StaticToken && declared == 0)
        {
            problems.Add(
                $"auth.mode is '{AuthModes.StaticToken}' but no [[auth.static_token]] blocks were "
                    + "found, so nobody could ever authenticate. Add at least one with a name, a "
                    + "subject and a token.");
        }

        var oauth = ReadOAuth(table, hosts, problems, warnings);

        if (mode == AuthModes.OAuth && oauth is null)
        {
            problems.Add(
                $"auth.mode is '{AuthModes.OAuth}' but there is no [auth.oauth] table, so there is "
                    + "no authorization server to trust and nobody could ever authenticate. It needs "
                    + "an issuer and a resource.");
        }

        RefuseUnknownKeys(table, ["mode", "static_token", "oauth"], "auth", problems);

        return mode is null
            ? null
            : new AuthSection { Mode = mode, StaticTokens = tokens, OAuth = oauth };
    }

    private static OAuthSection? ReadOAuth(
        TomlTable auth,
        IReadOnlyList<HostEntry> hosts,
        List<string> problems,
        List<string> warnings)
    {
        if (!TryGetTable(auth, "oauth", problems, out var table))
        {
            return null;
        }

        var issuer = ReadString(table, "issuer", "auth.oauth.issuer", problems);
        var resource = ReadString(table, "resource", "auth.oauth.resource", problems);

        foreach (var (value, key) in new[] { (issuer, "issuer"), (resource, "resource") })
        {
            if (value is null)
            {
                problems.Add($"auth.oauth.{key} is not set.");
            }
            else if (!value.StartsWith("https://", StringComparison.Ordinal))
            {
                // https only, and not negotiable. Both of these decide who this server trusts and
                // what it answers to; over plain http either can be rewritten in transit by whoever
                // carries the packets, and the failure looks like a working deployment.
                problems.Add($"auth.oauth.{key} is '{value}', which is not an https URL.");
            }
            else if (value.AsSpan().IndexOfAny('"', '\\') >= 0)
            {
                // Both of these values are spliced into a `WWW-Authenticate` header, where RFC 6750
                // §3 wraps every parameter in a quoted string. An embedded quote ends that string
                // early and everything after it - including the `resource_metadata` pointer a client
                // needs - is read as something else entirely. Refused here rather than escaped at
                // the header, because neither value has any business containing one: RFC 3986 does
                // not permit a raw quote or backslash in a URI, so a value carrying either is
                // already not the URL somebody meant to write.
                problems.Add(
                    $"auth.oauth.{key} contains a quote or a backslash. Neither is legal in a URI, "
                        + "and both would end a WWW-Authenticate parameter early - a client would "
                        + "read the rest of the challenge as something other than what it says.");
            }
        }

        var scopes = ReadStringArray(table, "scopes_supported", "auth.oauth.scopes_supported", problems);

        CheckScopesPublishNothing(scopes ?? [], hosts, problems, warnings);
        CheckScopesAreScopeTokens(scopes ?? [], problems);

        var allowPrivateIssuer = ReadBoolean(table, "allow_private_issuer", "auth.oauth.allow_private_issuer", problems)
            ?? false;

        if (allowPrivateIssuer)
        {
            // Warned about every start rather than only where it was written. Someone reading this
            // process's log to work out why it trusts what it trusts should not have to also be
            // holding the config file, and a check that was turned on for one afternoon and left on
            // is the failure mode this catches.
            warnings.Add(
                "auth.oauth.allow_private_issuer is on, so the fetch of the authorization "
                    + "server's metadata and signing keys may reach a loopback or private address. "
                    + "Correct for an authorization server on this network; nothing else needs it.");
        }

        // The three claim names, each defaulting to what an authorization server most often emits.
        // Read through one helper because the failure is the same for all three: a name that is
        // present and empty is a key somebody meant to set and did not, and reading it as "use the
        // default" would silently ignore what they wrote.
        var defaults = new OAuthSection { Issuer = "https://example.com", Resource = "https://example.com" };

        var clientIdClaim = ReadClaimName(table, "client_id_claim", defaults.ClientIdClaim, problems);
        var tokenIdClaim = ReadClaimName(table, "token_id_claim", defaults.TokenIdClaim, problems);
        var grantIdClaim = ReadClaimName(table, "grant_id_claim", defaults.GrantIdClaim, problems);

        RefuseUnknownKeys(
            table,
            [
                "issuer",
                "resource",
                "scopes_supported",
                "allow_private_issuer",
                "client_id_claim",
                "token_id_claim",
                "grant_id_claim",
            ],
            "auth.oauth",
            problems);

        return issuer is null || resource is null
            ? null
            : new OAuthSection
            {
                Issuer = issuer,
                Resource = resource,
                ScopesSupported = scopes ?? [],
                AllowPrivateIssuer = allowPrivateIssuer,
                ClientIdClaim = clientIdClaim,
                TokenIdClaim = tokenIdClaim,
                GrantIdClaim = grantIdClaim,
            };
    }

    /// <summary>Reads one claim-name setting, or the default when it is not there.</summary>
    /// <remarks>
    /// A key that is present and empty is refused rather than treated as absent. Somebody who wrote
    /// <c>grant_id_claim = ""</c> meant something by it, and the two readings - "use the default"
    /// and "there is no such claim" - are opposite; guessing either one is a decision the config
    /// file appears to have made and did not.
    /// </remarks>
    private static string ReadClaimName(TomlTable table, string key, string fallback, List<string> problems)
    {
        var value = ReadString(table, key, $"auth.oauth.{key}", problems);

        if (value is null)
        {
            return fallback;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            problems.Add(
                $"auth.oauth.{key} is empty. Name the claim your authorization server emits, or "
                    + $"remove the key to use '{fallback}'.");

            return fallback;
        }

        return value;
    }

    /// <summary>Refuses a published scope that names something this deployment has.</summary>
    /// <remarks>
    /// <para>
    /// The RFC 9728 document is unauthenticated, so <c>scopes_supported</c> is read by anyone who
    /// asks. docs/DESIGN.md §6.5.4 keeps scopes coarse for that reason: <c>ssh:exec</c>, never
    /// <c>ssh:exec:prod-web-1:/opt/app</c>, because the second publishes a production hostname to
    /// the internet and the grant table already decides which machine a call reaches.
    /// </para>
    /// <para>
    /// <strong>What is checked is a name this file declares, not a shape.</strong> The first
    /// version of this rule refused any scope containing a dot or a slash, which reads as a
    /// hostname test and is not one: <c>stories.read</c> and <c>ssh.exec</c> carry a dot and name
    /// nothing, and an authorization server whose scopes are URLs is a configuration somebody has.
    /// Refusing those is a loader that rejects a correct deployment to enforce a guess. Comparing
    /// against the hosts declared a few lines above is the same rule, checkable: it refuses exactly
    /// the disclosure the section is about, and it cannot refuse a scope that discloses nothing.
    /// </para>
    /// <para>
    /// It follows that a scope naming a host this file does not declare passes. That is the honest
    /// boundary rather than a gap to paper over - this process cannot know what somebody else's
    /// hostnames are, and a rule that guessed would be the dot check again.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Refuses a scope that is not a scope, by RFC 6749 §3.3's own definition of one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §3.3 defines a scope as one or more <c>scope-token</c>s separated by spaces, and a
    /// <c>scope-token</c> as <c>%x21 / %x23-5B / %x5D-7E</c> - printable ASCII without the space,
    /// the double quote and the backslash. This list is published in the metadata document and
    /// spliced into the <c>scope</c> parameter of every challenge, so a value outside that set
    /// breaks in two different ways at once.
    /// </para>
    /// <para>
    /// <strong>A space is the one somebody writes by accident.</strong> <c>scopes_supported = ["ssh
    /// run"]</c> reads as one scope and is two, and the metadata document publishes a name no
    /// authorization server will ever issue - so every client asks for something that cannot be
    /// granted, and the failure arrives as an authorization error with a correct-looking config
    /// file behind it.
    /// </para>
    /// <para>
    /// <strong>A quote is the one that changes what a client reads.</strong> RFC 6750 §3 wraps
    /// challenge parameters in quoted strings; an embedded quote ends the <c>scope</c> parameter
    /// early and the <c>resource_metadata</c> pointer after it stops being a parameter at all.
    /// Refused at the file rather than escaped at the header, because a scope containing one is not
    /// a scope any authorization server would accept either.
    /// </para>
    /// </remarks>
    private static void CheckScopesAreScopeTokens(IReadOnlyList<string> scopes, List<string> problems)
    {
        // An empty entry never reaches here: ReadStringArray refuses one and returns null, so this
        // is handed an empty list rather than a list with an empty string in it. Checking for it
        // again would be a branch no input can take, carrying a comment describing a rule that
        // lives somewhere else.
        foreach (var scope in scopes)
        {
            // By index rather than by FirstOrDefault, and that is not a style preference: the
            // value FirstOrDefault returns when it finds nothing is '\0', which is itself outside
            // the permitted set - so the one scope carrying a NUL would report as clean.
            var at = -1;

            for (var i = 0; i < scope.Length; i++)
            {
                if (scope[i] is < '\x21' or '\x22' or '\x5c' or > '\x7e')
                {
                    at = i;
                    break;
                }
            }

            // Named one by one rather than reported as a class, because "which character" is the
            // whole of what the operator needs and the file may hold several scopes that look alike.
            if (at >= 0)
            {
                var offending = scope[at];

                var described = offending switch
                {
                    ' ' => "a space, which RFC 6749 §3.3 uses to separate one scope from the next",
                    '"' => "a double quote",
                    '\\' => "a backslash",
                    _ => $"U+{(int)offending:X4}",
                };

                problems.Add(
                    $"auth.oauth.scopes_supported has '{scope}', which contains {described}. RFC "
                        + "6749 §3.3 allows printable ASCII without the space, the quote or the "
                        + "backslash - this list is published to clients and named in every 401, "
                        + "so a value outside that set is one no client can act on.");
            }
        }
    }

    private static void CheckScopesPublishNothing(
        IReadOnlyList<string> scopes,
        IReadOnlyList<HostEntry> hosts,
        List<string> problems,
        List<string> warnings)
    {
        var declared = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var host in hosts)
        {
            declared.Add(host.Name);
            declared.Add(host.ResolvedAddress);
        }

        foreach (var scope in scopes)
        {
            // Segment by segment rather than by substring, so a host called `db` does not refuse
            // `ssh:dbadmin`. These are the two separators a scope of the shape section 6.5.4 warns
            // about uses, and they are the only two that mean "and then this part".
            var named = scope
                .Split([':', '/'], StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault(declared.Contains);

            if (named is not null)
            {
                problems.Add(
                    $"auth.oauth.scopes_supported has '{scope}', which names the host '{named}' "
                        + "declared in this file. That list is published unauthenticated, so this "
                        + "tells anyone who asks that the host exists. Keep scopes coarse and let "
                        + "[[grant]] decide what a caller reaches.");
            }
            else if (scope.Contains('/', StringComparison.Ordinal))
            {
                // A warning and not a refusal, because the two readings are indistinguishable from
                // here: a path inside a scope publishes a directory layout, and a scope that is
                // simply a URL is how more than one authorization server names its scopes. Refusing
                // would break the second to catch the first; saying nothing would let the first
                // through in silence.
                warnings.Add(
                    $"auth.oauth.scopes_supported has '{scope}', which contains a path separator. "
                        + "If that is a path, it is published unauthenticated along with the rest "
                        + "of this list. If it is a URL-shaped scope from the authorization server, "
                        + "nothing is wrong here.");
            }
        }
    }

    private static List<StaticTokenEntry> ReadStaticTokens(
        TomlTable auth,
        List<string> problems,
        out int declared)
    {
        declared = 0;

        if (!auth.TryGetValue("static_token", out var raw))
        {
            return [];
        }

        if (raw is not TomlTableArray blocks)
        {
            problems.Add(
                "auth.static_token must be written as repeated [[auth.static_token]] blocks, one "
                    + "per credential.");
            return [];
        }

        declared = blocks.Count;

        var entries = new List<StaticTokenEntry>(blocks.Count);
        var names = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 0; index < blocks.Count; index++)
        {
            var block = blocks[index];
            var where = $"auth.static_token[{index}]";

            var name = ReadString(block, "name", $"{where}.name", problems);
            var subject = ReadString(block, "subject", $"{where}.subject", problems);
            var token = ReadString(block, "token", $"{where}.token", problems);
            var clientId = ReadString(block, "client_id", $"{where}.client_id", problems);

            RefuseUnknownKeys(block, ["name", "subject", "token", "client_id"], where, problems);

            if (name is null)
            {
                problems.Add(
                    $"{where}.name is not set. Every refusal and every startup line names the "
                        + "token it is about, and 'token 3' is not something anybody can act on.");
            }
            else if (!names.Add(name))
            {
                problems.Add(
                    $"{where}.name is '{name}', which another block already uses. Two credentials "
                        + "with one name cannot be told apart in the audit record.");
            }

            if (subject is null)
            {
                problems.Add(
                    $"{where}.subject is not set. It is what the grant table is keyed on and what "
                        + "the audit record writes as 'sub'.");
            }

            if (token is null)
            {
                problems.Add($"{where}.token is not set.");
            }
            else if (token.Length < MinimumTokenLength)
            {
                // Says the length required and the length found; never the value, not even its
                // first characters. A short credential in a log is a whole credential to whoever
                // reads the log.
                problems.Add(
                    $"{where}.token is {token.Length} characters, and at least "
                        + $"{MinimumTokenLength} are required. A static token does not expire, so "
                        + "being unguessable is the whole of its security. Generate one with "
                        + "'openssl rand -base64 32'.");
            }

            if (name is not null && subject is not null && token is not null
                && token.Length >= MinimumTokenLength)
            {
                entries.Add(new StaticTokenEntry
                {
                    Name = name,
                    Subject = subject,
                    Token = token,
                    ClientId = clientId,
                });
            }
        }

        return entries;
    }

    private static bool TryGetTable(
        TomlTable parent,
        string key,
        List<string> problems,
        out TomlTable table)
    {
        table = [];

        if (!parent.TryGetValue(key, out var raw))
        {
            return false;
        }

        if (raw is not TomlTable found)
        {
            problems.Add($"[{key}] must be a table.");
            return false;
        }

        table = found;
        return true;
    }

    private static bool? ReadBoolean(
        TomlTable table,
        string key,
        string keyPath,
        List<string> problems)
    {
        if (!table.TryGetValue(key, out var raw))
        {
            return null;
        }

        // Refused rather than coerced. TOML has real booleans, so `enabled = "false"` is somebody
        // writing a different language - and the coercion that reads it as true is how a switch
        // turns itself on.
        if (raw is not bool value)
        {
            problems.Add($"{keyPath} must be true or false, unquoted.");
            return null;
        }

        return value;
    }

    private static string? ReadString(
        TomlTable table,
        string key,
        string keyPath,
        List<string> problems)
    {
        if (!table.TryGetValue(key, out var raw))
        {
            return null;
        }

        if (raw is not string text)
        {
            problems.Add($"{keyPath} must be a string.");
            return null;
        }

        // Whitespace-only is treated as absent rather than accepted. A key present with an empty
        // value reads to the writer as "set", and there is no case here where the empty string is
        // the intended value.
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static void RefuseUnknownKeys(
        TomlTable table,
        IReadOnlyCollection<string> known,
        string keyPath,
        List<string> problems)
    {
        foreach (var key in table.Keys)
        {
            if (known.Contains(key, StringComparer.Ordinal))
            {
                continue;
            }

            var where = keyPath.Length == 0 ? key : $"{keyPath}.{key}";
            problems.Add(
                $"'{where}' is not something this build reads, so whatever it was meant to "
                    + "configure is not configured. Known keys here: "
                    + string.Join(", ", known) + ".");
        }
    }

    private static void WarnAboutListenAddress(ServerSection server, List<string> warnings)
    {
        if (!TryParseListenAddress(server.Listen, out var host, out _))
        {
            return;
        }

        if (IsLoopback(host))
        {
            return;
        }

        warnings.Add(
            $"server.listen is '{server.Listen}', which is not loopback. Clients reach SshWarden "
                + "from the internet, so something has to be publicly reachable - but the intended "
                + "shape is a reverse proxy terminating TLS in front of a loopback listener. A "
                + "socket open to the world is this process answering unauthenticated requests "
                + "directly.");
    }

    private static bool IsLoopback(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return System.Net.IPAddress.TryParse(host, out var address)
            && System.Net.IPAddress.IsLoopback(address);
    }

    private static bool TryParseListenAddress(string value, out string host, out int port)
    {
        host = string.Empty;
        port = 0;

        var separator = value.LastIndexOf(':');
        if (separator <= 0 || separator == value.Length - 1)
        {
            return false;
        }

        if (!int.TryParse(value[(separator + 1)..], out port) || port is < 1 or > 65535)
        {
            return false;
        }

        // A bracketed IPv6 literal keeps its own colons, so the brackets come off only after the
        // port has been split from the right. Written out rather than handed to System.Uri, which
        // would rewrite the host on the way through.
        host = value[..separator].Trim('[', ']');
        return host.Length > 0;
    }
}

/// <summary>What <see cref="ConfigurationLoader.Load" /> produced.</summary>
public sealed class ConfigurationLoadResult
{
    /// <summary>The configuration this process will run under.</summary>
    public required SshWardenConfiguration Configuration { get; init; }

    /// <summary>
    /// Things worth saying that are not reasons to refuse - including anything the loader could not
    /// check rather than checked and passed.
    /// </summary>
    /// <remarks>
    /// Kept separate from the problems because the two need opposite handling: a problem stops the
    /// process, a warning has to be visible without stopping it. Collapsing them either turns an
    /// unmeasured permission check into a refusal to start, or turns a public listener into a line
    /// nobody sees.
    /// </remarks>
    public required IReadOnlyList<string> Warnings { get; init; }
}
