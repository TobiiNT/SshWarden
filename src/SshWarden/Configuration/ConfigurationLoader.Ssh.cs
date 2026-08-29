using SshWarden.Authorization;

using Tomlyn.Model;

namespace SshWarden.Configuration;

/// <summary>
/// The parts of the config file that describe reaching a host and who may do it.
/// </summary>
public static partial class ConfigurationLoader
{
    /// <summary>
    /// Keys the design has settled on that this build has no handler for yet, and which step each
    /// arrives at.
    /// </summary>
    /// <remarks>
    /// Refused with their own message rather than falling into the generic unknown-key one. A
    /// reader who copies <c>paths</c> out of the design notes has not made a typo, and telling them
    /// "unknown key" would send them looking for one. Accepting it and gating nothing is the worse
    /// option: a path selector that parses and does not apply is a boundary somebody believes in.
    /// </remarks>
    private static readonly Dictionary<string, string> ReservedGrantKeys = new(StringComparer.Ordinal);

    /// <summary>The same, for <c>[ssh]</c>.</summary>
    private static readonly Dictionary<string, string> ReservedSshKeys = new(StringComparer.Ordinal)
    {
        ["max_output_bytes"] = "has arrived, as [output].max_bytes. It moved because it is not an "
            + "SSH setting: the tools that read files and tail logs are bounded by the same number, "
            + "and none of them are this table's business. Named here rather than left to the "
            + "generic unknown-key message so that anybody who read the note this replaces is sent "
            + "to the right place.",
    };

    private static SshSection? ReadSsh(TomlTable root, bool anyHosts, List<string> problems)
    {
        if (!TryGetTable(root, "ssh", problems, out var table))
        {
            if (anyHosts)
            {
                problems.Add(
                    "There are [[host]] blocks but no [ssh] table, so there is no key to reach them "
                        + "with. Set ssh.identity_file.");
            }

            return null;
        }

        var identityFile = ReadString(table, "identity_file", "ssh.identity_file", problems);
        if (identityFile is null)
        {
            problems.Add(
                "ssh.identity_file is not set. It should be a key made for this process alone: the "
                    + "unix account a key lands in is the boundary that actually holds, and a key "
                    + "with broad reach picks that account before the grant table gets a say.");
        }
        else
        {
            CheckPrivateKey(identityFile, problems);
        }

        var connectTimeout = ReadPositiveInteger(table, "connect_timeout_sec", "ssh.connect_timeout_sec", problems) ?? 15;
        var idleEviction = ReadPositiveInteger(table, "idle_eviction_sec", "ssh.idle_eviction_sec", problems) ?? 300;
        var defaultTimeout = ReadPositiveInteger(table, "default_timeout_sec", "ssh.default_timeout_sec", problems) ?? 60;
        var maxTimeout = ReadPositiveInteger(table, "max_timeout_sec", "ssh.max_timeout_sec", problems) ?? 900;

        if (defaultTimeout > maxTimeout)
        {
            problems.Add(
                $"ssh.default_timeout_sec is {defaultTimeout} and ssh.max_timeout_sec is "
                    + $"{maxTimeout}, so the default is above the ceiling and every call that does "
                    + "not name a timeout would be refused for asking too much.");
        }
        RefuseReservedKeys(ReservedSshKeys, table, "ssh", problems);
        RefuseUnknownKeys(
            table,
            [
                "identity_file", "connect_timeout_sec", "idle_eviction_sec",
                "default_timeout_sec", "max_timeout_sec",
            ],
            "ssh",
            problems);

        return identityFile is null
            ? null
            : new SshSection
            {
                IdentityFile = identityFile,
                ConnectTimeoutSeconds = connectTimeout,
                IdleEvictionSeconds = idleEviction,
                DefaultTimeoutSeconds = defaultTimeout,
                MaxTimeoutSeconds = maxTimeout,
            };
    }

    private static OutputSection ReadOutput(TomlTable root, List<string> problems)
    {
        if (!TryGetTable(root, "output", problems, out var table))
        {
            return new OutputSection();
        }

        var maxBytes = ReadPositiveInteger(table, "max_bytes", "output.max_bytes", problems)
            ?? new OutputSection().MaxBytes;

        // A budget below this cannot hold the head, the tail and the marker that says what was
        // dropped - it would produce output that is almost entirely an explanation of its own
        // absence. Refused rather than silently raised, because a number in this file should mean
        // what it says.
        const int Floor = 1024;
        if (maxBytes < Floor)
        {
            problems.Add(
                $"output.max_bytes is {maxBytes}, which is below {Floor}. Below that there is no "
                    + "room for a head, a tail and the marker naming what was cut, so the answer "
                    + "would be mostly marker.");
        }

        RefuseUnknownKeys(table, ["max_bytes"], "output", problems);
        return new OutputSection { MaxBytes = maxBytes };
    }

    private static JobsSection ReadJobs(TomlTable root, string auditPath, List<string> problems)
    {
        var beside = BesideTheAuditLog(auditPath);
        var defaults = new JobsSection { Registry = beside };

        if (!TryGetTable(root, "jobs", problems, out var table))
        {
            CheckJobRegistryIsWritable(defaults.Registry, problems);
            return defaults;
        }

        var registry = ReadString(table, "registry", "jobs.registry", problems) ?? beside;
        var remote = ReadString(table, "remote_directory", "jobs.remote_directory", problems)
            ?? defaults.RemoteDirectory;
        var pollLines = ReadPositiveInteger(table, "default_poll_lines", "jobs.default_poll_lines", problems)
            ?? defaults.DefaultPollLines;

        if (remote.StartsWith('/'))
        {
            problems.Add(
                $"jobs.remote_directory is '{remote}', which is absolute. It is created under the "
                    + "home of whichever unix account a rule maps to - an account that owns its own "
                    + "files - so an absolute path would put every caller's job output in one place "
                    + "somebody else may be able to read.");
        }

        RefuseUnknownKeys(table, ["registry", "remote_directory", "default_poll_lines"], "jobs", problems);
        CheckJobRegistryIsWritable(registry, problems);

        return new JobsSection
        {
            Registry = registry,
            RemoteDirectory = remote,
            DefaultPollLines = pollLines,
        };
    }

    private static MetricsSection ReadMetrics(TomlTable root, List<string> problems)
    {
        var defaults = new MetricsSection();

        if (!TryGetTable(root, "metrics", problems, out var table))
        {
            return defaults;
        }

        var enabled = ReadBoolean(table, "enabled", "metrics.enabled", problems) ?? defaults.Enabled;
        var path = ReadString(table, "path", "metrics.path", problems) ?? defaults.Path;

        if (!path.StartsWith('/'))
        {
            problems.Add(
                $"metrics.path is '{path}', which does not start with '/'. It is a route on this "
                    + "server, not a file.");
        }

        RefuseUnknownKeys(table, ["enabled", "path"], "metrics", problems);

        return new MetricsSection { Enabled = enabled, Path = path };
    }

    private static string BesideTheAuditLog(string auditPath)
    {
        var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(auditPath));
        return string.IsNullOrEmpty(directory)
            ? "jobs.jsonl"
            : System.IO.Path.Combine(directory, "jobs.jsonl");
    }

    private static void CheckJobRegistryIsWritable(string path, List<string> problems)
    {
        // The same check the audit log gets, for a related reason: a job started with no way to
        // record who owns it is a job the ownership gate cannot decide about afterwards, and
        // discovering that on the first start_job means the process is already running.
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
                $"The job registry at '{path}' cannot be written: {failure.Message} A job whose "
                    + "owner was never recorded cannot be polled or killed by anybody afterwards. "
                    + "Set jobs.registry somewhere this process can append.");
        }
    }

    private static WatchSection ReadWatch(TomlTable root, List<string> problems, List<string> warnings)
    {
        if (!TryGetTable(root, "watch", problems, out var table))
        {
            return new WatchSection();
        }

        var defaults = new WatchSection();
        var paths = ReadStringArray(table, "paths", "watch.paths", problems);
        var interval = ReadPositiveInteger(table, "interval_sec", "watch.interval_sec", problems)
            ?? defaults.IntervalSeconds;
        var retention = ReadPositiveInteger(table, "retention_min", "watch.retention_min", problems)
            ?? defaults.RetentionMinutes;
        var maxEntries = ReadPositiveInteger(table, "max_entries", "watch.max_entries", problems)
            ?? defaults.MaxEntries;

        if (paths is not null)
        {
            foreach (var path in paths)
            {
                if (!path.StartsWith('/'))
                {
                    problems.Add(
                        $"watch.paths contains '{path}', which is not absolute. A relative path "
                            + "means something different depending on where the sweep ran.");
                }
            }
        }

        if (paths is null or { Count: 0 })
        {
            warnings.Add(
                "watch.paths is empty, so change detection is off. list_changes will answer with "
                    + "nothing, and command records will carry no changes.");
        }

        RefuseUnknownKeys(
            table,
            ["paths", "interval_sec", "retention_min", "max_entries"],
            "watch",
            problems);

        return new WatchSection
        {
            Paths = paths ?? [],
            IntervalSeconds = interval,
            RetentionMinutes = retention,
            MaxEntries = maxEntries,
        };
    }

    private static List<HostEntry> ReadHosts(TomlTable root, List<string> problems)
    {
        if (!TryGetTableArray(root, "host", problems, out var blocks))
        {
            return [];
        }

        var hosts = new List<HostEntry>(blocks.Count);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < blocks.Count; index++)
        {
            var block = blocks[index];
            var where = $"host[{index}]";

            var name = ReadString(block, "name", $"{where}.name", problems);
            var address = ReadString(block, "address", $"{where}.address", problems);
            var fingerprint = ReadString(block, "fingerprint", $"{where}.fingerprint", problems);
            var port = ReadPositiveInteger(block, "port", $"{where}.port", problems) ?? 22;

            RefuseUnknownKeys(block, ["name", "address", "port", "fingerprint"], where, problems);

            if (name is null)
            {
                problems.Add($"{where}.name is not set. It is the name callers use and the name the "
                    + "grant table's globs match against.");
            }
            else if (!names.Add(name))
            {
                // Case-insensitive, because host names are (RFC 4343) and two blocks differing only
                // in case would be one host with two configurations and no way to say which applies.
                problems.Add(
                    $"{where}.name is '{name}', which another [[host]] block already uses.");
            }

            if (port is < 1 or > 65535)
            {
                problems.Add($"{where}.port is {port}, which is not a port number.");
            }

            if (fingerprint is null)
            {
                problems.Add(
                    $"{where}.fingerprint is not set. SshWarden will not open a connection it "
                        + "cannot verify - an unchecked host key hands the private key's authority "
                        + "and every command to whoever answered. Read it with "
                        + "'ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -', over a channel you "
                        + "trust.");
            }
            else if (!HostFingerprint.IsValid(fingerprint, out var fingerprintProblem))
            {
                problems.Add($"{where}.fingerprint {fingerprintProblem}.");
            }

            if (name is not null && fingerprint is not null
                && HostFingerprint.IsValid(fingerprint, out _))
            {
                hosts.Add(new HostEntry
                {
                    Name = name,
                    Address = address,
                    Port = port,
                    Fingerprint = fingerprint,
                });
            }
        }

        return hosts;
    }

    private static List<Grant> ReadGrants(
        TomlTable root,
        List<HostEntry> hosts,
        List<string> problems,
        List<string> warnings)
    {
        if (!TryGetTableArray(root, "grant", problems, out var blocks))
        {
            return [];
        }

        var grants = new List<Grant>(blocks.Count);
        var ids = new HashSet<string>(StringComparer.Ordinal);

        for (var index = 0; index < blocks.Count; index++)
        {
            var block = blocks[index];
            var where = $"grant[{index}]";

            var id = ReadString(block, "id", $"{where}.id", problems);
            var subject = ReadString(block, "subject", $"{where}.subject", problems);
            var sshUser = ReadString(block, "ssh_user", $"{where}.ssh_user", problems);
            var scopes = ReadStringArray(block, "scopes", $"{where}.scopes", problems);
            var tools = ReadStringArray(block, "tools", $"{where}.tools", problems);
            var hostPatterns = ReadStringArray(block, "hosts", $"{where}.hosts", problems);
            var pathPatterns = ReadStringArray(block, "paths", $"{where}.paths", problems);
            var unitPatterns = ReadStringArray(block, "units", $"{where}.units", problems);

            RefuseReservedKeys(ReservedGrantKeys, block, where, problems);
            RefuseUnknownKeys(
                block,
                ["id", "subject", "scopes", "tools", "hosts", "paths", "units", "ssh_user"],
                where,
                problems);

            if (id is null)
            {
                problems.Add(
                    $"{where}.id is not set. It goes into the audit record as the rule that allowed "
                        + "or refused a call, which is what a dashboard query matches on - so it is "
                        + "written here rather than derived from this block's position, which would "
                        + "renumber the moment somebody inserts a rule above it.");
            }
            else if (!ids.Add(id))
            {
                problems.Add(
                    $"{where}.id is '{id}', which another [[grant]] block already uses. Two rules "
                        + "with one id cannot be told apart in the audit record.");
            }

            if (subject is null)
            {
                problems.Add($"{where}.subject is not set.");
            }

            if (sshUser is null)
            {
                problems.Add(
                    $"{where}.ssh_user is not set. It is the unix account commands under this rule "
                        + "run as, and it is the boundary that cannot be worked around - everything "
                        + "else in the rule refuses early and writes a clear record, inside a "
                        + "process the target host does not trust.");
            }

            // **Warned, never refused.** An on-premises deployment can have a real reason to run
            // as the superuser, and a default is not a policy - so this says it once, out loud, and
            // then gets out of the way.
            //
            // It earns its place because of what the account is: `paths` and `units` do not reach
            // `run` or `start_job` (DESIGN.md 6.5.1), so for those two the ssh_user is the whole of
            // the gate, and every other line in the rule then describes intent rather than
            // capability. That made it the one setting in this file with no validation at all,
            // which is a strange place for the only real boundary to sit.
            //
            // Matched ordinally and exactly, because a unix username is case-sensitive: `Root` is a
            // different account, and warning about it would be a claim about the target's passwd
            // file that this process has never read. The same limit is why the message says what it
            // did not check rather than implying a clean bill of health.
            if (string.Equals(sshUser, "root", StringComparison.Ordinal))
            {
                warnings.Add(
                    $"{where}.ssh_user is 'root', so this rule's commands run as the superuser. "
                        + "'paths' and 'units' do not apply to 'run' or 'start_job', so for those "
                        + "tools the account is the only gate there is and the rest of this rule "
                        + "records intent rather than capability. Not checked: whether some other "
                        + "account named in this file is uid 0, or reaches root through sudo or the "
                        + "docker group. SshWarden has never read the target's passwd or group "
                        + "files, so this matches the name and nothing else.");
            }

            if (tools is null || tools.Count == 0)
            {
                problems.Add($"{where}.tools is empty, so this rule allows nothing.");
            }
            else
            {
                CheckToolNames(tools, where, problems);
            }

            if (hostPatterns is null || hostPatterns.Count == 0)
            {
                problems.Add($"{where}.hosts is empty, so this rule reaches nothing.");
            }
            else
            {
                CheckHostPatterns(hostPatterns, hosts, where, problems, warnings);
            }

            CheckSelectorPatterns(pathPatterns, PathPattern.IsValid, $"{where}.paths", problems);
            CheckSelectorPatterns(unitPatterns, UnitPattern.IsValid, $"{where}.units", problems);

            if (tools is { Count: > 0 })
            {
                CheckSelectorsReachSomething(tools, pathPatterns, unitPatterns, where, problems);
            }

            if (id is not null && subject is not null && sshUser is not null
                && tools is { Count: > 0 } && hostPatterns is { Count: > 0 })
            {
                grants.Add(new Grant
                {
                    Id = id,
                    Subject = subject,
                    Scopes = scopes ?? [],
                    Tools = tools,
                    Hosts = hostPatterns,
                    Paths = pathPatterns ?? [],
                    Units = unitPatterns ?? [],
                    SshUser = sshUser,
                });
            }
        }

        return grants;
    }

    private static void CheckToolNames(List<string> tools, string where, List<string> problems)
    {
        foreach (var tool in tools)
        {
            if (!ToolNames.All.Contains(tool, StringComparer.Ordinal))
            {
                problems.Add(
                    $"{where}.tools names '{tool}', which is not a tool. v0 has exactly seven and "
                        + "the list is closed: " + string.Join(", ", ToolNames.All) + ".");
            }
        }
    }

    private static void CheckHostPatterns(
        List<string> patterns,
        List<HostEntry> hosts,
        string where,
        List<string> problems,
        List<string> warnings)
    {
        foreach (var pattern in patterns)
        {
            if (!HostPattern.IsValid(pattern, out var problem))
            {
                problems.Add($"{where}.hosts contains '{pattern}', which {problem}.");
                continue;
            }

            // A pattern matching no declared host is a rule that cannot fire. Not a refusal: hosts
            // get added, and a rule written ahead of the machine it is for is reasonable. But it is
            // also what a typo looks like, so it is said out loud.
            if (!hosts.Any(host => HostPattern.Matches(pattern, host.Name)))
            {
                warnings.Add(
                    $"{where}.hosts contains '{pattern}', which matches no declared [[host]]. The "
                        + "rule is loaded and reaches nothing until one is added.");
            }
        }
    }

    private static void CheckSelectorPatterns(
        List<string>? patterns,
        Validator isValid,
        string where,
        List<string> problems)
    {
        if (patterns is null)
        {
            return;
        }

        foreach (var pattern in patterns)
        {
            if (!isValid(pattern, out var problem))
            {
                problems.Add($"{where} contains '{pattern}', which {problem}.");
            }
        }
    }

    private delegate bool Validator(string pattern, out string problem);

    private static void CheckSelectorsReachSomething(
        List<string> tools,
        List<string>? paths,
        List<string>? units,
        string where,
        List<string> problems)
    {
        // A rule granting a tool that acts on a file, with no file named, is deny-by-default doing
        // its job - and it reads exactly like a rule that works. The whole point of this table is
        // that reading it tells you who can touch what, so a rule that reaches nothing has to say
        // so at startup rather than at the first refused call.
        var hasPaths = paths is { Count: > 0 };
        var hasUnits = units is { Count: > 0 };

        if (tools.Contains(ToolNames.ReadFile, StringComparer.Ordinal) && !hasPaths)
        {
            problems.Add(
                $"{where}.tools includes '{ToolNames.ReadFile}' but the rule names no paths, so it "
                    + "could never allow a read. Add 'paths'.");
        }

        if (tools.Contains(ToolNames.TailLog, StringComparer.Ordinal) && !hasPaths && !hasUnits)
        {
            problems.Add(
                $"{where}.tools includes '{ToolNames.TailLog}' but the rule names no paths and no "
                    + "units, so it could never allow a tail. Add 'paths', 'units', or both.");
        }

        // The other direction. A selector nothing reads is a line somebody wrote believing it
        // narrowed something.
        if (hasPaths
            && !tools.Any(tool => ResourceArguments.PathArgumentByTool.ContainsKey(tool)))
        {
            problems.Add(
                $"{where}.paths is set but none of the rule's tools take a path, so it narrows "
                    + "nothing. Paths apply to " + string.Join(", ", ResourceArguments.PathArgumentByTool.Keys) + ".");
        }

        if (hasUnits && !tools.Contains(ToolNames.TailLog, StringComparer.Ordinal))
        {
            problems.Add(
                $"{where}.units is set but the rule does not grant '{ToolNames.TailLog}', which is "
                    + "the only tool that reads a unit, so it narrows nothing.");
        }
    }

    private static void RefuseReservedKeys(
        Dictionary<string, string> reserved,
        TomlTable table,
        string where,
        List<string> problems)
    {
        foreach (var (key, reason) in reserved)
        {
            if (table.ContainsKey(key))
            {
                problems.Add($"'{where}.{key}' is not something this build reads yet: it {reason}");
            }
        }
    }
}
