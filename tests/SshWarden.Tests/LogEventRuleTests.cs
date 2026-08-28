using System.Text.RegularExpressions;

using SshWarden.Diagnostics;

using Xunit;

namespace SshWarden.Tests;

/// <summary>
/// The rules that make adding a log message safe.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Read off the source, not off the assemblies, and that is deliberate.</strong> Reflection
/// would only reach what this test project references, and the one assembly with nothing referencing
/// it is the host - which is where two of the five original messages lived. A rule that cannot see
/// the host is a rule the host is exempt from, and nothing would say so.
/// </para>
/// <para>
/// The cost is a regex over C#, which is imprecise in general. It is precise enough here because
/// what it reads is an attribute argument list with a fixed shape, and because a declaration this
/// cannot parse fails the test rather than passing it.
/// </para>
/// </remarks>
public sealed class LogEventRuleTests
{
    private static readonly (string Directory, string Assembly, int Base)[] Ranges =
    [
        ("src/SshWarden", "SshWarden", LogEvents.Core),
        ("src/SshWarden.Mcp", "SshWarden.Mcp", LogEvents.Mcp),
        ("src/SshWarden.OAuth", "SshWarden.OAuth", LogEvents.OAuth),
        ("hosts/SshWarden.Server", "SshWarden.Server", LogEvents.Server),
    ];

    [Fact]
    public void No_two_messages_share_an_event_id()
    {
        // The failure this exists for is silent: two ids the same breaks nothing at runtime, and a
        // dashboard filtered on one counts two different things as one event.
        var seen = new Dictionary<int, string>();
        var clashes = new List<string>();

        foreach (var declaration in Declarations())
        {
            if (seen.TryGetValue(declaration.EventId, out var first))
            {
                clashes.Add($"{declaration.EventId}: {first} and {declaration.Where}");
            }
            else
            {
                seen[declaration.EventId] = declaration.Where;
            }
        }

        Assert.True(
            clashes.Count == 0,
            "These event ids are declared more than once:" + Environment.NewLine
                + string.Join(Environment.NewLine, clashes));
    }

    [Fact]
    public void Every_message_is_inside_its_assemblys_range()
    {
        // What makes the number worth reading on its own: the leading digit names the component, so
        // an operator holding a truncated line still knows which half of the process produced it.
        var strays = Declarations()
            .Where(declaration => declaration.EventId < declaration.Base
                || declaration.EventId >= declaration.Base + LogEvents.RangeSize)
            .Select(declaration =>
                $"{declaration.Where} uses {declaration.EventId}, outside "
                    + $"{declaration.Base}..{declaration.Base + LogEvents.RangeSize - 1}")
            .ToList();

        Assert.True(
            strays.Count == 0,
            "LogEvents allocates a range per assembly:" + Environment.NewLine
                + string.Join(Environment.NewLine, strays));
    }

    [Fact]
    public void Every_message_carries_an_event_name()
    {
        // The id is what a query filters on and the name is what makes the query readable. Without
        // one, a structured sink has an integer and a rendered string, and matching on message text
        // is how a query breaks the day somebody fixes a typo in it.
        var unnamed = Declarations()
            .Where(declaration => declaration.EventName is null)
            .Select(declaration => declaration.Where)
            .ToList();

        Assert.True(
            unnamed.Count == 0,
            "These messages have no EventName:" + Environment.NewLine
                + string.Join(Environment.NewLine, unnamed));
    }

    [Fact]
    public void There_are_messages_to_check()
    {
        // The control, and it is not a formality: every assertion above passes against a scan that
        // found nothing, which is exactly what a moved directory or a renamed attribute would
        // produce. A green suite that measured nothing is the failure this repository keeps finding.
        Assert.NotEmpty(Declarations());
    }

    private static List<Declaration> Declarations()
    {
        var root = RepositoryRoot();
        var found = new List<Declaration>();

        foreach (var (directory, assembly, @base) in Ranges)
        {
            var path = Path.Combine(root, directory);

            if (!Directory.Exists(path))
            {
                throw new DirectoryNotFoundException(
                    $"'{directory}' is in the range table and not on disk. A project that moved "
                        + "leaves this scan reading nothing, and every rule here passes on nothing.");
            }

            foreach (var file in Directory.EnumerateFiles(path, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                    || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                {
                    continue;
                }

                found.AddRange(Parse(File.ReadAllText(file), assembly, Path.GetFileName(file), @base));
            }
        }

        return found;
    }

    /// <summary>Every <c>[LoggerMessage(...)]</c> in one file.</summary>
    /// <remarks>
    /// An id written as an expression rather than a literal - which is how every declaration here is
    /// written, as <c>LogEvents.Core + 1</c> - is evaluated by this rather than looked up, because
    /// the alternative is a test that only understands the constants it was taught.
    /// </remarks>
    private static IEnumerable<Declaration> Parse(string source, string assembly, string file, int @base)
    {
        foreach (Match match in Regex.Matches(
            source,
            @"\[LoggerMessage\s*\((?<args>[^\]]*)\)\s*\]",
            RegexOptions.Singleline,
            TimeSpan.FromSeconds(5)))
        {
            var arguments = match.Groups["args"].Value;

            var id = Regex.Match(
                arguments,
                @"EventId\s*=\s*(?:LogEvents\.(?<range>\w+)\s*\+\s*)?(?<offset>\d+)",
                RegexOptions.None,
                TimeSpan.FromSeconds(5));

            Assert.True(
                id.Success,
                $"A [LoggerMessage] in {file} has no EventId this rule can read. Every message needs "
                    + "one, and one written in a shape this cannot parse is one nothing checks.");

            var offset = int.Parse(id.Groups["offset"].Value, System.Globalization.CultureInfo.InvariantCulture);

            var start = id.Groups["range"].Success
                ? id.Groups["range"].Value switch
                {
                    "Core" => LogEvents.Core,
                    "Mcp" => LogEvents.Mcp,
                    "OAuth" => LogEvents.OAuth,
                    "Server" => LogEvents.Server,
                    var other => throw new InvalidOperationException(
                        $"{file} builds an event id from LogEvents.{other}, which this rule does not "
                            + "know. Add it here and to the range table above, together."),
                }
                : 0;

            var name = Regex.Match(
                arguments,
                @"EventName\s*=\s*""(?<name>[^""]+)""",
                RegexOptions.None,
                TimeSpan.FromSeconds(5));

            yield return new Declaration
            {
                EventId = start + offset,
                EventName = name.Success ? name.Groups["name"].Value : null,
                Base = @base,
                Where = $"{assembly}/{file}",
            };
        }
    }

    /// <summary>The repository root, found by walking up for the solution file.</summary>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SshWarden.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("SshWarden.slnx was not found above " + AppContext.BaseDirectory);
    }

    private sealed class Declaration
    {
        public required int EventId { get; init; }

        public required string? EventName { get; init; }

        public required int Base { get; init; }

        public required string Where { get; init; }
    }
}
