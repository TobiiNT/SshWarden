using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using SshWarden.Configuration;

namespace SshWarden.Ssh.IntegrationTests;

/// <summary>An OpenSSH server on loopback, for the length of one test class.</summary>
/// <remarks>
/// <para>
/// A real server rather than a stand-in, because everything worth checking at this layer is about
/// what a real one does: whether a host key is verified, whether a quoted argument survives the
/// shell, whether a remote timeout actually kills the process, and whether several commands can
/// share one connection. A fake would answer all of those the way it was written to.
/// </para>
/// <para>
/// <strong>It fails rather than skips when there is no <c>sshd</c> to run.</strong> A suite that
/// skips itself is green in exactly the situation where it measured nothing, which is the same
/// reason Boltway's storage suite refuses to skip without a database.
/// </para>
/// </remarks>
public sealed class LocalSshServer : IDisposable
{
    private const string SshdPath = "/usr/sbin/sshd";

    private readonly string _directory;
    private Process? _sshd;

    private LocalSshServer(string directory) => _directory = directory;

    /// <summary>The port it listens on.</summary>
    public int Port { get; private set; }

    /// <summary>The private key a client authenticates with.</summary>
    public string ClientKeyPath => Path.Combine(_directory, "client_ed25519");

    /// <summary>The account to log in as.</summary>
    public string User { get; private set; } = string.Empty;

    /// <summary>The fingerprint of the host key it presents.</summary>
    public string Fingerprint { get; private set; } = string.Empty;

    /// <summary>A host entry pointing at this server.</summary>
    public HostEntry AsHostEntry(string? fingerprint = null) => new()
    {
        Name = "local-test",
        Address = "127.0.0.1",
        Port = Port,
        Fingerprint = fingerprint ?? Fingerprint,
    };

    /// <summary>The <c>[ssh]</c> settings pointing at this server's client key.</summary>
    public SshSection Options => new()
    {
        IdentityFile = ClientKeyPath,
        ConnectTimeoutSeconds = 10,
        IdleEvictionSeconds = 300,
    };

    /// <summary>Starts a server.</summary>
    /// <exception cref="InvalidOperationException">There is no usable sshd on this machine.</exception>
    public static LocalSshServer Start()
    {
        if (!File.Exists(SshdPath))
        {
            throw new InvalidOperationException(
                $"This suite needs a real OpenSSH server at {SshdPath} and there is not one. It "
                    + "fails rather than skipping on purpose: a skipped SSH suite is green in "
                    + "exactly the situation where it measured nothing. Install openssh-server.");
        }

        var directory = Path.Combine(Path.GetTempPath(), "sshwarden-sshd", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        var server = new LocalSshServer(directory);
        try
        {
            server.Prepare();
            server.Launch();
            return server;
        }
        catch
        {
            server.Dispose();
            throw;
        }
    }

    /// <summary>Stops the server and removes its files.</summary>
    public void Dispose()
    {
        try
        {
            if (_sshd is { HasExited: false })
            {
                _sshd.Kill(entireProcessTree: true);
                _ = _sshd.WaitForExit(5000);
            }

            _sshd?.Dispose();
        }
        catch (InvalidOperationException)
        {
            // Already gone. Nothing to do, and nothing worth failing a test's teardown over.
        }

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A temporary directory that outlives one test run is untidy, not broken.
        }
    }

    private void Prepare()
    {
        User = Environment.UserName;

        RunToCompletion("ssh-keygen", $"-q -t ed25519 -f {Path.Combine(_directory, "host_ed25519")} -N \"\" -C host");
        RunToCompletion("ssh-keygen", $"-q -t ed25519 -f {ClientKeyPath} -N \"\" -C client");

        var sshDirectory = Path.Combine(_directory, "ssh");
        Directory.CreateDirectory(sshDirectory);

        var authorized = Path.Combine(sshDirectory, "authorized_keys");
        File.Copy(ClientKeyPath + ".pub", authorized);
        // Unreachable on a platform without file modes - Start() has already refused when there is
        // no sshd at a Unix path - but the analyzer cannot see that, and a guard is cheaper than
        // teaching it. sshd refuses to use an authorized_keys anyone else can write, and SshWarden's
        // own loader refuses a private key anyone else can read, so both modes are load-bearing.
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(authorized, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.SetUnixFileMode(ClientKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        Fingerprint = FingerprintOf(Path.Combine(_directory, "host_ed25519.pub"));
        Port = FreePort();

        File.WriteAllText(Path.Combine(_directory, "sshd_config"), $"""
            Port {Port}
            ListenAddress 127.0.0.1
            HostKey {Path.Combine(_directory, "host_ed25519")}
            PidFile {Path.Combine(_directory, "sshd.pid")}
            AuthorizedKeysFile {authorized}
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            UsePAM no
            StrictModes no
            PermitRootLogin yes
            PrintMotd no
            AcceptEnv LANG LC_*
            """);
    }

    private void Launch()
    {
        // Foreground, so the fixture owns the process and can kill it. sshd daemonises by default,
        // which would leave a server behind holding a port when a test run is interrupted.
        _sshd = Process.Start(new ProcessStartInfo(SshdPath)
        {
            Arguments = $"-D -f {Path.Combine(_directory, "sshd_config")} -e",
            RedirectStandardError = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException("sshd did not start.");

        WaitUntilAccepting();
    }

    private void WaitUntilAccepting()
    {
        // Polled on the socket rather than slept for. A fixed sleep is either flaky on a loaded
        // machine or wasted time on an idle one, and this waits on the thing that actually has to
        // become true.
        var deadline = DateTime.UtcNow.AddSeconds(20);

        while (DateTime.UtcNow < deadline)
        {
            if (_sshd is { HasExited: true })
            {
                throw new InvalidOperationException(
                    "sshd exited during startup: " + _sshd.StandardError.ReadToEnd());
            }

            try
            {
                using var probe = new TcpClient();
                probe.Connect(IPAddress.Loopback, Port);
                return;
            }
            catch (SocketException)
            {
                Thread.Sleep(50);
            }
        }

        throw new InvalidOperationException($"sshd did not begin accepting on port {Port}.");
    }

    private static string FingerprintOf(string publicKeyPath)
    {
        // Computed from the key file rather than shelled out to ssh-keygen, so the value under test
        // is derived the same way the code under test derives it - from the key blob itself.
        var fields = File.ReadAllText(publicKeyPath).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var blob = Convert.FromBase64String(fields[1]);

        return "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static void RunToCompletion(string fileName, string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(fileName)
        {
            Arguments = arguments,
            RedirectStandardError = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException($"{fileName} did not start.");

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"{fileName} {arguments} failed: {process.StandardError.ReadToEnd()}");
        }
    }
}
