using Microsoft.Extensions.Logging;

namespace SshWarden.Tests;

/// <summary>Every line a component wrote, for the tests that are about whether it wrote one.</summary>
/// <remarks>
/// Through the real <see cref="ILogger" /> seam rather than a flag on the component, because what
/// these tests check is what an operator would see - and a component that recorded "I would have
/// logged" and did not log is the defect, not the test's problem.
/// </remarks>
internal sealed class CapturedLog : ILogger
{
    private readonly List<(LogLevel Level, EventId Event, string Message)> _lines = [];

    public IReadOnlyList<(LogLevel Level, EventId Event, string Message)> Lines => _lines;

    /// <summary>Types this as the generic logger a component's constructor asks for.</summary>
    public ILogger<T> For<T>() => new Typed<T>(this);

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    /// <summary>Everything is enabled, so a level filter cannot make a test pass.</summary>
    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        _lines.Add((logLevel, eventId, formatter(state, exception)));
    }

    private sealed class Typed<T>(CapturedLog inner) : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => inner.Log(logLevel, eventId, state, exception, formatter);
    }
}
