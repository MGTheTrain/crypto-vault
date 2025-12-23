package logger

import (
	"log/slog"
	"os"
)

// ConsoleLogger is an implementation of Logger that logs to the console.
type ConsoleLogger struct {
	logger *slog.Logger
}

// NewConsoleLogger creates a new console logger with the specified log level.
func NewConsoleLogger(level string) Logger {
	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &ConsoleLogger{logger: logger}
}

// Info logs an informational message to the console.
func (l *ConsoleLogger) Info(args ...interface{}) {
	l.logger.Info(formatArgs(args...))
}

// Warn logs a warning message to the console.
func (l *ConsoleLogger) Warn(args ...interface{}) {
	l.logger.Warn(formatArgs(args...))
}

// Error logs an error message to the console.
func (l *ConsoleLogger) Error(args ...interface{}) {
	l.logger.Error(formatArgs(args...))
}

// Fatal logs a fatal message and exits.
func (l *ConsoleLogger) Fatal(args ...interface{}) {
	l.logger.Error(formatArgs(args...))
	os.Exit(1)
}

// Panic logs a panic message and panics.
func (l *ConsoleLogger) Panic(args ...interface{}) {
	msg := formatArgs(args...)
	l.logger.Error(msg)
	panic(msg)
}
