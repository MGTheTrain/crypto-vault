package logger

import (
	"log/slog"
	"os"

	"github.com/natefinch/lumberjack"
)

// FileLogger is an implementation of Logger that logs to a file.
type FileLogger struct {
	logger *slog.Logger
}

// NewFileLogger creates a new file logger with rotation settings.
func NewFileLogger(level string, filePath string, maxSize int, maxBackups int, maxAge int) Logger {
	writer := &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   true,
	}

	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}
	handler := slog.NewJSONHandler(writer, opts)
	logger := slog.New(handler)

	return &FileLogger{logger: logger}
}

// Info logs an informational message.
func (l *FileLogger) Info(args ...interface{}) {
	l.logger.Info(formatArgs(args...))
}

// Warn logs a warning message.
func (l *FileLogger) Warn(args ...interface{}) {
	l.logger.Warn(formatArgs(args...))
}

// Error logs an error message.
func (l *FileLogger) Error(args ...interface{}) {
	l.logger.Error(formatArgs(args...))
}

// Fatal logs a fatal message and exits.
func (l *FileLogger) Fatal(args ...interface{}) {
	l.logger.Error(formatArgs(args...))
	os.Exit(1)
}

// Panic logs a panic message and panics.
func (l *FileLogger) Panic(args ...interface{}) {
	msg := formatArgs(args...)
	l.logger.Error(msg)
	panic(msg)
}
