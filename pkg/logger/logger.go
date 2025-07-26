package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

// LogLevel represents different log levels
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger interface for logging functionality
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// StandardLogger implements Logger interface
type StandardLogger struct {
	verbose bool
	logger  *log.Logger
}

// New creates a new logger instance
func New(verbose bool) Logger {
	return &StandardLogger{
		verbose: verbose,
		logger:  log.New(os.Stdout, "", 0),
	}
}

// Debug logs debug messages (only in verbose mode)
func (l *StandardLogger) Debug(format string, args ...interface{}) {
	if l.verbose {
		l.logWithLevel("DEBUG", format, args...)
	}
}

// Info logs informational messages
func (l *StandardLogger) Info(format string, args ...interface{}) {
	l.logWithLevel("INFO", format, args...)
}

// Warn logs warning messages
func (l *StandardLogger) Warn(format string, args ...interface{}) {
	l.logWithLevel("WARN", format, args...)
}

// Error logs error messages
func (l *StandardLogger) Error(format string, args ...interface{}) {
	l.logWithLevel("ERROR", format, args...)
}

// logWithLevel logs a message with the specified level
func (l *StandardLogger) logWithLevel(level string, format string, args ...interface{}) {
	// Skip logging if logger is nil (quiet mode)
	if l.logger == nil {
		return
	}
	timestamp := time.Now().Format("15:04:05")
	prefix := fmt.Sprintf("[%s] %s: ", timestamp, level)
	message := fmt.Sprintf(format, args...)
	l.logger.Printf("%s%s", prefix, message)
}
