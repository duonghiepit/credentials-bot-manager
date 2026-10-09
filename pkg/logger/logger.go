package logger

import (
	"log/slog"
	"os"
	"strings"
)

var defaultLogger *slog.Logger

func init() {
	defaultLogger = Init("json", "info")
}

// Init sets up the structured logger based on format and level.
func Init(format, levelStr string) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.ToLower(format) == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		// Default to production-grade JSON
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler).With(
		slog.String("app", "platform-controller"),
	)

	slog.SetDefault(logger)
	defaultLogger = logger
	return logger
}

// L returns the active structured logger.
func L() *slog.Logger {
	return defaultLogger
}
