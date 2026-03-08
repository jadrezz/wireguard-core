package config

import (
	"io"
	"log/slog"
)

func NewLogger(w io.Writer) *slog.Logger {
	logger := slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	return logger
}
