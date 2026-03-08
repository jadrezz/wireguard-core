package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wireguard-core/api"
	"wireguard-core/config"
	"wireguard-core/internal/delivery"
	"wireguard-core/internal/usecase"
)

func main() {
	logger := config.NewLogger(os.Stdout)

	wg, err := config.InitWireGuard()
	if err != nil {
		log.Fatal(err)
	}

	wgService := usecase.NewWireGuardService(wg.Manager, wg.Persister, wg.ServerManager, wg.DisabledStore, wg.Firewall, logger)
	router := delivery.NewRouter(logger, wgService)
	api.RegisterSwagger(router)

	server := http.Server{
		Addr:              ":7777",
		Handler:           router,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("Server starting", slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Server failed", "error", err.Error())
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("Shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown failed", "error", err.Error())
	}

	if err := wg.Manager.Close(); err != nil {
		logger.Error("wgctrl client close failed", "error", err.Error())
	}

	logger.Info("Server stopped gracefully")
}
