package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"net-zilla/internal/ai"
	"net-zilla/internal/analyzer"
	"net-zilla/internal/api"
	"net-zilla/internal/config"
	"net-zilla/internal/utils"
)

func main() {
	// Display banner (only if running CLI directly, not as a background service)
	// This will be handled by the menu or server startup for cleaner output
	// utils.DisplayBanner() 

	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("❌ Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := utils.NewLogger() // NewLogger is now in utils

	// Initialize AI agent
	mlAgent, err := ai.NewMLAgent(&cfg.AI)
	if err != nil {
		logger.Error("Failed to initialize AI agent: %v", err)
		fmt.Printf("❌ AI features disabled. Continuing with basic analysis...\n\n")
	}

	// Initialize analyzer (pass config to analyzer as well if needed for timeouts etc.)
	hreatAnalyzer := analyzer.NewThreatAnalyzer(mlAgent, logger, mlAgent.orchestrator) // Pass mlAgent.orchestrator

	// Handle graceful shutdown for both CLI and API server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cancel is called on exit

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Printf("\n\n%s🛑 Shutting down Net-Zilla...%s\n", "\033[33m", "\033[0m")
		cancel() // Signal all goroutines to stop
	}()

	if cfg.Server.EnableAPI {
		logger.Info("Starting Net-Zilla API server...")
		apiServer := api.NewServer(threatAnalyzer, logger, cfg) // NewServer needs appropriate parameters
		if err := apiServer.Run(ctx); err != nil { // Run should accept context
			logger.Error("API server failed: %v", err)
			os.Exit(1)
		}
	} else if cfg.Server.EnableCLI {
		logger.Info("Starting Net-Zilla CLI...")
		utils.DisplayBanner() // Display banner specifically for CLI mode
		menu := utils.NewMenu(threatAnalyzer, logger, mlAgent)
		if err := menu.Run(); err != nil {
			logger.Error("CLI menu failed: %v", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("❌ No mode enabled. Please enable either API server or CLI in configuration.\n")
		os.Exit(1)
	}

	logger.Info("Net-Zilla stopped gracefully.")
}

// Removed setupGracefulShutdown as it's now integrated directly into main.