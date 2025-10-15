package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"net-zilla/internal/ai"
	"net-zilla/internal/analyzer"
	"net-zilla/internal/utils"
	"net-zilla/internal/config"
)

func main() {
	// Display banner
	displayBanner()

	// Initialize configuration
	cfg := config.Load()

	// Initialize logger
	logger := utils.NewLogger()

	// Initialize AI agent
	mlAgent, err := ai.NewMLAgent()
	if err != nil {
		logger.Error("Failed to initialize AI agent: %v", err)
		fmt.Printf("❌ AI features disabled. Continuing with basic analysis...\n\n")
	}

	// Initialize analyzer
	threatAnalyzer := analyzer.NewThreatAnalyzer(mlAgent, logger)

	// Start main menu
	menu := utils.NewMenu(threatAnalyzer, logger, mlAgent)
	
	// Handle graceful shutdown
	setupGracefulShutdown(menu)

	// Run menu
	if err := menu.Run(); err != nil {
		logger.Error("Menu execution failed: %v", err)
		os.Exit(1)
	}
}

func displayBanner() {
	red := "\033[31m"
	yellow := "\033[33m"
	reset := "\033[0m"
	
	banner := `
███╗   ██╗███████╗████████╗    ███████╗██╗██╗     ██╗     
████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██║██║     ██║     
██╔██╗ ██║█████╗     ██║       ███████╗██║██║     ██║     
██║╚██╗██║██╔══╝     ██║       ╚════██║██║██║     ██║     
██║ ╚████║███████╗   ██║       ███████║██║███████╗███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚═╝╚══════╝╚══════╝
	`
	
	subtitle := "[ A network - ip - Link - SMS - DNS-Whois lookup enterprise level checker with A.I. ]"
	
	fmt.Printf("%s%s%s\n", red, banner, reset)
	fmt.Printf("%s%s%s\n\n", yellow, subtitle, reset)
}

func setupGracefulShutdown(menu *utils.Menu) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		fmt.Printf("\n\n%s🛑 Shutting down Net-Zilla...%s\n", "\033[33m", "\033[0m")
		menu.Cleanup()
		os.Exit(0)
	}()
}
