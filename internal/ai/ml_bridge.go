package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"net-zilla/internal/config" // Added import
	"net-zilla/internal/models"
)

// MLAgent provides an interface to interact with Julia-based machine learning models.
type MLAgent struct {
	juliaPath    string
	modelsPath   string
	isAvailable  bool // Indicates if Julia environment and models are ready
	orchestrator *Orchestrator
	aiConfig     *config.AIConfig // Store AI config
}

// AIAnalysisResult represents the structured output from an ML-powered link analysis.
// This is used by models.ThreatAnalysis.AIResult
type AIAnalysisResult struct {
	IsSafe          bool     `json:"is_safe"`
	Confidence      float64  `json:"confidence"` // Confidence score of the analysis [0.0 - 1.0]
	RiskLevel       string   `json:"risk_level"` // E.g., "LOW", "MEDIUM", "HIGH"
	IsShortened     bool     `json:"is_shortened"`
	HealthScore     float64  `json:"health_score"` // Overall health score [0.0 - 1.0]
	Threats         []string `json:"threats"`      // List of detected threats
	Recommendations []string `json:"recommendations"`
	Error           string   `json:"error,omitempty"` // Error message if analysis failed
}

// Orchestrator manages the execution of multiple AI/ML tasks.
type Orchestrator struct {
	juliaPath  string
	scriptPath string // Path to the orchestrator.jl script
}

// OrchestrationResult represents the outcome of an AI orchestration process.
// This is used by models.ThreatAnalysis.AIOrchestration
type OrchestrationResult struct {
	Success            bool               `json:"success"`
	TasksExecuted      []string           `json:"tasks_executed"`
	Errors             []string           `json:"errors"`
	PerformanceMetrics map[string]float64 `json:"performance_metrics"`
	Recommendations    []string           `json:"recommendations"`
	NextActions        []string           `json:"next_actions"`
	RawOutput          string             `json:"raw_output,omitempty"`
}

// NewMLAgent creates and initializes a new MLAgent instance.
func NewMLAgent(cfg *config.AIConfig) (*MLAgent, error) {
	agent := &MLAgent{
		juliaPath:   cfg.JuliaPath,
		modelsPath:  cfg.MLModelsPath,
		isAvailable: false,
		orchestrator: &Orchestrator{
			juliaPath:  cfg.JuliaPath,
			scriptPath: fmt.Sprintf("%s/orchestrator.jl", cfg.MLModelsPath),
		},
		aiConfig: cfg,
	}

	if !cfg.EnableAI {
		return agent, nil // AI is explicitly disabled, return non-available agent
	}

	// Check if Julia is available
	if err := agent.checkJulia(); err != nil {
		return agent, fmt.Errorf("Julia not available: %v", err)
	}

	// Check if ML model scripts are available
	if err := agent.checkScripts(); err != nil {
		return agent, fmt.Errorf("ML scripts not available: %v", err)
	}

	agent.isAvailable = true
	return agent, nil
}

// checkJulia verifies if the Julia executable is accessible.
func (a *MLAgent) checkJulia() error {
	cmd := exec.Command(a.juliaPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("julia executable not found or not working: %w", err)
	}
	return nil
}

// checkScripts verifies if essential Julia scripts for ML models are present.
func (a *MLAgent) checkScripts() error {
	requiredScripts := []string{
		"julia_agent.jl",
		"orchestrator.jl",
		"sms_analyzer.jl", // Assuming this exists based on AnalyzeSMS
		// Add other critical Julia script files here
	}

	for _, script := range requiredScripts {
		fullPath := fmt.Sprintf("%s/%s", a.modelsPath, script)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("missing Julia script file: %s at %s", script, fullPath)
		}
	}
	return nil
}

// OrchestrateAnalysis performs a multi-step AI analysis coordinated by the Julia orchestrator.
func (a *MLAgent) OrchestrateAnalysis(ctx context.Context, target, analysisType string) (*models.OrchestrationResult, error) {
	if !a.isAvailable || !a.aiConfig.EnableAI {
		return a.getFallbackOrchestration(), nil
	}

	// Prepare command with context
	cmd := exec.CommandContext(ctx, a.orchestrator.juliaPath, a.orchestrator.scriptPath, a.aiConfig.MLModelsPath, target, analysisType)
	output, err := cmd.Output()

	if err != nil {
		// Log Julia's stderr if available
		if exitError, ok := err.(*exec.ExitError); ok {
			return a.getFallbackOrchestration(), fmt.Errorf("orchestrator execution failed (exit code %d): %s, stderr: %s", exitError.ExitCode(), err, exitError.Stderr)
		}
		return a.getFallbackOrchestration(), fmt.Errorf("orchestrator execution failed: %v, output: %s", err, string(output))
	}

	var result models.OrchestrationResult
	if err := json.Unmarshal(output, &result); err != nil {
		return a.getFallbackOrchestration(), fmt.Errorf("failed to parse orchestration result: %v, raw output: %s", err, string(output))
	}
	result.RawOutput = string(output) // Store raw output for debugging

	return &result, nil
}

// SystemDiagnostics checks the health and readiness of the AI/ML system.
func (a *MLAgent) SystemDiagnostics(ctx context.Context) (*models.OrchestrationResult, error) {
	if !a.isAvailable || !a.aiConfig.EnableAI {
		return a.getFallbackOrchestration(), fmt.Errorf("MLAgent is not available or AI is disabled")
	}
	// Use the orchestrator to run a diagnostic analysis
	return a.OrchestrateAnalysis(ctx, "diagnostic_test_url.com", "diagnostic")
}

// AnalyzeLink performs AI-powered analysis of a suspicious link.
func (a *MLAgent) AnalyzeLink(ctx context.Context, url, ip string) (*models.AIAnalysisResult, error) {
	if !a.isAvailable || !a.aiConfig.EnableAI {
		return a.getFallbackAIAnalysisResult(), nil
	}

	scriptPath := fmt.Sprintf("%s/julia_agent.jl", a.modelsPath) // Specific script for link analysis
	cmd := exec.CommandContext(ctx, a.juliaPath, scriptPath, a.aiConfig.MLModelsPath, url, ip)
	output, err := cmd.Output()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return a.getFallbackAIAnalysisResult(), fmt.Errorf("Julia link analysis failed (exit code %d): %s, stderr: %s", exitError.ExitCode(), err, exitError.Stderr)
		}
		return a.getFallbackAIAnalysisResult(), fmt.Errorf("Julia link analysis failed: %v, output: %s", err, string(output))
	}

	var result models.AIAnalysisResult
	if err := json.Unmarshal(output, &result); err != nil {
		return a.getFallbackAIAnalysisResult(), fmt.Errorf("failed to parse AI link analysis result: %v, raw output: %s", err, string(output))
	}
	// Post-process result to check confidence threshold
	if result.Confidence < a.aiConfig.ConfidenceThreshold {
		result.IsSafe = false
		result.RiskLevel = "UNKNOWN (Low Confidence)"
		result.Threats = append(result.Threats, "AI analysis confidence below threshold")
		result.Recommendations = append(result.Recommendations, "Manual verification recommended due to low AI confidence")
	}

	return &result, nil
}

// AnalyzeSMS performs AI-powered analysis of an SMS message.
func (a *MLAgent) AnalyzeSMS(ctx context.Context, message string) (*models.AIAnalysisResult, error) {
	if !a.isAvailable || !a.aiConfig.EnableAI {
		return a.getFallbackAIAnalysisResult(), nil
	}

	scriptPath := fmt.Sprintf("%s/sms_analyzer.jl", a.modelsPath) // Assuming a separate script for SMS
	cmd := exec.CommandContext(ctx, a.juliaPath, scriptPath, a.aiConfig.MLModelsPath, message)
	output, err := cmd.Output()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return a.getFallbackAIAnalysisResult(), fmt.Errorf("Julia SMS analysis failed (exit code %d): %s, stderr: %s", exitError.ExitCode(), err, exitError.Stderr)
		}
		return a.getFallbackAIAnalysisResult(), fmt.Errorf("Julia SMS analysis failed: %v, output: %s", err, string(output))
	}

	var result models.AIAnalysisResult
	if err := json.Unmarshal(output, &result); err != nil {
		return a.getFallbackAIAnalysisResult(), fmt.Errorf("failed to parse AI SMS analysis result: %v, raw output: %s", err, string(output))
	}
	// Post-process result to check confidence threshold
	if result.Confidence < a.aiConfig.ConfidenceThreshold {
		result.IsSafe = false
		result.RiskLevel = "UNKNOWN (Low Confidence)"
		result.Threats = append(result.Threats, "AI analysis confidence below threshold")
		result.Recommendations = append(result.Recommendations, "Manual verification recommended due to low AI confidence")
	}

	return &result, nil
}

// IsAvailable checks if the MLAgent is operational and AI is enabled in config.
func (a *MLAgent) IsAvailable() bool {
	return a.isAvailable && a.aiConfig.EnableAI
}

// GetPlatform returns the current operating system.
func (a *MLAgent) GetPlatform() string {
	return runtime.GOOS
}

// getFallbackOrchestration provides a default result when AI orchestration is unavailable or fails.
func (a *MLAgent) getFallbackOrchestration() *models.OrchestrationResult {
	return &models.OrchestrationResult{
		Success:            false,
		TasksExecuted:      []string{"basic_analysis_fallback"},
		Errors:             []string{"AI orchestrator unavailable or failed"},
		PerformanceMetrics: map[string]float64{"efficiency_score": 0.1},
		Recommendations:    []string{"Ensure Julia is installed and scripts are in place", "Check network connection", "Review configuration 'ai.enable_ai'"},
		NextActions:        []string{"Proceed with basic, non-AI analysis if possible"},
	}
}

// getFallbackAIAnalysisResult provides a default result when AI link/SMS analysis is unavailable or fails.
func (a *MLAgent) getFallbackAIAnalysisResult() *models.AIAnalysisResult {
	return &models.AIAnalysisResult{
		IsSafe:          false,
		Confidence:      0.0,
		RiskLevel:       "UNKNOWN",
		IsShortened:     false,
		HealthScore:     0.1,
		Threats:         []string{"AI analysis unavailable or failed"},
		Recommendations: []string{"Exercise extreme caution", "Verify manually using other tools", "Review configuration 'ai.enable_ai' and paths"},
		Error:           "AI analysis module not operational or encountered an error.",
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
