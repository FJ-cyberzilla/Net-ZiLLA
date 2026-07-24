package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"neta-zilla/internal/config"
	"neta-zilla/internal/models"
)

// MLAgent bridges the Go service to Julia-based ML models.
type MLAgent struct {
	juliaPath   string
	modelsDir   string
	isAvailable bool
	aiConfig    *config.AIConfig
}

// Orchestrator is now integrated into MLAgent; its script path is derived from modelsDir.
// No separate struct is needed.

// NewMLAgent initialises the agent, validates the environment, and sets availability.
func NewMLAgent(cfg *config.AIConfig) (*MLAgent, error) {
	agent := &MLAgent{
		juliaPath:   cfg.JuliaPath,
		modelsDir:   cfg.MLModelsPath,
		isAvailable: false,
		aiConfig:    cfg,
	}

	if !cfg.EnableAI {
		return agent, nil // AI disabled intentionally
	}

	if err := agent.validateEnvironment(); err != nil {
		return agent, err
	}

	agent.isAvailable = true
	return agent, nil
}

// IsAvailable reports whether the agent is fully operational.
func (a *MLAgent) IsAvailable() bool {
	return a.isAvailable && a.aiConfig.EnableAI
}

// OrchestrateAnalysis performs a multi‑step analysis using the Julia orchestrator script.
func (a *MLAgent) OrchestrateAnalysis(ctx context.Context, target, analysisType string) (*models.OrchestrationResult, error) {
	if !a.IsAvailable() {
		return a.getFallbackOrchestration(), nil
	}

	scriptPath := filepath.Join(a.modelsDir, "orchestrator.jl")
	args := []string{scriptPath, a.modelsDir, target, analysisType}
	output, err := runJuliaCommand(ctx, a.juliaPath, args...)
	if err != nil {
		// attach raw output to the error message but return a fallback result
		return a.getFallbackOrchestration(), fmt.Errorf("%w (raw: %s)", err, output)
	}

	var result models.OrchestrationResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return a.getFallbackOrchestration(), fmt.Errorf("unmarshal orchestration result: %w (raw: %s)", err, output)
	}
	result.RawOutput = output
	return &result, nil
}

// SystemDiagnostics runs a health check through the orchestrator.
func (a *MLAgent) SystemDiagnostics(ctx context.Context) (*models.OrchestrationResult, error) {
	if !a.IsAvailable() {
		return a.getFallbackOrchestration(), fmt.Errorf("MLAgent not available")
	}
	return a.OrchestrateAnalysis(ctx, "diagnostic_test_url.com", "diagnostic")
}

// AnalyzeLink performs ML‑based threat analysis of a URL.
func (a *MLAgent) AnalyzeLink(ctx context.Context, url, ip string) (*models.AIAnalysisResult, error) {
	return a.runAnalysisScript(ctx, "julia_agent.jl", url, ip)
}

// AnalyzeSMS performs ML‑based threat analysis of an SMS message.
func (a *MLAgent) AnalyzeSMS(ctx context.Context, message string) (*models.AIAnalysisResult, error) {
	return a.runAnalysisScript(ctx, "sms_analyzer.jl", message)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// runAnalysisScript executes a named Julia analysis script, parses the JSON output,
// applies the confidence threshold, and returns a models.AIAnalysisResult.
func (a *MLAgent) runAnalysisScript(ctx context.Context, scriptName string, args ...string) (*models.AIAnalysisResult, error) {
	if !a.IsAvailable() {
		return a.getFallbackAnalysisResult(), nil
	}

	scriptPath := filepath.Join(a.modelsDir, scriptName)
	// Prepend script path and models directory as required by Julia scripts
	juliaArgs := append([]string{scriptPath, a.modelsDir}, args...)
	output, err := runJuliaCommand(ctx, a.juliaPath, juliaArgs...)
	if err != nil {
		return a.getFallbackAnalysisResult(), fmt.Errorf("%w (raw: %s)", err, output)
	}

	var result models.AIAnalysisResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return a.getFallbackAnalysisResult(), fmt.Errorf("unmarshal analysis result: %w (raw: %s)", err, output)
	}

	// Enforce global confidence threshold
	if result.Confidence < a.aiConfig.ConfidenceThreshold {
		result.IsSafe = false
		result.RiskLevel = "UNKNOWN (Low Confidence)"
		result.Threats = append(result.Threats, "AI analysis confidence below threshold")
		result.Recommendations = append(result.Recommendations, "Manual verification recommended due to low AI confidence")
	}

	return &result, nil
}

// runJuliaCommand executes a Julia script with the given arguments, returns the combined
// stdout output. It respects context cancellation and captures stderr for error messages.
func runJuliaCommand(ctx context.Context, juliaPath string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, juliaPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(out), fmt.Errorf("julia exited %d: %s (stderr: %s)", exitErr.ExitCode(), exitErr, exitErr.Stderr)
		}
		return string(out), fmt.Errorf("julia execution failed: %w", err)
	}
	return string(out), nil
}

// validateEnvironment ensures the Julia binary exists, the models directory is present,
// and all required script files are accessible.
func (a *MLAgent) validateEnvironment() error {
	// 1. Julia executable
	cmd := exec.Command(a.juliaPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("julia not found at %q: %w", a.juliaPath, err)
	}

	// 2. Models directory
	info, err := os.Stat(a.modelsDir)
	if err != nil {
		return fmt.Errorf("models directory %q does not exist: %w", a.modelsDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("models path %q is not a directory", a.modelsDir)
	}

	// 3. Required script files
	required := []string{
		"julia_agent.jl",
		"orchestrator.jl",
		"sms_analyzer.jl",
	}
	for _, script := range required {
		fullPath := filepath.Join(a.modelsDir, script)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("required script %q missing from %s", script, a.modelsDir)
		}
	}

	// Optional: check that Julia can load required packages (e.g., JSON, MLJ)
	// This can be done with a short –e "using JSON, MLJ" command, but is left as an
	// exercise for the deployment pipeline.

	return nil
}

// ---------------------------------------------------------------------------
// Fallback results – safe defaults when AI is unavailable
// ---------------------------------------------------------------------------

func (a *MLAgent) getFallbackOrchestration() *models.OrchestrationResult {
	return &models.OrchestrationResult{
		Success:            false,
		TasksExecuted:      []string{"basic_analysis_fallback"},
		Errors:             []string{"AI orchestrator unavailable or disabled"},
		PerformanceMetrics: map[string]float64{"efficiency_score": 0.1},
		Recommendations:    []string{"Ensure Julia is installed and scripts are in place", "Check network connection", "Review configuration 'ai.enable_ai'"},
		NextActions:        []string{"Proceed with non‑AI analysis if possible"},
	}
}

func (a *MLAgent) getFallbackAnalysisResult() *models.AIAnalysisResult {
	return &models.AIAnalysisResult{
		IsSafe:          false,
		Confidence:      0.0,
		RiskLevel:       "UNKNOWN",
		IsShortened:     false,
		HealthScore:     0.1,
		Threats:         []string{"AI analysis unavailable"},
		Recommendations: []string{"Exercise extreme caution", "Verify manually", "Check AI configuration"},
		Error:           "AI analysis module not operational.",
	}
}
