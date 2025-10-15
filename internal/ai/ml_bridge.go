package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"net-zilla/internal/models"
)

type MLAgent struct {
	juliaPath    string
	modelsPath   string
	isAvailable  bool
}

type AIAnalysisResult struct {
	IsSafe       bool     `json:"is_safe"`
	Confidence   float64  `json:"confidence"`
	RiskLevel    string   `json:"risk_level"`
	IsShortened  bool     `json:"is_shortened"`
	HealthScore  float64  `json:"health_score"`
	Threats      []string `json:"threats"`
	Recommendations []string `json:"recommendations"`
	Error        string   `json:"error,omitempty"`
}

func NewMLAgent() (*MLAgent, error) {
	agent := &MLAgent{
		juliaPath:   "julia",
		modelsPath:  "./ml/models",
		isAvailable: false,
	}

	// Check if Julia is available
	if err := agent.checkJulia(); err != nil {
		return agent, fmt.Errorf("Julia not available: %v", err)
	}

	// Check if ML models are available
	if err := agent.checkModels(); err != nil {
		return agent, fmt.Errorf("ML models not available: %v", err)
	}

	agent.isAvailable = true
	return agent, nil
}

func (a *MLAgent) checkJulia() error {
	cmd := exec.Command(a.juliaPath, "--version")
	return cmd.Run()
}

func (a *MLAgent) checkModels() error {
	requiredFiles := []string{
		"link_health.jl",
		"ip_reputation.jl", 
		"url_shortener.jl",
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(fmt.Sprintf("%s/%s", a.modelsPath, file)); os.IsNotExist(err) {
			return fmt.Errorf("missing model file: %s", file)
		}
	}
	return nil
}

func (a *MLAgent) AnalyzeLink(url, ip string) (*AIAnalysisResult, error) {
	if !a.isAvailable {
		return a.getFallbackResult(), nil
	}

	scriptPath := fmt.Sprintf("%s/julia_agent.jl", a.modelsPath)
	
	cmd := exec.Command(a.juliaPath, scriptPath, url, ip)
	output, err := cmd.Output()
	if err != nil {
		return a.getFallbackResult(), fmt.Errorf("Julia execution failed: %v", err)
	}

	var result AIAnalysisResult
	if err := json.Unmarshal(output, &result); err != nil {
		return a.getFallbackResult(), fmt.Errorf("failed to parse AI result: %v", err)
	}

	return &result, nil
}

func (a *MLAgent) getFallbackResult() *AIAnalysisResult {
	return &AIAnalysisResult{
		IsSafe:       false,
		Confidence:   0.0,
		RiskLevel:    "UNKNOWN",
		IsShortened:  false,
		HealthScore:  0.5,
		Threats:      []string{"AI analysis unavailable"},
		Recommendations: []string{"Use caution", "Verify manually"},
	}
}

func (a *MLAgent) IsAvailable() bool {
	return a.isAvailable
}

func (a *MLAgent) GetPlatform() string {
	return runtime.GOOS
}
package ai

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// Enhanced MLAgent with Orchestrator
type MLAgent struct {
	juliaPath      string
	modelsPath     string
	isAvailable    bool
	orchestrator   *Orchestrator
}

type Orchestrator struct {
	juliaPath    string
	modelsPath   string
}

type OrchestrationResult struct {
	Success           bool              `json:"success"`
	TasksExecuted     []string          `json:"tasks_executed"`
	Errors           []string          `json:"errors"`
	PerformanceMetrics map[string]float64 `json:"performance_metrics"`
	Recommendations   []string          `json:"recommendations"`
	NextActions      []string          `json:"next_actions"`
}

func NewMLAgent() (*MLAgent, error) {
	agent := &MLAgent{
		juliaPath:   "julia",
		modelsPath:  "./ml/models",
		isAvailable: false,
		orchestrator: &Orchestrator{
			juliaPath:  "julia",
			modelsPath: "./ml/models",
		},
	}

	// Check if Julia is available
	if err := agent.checkJulia(); err != nil {
		return agent, fmt.Errorf("Julia not available: %v", err)
	}

	agent.isAvailable = true
	return agent, nil
}

// OrchestrateAnalysis - Main AI orchestration function
func (a *MLAgent) OrchestrateAnalysis(target, analysisType string) (*OrchestrationResult, error) {
	if !a.isAvailable {
		return a.getFallbackOrchestration(), nil
	}

	scriptPath := fmt.Sprintf("%s/orchestrator.jl", a.modelsPath)
	cmd := exec.Command(a.juliaPath, scriptPath, target, analysisType)
	
	output, err := cmd.Output()
	if err != nil {
		return a.getFallbackOrchestration(), fmt.Errorf("orchestrator execution failed: %v", err)
	}

	var result OrchestrationResult
	if err := json.Unmarshal(output, &result); err != nil {
		return a.getFallbackOrchestration(), fmt.Errorf("failed to parse orchestration result: %v", err)
	}

	return &result, nil
}

// SystemDiagnostics - Check if system is ready for analysis
func (a *MLAgent) SystemDiagnostics() *OrchestrationResult {
	if !a.isAvailable {
		return a.getFallbackOrchestration()
	}

	// Use a simple target to test system functionality
	return a.OrchestrateAnalysis("https://example.com", "diagnostic")
}

func (a *MLAgent) getFallbackOrchestration() *OrchestrationResult {
	return &OrchestrationResult{
		Success:       false,
		TasksExecuted: []string{"basic_analysis"},
		Errors:       []string{"AI orchestrator unavailable"},
		PerformanceMetrics: map[string]float64{
			"total_time": 2.0,
			"efficiency_score": 0.5,
		},
		Recommendations: []string{"Use basic analysis mode", "Check system configuration"},
		NextActions:    []string{"Continue with standard analysis"},
	}
}

// Existing analysis functions remain but are now orchestrated
func (a *MLAgent) AnalyzeLink(url, ip string) (*AIAnalysisResult, error) {
	// This now goes through the orchestrator
	orchestration, err := a.OrchestrateAnalysis(url, "link_analysis")
	if err != nil {
		return a.getFallbackResult(), err
	}

	// Convert orchestration to analysis result
	return a.orchestrationToAnalysis(orchestration, url, ip), nil
}

func (a *MLAgent) orchestrationToAnalysis(orc *OrchestrationResult, url, ip string) *AIAnalysisResult {
	return &AIAnalysisResult{
		IsSafe:          orc.Success && len(orc.Errors) == 0,
		Confidence:      orc.PerformanceMetrics["efficiency_score"],
		RiskLevel:       a.determineRiskLevel(orc),
		IsShortened:     a.detectShortenedURL(url),
		HealthScore:     orc.PerformanceMetrics["efficiency_score"],
		Threats:         orc.Errors,
		Recommendations: orc.Recommendations,
	}
}

func (a *MLAgent) determineRiskLevel(orc *OrchestrationResult) string {
	if !orc.Success || len(orc.Errors) > 0 {
		return "HIGH"
	}
	if orc.PerformanceMetrics["efficiency_score"] < 0.7 {
		return "MEDIUM"
	}
	return "LOW"
}

func (a *MLAgent) detectShortenedURL(url string) bool {
	shorteners := []string{"bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"}
	for _, shortener := range shorteners {
		if contains(url, shortener) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[0:len(substr)] == substr || contains(s[1:], substr)))
}
