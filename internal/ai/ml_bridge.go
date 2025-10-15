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
