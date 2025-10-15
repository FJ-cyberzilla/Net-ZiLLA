package analyzer

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"net-zilla/internal/ai"
	"net-zilla/internal/models"
	"net-zilla/internal/utils"
)

type ThreatAnalyzer struct {
	mlAgent        *ai.MLAgent
	logger         *utils.Logger
	redirectTracer *RedirectTracer
	domainAnalyzer *DomainAnalyzer
	securityClient *SafeHTTPClient
}

func NewThreatAnalyzer(mlAgent *ai.MLAgent, logger *utils.Logger) *ThreatAnalyzer {
	return &ThreatAnalyzer{
		mlAgent:        mlAgent,
		logger:         logger,
		redirectTracer: NewRedirectTracer(logger),
		domainAnalyzer: NewDomainAnalyzer(),
		securityClient: NewSafeHTTPClient(),
	}
}

func (ta *ThreatAnalyzer) ComprehensiveAnalysis(ctx context.Context, targetURL string) (*models.ThreatAnalysis, error) {
	startTime := time.Now()
	
	analysis := &models.ThreatAnalysis{
		URL:         targetURL,
		AnalyzedAt:  startTime,
		AnalysisID:  generateAnalysisID(),
	}

	// Normalize URL
	normalizedURL, err := ta.normalizeURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	analysis.URL = normalizedURL

	// Parse URL
	parsedURL, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("URL parsing failed: %w", err)
	}

	// Perform concurrent analyses
	results := make(chan analysisResult, 5)
	
	go ta.analyzeDomain(parsedURL, analysis, results)
	go ta.analyzeRedirects(ctx, normalizedURL, analysis, results)
	go ta.analyzeDNS(parsedURL.Host, analysis, results)
	go ta.analyzeAI(normalizedURL, parsedURL.Host, analysis, results)
	go ta.analyzeSecurityHeaders(ctx, normalizedURL, analysis, results)

	// Collect results
	var totalScore int
	for i := 0; i < 5; i++ {
		result := <-results
		if result.err != nil {
			ta.logger.Warn("Analysis component failed: %v", result.err)
		}
		totalScore += result.score
	}

	// Calculate final threat score
	analysis.ThreatScore = totalScore
	analysis.ThreatLevel = ta.determineThreatLevel(totalScore)
	analysis.AnalysisDuration = time.Since(startTime)

	// Generate comprehensive report
	ta.generateSafetyRecommendations(analysis)

	ta.logger.Info("Analysis completed", 
		"url", targetURL, 
		"score", totalScore,
		"level", analysis.ThreatLevel,
		"duration", analysis.AnalysisDuration)

	return analysis, nil
}

func (ta *ThreatAnalyzer) normalizeURL(rawURL string) (string, error) {
	// Ensure URL has scheme
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Validate URL format
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	return parsed.String(), nil
}

func (ta *ThreatAnalyzer) analyzeDomain(parsedURL *url.URL, analysis *models.ThreatAnalysis, results chan<- analysisResult) {
	score := ta.domainAnalyzer.Analyze(parsedURL, analysis)
	results <- analysisResult{score: score}
}

func (ta *ThreatAnalyzer) analyzeRedirects(ctx context.Context, url string, analysis *models.ThreatAnalysis, results chan<- analysisResult) {
	redirects, score, err := ta.redirectTracer.TraceRedirects(ctx, url)
	if err != nil {
		ta.logger.Warn("Redirect tracing failed: %v", err)
		results <- analysisResult{score: 20, err: err} // Penalty for failed analysis
		return
	}
	
	analysis.RedirectChain = redirects
	analysis.RedirectCount = len(redirects)
	results <- analysisResult{score: score}
}

func (ta *ThreatAnalyzer) analyzeDNS(host string, analysis *models.ThreatAnalysis, results chan<- analysisResult) {
	score := ta.domainAnalyzer.AnalyzeDNS(host, analysis)
	results <- analysisResult{score: score}
}

func (ta *ThreatAnalyzer) analyzeAI(url, host string, analysis *models.ThreatAnalysis, results chan<- analysisResult) {
	if ta.mlAgent != nil && ta.mlAgent.IsAvailable() {
		aiResult, err := ta.mlAgent.AnalyzeLink(url, host)
		if err == nil {
			analysis.AIResult = aiResult
			
			// Convert AI confidence to threat score
			aiScore := int((1 - aiResult.Confidence) * 100)
			if aiScore < 0 {
				aiScore = 0
			}
			results <- analysisResult{score: aiScore}
			return
		}
		ta.logger.Warn("AI analysis failed: %v", err)
	}
	
	// Fallback without AI
	results <- analysisResult{score: 25}
}

func (ta *ThreatAnalyzer) analyzeSecurityHeaders(ctx context.Context, url string, analysis *models.ThreatAnalysis, results chan<- analysisResult) {
	headers, score, err := ta.securityClient.CheckSecurityHeaders(ctx, url)
	if err != nil {
		ta.logger.Warn("Security headers check failed: %v", err)
		results <- analysisResult{score: 15, err: err}
		return
	}
	
	analysis.SecurityHeaders = headers
	results <- analysisResult{score: score}
}

func (ta *ThreatAnalyzer) determineThreatLevel(score int) models.ThreatLevel {
	switch {
	case score >= 80:
		return models.ThreatLevelCritical
	case score >= 60:
		return models.ThreatLevelHigh
	case score >= 40:
		return models.ThreatLevelMedium
	case score >= 20:
		return models.ThreatLevelLow
	default:
		return models.ThreatLevelSafe
	}
}

func (ta *ThreatAnalyzer) generateSafetyRecommendations(analysis *models.ThreatAnalysis) {
	recommendations := []string{
		"Never enter personal information on links from unknown sources",
		"Verify sender identity through official channels",
		"Enable two-factor authentication on important accounts",
	}

	if analysis.ThreatScore >= 60 {
		recommendations = append(recommendations,
			"🚨 DO NOT OPEN THIS LINK - Delete immediately",
			"Report to your mobile carrier (forward to 7726)",
			"Block the sender number",
		)
	}

	if analysis.RedirectCount > 3 {
		recommendations = append(recommendations,
			"Multiple redirects detected - potential tracking or malicious behavior",
		)
	}

	if analysis.AIResult != nil && analysis.AIResult.IsShortened {
		recommendations = append(recommendations,
			"URL appears to be shortened - original destination hidden",
		)
	}

	analysis.SafetyTips = recommendations
}

type analysisResult struct {
	score int
	err   error
}

func generateAnalysisID() string {
	return fmt.Sprintf("nz-%d", time.Now().UnixNano())
}
package analyzer

import (
	"context"
	"fmt"
	"time"

	"net-zilla/internal/ai"
	"net-zilla/internal/models"
	"net-zilla/internal/utils"
)

// Enhanced ThreatAnalyzer with AI Orchestration
type ThreatAnalyzer struct {
	mlAgent        *ai.MLAgent
	logger         *utils.Logger
	redirectTracer *RedirectTracer
	domainAnalyzer *DomainAnalyzer
	securityClient *SafeHTTPClient
	orchestrator   *ai.Orchestrator
}

func NewThreatAnalyzer(mlAgent *ai.MLAgent, logger *utils.Logger) *ThreatAnalyzer {
	return &ThreatAnalyzer{
		mlAgent:        mlAgent,
		logger:         logger,
		redirectTracer: NewRedirectTracer(logger),
		domainAnalyzer: NewDomainAnalyzer(),
		securityClient: NewSafeHTTPClient(),
	}
}

// ComprehensiveAnalysis with AI Orchestration
func (ta *ThreatAnalyzer) ComprehensiveAnalysis(ctx context.Context, targetURL string) (*models.ThreatAnalysis, error) {
	startTime := time.Now()
	
	// Step 1: AI Orchestration
	ta.logger.Info("🤖 Initializing AI Orchestrator...")
	orchestration, err := ta.mlAgent.OrchestrateAnalysis(targetURL, "comprehensive")
	if err != nil {
		ta.logger.Warn("AI orchestration failed, using fallback: %v", err)
	}

	// Step 2: Perform analysis based on orchestration plan
	analysis := &models.ThreatAnalysis{
		URL:              targetURL,
		AnalyzedAt:       startTime,
		AnalysisID:       generateAnalysisID(),
		AIOrchestration:  orchestration,
	}

	// Execute orchestrated tasks
	if orchestration.Success {
		ta.executeOrchestratedTasks(ctx, targetURL, analysis, orchestration)
	} else {
		// Fallback to standard analysis
		ta.executeStandardAnalysis(ctx, targetURL, analysis)
	}

	analysis.AnalysisDuration = time.Since(startTime)
	analysis.ThreatLevel = ta.determineThreatLevel(analysis.ThreatScore)

	ta.logger.Info("Analysis completed with AI orchestration", 
		"tasks", len(orchestration.TasksExecuted),
		"performance", orchestration.PerformanceMetrics["efficiency_score"])

	return analysis, nil
}

func (ta *ThreatAnalyzer) executeOrchestratedTasks(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis, orchestration *ai.OrchestrationResult) {
	// Execute tasks based on AI orchestration
	for _, task := range orchestration.TasksExecuted {
		switch task {
		case "core_analysis":
			ta.performCoreAnalysis(targetURL, analysis)
		case "threat_analysis":
			ta.performThreatAnalysis(ctx, targetURL, analysis)
		case "ml_analysis":
			ta.performMLAnalysis(targetURL, analysis)
		case "web_analysis":
			ta.performWebAnalysis(ctx, targetURL, analysis)
		case "dns_analysis":
			ta.performDNSAnalysis(targetURL, analysis)
		}
	}
}

func (ta *ThreatAnalyzer) performCoreAnalysis(targetURL string, analysis *models.ThreatAnalysis) {
	// Basic URL analysis and parsing
	parsedURL, err := ta.normalizeURL(targetURL)
	if err == nil {
		analysis.URL = parsedURL
	}
	
	// Domain analysis
	if parsedURL != "" {
		score := ta.domainAnalyzer.AnalyzeBasic(parsedURL, analysis)
		analysis.ThreatScore += score
	}
}

func (ta *ThreatAnalyzer) performThreatAnalysis(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis) {
	// Advanced threat detection
	redirects, score, err := ta.redirectTracer.TraceRedirects(ctx, targetURL)
	if err == nil {
		analysis.RedirectChain = redirects
		analysis.RedirectCount = len(redirects)
		analysis.ThreatScore += score
	}
	
	// Security headers check
	headers, securityScore, err := ta.securityClient.CheckSecurityHeaders(ctx, targetURL)
	if err == nil {
		analysis.SecurityHeaders = headers
		analysis.ThreatScore += securityScore
	}
}

func (ta *ThreatAnalyzer) performMLAnalysis(targetURL string, analysis *models.ThreatAnalysis) {
	// AI-powered analysis
	if ta.mlAgent != nil {
		aiResult, err := ta.mlAgent.AnalyzeLink(targetURL, "")
		if err == nil {
			analysis.AIResult = aiResult
			analysis.ThreatScore += int((1 - aiResult.Confidence) * 100)
		}
	}
}

// ... other task implementations
