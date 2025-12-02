package analyzer

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time""

	"net-zilla/internal/ai"
	"net-zilla/internal/models"
	"net-zilla/internal/network" // Assuming network package for HTTP client and DNS/WHOIS/IP lookups
	"net-zilla/internal/utils"
)

// ThreatAnalyzer is the core component for performing various security analyses.
type ThreatAnalyzer struct {
	mlAgent        *ai.MLAgent
	logger         *utils.Logger
	redirectTracer *network.RedirectTracer // Assuming RedirectTracer is in network package
	domainAnalyzer *DomainAnalyzer         // Local to analyzer package, if it's a simple helper
	ipAnalyzer     *network.IPAnalyzer     // Assuming IPAnalyzer is in network package
	dnsClient      *network.DNSClient      // Assuming DNSClient is in network package
	whoisClient    *network.WhoisClient    // Assuming WhoisClient is in network package
	sslAnalyzer    *network.SSLAnalyzer    // Assuming SSLAnalyzer is in network package
	httpClient     *network.HTTPClient     // General purpose HTTP client
	orchestrator   *ai.Orchestrator
}

// NewThreatAnalyzer creates and initializes a new ThreatAnalyzer instance.
func NewThreatAnalyzer(mlAgent *ai.MLAgent, logger *utils.Logger, orchestrator *ai.Orchestrator) *ThreatAnalyzer {
	return &ThreatAnalyzer{
		mlAgent:        mlAgent,
		logger:         logger,
		redirectTracer: network.NewRedirectTracer(logger),
		domainAnalyzer: NewDomainAnalyzer(logger, dnsClient, whoisClient), // Needs to be defined or moved
		ipAnalyzer:     network.NewIPAnalyzer(logger),
		dnsClient:      network.NewDNSClient(logger),
		whoisClient:    network.NewWhoisClient(logger),
		sslAnalyzer:    network.NewSSLAnalyzer(logger),
		httpClient:     network.NewHTTPClient(logger),
		orchestrator:   orchestrator,
	}
}

// ComprehensiveAnalysis performs a detailed security analysis of the target, potentially using AI orchestration.
func (ta *ThreatAnalyzer) ComprehensiveAnalysis(ctx context.Context, targetURL string) (*models.ThreatAnalysis, error) {
	startTime := time.Now()

	analysis := &models.ThreatAnalysis{
		URL:        targetURL,
		AnalyzedAt: startTime,
		AnalysisID: generateAnalysisID(),
	}

	// Normalize URL
	normalizedURL, err := ta.normalizeURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	analysis.URL = normalizedURL

	// Attempt AI orchestration first
	var orchestration *ai.OrchestrationResult
	if ta.mlAgent != nil && ta.orchestrator != nil {
		ta.logger.Info("🤖 Initializing AI Orchestrator...")
		orchestration, err = ta.orchestrator.OrchestrateAnalysis(ctx, targetURL, "comprehensive")
		if err != nil {
			ta.logger.Warn("AI orchestration failed, falling back to standard analysis: %v", err)
			orchestration = nil // Ensure we fall back
		} else {
			analysis.AIOrchestration = orchestration
		}
	}

	if orchestration != nil && orchestration.Success {
		ta.executeOrchestratedTasks(ctx, normalizedURL, analysis, orchestration)
	} else {
		// Fallback or standard execution
		ta.executeStandardAnalysis(ctx, normalizedURL, analysis)
	}

	analysis.AnalysisDuration = time.Since(startTime)
	analysis.ThreatLevel = ta.determineThreatLevel(analysis.ThreatScore)

	ta.logger.Info("Analysis completed",
		"url", targetURL,
		"score", analysis.ThreatScore,
		"level", analysis.ThreatLevel,
		"duration", analysis.AnalysisDuration)

	return analysis, nil
}

// executeOrchestratedTasks runs analysis tasks based on AI orchestration.
func (ta *ThreatAnalyzer) executeOrchestratedTasks(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis, orchestration *ai.OrchestrationResult) {
	// Use a wait group to run tasks concurrently
	var wg sync.WaitGroup
	resultsChan := make(chan analysisResult, len(orchestration.TasksExecuted))

	for _, task := range orchestration.TasksExecuted {
		wg.Add(1)
		go func(taskName string) {
			defer wg.Done()
			var score int
			var err error
			switch taskName {
			case "core_analysis":
				score, err = ta.performCoreAnalysis(ctx, targetURL, analysis)
			case "threat_analysis":
				score, err = ta.performThreatAnalysis(ctx, targetURL, analysis)
			case "ml_analysis":
				score, err = ta.performMLAnalysis(ctx, targetURL, analysis)
			case "web_analysis":
				score, err = ta.performWebAnalysis(ctx, targetURL, analysis)
			case "dns_analysis":
				score, err = ta.performDNSAnalysisComponent(ctx, targetURL, analysis) // Renamed to avoid conflict
			case "whois_analysis":
				score, err = ta.performWhoisAnalysisComponent(ctx, targetURL, analysis)
			case "ip_analysis":
				score, err = ta.performIPAnalysisComponent(ctx, targetURL, analysis)
			case "ssl_analysis":
				score, err = ta.performSSLAnalysisComponent(ctx, targetURL, analysis)
			case "redirect_trace":
				score, err = ta.performRedirectTraceComponent(ctx, targetURL, analysis)
			default:
				err = fmt.Errorf("unknown orchestrated task: %s", taskName)
			}
			resultsChan <- analysisResult{score: score, err: err}
		}(task)
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		if res.err != nil {
			ta.logger.Warn("Orchestrated analysis component failed: %v", res.err)
		}
		analysis.ThreatScore += res.score
	}
}

// executeStandardAnalysis performs a predefined set of analyses without AI orchestration.
func (ta *ThreatAnalyzer) executeStandardAnalysis(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis) {
	var wg sync.WaitGroup
	resultsChan := make(chan analysisResult, 7) // Number of standard analysis components

	wg.Add(1)
	go func() { defer wg.Done(); resultsChan <- ta.performCoreAnalysis(ctx, targetURL, analysis) }()
	wg.Add(1)
	go func() { defer wg.Done(); resultsChan <- ta.performThreatAnalysis(ctx, targetURL, analysis) }()
	wg.Add(1)
	go func() { defer wg.Done(); resultsChan <- ta.performMLAnalysis(ctx, targetURL, analysis) }()
	wg.Add(1)
	go func() { defer wg.Done(); resultsChan <- ta.performDNSAnalysisComponent(ctx, targetURL, analysis) }()
	wg.Add(1)
	go func() { defer wg.Done(); resultsChan <- ta.performWhoisAnalysisComponent(ctx, targetURL, analysis) }()
	wg.Add(1)
	go func() { defer wg.Done(); resultsChan <- ta.performIPAnalysisComponent(ctx, targetURL, analysis) }()
	wg.Add(1)
	go func() { defer wg.Done(); resultsChan <- ta.performSSLAnalysisComponent(ctx, targetURL, analysis) }()

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		if res.err != nil {
			ta.logger.Warn("Standard analysis component failed: %v", res.err)
		}
		analysis.ThreatScore += res.score
	}
	ta.generateSafetyRecommendations(analysis)
}

// performCoreAnalysis handles basic URL parsing and domain analysis.
func (ta *ThreatAnalyzer) performCoreAnalysis(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis) (int, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return 0, fmt.Errorf("URL parsing failed: %w", err)
	}
	analysis.URL = parsedURL.String() // Ensure it's the normalized/parsed version

	score, err := ta.domainAnalyzer.Analyze(ctx, parsedURL, analysis)
	if err != nil {
		ta.logger.Warn("Domain analysis failed: %v", err)
		return 10, err // Return penalty score and error
	} // Assuming DomainAnalyzer.Analyze updates analysis struct
	return score, nil
}

// performThreatAnalysis handles redirect tracing and security header checks.
func (ta *ThreatAnalyzer) performThreatAnalysis(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis) (int, error) {
	totalScore := 0

	// Redirect tracing
	redirects, score, err := ta.redirectTracer.TraceRedirects(ctx, targetURL)
	if err != nil {
		ta.logger.Warn("Redirect tracing failed: %v", err)
		// Add penalty if tracing fails, but don't stop the whole analysis
		totalScore += 20 // Example penalty
	} else {
		analysis.RedirectChain = redirects
		analysis.RedirectCount = len(redirects)
		totalScore += score
	}

	// Security headers check
	headers, securityScore, err := ta.httpClient.CheckSecurityHeaders(ctx, targetURL) // Assuming this is a method of HTTPClient
	if err != nil {
		ta.logger.Warn("Security headers check failed: %v", err)
		totalScore += 15 // Example penalty
	} else {
		analysis.SecurityHeaders = headers
		totalScore += securityScore
	}
	return totalScore, nil
}

// performMLAnalysis handles AI-powered link analysis.
func (ta *ThreatAnalyzer) performMLAnalysis(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis) (int, error) {
	if ta.mlAgent != nil && ta.mlAgent.IsAvailable() {
		aiResult, err := ta.mlAgent.AnalyzeLink(ctx, targetURL, "") // Assuming AnalyzeLink takes context
		if err == nil {
			analysis.AIResult = aiResult
			// Convert AI confidence to threat score (higher confidence in threat -> higher score)
			aiScore := int((1 - aiResult.Confidence) * 100)
			if aiScore < 0 {
				aiScore = 0
			}
			return aiScore, nil
		}
		ta.logger.Warn("AI analysis failed: %v", err)
	}
	// Fallback without AI
	return 25, fmt.Errorf("AI agent not available or failed")
}

// performWebAnalysis is a placeholder for web content analysis (e.g., link extraction, content patterns)
func (ta *ThreatAnalyzer) performWebAnalysis(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis) (int, error) {
	ta.logger.Info("Web content analysis not fully implemented, skipping for now.", "url", targetURL)
	return 0, nil
}

// performDNSAnalysisComponent performs DNS lookup and updates the analysis struct.
func (ta *ThreatAnalyzer) performDNSAnalysisComponent(ctx context.Context, target string, analysis *models.ThreatAnalysis) (int, error) {
	dnsInfo, err := ta.dnsClient.Lookup(ctx, target)
	if err != nil {
		return 10, fmt.Errorf("DNS lookup failed: %w", err)
	}
	analysis.DNSInfo = dnsInfo
	return 0, nil
}

// performWhoisAnalysisComponent performs WHOIS lookup and updates the analysis struct.
func (ta *ThreatAnalyzer) performWhoisAnalysisComponent(ctx context.Context, target string, analysis *models.ThreatAnalysis) (int, error) {
	whoisInfo, err := ta.whoisClient.Lookup(ctx, target)
	if err != nil {
		return 5, fmt.Errorf("WHOIS lookup failed: %w", err)
	}
	analysis.WhoisInfo = whoisInfo
	return 0, nil
}

// performIPAnalysisComponent performs IP geolocation and updates the analysis struct.
func (ta *ThreatAnalyzer) performIPAnalysisComponent(ctx context.Context, target string, analysis *models.ThreatAnalysis) (int, error) {
	ipGeo, err := ta.ipAnalyzer.GetGeolocation(ctx, target)
	if err != nil {
		return 5, fmt.Errorf("IP geolocation failed: %w", err)
	}
	analysis.GeoLocation = ipGeo
	return 0, nil
}

// performSSLAnalysisComponent performs SSL/TLS analysis and updates the analysis struct.
func (ta *ThreatAnalyzer) performSSLAnalysisComponent(ctx context.Context, target string, analysis *models.ThreatAnalysis) (int, error) {
	sslInfo, err := ta.sslAnalyzer.Analyze(ctx, target)
	if err != nil {
		return 10, fmt.Errorf("SSL/TLS analysis failed: %w", err)
	}
	analysis.TLSInfo = sslInfo
	return 0, nil
}

// performRedirectTraceComponent traces redirects and updates analysis (can be integrated into threat analysis)
func (ta *ThreatAnalyzer) performRedirectTraceComponent(ctx context.Context, targetURL string, analysis *models.ThreatAnalysis) (int, error) {
	redirects, score, err := ta.redirectTracer.TraceRedirects(ctx, targetURL)
	if err != nil {
		return 20, fmt.Errorf("redirect tracing failed: %w", err)
	}
	analysis.RedirectChain = redirects
	analysis.RedirectCount = len(redirects)
	return score, nil
}

// normalizeURL ensures the URL has a scheme and is properly formatted.
func (ta *ThreatAnalyzer) normalizeURL(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL // Default to HTTPS
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// determineThreatLevel assigns a threat level based on the total score.
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

// generateSafetyRecommendations adds safety tips to the analysis based on findings.
func (ta *ThreatAnalyzer) generateSafetyRecommendations(analysis *models.ThreatAnalysis) {
	recommendations := []string{
		"Always verify the sender of an email or message before clicking on links or downloading attachments",
		"Use strong, unique passwords for all your online accounts and enable two-factor authentication (2FA)",
		"Be wary of urgent or emotionally charged messages; these are common phishing tactics",
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

// generateAnalysisID creates a unique ID for each analysis.
func generateAnalysisID() string {
	return fmt.Sprintf("nz-%d", time.Now().UnixNano())
}

// analysisResult is a helper struct for collecting results from concurrent analysis components.
type analysisResult struct {
	score int
	err   error
}


// Helper methods from menu.go that are now called directly from here or should be global
// These are not methods of ThreatAnalyzer but rather standalone functions in the utils package,
// but they might be called from within ThreatAnalyzer in some cases for consistency or data enrichment.

// PerformDNSLookup method for ThreatAnalyzer
func (ta *ThreatAnalyzer) PerformDNSLookup(ctx context.Context, target string) (*models.DNSAnalysis, error) {
	return ta.dnsClient.Lookup(ctx, target)
}

// PerformWhoisLookup method for ThreatAnalyzer
func (ta *ThreatAnalyzer) PerformWhoisLookup(ctx context.Context, target string) (*models.WhoisAnalysis, error) {
	return ta.whoisClient.Lookup(ctx, target)
}

// PerformIPGeolocation method for ThreatAnalyzer
func (ta *ThreatAnalyzer) PerformIPGeolocation(ctx context.Context, target string) (*models.GeoAnalysis, error) {
	return ta.ipAnalyzer.GetGeolocation(ctx, target)
}

// PerformTLSAnalysis method for ThreatAnalyzer (assuming it uses sslAnalyzer)
func (ta *ThreatAnalyzer) PerformTLSAnalysis(ctx context.Context, target string) (*models.TLSAnalysis, error) {
	return ta.sslAnalyzer.Analyze(ctx, target)
}

// PerformTraceroute method for ThreatAnalyzer (assuming network package has this)
func (ta *ThreatAnalyzer) PerformTraceroute(ctx context.Context, target string) (*models.NetworkAnalysis, error) {
	// Placeholder: Actual traceroute implementation would be here
	// For now, returning dummy data
	return &models.NetworkAnalysis{
		HopCount:       5,
		AverageLatency: 20 * time.Millisecond,
		GeoPath:        "Local -> Internet -> Target",
	}, nil
}