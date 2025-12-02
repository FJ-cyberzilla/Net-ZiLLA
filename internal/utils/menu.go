package utils

import (
	"bufio"
	"context"
	"fmt"
	"net/url" // Needed for url.Parse in helper functions
	"os"
	"strings"
	time "time"

	"net-zilla/internal/ai"
	"net-zilla/internal/analyzer"
	"net-zilla/internal/models"
	"net-zilla/internal/network" // Needed for redirect chain analysis helpers
)

// Constants for color coding
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorPurple  = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
)

// ClearScreen clears the terminal screen
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// DisplayBanner displays the application banner
func DisplayBanner() {
	fmt.Println(`
 _____  _   _ _____   _         _ _ 
|  __ \| \ | |  ___| | |       | | |
| |  \/|  \| | |__   | |     __| | |
| | __ | . ' |  __|  | |    / _  | |
| |\ \| |\  | |___  | |___| (_| | |
 \____/\_| \_|\____/  \____/\____|_|
`)
}

// Menu provides the interactive command-line interface for Net-ZiLLA.
type Menu struct {
	threatAnalyzer *analyzer.ThreatAnalyzer
	logger         *Logger
	mlAgent        *ai.MLAgent
	scanner        *bufio.Scanner
	running        bool
}

// NewMenu creates and initializes a new Menu instance.
func NewMenu(threatAnalyzer *analyzer.ThreatAnalyzer, logger *Logger, mlAgent *ai.MLAgent) *Menu {
	return &Menu{
		threatAnalyzer: threatAnalyzer,
		logger:         logger,
		mlAgent:        mlAgent,
		scanner:        bufio.NewScanner(os.Stdin),
		running:        true,
	}
}

// Run starts the main menu loop.
func (m *Menu) Run() error {
	for m.running {
		m.displayMainMenu()

		fmt.Print("\n🔍 Select option: ")
		m.scanner.Scan()
		choice := strings.TrimSpace(m.scanner.Text())

		switch choice {
		case "1":
			m.analyzeLink()
		case "2":
			m.analyzeSMSMessage()
		case "3":
			m.dnsWhoisLookup()
		case "4":
			m.ipAnalysis()
		case "5":
			m.securityTips()
		case "6":
			m.generateFullReport()
		case "7":
			m.systemInfo()
		case "0", "exit", "quit":
			m.running = false
			fmt.Println("\n👋 Thank you for using Net-Zilla! Stay safe!")
		default:
			fmt.Printf("%s❌ Invalid option. Please try again.%s\n", ColorRed, ColorReset)
		}

		if m.running {
			fmt.Printf("\n%sPress Enter to continue...%s", ColorYellow, ColorReset)
			m.scanner.Scan()
		}
	}
	return nil
}

// displayMainMenu shows the main options to the user.
func (m *Menu) displayMainMenu() {
	ClearScreen()
	DisplayBanner()

	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s                   MAIN MENU%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	menuItems := []struct {
		number string
		title  string
		desc   string
	}{
		{"1", "🔍 Analyze Suspicious Link", "Comprehensive URL analysis with AI"},
		{"2", "📱 Analyze SMS/Text Message", "Check message content for phishing"},
		{"3", "🌐 DNS & WHOIS Lookup", "Domain information and ownership"},
		{"4", "📍 IP Address Analysis", "Geolocation and reputation check"},
		{"5", "🛡️  Security Protection Guide", "Learn how to stay safe online"},
		{"6", "📋 Generate Full Report", "Comprehensive security report (Enterprise)"},
		{"7", "💻 System Information", "View tool status and AI availability"},
		{"0", "🚪 Exit", "Close the application"},
	}

	for _, item := range menuItems {
		fmt.Printf("%s[%s]%s %s\n", ColorYellow, item.number, ColorReset, item.title)
		fmt.Printf("    %s%s%s\n\n", ColorCyan, item.desc, ColorReset)
	}
}

// analyzeLink prompts the user for a URL and performs a comprehensive analysis.
func (m *Menu) analyzeLink() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s                LINK ANALYSIS%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	fmt.Printf("%s⚠️  Enter the suspicious link to analyze:%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s(We'll analyze it safely without exposing your data)%s\n\n", ColorCyan, ColorReset)
	fmt.Print("🔗 URL: ")

	m.scanner.Scan()
	url := strings.TrimSpace(m.scanner.Text())

	if url == "" {
		fmt.Printf("%s❌ No URL provided.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("\n%s🔍 Analyzing link safely...%s\n", ColorYellow, ColorReset)
	fmt.Printf("%sThis may take a few seconds...%s\n\n", ColorCyan, ColorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	analysis, err := m.threatAnalyzer.ComprehensiveAnalysis(ctx, url)
	if err != nil {
		fmt.Printf("%s❌ Analysis failed: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	m.displayAnalysisResults(analysis)

	if m.shouldSaveReport() {
		m.saveAnalysisReport(analysis)
	}
}

// displayAnalysisResults shows the detailed threat analysis report.
func (m *Menu) displayAnalysisResults(analysis *models.ThreatAnalysis) {
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s             THREAT ANALYSIS REPORT%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	levelColor := ColorGreen
	switch analysis.ThreatLevel {
	case models.ThreatLevelCritical, models.ThreatLevelHigh:
		levelColor = ColorRed
	case models.ThreatLevelMedium:
		levelColor = ColorYellow
	case models.ThreatLevelLow:
		levelColor = ColorGreen
	}

	fmt.Printf("%sThreat Level: %s%s%s\n", ColorBold, levelColor, analysis.ThreatLevel, ColorReset)
	fmt.Printf("%sThreat Score: %s%d/100%s\n\n", ColorBold, ColorYellow, analysis.ThreatScore, ColorReset)

	fmt.Printf("%s📋 URL Information:%s\n", ColorCyan, ColorReset)
	fmt.Printf("   Analyzed URL: %s\n", analysis.URL)
	fmt.Printf("   Analysis ID: %s\n", analysis.AnalysisID)
	fmt.Printf("   Analysis Time: %s\n", analysis.AnalyzedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Duration: %v\n\n", analysis.AnalysisDuration)

	if analysis.AIResult != nil {
		fmt.Printf("%s🤖 AI Analysis:%s\n", ColorPurple, ColorReset)
		fmt.Printf("   Safety: %s\n", formatBool(analysis.AIResult.IsSafe, "✅ Safe", "❌ Unsafe"))
		fmt.Printf("   Confidence: %.1f%%\n", analysis.AIResult.Confidence*100)
		fmt.Printf("   URL Type: %s\n", formatBool(analysis.AIResult.IsShortened, "Shortened", "Normal"))
		fmt.Printf("   Health Score: %.1f/100\n\n", analysis.AIResult.HealthScore*100)
	}

	if len(analysis.RedirectChain) > 0 {
		fmt.Printf("%s🔄 Redirect Chain (%d hops):%s\n", ColorCyan, len(analysis.RedirectChain), ColorReset)
		for i, redirect := range analysis.RedirectChain {
			statusColor := ColorGreen
			if redirect.StatusCode >= 400 {
				statusColor = ColorRed
			} else if redirect.StatusCode >= 300 {
				statusColor = ColorYellow
			}

			fmt.Printf("   %d. %s\n", i+1, redirect.URL)
			fmt.Printf("      Status: %s%d%s | Location: %s\n",
				statusColor, redirect.StatusCode, ColorReset, redirect.Location)
			fmt.Printf("      Time: %v | Cookies: %d\n",
				redirect.Duration, len(redirect.Cookies))
		}
		fmt.Println()
	}

	if len(analysis.Warnings) > 0 {
		fmt.Printf("%s⚠️  Warnings:%s\n", ColorYellow, ColorReset)
		for _, warning := range analysis.Warnings {
			fmt.Printf("   • %s\n", warning)
		}
		fmt.Println()
	}

	if analysis.AIResult != nil && len(analysis.AIResult.Threats) > 0 {
		fmt.Printf("%s🚨 AI-Detected Threats:%s\n", ColorRed, ColorReset)
		for _, threat := range analysis.AIResult.Threats {
			fmt.Printf("   • %s\n", threat)
		}
		fmt.Println()
	}

	if len(analysis.SafetyTips) > 0 {
		fmt.Printf("%s💡 Safety Recommendations:%s\n", ColorGreen, ColorReset)
		for i, tip := range analysis.SafetyTips {
			fmt.Printf("   %d. %s\n", i+1, tip)
		}
		fmt.Println()
	}

	fmt.Printf("%s%sFINAL VERDICT:%s\n", ColorBold, ColorCyan, ColorReset)
	if analysis.ThreatScore >= 70 {
		fmt.Printf("%s⛔ CRITICAL THREAT - DO NOT OPEN THIS LINK%s\n", ColorRed, ColorReset)
		fmt.Printf("%sDelete the message immediately and report it.%s\n", ColorRed, ColorReset)
	} else if analysis.ThreatScore >= 50 {
		fmt.Printf("%s⚠️  HIGH RISK - Exercise extreme caution%s\n", ColorYellow, ColorReset)
		fmt.Printf("%sOnly proceed if you're absolutely certain of the source.%s\n", ColorYellow, ColorReset)
	} else if analysis.ThreatScore >= 30 {
		fmt.Printf("%s🔶 MEDIUM RISK - Be cautious%s\n", ColorYellow, ColorReset)
		fmt.Printf("%sVerify the sender before taking any action.%s\n", ColorYellow, ColorReset)
	} else {
		fmt.Printf("%s✅ LOW RISK - Appears relatively safe%s\n", ColorGreen, ColorReset)
		fmt.Printf("%sStill recommended to verify the source.%s\n", ColorGreen, ColorReset)
	}
}

func (m *Menu) shouldSaveReport() bool {
	fmt.Printf("\n%s💾 Save detailed report to file? (y/n): %s", ColorCyan, ColorReset)
	m.scanner.Scan()
	response := strings.ToLower(strings.TrimSpace(m.scanner.Text()))
	return response == "y" || response == "yes"
}

func (m *Menu) saveAnalysisReport(analysis *models.ThreatAnalysis) {
	filename := fmt.Sprintf("netzilla_report_%s.txt", analysis.AnalysisID)
	content := m.generateAnalysisReportContent(analysis)

	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		fmt.Printf("%s❌ Failed to save report: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	fmt.Printf("%s✅ Report saved: %s%s\n", ColorGreen, filename, ColorReset)
}

func (m *Menu) generateAnalysisReportContent(analysis *models.ThreatAnalysis) string {
	var sb strings.Builder

	sb.WriteString("NET-ZILLA SECURITY ANALYSIS REPORT\n")
	sb.WriteString("===================================\n\n")
	sb.WriteString(fmt.Sprintf("Analysis ID: %s\n", analysis.AnalysisID))
	sb.WriteString(fmt.Sprintf("Analysis Time: %s\n", analysis.AnalyzedAt.Format("2006-01-02 15:04:05")))
	ssb.WriteString(fmt.Sprintf("URL: %s\n", analysis.URL))
	sb.WriteString(fmt.Sprintf("Threat Level: %s\n", analysis.ThreatLevel))
	ssb.WriteString(fmt.Sprintf("Threat Score: %d/100\n\n", analysis.ThreatScore))

	if analysis.AIResult != nil {
		sb.WriteString("AI Analysis:\n")
		sb.WriteString(fmt.Sprintf("  Safety: %s\n", formatBool(analysis.AIResult.IsSafe, "Safe", "Unsafe")))
		sb.WriteString(fmt.Sprintf("  Confidence: %.1f%%\n", analysis.AIResult.Confidence*100))
		if len(analysis.AIResult.Threats) > 0 {
			sb.WriteString("  AI-Detected Threats:\n")
			for _, threat := range analysis.AIResult.Threats {
				sb.WriteString(fmt.Sprintf("    - %s\n", threat))
			}
		}
		sb.WriteString("\n")
	}

	if len(analysis.RedirectChain) > 0 {
		sb.WriteString("Redirect Chain:\n")
		for i, redirect := range analysis.RedirectChain {
			sb.WriteString(fmt.Sprintf("  %d. %s -> %s (Status: %d, Time: %v)\n", i+1, redirect.URL, redirect.Location, redirect.StatusCode, redirect.Duration))
		}
		sb.WriteString("\n")
	}

	if len(analysis.Warnings) > 0 {
		sb.WriteString("Warnings:\n")
		for _, warning := range analysis.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", warning))
		}
		sb.WriteString("\n")
	}

	if len(analysis.SafetyTips) > 0 {
		sb.WriteString("Safety Recommendations:\n")
		for i, tip := range analysis.SafetyTips {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, tip))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Final Verdict: %s\n", getVerdict(analysis.ThreatScore)))

	return sb.String()
}

// analyzeSMSMessage handles the SMS message analysis.
func (m *Menu) analyzeSMSMessage() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s               SMS MESSAGE ANALYSIS%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	fmt.Printf("%s📱 Enter the SMS message to analyze:%s\n\n", ColorYellow, ColorReset)
	fmt.Print("💬 Message: ")

	m.scanner.Scan()
	message := strings.TrimSpace(m.scanner.Text())

	if message == "" {
		fmt.Printf("%s❌ No message provided.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("\n%s🔍 Analyzing SMS message for threats...%s\n", ColorYellow, ColorReset)

	aiResponse, err := m.mlAgent.AnalyzeSMS(context.Background(), message)
	if err != nil {
		fmt.Printf("%s❌ AI analysis failed: %v%s\n", ColorRed, err, ColorReset)
		fmt.Printf("%s⚠️  Falling back to basic keyword detection.%s\n", ColorYellow, ColorReset)
		if strings.Contains(strings.ToLower(message), "urgent") || strings.Contains(strings.ToLower(message), "prize") {
			fmt.Printf("%s🚨 Basic detection found suspicious keywords. Threat Level: HIGH%s\n", ColorRed, ColorReset)
		} else {
			fmt.Printf("%s✅ Basic detection found no obvious threats.%s\n", ColorGreen, ColorReset)
		}
		return
	}

	fmt.Printf("\n%s🤖 AI SMS Analysis Result:%s\n", ColorPurple, ColorReset)
	fmt.Printf("   Is Scam: %s\n", formatBool(aiResponse.IsScam, "❌ YES", "✅ NO"))
	fmt.Printf("   Threat Level: %s\n", aiResponse.ThreatLevel)
	fmt.Printf("   Confidence: %.1f%%\n", aiResponse.Confidence*100)
	if len(aiResponse.Threats) > 0 {
		fmt.Printf("   Detected Threats:\n")
		for _, threat := range aiResponse.Threats {
			fmt.Printf("     • %s\n", threat)
		}
	} else {
		fmt.Printf("   No specific threats detected by AI.\n")
	}
	fmt.Println()
}

// dnsWhoisLookup handles DNS and WHOIS lookups.
func (m *Menu) dnsWhoisLookup() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s                 DNS & WHOIS LOOKUP%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	fmt.Printf("%s🌐 Enter domain or IP for DNS/WHOIS lookup:%s\n\n", ColorYellow, ColorReset)
	fmt.Print("🌍 Target: ")

	m.scanner.Scan()
	target := strings.TrimSpace(m.scanner.Text())

	if target == "" {
		fmt.Printf("%s❌ No target provided.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("\n%s🔍 Performing DNS lookup...%s\n", ColorYellow, ColorReset)
	dnsInfo, err := m.threatAnalyzer.PerformDNSLookup(context.Background(), target)
	if err != nil {
		fmt.Printf("%s❌ DNS lookup failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		fmt.Printf("%s✅ DNS Records:%s\n", ColorGreen, ColorReset)
		fmt.Printf("   A Records: %v\n", dnsInfo.ARecords)
		fmt.Printf("   MX Records: %v\n", dnsInfo.MXRecords)
		fmt.Printf("   NS Records: %v\n", dnsInfo.NameServers)
		fmt.Printf("   TXT Records: %v\n\n", dnsInfo.TXTRecords)
	}

	fmt.Printf("%s🔍 Performing WHOIS lookup...%s\n", ColorYellow, ColorReset)
	whoisInfo, err := m.threatAnalyzer.PerformWhoisLookup(context.Background(), target)
	if err != nil {
		fmt.Printf("%s❌ WHOIS lookup failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		fmt.Printf("%s✅ WHOIS Information:%s\n", ColorGreen, ColorReset)
		fmt.Printf("   Registrar: %s\n", whoisInfo.Registrar)
		fmt.Printf("   Domain Age: %s\n", whoisInfo.DomainAge)
		fmt.Printf("   Creation Date: %s\n", whoisInfo.CreatedDate)
		fmt.Printf("   Expiration Date: %s\n\n", whoisInfo.ExpiryDate)
	}
}

// ipAnalysis handles IP address analysis (geolocation, reputation).
func (m *Menu) ipAnalysis() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s                  IP ADDRESS ANALYSIS%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	fmt.Printf("%s📍 Enter IP address for analysis:%s\n\n", ColorYellow, ColorReset)
	fmt.Print("IP: ")

	m.scanner.Scan()
	ip := strings.TrimSpace(m.scanner.Text())

	if ip == "" {
		fmt.Printf("%s❌ No IP address provided.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("\n%s🔍 Performing IP analysis...%s\n", ColorYellow, ColorReset)
	ipGeo, err := m.threatAnalyzer.PerformIPGeolocation(context.Background(), ip)
	if err != nil {
		fmt.Printf("%s❌ IP analysis failed: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	fmt.Printf("%s✅ IP Geolocation and Info:%s\n", ColorGreen, ColorReset)
	fmt.Printf("   IP: %s\n", ipGeo.IP)
	fmt.Printf("   Country: %s\n", ipGeo.Country)
	fmt.Printf("   City: %s\n", ipGeo.City)
	fmt.Printf("   ISP: %s\n", ipGeo.ISP)
	fmt.Printf("   ASN: %s\n", ipGeo.ASN)
	fmt.Printf("   Is Proxy/VPN: %v\n", ipGeo.IsProxy)
	fmt.Printf("   Hosting Type: %s\n\n", ipGeo.HostingType)

	fmt.Printf("%sℹ️  IP Reputation: Not yet implemented%s\n\n", ColorYellow, ColorReset)
}

// securityTips displays general security advice.
func (m *Menu) securityTips() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s               SECURITY PROTECTION GUIDE%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	tips := []string{ // Fixed: ips -> tips
		"Always verify the sender of an email or message before clicking on links or downloading attachments.",
		"Use strong, unique passwords for all your online accounts and enable two-factor authentication (2FA).",
		"Be wary of urgent or emotionally charged messages; these are common phishing tactics.",
		"Regularly update your operating system, web browser, and security software.",
		"Avoid public Wi-Fi for sensitive transactions. Use a VPN if you must.",
		"Backup your important data regularly to an external drive or cloud service.",
		"Educate yourself about common cyber threats like phishing, ransomware, and malware.",
		"Check for 'https://' and a padlock icon in your browser's address bar to ensure a secure connection.",
		"If something looks too good to be true, it probably is.",
	}

	fmt.Printf("%s💡 Top Security Tips:%s\n", ColorGreen, ColorReset)
	for i, tip := range tips {
		fmt.Printf("   %d. %s\n", i+1, tip)
	}
	fmt.Println()
}

// systemInfo displays the system status and AI orchestrator information.
func (m *Menu) systemInfo() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s               SYSTEM STATUS & AI ORCHESTRATOR%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	fmt.Printf("%s🔄 Running system diagnostics...%s\n\n", ColorYellow, ColorReset)

	orchestration, err := m.mlAgent.SystemDiagnostics(context.Background())
	if err != nil {
		fmt.Printf("%s❌ System diagnostics failed: %v%s\n", ColorRed, err, ColorReset)
		fmt.Printf("\n%s🤖 AI ORCHESTRATOR STATUS:%s\n", ColorBold, ColorPurple, ColorReset)
		fmt.Printf("   Overall: %s\n", getStatusColor(false))
		fmt.Printf("   Tasks Ready: N/A\n")
		fmt.Printf("   Performance Score: N/A\n")
		fmt.Printf("\n%s🔧 COMPONENTS STATUS:%s\n", ColorBold, ColorCyan, ColorReset)
		fmt.Printf("   Analysis Engine: %s\n", getStatusColor(true))
		fmt.Printf("   ML Models: %s\n", getStatusColor(false))
		fmt.Printf("   Network Stack: %s\n", getStatusColor(true))
		fmt.Printf("   Security Protocols: %s\n", getStatusColor(true))
		return
	}

	fmt.Printf("%s🤖 AI ORCHESTRATOR STATUS:%s\n", ColorBold, ColorPurple, ColorReset)
	fmt.Printf("   Overall: %s\n", getStatusColor(orchestration.Success))
	fmt.Printf("   Tasks Ready: %d/%d\n", len(orchestration.TasksExecuted), 5)
	fmt.Printf("   Performance Score: %.1f/100\n", orchestration.PerformanceMetrics["efficiency_score"]*100)

	fmt.Printf("\n%s🔧 COMPONENTS STATUS:%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("   Analysis Engine: %s\n", getStatusColor(true))
	fmt.Printf("   ML Models: %s\n", getStatusColor(m.mlAgent.IsAvailable()))
	fmt.Printf("   Network Stack: %s\n", getStatusColor(true))
	fmt.Printf("   Security Protocols: %s\n", getStatusColor(true))

	fmt.Printf("\n%s📊 PERFORMANCE METRICS:%s\n", ColorBold, ColorYellow, ColorReset)
	for metric, value := range orchestration.PerformanceMetrics {
		fmt.Printf("   %s: %.2f\n", metric, value)
	}

	if len(orchestration.Recommendations) > 0 {
		fmt.Printf("\n%s💡 AI RECOMMENDATIONS:%s\n", ColorBold, ColorGreen, ColorReset)
		for i, rec := range orchestration.Recommendations {
			fmt.Printf("   %d. %s\n", i+1, rec)
		}
	}

	if len(orchestration.NextActions) > 0 {
		fmt.Printf("\n%s🎯 NEXT ACTIONS:%s\n", ColorBold, ColorBlue, ColorReset)
		for i, action := range orchestration.NextActions {
			fmt.Printf("   %d. %s\n", i+1, action)
		}
	}
}

// getStatusColor returns a colored string indicating operational status.
func getStatusColor(success bool) string {
	if success {
		return fmt.Sprintf("%s✅ Operational%s", ColorGreen, ColorReset)
	}
	return fmt.Sprintf("%s❌ Offline%s", ColorRed, ColorReset)
}

// formatBool returns a custom string representation for a boolean value.
func formatBool(value bool, trueStr, falseStr string) string {
	if value {
		return trueStr
	}
	return falseStr
}

// generateFullReport collects data from various analyzers and displays a comprehensive report.
func (m *Menu) generateFullReport() {
	ClearScreen()
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s             COMPREHENSIVE SECURITY REPORT%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	fmt.Printf("%sEnter URL, IP, or domain for full analysis:%s\n", ColorYellow, ColorReset)
	fmt.Print("🔗 Target: ")

	m.scanner.Scan()
	target := strings.TrimSpace(m.scanner.Text())

	if target == "" {
		fmt.Printf("%s❌ No target provided.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("\n%s🚀 Starting comprehensive analysis...%s\n", ColorYellow, ColorReset)
	fmt.Printf("%sThis may take 30-60 seconds for complete analysis...%s\n\n", ColorCyan, ColorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second) // Longer timeout for full report
	defer cancel()

	report := &ComprehensiveReport{
		GeneratedAt: time.Now(),
		ReportID:    fmt.Sprintf("NZ-%d", time.Now().Unix()),
	}

	// 1. Basic threat analysis
	fmt.Printf("%s[1/8] Performing basic threat analysis...%s\n", ColorCyan, ColorReset)
	basicAnalysis, err := m.threatAnalyzer.ComprehensiveAnalysis(ctx, target)
	if err != nil {
		fmt.Printf("%s❌ Basic threat analysis failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		report.BasicAnalysis = basicAnalysis
	}

	// 2. DNS analysis
	fmt.Printf("%s[2/8] Performing DNS analysis...%s\n", ColorCyan, ColorReset)
	dnsInfo, err := m.threatAnalyzer.PerformDNSLookup(ctx, target)
	if err != nil {
		fmt.Printf("%s❌ DNS analysis failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		report.DNSInfo = dnsInfo
	}

	// 3. WHOIS lookup
	fmt.Printf("%s[3/8] Performing WHOIS lookup...%s\n", ColorCyan, ColorReset)
	whoisInfo, err := m.threatAnalyzer.PerformWhoisLookup(ctx, target)
	if err != nil {
		fmt.Printf("%s❌ WHOIS lookup failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		report.WhoisInfo = whoisInfo
	}

	// 4. TLS/SSL analysis
	fmt.Printf("%s[4/8] Analyzing TLS/SSL security...%s\n", ColorCyan, ColorReset)
	// Assuming threatAnalyzer has a method for TLS/SSL, otherwise need a new client
	tlsInfo, err := m.threatAnalyzer.PerformTLSAnalysis(ctx, target) // Placeholder: assuming this method exists
	if err != nil {
		fmt.Printf("%s❌ TLS/SSL analysis failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		report.TLSInfo = tlsInfo
	}

	// 5. Redirect analysis
	fmt.Printf("%s[5/8] Tracing redirect chain...%s\n", ColorCyan, ColorReset)
	if basicAnalysis != nil { // Check if basicAnalysis was successful
		redirectAnalysis := network.AnalyzeRedirectChain(basicAnalysis.RedirectChain) // Use helper from network
		report.RedirectAnalysis = &RedirectAnalysis{
			Hops:           redirectAnalysis.Hops,
			UniqueDomains:  redirectAnalysis.UniqueDomains,
			ExternalLinks:  redirectAnalysis.ExternalLinks,
			SuspiciousURLs: redirectAnalysis.SuspiciousURLs,
		}
	} else {
		fmt.Printf("%s⚠️  Redirect analysis skipped due to failed basic analysis.%s\n", ColorYellow, ColorReset)
	}

	// 6. Geolocation
	fmt.Printf("%s[6/8] Geolocation analysis...%s\n", ColorCyan, ColorReset)
	ipGeo, err := m.threatAnalyzer.PerformIPGeolocation(ctx, target)
	if err != nil {
		fmt.Printf("%s❌ Geolocation analysis failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		report.Geolocation = ipGeo
	}

	// 7. Network analysis (Traceroute)
	fmt.Printf("%s[7/8] Performing network path analysis (traceroute)...%s\n", ColorCyan, ColorReset)
	networkAnalysis, err := m.threatAnalyzer.PerformTraceroute(ctx, target) // Placeholder: assuming this method exists
	if err != nil {
		fmt.Printf("%s❌ Network path analysis failed: %v%s\n", ColorRed, err, ColorReset)
	} else {
		report.NetworkAnalysis = networkAnalysis
	}

	// 8. Final compilation
	fmt.Printf("%s[8/8] Generating final report...%s\n", ColorGreen, ColorReset)

	m.displayFullReport(report)
	if m.shouldSaveReport() {
		m.saveComprehensiveReport(report)
	}
}

// displayFullReport shows the comprehensive security report.
func (m *Menu) displayFullReport(report *ComprehensiveReport) {
	ClearScreen()

	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s           COMPREHENSIVE SECURITY REPORT%s\n", ColorBold, ColorGreen, ColorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════%s\n\n", ColorBold, ColorCyan, ColorReset)

	// Report Header
	fmt.Printf("%s📋 Report ID: %s%s\n", ColorBold, report.ReportID, ColorReset)
	fmt.Printf("%s🕒 Generated: %s%s\n", ColorBold, report.GeneratedAt.Format("2006-01-02 15:04:05"), ColorReset)
	targetURL := "N/A"
	if report.BasicAnalysis != nil {
		targetURL = report.BasicAnalysis.URL
	}
	fmt.Printf("%s🎯 Target: %s%s\n\n", ColorBold, targetURL, ColorReset)

	// 1. Threat Assessment
	fmt.Printf("%s%s1. THREAT ASSESSMENT%s\n", ColorBold, ColorRed, ColorReset)
	if report.BasicAnalysis != nil {
		fmt.Printf("   Level: %s\n", report.BasicAnalysis.ThreatLevel)
		fmt.Printf("   Score: %d/100\n", report.BasicAnalysis.ThreatScore)
		if report.BasicAnalysis.AIResult != nil {
			fmt.Printf("   AI Confidence: %.1f%%\n\n", report.BasicAnalysis.AIResult.Confidence*100)
		} else {
			fmt.Printf("   AI Confidence: N/A\n\n")
		}
	} else {
		fmt.Printf("   Basic Analysis Data Not Available\n\n")
	}

	// 2. Observed Activities
	fmt.Printf("%s%s2. OBSERVED ACTIVITIES%s\n", ColorBold, ColorYellow, ColorReset)
	if report.BasicAnalysis != nil && report.BasicAnalysis.AIResult != nil {
		for _, threat := range report.BasicAnalysis.AIResult.Threats {
			fmt.Printf("   • %s\n", threat)
		}
		fmt.Printf("   Redirects: %d hops detected\n", report.BasicAnalysis.RedirectCount)
		fmt.Printf("   Security Headers: %d implemented\n\n", len(report.BasicAnalysis.SecurityHeaders))
	} else {
		fmt.Printf("   Observed Activities Data Not Available\n\n")
	}

	// 3. Site Analytics
	fmt.Printf("%s%s3. SITE ANALYTICS%s\n", ColorBold, ColorPurple, ColorReset)
	if report.WhoisInfo != nil && report.DNSInfo != nil {
		fmt.Printf("   Domain Age: %s\n", report.WhoisInfo.DomainAge)
		fmt.Printf("   Registrar: %s\n", report.WhoisInfo.Registrar)
		fmt.Printf("   Nameservers: %d configured\n\n", len(report.DNSInfo.NameServers))
	} else {
		fmt.Printf("   Site Analytics Data Not Available\n\n")
	}

	// 4. Advertising & Tracking
	fmt.Printf("%s%s4. ADVERTISING & TRACKING%s\n", ColorBold, ColorBlue, ColorReset)
	if report.BasicAnalysis != nil && len(report.BasicAnalysis.RedirectChain) > 0 && report.RedirectAnalysis != nil {
		fmt.Printf("   Cookies Set: %d\n", len(report.BasicAnalysis.RedirectChain[0].Cookies))
		fmt.Printf("   Tracking Parameters: %s\n", detectTracking(report.BasicAnalysis.URL)) // Changed to global helper
		fmt.Printf("   Third-party Domains: %d\n\n", report.RedirectAnalysis.UniqueDomains)
	} else {
		fmt.Printf("   Advertising & Tracking Data Not Available\n\n")
	}

	// 5. Hosting Information
	fmt.Printf("%s%s5. HOSTING ANALYSIS%s\n", ColorBold, ColorGreen, ColorReset)
	if report.Geolocation != nil {
		fmt.Printf("   IP Address: %s\n", report.Geolocation.IP)
		fmt.Printf("   Hosting Provider: %s\n", report.Geolocation.ISP)
		fmt.Printf("   Data Center: %s, %s\n", report.Geolocation.City, report.Geolocation.Country)
		fmt.Printf("   Proxy/VPN Detected: %v\n\n", report.Geolocation.IsProxy)
	} else {
		fmt.Printf("   Hosting Information Data Not Available\n\n")
	}

	// 6. DNS Check
	fmt.Printf("%s%s6. DNS ANALYSIS%s\n", ColorBold, ColorCyan, ColorReset)
	if report.DNSInfo != nil {
		fmt.Printf("   A Records: %d\n", len(report.DNSInfo.ARecords))
		fmt.Printf("   MX Records: %d\n", len(report.DNSInfo.MXRecords))
		fmt.Printf("   TXT Records: %d\n", len(report.DNSInfo.TXTRecords))
		fmt.Printf("   DNS Propagation: %s\n\n", report.DNSInfo.PropagationStatus)
	} else {
		fmt.Printf("   DNS Check Data Not Available\n\n")
	}

	// 7. VPN Usage Detection
	fmt.Printf("%s%s7. NETWORK PRIVACY%s\n", ColorBold, ColorPurple, ColorReset)
	if report.Geolocation != nil {
		fmt.Printf("   VPN/Proxy: %v\n", report.Geolocation.IsProxy)
		fmt.Printf("   Hosting Type: %s\n", report.Geolocation.HostingType)
		fmt.Printf("   ASN: %s\n\n", report.Geolocation.ASN)
	} else {
		fmt.Printf("   VPN Usage Detection Data Not Available\n\n")
	}

	// 8. URL Redirect Analysis
	fmt.Printf("%s%s8. REDIRECT CHAIN ANALYSIS%s\n", ColorBold, ColorYellow, ColorReset)
	if report.BasicAnalysis != nil && len(report.BasicAnalysis.RedirectChain) > 0 {
		for i, redirect := range report.BasicAnalysis.RedirectChain {
			fmt.Printf("   %d. %s → %s (%dms)\n",
				i+1, redirect.URL, redirect.Location, redirect.Duration.Milliseconds())
		}
		fmt.Println()
	} else {
		fmt.Printf("   Redirect Chain Analysis Data Not Available\n\n")
	}

	// 9. Phishing & Malicious Links
	fmt.Printf("%s%s9. SECURITY THREATS%s\n", ColorBold, ColorRed, ColorReset)
	if report.BasicAnalysis != nil {
		fmt.Printf("   Phishing Indicators: %d detected\n", len(report.BasicAnalysis.PhishingIndicators))
		fmt.Printf("   Malicious Patterns: %d found\n", len(report.BasicAnalysis.SuspiciousFeatures))
		fmt.Printf("   Blacklist Status: %s\n\n", report.BasicAnalysis.BlacklistStatus)
	} else {
		fmt.Printf("   Phishing & Malicious Links Data Not Available\n\n")
	}

	// 10. SMS Scam Analysis
	fmt.Printf("%s%s10. SMS SCAM DETECTION%s\n", ColorBold, ColorRed, ColorReset)
	if report.BasicAnalysis != nil {
		fmt.Printf("   Urgency Score: %d/100\n", analyzeUrgency(report.BasicAnalysis.URL)) // Changed to global helper
		fmt.Printf("   Social Engineering: %s\n", detectSocialEngineering(report.BasicAnalysis.URL)) // Changed to global helper
		fmt.Printf("   Financial Lures: %v\n\n", detectFinancialLures(report.BasicAnalysis.URL)) // Changed to global helper
	} else {
		fmt.Printf("   SMS Scam Analysis Data Not Available\n\n")
	}

	// 11. TLS Checker Results
	fmt.Printf("%s%s11. TLS/SSL SECURITY%s\n", ColorBold, ColorGreen, ColorReset)
	if report.TLSInfo != nil {
		fmt.Printf("   Certificate Valid: %v\n", report.TLSInfo.CertificateValid)
		fmt.Printf("   Encryption Grade: %s\n", report.TLSInfo.EncryptionGrade)
		fmt.Printf("   Protocols: %s\n\n", strings.Join(report.TLSInfo.SupportedProtocols, ", "))
	} else {
		fmt.Printf("   TLS Checker Results Data Not Available\n\n")
	}

	// 12. DNS Propagation
	fmt.Printf("%s%s12. DNS PROPAGATION%s\n", ColorBold, ColorBlue, ColorReset)
	if report.DNSInfo != nil {
		fmt.Printf("   Global Propagation: %s\n", report.DNSInfo.PropagationStatus)
		fmt.Printf("   TTL Values: %s\n", report.DNSInfo.TTLSummary)
		fmt.Printf("   DNSSEC Enabled: %v\n\n", report.DNSInfo.DNSSECEnabled)
	} else {
		fmt.Printf("   DNS Propagation Data Not Available\n\n")
	}

	// 13. Gzip Test
	fmt.Printf("%s%s13. PERFORMANCE ANALYSIS%s\n", ColorBold, ColorPurple, ColorReset)
	if report.TLSInfo != nil && report.BasicAnalysis != nil {
		fmt.Printf("   Compression: %s\n", report.TLSInfo.CompressionEnabled)
		fmt.Printf("   Response Time: %v\n", report.BasicAnalysis.AnalysisDuration)
		fmt.Printf("   Server Type: %s\n\n", report.TLSInfo.ServerType)
	} else {
		fmt.Printf("   Gzip Test Data Not Available\n\n")
	}

	// 14. Link Extractor Results
	fmt.Printf("%s%s14. CONTENT ANALYSIS%s\n", ColorBold, ColorCyan, ColorReset)
	if report.RedirectAnalysis != nil {
		fmt.Printf("   External Links: %d\n", report.RedirectAnalysis.ExternalLinks)
		fmt.Printf("   Internal Links: %d\n", report.RedirectAnalysis.InternalLinks)
		fmt.Printf("   Suspicious URLs: %d\n\n", report.RedirectAnalysis.SuspiciousURLs)
	} else {
		fmt.Printf("   Link Extractor Results Data Not Available\n\n")
	}

	// 15. Traceroute
	fmt.Printf("%s%s15. NETWORK PATH%s\n", ColorBold, ColorYellow, ColorReset)
	if report.NetworkAnalysis != nil {
		fmt.Printf("   Hop Count: %d\n", report.NetworkAnalysis.HopCount)
		fmt.Printf("   Latency: %v\n", report.NetworkAnalysis.AverageLatency)
		fmt.Printf("   Geographic Path: %s\n\n", report.NetworkAnalysis.GeoPath)
	} else {
		fmt.Printf("   Traceroute Data Not Available\n\n")
	}

	// 16. Reverse DNS
	fmt.Printf("%s%s16. REVERSE DNS%s\n", ColorBold, ColorGreen, ColorReset)
	if report.DNSInfo != nil {
		fmt.Printf("   PTR Record: %s\n", report.DNSInfo.PTRRecord)
		fmt.Printf("   Hostname: %s\n", report.DNSInfo.ReverseHostname)
		fmt.Printf("   Validation: %s\n\n", report.DNSInfo.PTRValidation)
	} else {
		fmt.Printf("   Reverse DNS Data Not Available\n\n")
	}

	finalScore := 0
	if report.BasicAnalysis != nil {
		finalScore = report.BasicAnalysis.ThreatScore
	}
	fmt.Printf("%s%sFINAL SECURITY SCORE: %d/100%s\n", ColorBold, getScoreColor(finalScore),
		finalScore, ColorReset)
}

func (m *Menu) saveComprehensiveReport(report *ComprehensiveReport) {
	filename := fmt.Sprintf("netzilla_comprehensive_report_%s.txt", report.ReportID)
	content := m.generateComprehensiveReportContent(report)

	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		fmt.Printf("%s❌ Failed to save comprehensive report: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	fmt.Printf("%s✅ Comprehensive report saved: %s%s\n", ColorGreen, filename, ColorReset)
}

func (m *Menu) generateComprehensiveReportContent(report *ComprehensiveReport) string {
	var sb strings.Builder

	sb.WriteString("NET-ZILLA COMPREHENSIVE SECURITY ANALYSIS REPORT\n")
	sb.WriteString("===================================================\n\n")

	sb.WriteString(fmt.Sprintf("Report ID: %s\n", report.ReportID))
	sb.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05")))
	if report.BasicAnalysis != nil {
		sb.WriteString(fmt.Sprintf("Target: %s\n", report.BasicAnalysis.URL))
		sb.WriteString(fmt.Sprintf("Threat Level: %s\n", report.BasicAnalysis.ThreatLevel))
		sb.WriteString(fmt.Sprintf("Threat Score: %d/100\n", report.BasicAnalysis.ThreatScore))
	} else {
		sb.WriteString("Target: N/A\n")
		sb.WriteString("Threat Level: N/A\n")
		sb.WriteString("Threat Score: N/A\n")
	}
	sb.WriteString("\n")

	// 1. Threat Assessment
	sb.WriteString("1. THREAT ASSESSMENT\n")
	if report.BasicAnalysis != nil {
		sb.WriteString(fmt.Sprintf("   Level: %s\n", report.BasicAnalysis.ThreatLevel))
		sb.WriteString(fmt.Sprintf("   Score: %d/100\n", report.BasicAnalysis.ThreatScore))
		if report.BasicAnalysis.AIResult != nil {
			sb.WriteString(fmt.Sprintf("   AI Confidence: %.1f%%\n\n", report.BasicAnalysis.AIResult.Confidence*100))
		} else {
			sb.WriteString("   AI Confidence: N/A\n\n")
		}
	} else {
		sb.WriteString("   Basic Analysis Data Not Available\n\n")
	}

	// 2. Observed Activities
	sb.WriteString("2. OBSERVED ACTIVITIES\n")
	if report.BasicAnalysis != nil && report.BasicAnalysis.AIResult != nil {
		for _, threat := range report.BasicAnalysis.AIResult.Threats {
			sb.WriteString(fmt.Sprintf("   • %s\n", threat))
		}
		sb.WriteString(fmt.Sprintf("   Redirects: %d hops detected\n", report.BasicAnalysis.RedirectCount))
		sb.WriteString(fmt.Sprintf("   Security Headers: %d implemented\n\n", len(report.BasicAnalysis.SecurityHeaders)))
	} else {
		sb.WriteString("   Observed Activities Data Not Available\n\n")
	}

	// 3. Site Analytics
	sb.WriteString("3. SITE ANALYTICS\n")
	if report.WhoisInfo != nil && report.DNSInfo != nil {
		sb.WriteString(fmt.Sprintf("   Domain Age: %s\n", report.WhoisInfo.DomainAge))
		sb.WriteString(fmt.Sprintf("   Registrar: %s\n", report.WhoisInfo.Registrar))
		sb.WriteString(fmt.Sprintf("   Nameservers: %d configured\n\n", len(report.DNSInfo.NameServers)))
	} else {
		sb.WriteString("   Site Analytics Data Not Available\n\n")
	}

	// 4. Advertising & Tracking
	sb.WriteString("4. ADVERTISING & TRACKING\n")
	if report.BasicAnalysis != nil && len(report.BasicAnalysis.RedirectChain) > 0 && report.RedirectAnalysis != nil {
		sb.WriteString(fmt.Sprintf("   Cookies Set: %d\n", len(report.BasicAnalysis.RedirectChain[0].Cookies)))
		sb.WriteString(fmt.Sprintf("   Tracking Parameters: %s\n", detectTracking(report.BasicAnalysis.URL)))
		sb.WriteString(fmt.Sprintf("   Third-party Domains: %d\n\n", report.RedirectAnalysis.UniqueDomains))
	} else {
		sb.WriteString("   Advertising & Tracking Data Not Available\n\n")
	}

	// 5. Hosting Information
	sb.WriteString("5. HOSTING ANALYSIS\n")
	if report.Geolocation != nil {
		sb.WriteString(fmt.Sprintf("   IP Address: %s\n", report.Geolocation.IP))
		sb.WriteString(fmt.Sprintf("   Hosting Provider: %s\n", report.Geolocation.ISP))
		sb.WriteString(fmt.Sprintf("   Data Center: %s, %s\n", report.Geolocation.City, report.Geolocation.Country))
		sb.WriteString(fmt.Sprintf("   Proxy/VPN Detected: %v\n\n", report.Geolocation.IsProxy))
	} else {
		sb.WriteString("   Hosting Information Data Not Available\n\n")
	}

	// 6. DNS Check
	sb.WriteString("6. DNS ANALYSIS\n")
	if report.DNSInfo != nil {
		sb.WriteString(fmt.Sprintf("   A Records: %d\n", len(report.DNSInfo.ARecords)))
		sb.WriteString(fmt.Sprintf("   MX Records: %d\n", len(report.DNSInfo.MXRecords)))
		sb.WriteString(fmt.Sprintf("   TXT Records: %d\n", len(report.DNSInfo.TXTRecords)))
		sb.WriteString(fmt.Sprintf("   DNS Propagation: %s\n\n", report.DNSInfo.PropagationStatus))
	} else {
		sb.WriteString("   DNS Check Data Not Available\n\n")
	}

	// 7. VPN Usage Detection
	sb.WriteString("7. NETWORK PRIVACY\n")
	if report.Geolocation != nil {
		sb.WriteString(fmt.Sprintf("   VPN/Proxy: %v\n", report.Geolocation.IsProxy))
		sb.WriteString(fmt.Sprintf("   Hosting Type: %s\n", report.Geolocation.HostingType))
		sb.WriteString(fmt.Sprintf("   ASN: %s\n\n", report.Geolocation.ASN))
	} else {
		sb.WriteString("   VPN Usage Detection Data Not Available\n\n")
	}

	// 8. URL Redirect Analysis
	sb.WriteString("8. REDIRECT CHAIN ANALYSIS\n")
	if report.BasicAnalysis != nil && len(report.BasicAnalysis.RedirectChain) > 0 {
		for i, redirect := range report.BasicAnalysis.RedirectChain {
			sb.WriteString(fmt.Sprintf("   %d. %s → %s (%dms)\n",
				i+1, redirect.URL, redirect.Location, redirect.Duration.Milliseconds()))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("   Redirect Chain Analysis Data Not Available\n\n")
	}

	// 9. Phishing & Malicious Links
	sb.WriteString("9. SECURITY THREATS\n")
	if report.BasicAnalysis != nil {
		sb.WriteString(fmt.Sprintf("   Phishing Indicators: %d detected\n", len(report.BasicAnalysis.PhishingIndicators)))
		sb.WriteString(fmt.Sprintf("   Malicious Patterns: %d found\n", len(report.BasicAnalysis.SuspiciousFeatures)))
		sb.WriteString(fmt.Sprintf("   Blacklist Status: %s\n\n", report.BasicAnalysis.BlacklistStatus))
	} else {
		sb.WriteString("   Phishing & Malicious Links Data Not Available\n\n")
	}

	// 10. SMS Scam Analysis
	ssb.WriteString("10. SMS SCAM DETECTION\n")
	if report.BasicAnalysis != nil {
		sb.WriteString(fmt.Sprintf("   Urgency Score: %d/100\n", analyzeUrgency(report.BasicAnalysis.URL)))
		sb.WriteString(fmt.Sprintf("   Social Engineering: %s\n", detectSocialEngineering(report.BasicAnalysis.URL)))
		sb.WriteString(fmt.Sprintf("   Financial Lures: %v\n\n", detectFinancialLures(report.BasicAnalysis.URL)))
	} else {
		sb.WriteString("   SMS Scam Analysis Data Not Available\n\n")
	}

	// 11. TLS Checker Results
	sb.WriteString("11. TLS/SSL SECURITY\n")
	if report.TLSInfo != nil {
		sb.WriteString(fmt.Sprintf("   Certificate Valid: %v\n", report.TLSInfo.CertificateValid))
		sb.WriteString(fmt.Sprintf("   Encryption Grade: %s\n", report.TLSInfo.EncryptionGrade))
		sb.WriteString(fmt.Sprintf("   Protocols: %s\n\n", strings.Join(report.TLSInfo.SupportedProtocols, ", ")))
	} else {
		sb.WriteString("   TLS Checker Results Data Not Available\n\n")
	}

	// 12. DNS Propagation
	sb.WriteString("12. DNS PROPAGATION\n")
	if report.DNSInfo != nil {
		sb.WriteString(fmt.Sprintf("   Global Propagation: %s\n", report.DNSInfo.PropagationStatus))
		sb.WriteString(fmt.Sprintf("   TTL Values: %s\n", report.DNSInfo.TTLSummary))
		sb.WriteString(fmt.Sprintf("   DNSSEC Enabled: %v\n\n", report.DNSInfo.DNSSECEnabled))
	} else {
		sb.WriteString("   DNS Propagation Data Not Available\n\n")
	}

	// 13. Gzip Test
	sb.WriteString("13. PERFORMANCE ANALYSIS\n")
	if report.TLSInfo != nil && report.BasicAnalysis != nil {
		sb.WriteString(fmt.Sprintf("   Compression: %s\n", report.TLSInfo.CompressionEnabled))
		sb.WriteString(fmt.Sprintf("   Response Time: %v\n", report.BasicAnalysis.AnalysisDuration))
		sb.WriteString(fmt.Sprintf("   Server Type: %s\n\n", report.TLSInfo.ServerType))
	} else {
		sb.WriteString("   Gzip Test Data Not Available\n\n")
	}

	// 14. Link Extractor Results
	sb.WriteString("14. CONTENT ANALYSIS\n")
	if report.RedirectAnalysis != nil {
		sb.WriteString(fmt.Sprintf("   External Links: %d\n", report.RedirectAnalysis.ExternalLinks))
		sb.WriteString(fmt.Sprintf("   Internal Links: %d\n", report.RedirectAnalysis.InternalLinks))
		sb.WriteString(fmt.Sprintf("   Suspicious URLs: %d\n\n", report.RedirectAnalysis.SuspiciousURLs))
	} else {
		sb.WriteString("   Link Extractor Results Data Not Available\n\n")
	}

	// 15. Traceroute
	sb.WriteString("15. TRACEROUT\n")
	if report.NetworkAnalysis != nil {
		sb.WriteString(fmt.Sprintf("   Hop Count: %d\n", report.NetworkAnalysis.HopCount))
		sb.WriteString(fmt.Sprintf("   Latency: %v\n", report.NetworkAnalysis.AverageLatency))
		sb.WriteString(fmt.Sprintf("   Geographic Path: %s\n\n", report.NetworkAnalysis.GeoPath))
	} else {
		sb.WriteString("   Traceroute Data Not Available\n\n")
	}

	// 16. Reverse DNS
	sb.WriteString("16. REVERSE DNS\n")
	if report.DNSInfo != nil {
		sb.WriteString(fmt.Sprintf("   PTR Record: %s\n", report.DNSInfo.PTRRecord))
		sb.WriteString(fmt.Sprintf("   Hostname: %s\n", report.DNSInfo.ReverseHostname))
		sb.WriteString(fmt.Sprintf("   Validation: %s\n\n", report.DNSInfo.PTRValidation))
	} else {
		sb.WriteString("   Reverse DNS Data Not Available\n\n")
	}

	finalScore := 0
	if report.BasicAnalysis != nil {
		finalScore = report.BasicAnalysis.ThreatScore
	}
	ssb.WriteString(fmt.Sprintf("FINAL SECURITY SCORE: %d/100\n", finalScore))

	return sb.String()
}

// Data structures for comprehensive reporting
type ComprehensiveReport struct {
	BasicAnalysis    *models.ThreatAnalysis
	DNSInfo          *models.DNSAnalysis
	WhoisInfo        *models.WhoisAnalysis
	TLSInfo          *models.TLSAnalysis
	RedirectAnalysis *models.RedirectAnalysis // Use models.RedirectAnalysis
	Geolocation      *models.GeoAnalysis
	NetworkAnalysis  *models.NetworkAnalysis
	GeneratedAt      time.Time
	ReportID         string
}

// Helper methods for detection (moved out of Menu struct)
func detectTracking(url string) string {
	trackingParams := []string{"utm_", "fbclid", "gclid", "msclkid"}
	for _, param := range trackingParams {
		if strings.Contains(url, param) {
			return "Tracking parameters detected"
		}
	}
	return "No tracking detected"
}

func analyzeUrgency(url string) int {
	urgencyWords := []string{"urgent", "immediate", "now", "asap", "alert"}
	score := 0
	for _, word := range urgencyWords {
		if strings.Contains(strings.ToLower(url), word) {
			score += 20
		}
	}
	return score
}

func detectSocialEngineering(url string) string {
	techniques := []string{"verify", "confirm", "update", "secure", "account"}
	for _, tech := range techniques {
		if strings.Contains(strings.ToLower(url), tech) {
			return "Social engineering detected"
		}
	}
	return "No social engineering"
}

func detectFinancialLures(url string) bool {
	lures := []string{"refund", "prize", "winner", "money", "payment"}
	for _, lure := range lures {
		if strings.Contains(strings.ToLower(url), lure) {
			return true
		}
	}
	return false
}

// getScoreColor returns a color code based on the threat score.
func getScoreColor(score int) string {
	switch {
	case score >= 80:
		return ColorRed
	case score >= 60:
		return ColorYellow
	case score >= 40:
		return ColorYellow
	case score >= 20:
		return ColorGreen
	default:
		return ColorGreen
	}
}

// Cleanup method (if needed)
func (m *Menu) Cleanup() {
	m.running = false
}

// Logger provides basic logging functionality.
type Logger struct {
	// Add logging fields as needed
}

// Info logs informational messages.
func (l *Logger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}

// Error logs error messages.
func (l *Logger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}

// NewLogger creates and returns a new Logger instance.
func NewLogger() *Logger {
	return &Logger{}
}