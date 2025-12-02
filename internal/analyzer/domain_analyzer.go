package analyzer

import (
	"context"
	"net/url"
	"net-zilla/internal/models"
	"net-zilla/internal/network"
	"net-zilla/internal/utils"
)

// DomainAnalyzer is responsible for performing domain-specific analyses.
type DomainAnalyzer struct {
	logger      *utils.Logger
	dnsClient   *network.DNSClient
	whoisClient *network.WhoisClient
}

// NewDomainAnalyzer creates a new DomainAnalyzer.
func NewDomainAnalyzer(logger *utils.Logger, dnsClient *network.DNSClient, whoisClient *network.WhoisClient) *DomainAnalyzer {
	return &DomainAnalyzer{
		logger:      logger,
		dnsClient:   dnsClient,
		whoisClient: whoisClient,
	}
}

// Analyze performs basic domain analysis and enriches the ThreatAnalysis object.
func (da *DomainAnalyzer) Analyze(ctx context.Context, parsedURL *url.URL, analysis *models.ThreatAnalysis) int {
	analysis.Domain = parsedURL.Hostname()
	score := 0

	// Example: Check WHOIS for domain age (if not already done in comprehensive analysis)
	if analysis.WhoisInfo == nil {
		whoisInfo, err := da.whoisClient.Lookup(ctx, parsedURL.Hostname())
		if err == nil {
			analysis.WhoisInfo = whoisInfo
			// Score logic based on domain age (e.g., very new domains could be suspicious)
			if whoisInfo.DomainAge == "Unknown" || whoisInfo.DomainAge == "Less than 30 days" {
				score += 10
				analysis.Warnings = append(analysis.Warnings, "Domain is very new, potential risk")
			}
		} else {
			da.logger.Warn("Failed to perform WHOIS lookup for domain analyzer: %v", err)
			score += 5 // Small penalty for WHOIS lookup failure
		}
	}
	
	// Example: Check DNS for suspicious records (if not already done)
	if analysis.DNSInfo == nil {
		dnsInfo, err := da.dnsClient.Lookup(ctx, parsedURL.Hostname())
		if err == nil {
			analysis.DNSInfo = dnsInfo
			// Score logic based on DNS records (e.g., suspicious TXT records, unusual NS)
			if len(dnsInfo.TXTRecords) == 0 {
				score += 2
			}
		} else {
			da.logger.Warn("Failed to perform DNS lookup for domain analyzer: %v", err)
			score += 3 // Small penalty for DNS lookup failure
		}
	}


	return score
}

