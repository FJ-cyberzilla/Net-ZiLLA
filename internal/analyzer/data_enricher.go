package analyzer

import (
	"context"
	"fmt"
	"time"

	"net-zilla/internal/models"
	"net-zilla/internal/network"
	"net-zilla/pkg/threatintel"
)

type DataEnricher struct {
	threatIntel   *threatintel.Manager
	dnsClient     *network.DNSClient
	whoisClient   *network.WhoisClient
	cache         map[string]EnrichmentData
}

type EnrichmentData struct {
	IPReputation    *IPReputation
	DomainHistory   *DomainHistory
	ThreatFeeds     []ThreatFeed
	GeoData         *GeoData
	SSLData         *SSLData
	EnrichedAt      time.Time
}

type IPReputation struct {
	Score       int
	Confidence  float64
	AbuseReports int
	Country     string
	ISP         string
	ASN         string
	IsProxy     bool
	IsVPN       bool
}

type DomainHistory struct {
	CreatedDate   time.Time
	UpdatedDate   time.Time
	ExpiresDate   time.Time
	Registrar     string
	NameServers   []string
	Registrant    string
}

type ThreatFeed struct {
	Source    string
	Indicator string
	Score     int
	FirstSeen time.Time
	LastSeen  time.Time
}

type GeoData struct {
	Country     string
	City        string
	Region      string
	Latitude    float64
	Longitude   float64
	Timezone    string
}

type SSLData struct {
	Valid         bool
	Expires       time.Time
	Issuer        string
	Subject       string
	KeySize       int
	SignatureAlgo string
}

func NewDataEnricher() *DataEnricher {
	return &DataEnricher{
		threatIntel: threatintel.NewManager(),
		dnsClient:   network.NewDNSClient(),
		whoisClient: network.NewWhoisClient(),
		cache:       make(map[string]EnrichmentData),
	}
}

func (d *DataEnricher) EnrichAnalysis(ctx context.Context, analysis *models.ThreatAnalysis) error {
	// Enrich with IP intelligence
	if analysis.IPInfo != nil {
		ipData, err := d.enrichIPData(ctx, analysis.IPInfo.IP)
		if err == nil {
			analysis.EnrichmentData = ipData
		}
	}

	// Enrich with domain intelligence
	domain := extractDomain(analysis.URL)
	if domain != "" {
		domainData, err := d.enrichDomainData(ctx, domain)
		if err == nil {
			analysis.DomainHistory = domainData
		}
	}

	// Enrich with threat intelligence
	threatData, err := d.enrichThreatData(ctx, analysis.URL, domain)
	if err == nil {
		analysis.ThreatFeeds = threatData
	}

	// Enrich with SSL data
	sslData, err := d.enrichSSLData(ctx, analysis.URL)
	if err == nil {
		analysis.SSLData = sslData
	}

	return nil
}

func (d *DataEnricher) enrichIPData(ctx context.Context, ip string) (*EnrichmentData, error) {
	// Check cache first
	if cached, exists := d.cache[ip]; exists && time.Since(cached.EnrichedAt) < time.Hour {
		return &cached, nil
	}

	enrichment := &EnrichmentData{
		EnrichedAt: time.Now(),
	}

	// Get IP reputation
	reputation, err := d.threatIntel.CheckIP(ip)
	if err == nil {
		enrichment.IPReputation = &IPReputation{
			Score:       reputation.Score,
			Confidence:  reputation.Confidence,
			AbuseReports: reputation.AbuseCount,
			Country:     reputation.Country,
			ISP:         reputation.ISP,
			ASN:         reputation.ASN,
			IsProxy:     reputation.IsProxy,
			IsVPN:       reputation.IsVPN,
		}
	}

	// Get geolocation data
	geo, err := d.threatIntel.GeoLocate(ip)
	if err == nil {
		enrichment.GeoData = &GeoData{
			Country:  geo.Country,
			City:     geo.City,
			Region:   geo.Region,
			Latitude: geo.Latitude,
			Longitude: geo.Longitude,
			Timezone: geo.Timezone,
		}
	}

	// Cache the results
	d.cache[ip] = *enrichment

	return enrichment, nil
}

func (d *DataEnricher) enrichDomainData(ctx
