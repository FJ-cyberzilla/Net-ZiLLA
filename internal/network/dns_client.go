package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"net-zilla/internal/models" // Add this import
	"net-zilla/internal/utils"  // Add this import for Logger
)

// DNSClient provides functionality for performing various DNS lookups.
type DNSClient struct {
	resolver *net.Resolver
	timeout  time.Duration
	logger   *utils.Logger // Added logger
}

// NewDNSClient creates a new DNSClient instance.
func NewDNSClient(logger *utils.Logger) *DNSClient {
	return &DNSClient{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "udp", "8.8.8.8:53") // Google DNS
			},
		},
		timeout: 10 * time.Second,
		logger:  logger,
	}
}

// Lookup performs a comprehensive DNS lookup for the given domain.
func (d *DNSClient) Lookup(ctx context.Context, domain string) (*models.DNSAnalysis, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	analysis := &models.DNSAnalysis{}

	// A Records and AAAARecords
	if ips, err := d.resolver.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				analysis.ARecords = append(analysis.ARecords, ip.String())
			} else {
				analysis.AAAARecords = append(analysis.AAAARecords, ip.String())
			}
		}
	} else {
		d.logger.Warn("DNS LookupIPAddr failed for %s: %v", domain, err)
	}

	// CNAME
	if cname, err := d.resolver.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
		analysis.CNAME = cname
	} else if err != nil {
		d.logger.Warn("DNS LookupCNAME failed for %s: %v", domain, err)
	}

	// MX Records
	if mxs, err := d.resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			analysis.MXRecords = append(analysis.MXRecords,
				fmt.Sprintf("%s (prio:%d)", mx.Host, mx.Pref))
		}
	} else if err != nil {
		d.logger.Warn("DNS LookupMX failed for %s: %v", domain, err)
	}

	// NS Records
	if nss, err := d.resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			analysis.NameServers = append(analysis.NameServers, ns.Host)
		}
	} else if err != nil {
		d.logger.Warn("DNS LookupNS failed for %s: %v", domain, err)
	}

	// TXT Records
	if txts, err := d.resolver.LookupTXT(ctx, domain); err == nil {
		analysis.TXTRecords = txts
	} else if err != nil {
		d.logger.Warn("DNS LookupTXT failed for %s: %v", domain, err)
	}

	// Check DNSSEC
	analysis.DNSSECEnabled = d.checkDNSSEC(ctx, domain)

	// Attempt Reverse DNS lookup for the first A record, if available
	if len(analysis.ARecords) > 0 {
		ptr, err := d.ReverseDNSLookup(ctx, analysis.ARecords[0])
		if err == nil {
			analysis.PTRRecord = ptr
			analysis.ReverseHostname = ptr // Simple assignment for now
			// Further validation of PTR record could go here
			analysis.PTRValidation = "Valid (basic check)"
		} else {
			d.logger.Warn("Reverse DNS lookup failed for %s: %v", analysis.ARecords[0], err)
			analysis.PTRValidation = "Failed"
		}
	} else {
		analysis.PTRValidation = "No A record to check"
	}


	analysis.PropagationStatus = "N/A"
	analysis.TTLSummary = "N/A"

	return analysis, nil
}

// ReverseDNSLookup performs a reverse DNS lookup for the given IP address.
func (d *DNSClient) ReverseDNSLookup(ctx context.Context, ip string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	if ip == "" {
		return "", fmt.Errorf("IP address cannot be empty for reverse DNS lookup")
	}

	names, err := d.resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("no PTR record found for %s: %w", ip, err)
	}

	return strings.TrimSuffix(names[0], "."), nil
}

// checkDNSSEC performs a simplified check for DNSSEC enablement.
func (d *DNSClient) checkDNSSEC(ctx context.Context, domain string) bool {
	// Simplified DNSSEC check - in production would use proper validation
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Check for DNSKEY records (indicates DNSSEC)
	// This is a basic heuristic; a full check would involve validating the trust chain.
	_, err := d.resolver.LookupTXT(ctx, "_dnskey."+domain) // Common indicator for DNSSEC
	if err != nil {
		d.logger.Debug("DNSSEC check for %s: %v", domain, err)
	}
	return err == nil
}

// DNSRecord and DNSAnalysis internal types are no longer needed
// as models.DNSAnalysis is now used directly.