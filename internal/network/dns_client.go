// internal/network/dns_client.go
package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type DNSClient struct {
	resolver *net.Resolver
	timeout  time.Duration
}

type DNSRecord struct {
	Type    string
	Values  []string
	TTL     int
}

type DNSAnalysis struct {
	ARecords    []string
	AAAARecords []string
	CNAME       string
	MXRecords   []string
	NSRecords   []string
	TXTRecords  []string
	PTRRecord   string
	DNSSEC      bool
}

func NewDNSClient() *DNSClient {
	return &DNSClient{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "udp", "8.8.8.8:53") // Google DNS
			},
		},
		timeout: 10 * time.Second,
	}
}

func (d *DNSClient) ComprehensiveLookup(domain string) (*DNSAnalysis, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	analysis := &DNSAnalysis{}

	// A Records
	if ips, err := d.resolver.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				analysis.ARecords = append(analysis.ARecords, ip.String())
			} else {
				analysis.AAAARecords = append(analysis.AAAARecords, ip.String())
			}
		}
	}

	// CNAME
	if cname, err := d.resolver.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
		analysis.CNAME = cname
	}

	// MX Records
	if mxs, err := d.resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			analysis.MXRecords = append(analysis.MXRecords, 
				fmt.Sprintf("%s (prio:%d)", mx.Host, mx.Pref))
		}
	}

	// NS Records
	if nss, err := d.resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			analysis.NSRecords = append(analysis.NSRecords, ns.Host)
		}
	}

	// TXT Records
	if txts, err := d.resolver.LookupTXT(ctx, domain); err == nil {
		analysis.TXTRecords = txts
	}

	// Check DNSSEC
	analysis.DNSSEC = d.checkDNSSEC(domain)

	return analysis, nil
}

func (d *DNSClient) ReverseDNSLookup(ip string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	names, err := d.resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("no PTR record found")
	}

	return strings.TrimSuffix(names[0], "."), nil
}

func (d *DNSClient) checkDNSSEC(domain string) bool {
	// Simplified DNSSEC check - in production would use proper validation
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	// Check for DNSKEY records (indicates DNSSEC)
	_, err := d.resolver.LookupTXT(ctx, "dnssec."+domain)
	return err == nil
}
