package network

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type WhoisClient struct {
	timeout time.Duration
	servers map[string]string // TLD -> WHOIS server
}

type WhoisInfo struct {
	Domain        string
	Registrar     string
	Registrant    string
	CreatedDate   time.Time
	UpdatedDate   time.Time
	ExpiresDate   time.Time
	NameServers   []string
	Status        []string
	RawResponse   string
}

func NewWhoisClient() *WhoisClient {
	return &WhoisClient{
		timeout: 10 * time.Second,
		servers: map[string]string{
			"com":      "whois.verisign-grs.com",
			"net":      "whois.verisign-grs.com",
			"org":      "whois.pir.org",
			"io":       "whois.nic.io",
			"co":       "whois.nic.co",
			"app":      "whois.nic.google",
			"dev":      "whois.nic.google",
			"page":     "whois.nic.google",
		},
	}
}

func (w *WhoisClient) Lookup(domain string) (*WhoisInfo, error) {
	info := &WhoisInfo{
		Domain: domain,
	}

	// Determine WHOIS server based on TLD
	server, err := w.getWhoisServer(domain)
	if err != nil {
		return info, err
	}

	// Perform WHOIS query
	response, err := w.queryWhoisServer(server, domain)
	if err != nil {
		return info, err
	}

	info.RawResponse = response

	// Parse WHOIS response
	w.parseWhoisResponse(response, info)

	return info, nil
}

func (w *WhoisClient) getWhoisServer(domain string) (string, error) {
	// Extract TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}

	tld := parts[len(parts)-1]

	// Lookup WHOIS server
	server, exists := w.servers[tld]
	if !exists {
		// Fallback to IANA for unknown TLDs
		return "whois.iana.org", nil
	}

	return server, nil
}

func (w *WhoisClient) queryWhoisServer(server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", w.timeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server: %w", err)
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(w.timeout))

	// Send query
	fmt.Fprintf(conn, "%s\r\n", domain)

	// Read response
	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	
	for scanner.Scan() {
		line := scanner.Text()
		response.WriteString(line + "\n")
		
		// Stop if we see end of data marker
		if strings.Contains(line, ">>> Last update") || 
		   strings.Contains(line, "% IANA WHOIS server") {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading WHOIS response: %w", err)
	}

	return response.String(), nil
}

func (w *WhoisClient) parseWhoisResponse(response string, info *WhoisInfo) {
	lines := strings.Split(response, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse common WHOIS fields
		switch {
		case strings.HasPrefix(line, "Registrar:"):
			info.Registrar = w.extractValue(line)
		case strings.HasPrefix(line, "Creation Date:"):
			info.CreatedDate = w.parseDate(w.extractValue(line))
		case strings.HasPrefix(line, "Updated Date:"):
			info.UpdatedDate = w.parseDate(w.extractValue(line))
		case strings.HasPrefix(line, "Registry Expiry Date:"):
			info.ExpiresDate = w.parseDate(w.extractValue(line))
		case strings.HasPrefix(line, "Name Server:"):
			ns := w.extractValue(line)
			if ns != "" {
				info.NameServers = append(info.NameServers, ns)
			}
		case strings.HasPrefix(line, "Domain Status:"):
			status := w.extractValue(line)
			if status != "" {
				info.Status = append(info.Status, status)
			}
		}
	}
}

func (w *WhoisClient) extractValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func (w *WhoisClient) parseDate(dateStr string) time.Time {
	formats := []string{
		"2006-01-02",
		"2006-01-02T15:04:05Z",
		"02-Jan-2006",
		"2006.01.02",
		"2006/01/02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}

	return time.Time{}
}
