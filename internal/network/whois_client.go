package network

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"net-zilla/internal/models" // Added import
	"net-zilla/internal/utils"  // Added import for Logger
)

// WhoisClient performs WHOIS lookups for domains.
type WhoisClient struct {
	timeout time.Duration
	servers map[string]string // TLD -> WHOIS server
	logger  *utils.Logger     // Added logger
}

// NewWhoisClient creates and initializes a new WhoisClient.
func NewWhoisClient(logger *utils.Logger) *WhoisClient {
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
			"ai":       "whois.nic.ai", // Common TLD
			"me":       "whois.nic.me", // Common TLD
			"xyz":      "whois.nic.xyz", // Common TLD
			"online":   "whois.nic.online", // Common TLD
		},
		logger: logger,
	}
}

// Lookup performs a WHOIS lookup for the given domain.
func (w *WhoisClient) Lookup(ctx context.Context, domain string) (*models.WhoisAnalysis, error) {
	internalInfo := &WhoisInfo{
		Domain: domain,
	}

	// Determine WHOIS server based on TLD
	server, err := w.getWhoisServer(ctx, domain) // Pass context
	if err != nil {
		w.logger.Error("Failed to get WHOIS server for %s: %v", domain, err)
		return nil, err
	}

	// Perform WHOIS query
	response, err := w.queryWhoisServer(ctx, server, domain) // Pass context
	if err != nil {
		w.logger.Error("Failed to query WHOIS server %s for %s: %v", server, domain, err)
		return nil, err
	}

	internalInfo.RawResponse = response

	// Parse WHOIS response
	w.parseWhoisResponse(response, internalInfo)

	// Convert internal WhoisInfo to models.WhoisAnalysis
	analysis := &models.WhoisAnalysis{
		Domain:      internalInfo.Domain,
		Registrar:   internalInfo.Registrar,
		CreatedDate: internalInfo.CreatedDate.Format("2006-01-02"), // Format date
		UpdatedDate: internalInfo.UpdatedDate.Format("2006-01-02"), // Format date
		ExpiryDate:  internalInfo.ExpiresDate.Format("2006-01-02"), // Format date
		NameServers: internalInfo.NameServers,
		Status:      internalInfo.Status,
		RawWhois:    internalInfo.RawResponse,
		DomainAge:   calculateDomainAge(internalInfo.CreatedDate),
	}

	return analysis, nil
}

// getWhoisServer determines the correct WHOIS server for a given domain.
func (w *WhoisClient) getWhoisServer(ctx context.Context, domain string) (string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}

	tld := parts[len(parts)-1]

	server, exists := w.servers[tld]
	if !exists {
		w.logger.Warn("No specific WHOIS server for TLD '%s', falling back to IANA", tld)
		return "whois.iana.org", nil // Fallback to IANA for unknown TLDs
	}

	return server, nil
}

// queryWhoisServer sends a query to the specified WHOIS server and returns the response.
func (w *WhoisClient) queryWhoisServer(ctx context.Context, server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", w.timeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server %s: %w", server, err)
	}
	defer conn.Close()

	// Set timeout for connection operations
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		conn.SetDeadline(time.Now().Add(w.timeout))
	}

	// Send query
	fmt.Fprintf(conn, "%s\r\n", domain)

	// Read response
	var response strings.Builder
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			line := scanner.Text()
			response.WriteString(line + "\n")

			// Stop if we see end of data marker (common for some WHOIS servers)
			if strings.Contains(line, ">>> Last update") ||
			   strings.Contains(line, "% IANA WHOIS server") ||
			   strings.Contains(line, "TERMS OF USE") {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading WHOIS response from %s: %w", server, err)
	}

	return response.String(), nil
}

// parseWhoisResponse parses the raw WHOIS response into a WhoisInfo struct.
func (w *WhoisClient) parseWhoisResponse(response string, info *WhoisInfo) {
	lines := strings.Split(response, "\n")

	// Regex for common fields
	registrarRe := regexp.MustCompile(`(?i)Registrar Name:\s*(.*)`)
	registrantRe := regexp.MustCompile(`(?i)Registrant Organization:\s*(.*)|Registrant Name:\s*(.*)`)
	creationDateRe := regexp.MustCompile(`(?i)Creation Date:\s*(.*)|Created On:\s*(.*)`)
	updatedDateRe := regexp.MustCompile(`(?i)Updated Date:\s*(.*)|Last Updated On:\s*(.*)`)
	expiryDateRe := regexp.MustCompile(`(?i)Registry Expiry Date:\s*(.*)|Expiration Date:\s*(.*)`)
	nameServerRe := regexp.MustCompile(`(?i)Name Server:\s*(.*)|Nameserver:\s*(.*)`)
	domainStatusRe := regexp.MustCompile(`(?i)Domain Status:\s*(.*)`)


	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%" ) || strings.HasPrefix(line, "#") {
			continue
		}

		if match := registrarRe.FindStringSubmatch(line); len(match) > 1 && info.Registrar == "" {
			info.Registrar = strings.TrimSpace(match[1])
		} else if match := registrantRe.FindStringSubmatch(line); len(match) > 1 && info.Registrant == "" {
			info.Registrant = strings.TrimSpace(match[1])
			if match[2] != "" { // Prioritize Registrant Name if present
				info.Registrant = strings.TrimSpace(match[2])
			}
		} else if match := creationDateRe.FindStringSubmatch(line); len(match) > 1 && info.CreatedDate.IsZero() {
			info.CreatedDate = parseDate(w.extractValueFromMatch(match))
		} else if match := updatedDateRe.FindStringSubmatch(line); len(match) > 1 && info.UpdatedDate.IsZero() {
			info.UpdatedDate = parseDate(w.extractValueFromMatch(match))
		} else if match := expiryDateRe.FindStringSubmatch(line); len(match) > 1 && info.ExpiresDate.IsZero() {
			info.ExpiresDate = parseDate(w.extractValueFromMatch(match))
		} else if match := nameServerRe.FindStringSubmatch(line); len(match) > 1 {
			ns := w.extractValueFromMatch(match)
			if ns != "" && !w.contains(info.NameServers, ns) { // Avoid duplicates
				info.NameServers = append(info.NameServers, ns)
			}
		} else if match := domainStatusRe.FindStringSubmatch(line); len(match) > 1 {
			status := w.extractValueFromMatch(match)
			if status != "" && !w.contains(info.Status, status) { // Avoid duplicates
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

func (w *WhoisClient) extractValueFromMatch(match []string) string {
	for i := 1; i < len(match); i++ {
		if match[i] != "" {
			return match[i]
		}
	}
	return ""
}

func (w *WhoisClient) contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

// parseDate attempts to parse a date string using multiple common formats.
func parseDate(dateStr string) time.Time {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05Z",
		"2006-01-02",
		"02-Jan-2006",
		"02-Jan-2006 15:04:05 MST", // e.g., 20-Dec-2023 00:00:00 UTC
		"Mon Jan 02 15:04:05 MST 2006", // e.g., Tue Jun 21 00:00:00 GMT 2023
		"2006.01.02",
		"2006/01/02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}
	return time.Time{} // Return zero time if parsing fails
}

// calculateDomainAge returns a human-readable string of the domain's age.
func calculateDomainAge(creationDate time.Time) string {
	if creationDate.IsZero() {
		return "Unknown"
	}
	
duration := time.Since(creationDate)
	
years := int(duration.Hours() / 24 / 365)
	if years > 0 {
		return fmt.Sprintf("%d years", years)
	}
	
	months := int(duration.Hours() / 24 / 30)
	if months > 0 {
		return fmt.Sprintf("%d months", months)
	}
	
days := int(duration.Hours() / 24)
	return fmt.Sprintf("%d days", days)
}

// WhoisInfo is an internal struct for parsing raw WHOIS responses.
type WhoisInfo struct {
	Domain        string
	Registrar     string
	Registrant    string // New field to capture registrant organization/name
	CreatedDate   time.Time
	UpdatedDate   time.Time
	ExpiresDate   time.Time
	NameServers   []string
	Status        []string
	RawResponse   string
}