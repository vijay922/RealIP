package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Result structure for IP discovery results
type Result struct {
	IP     string `json:"ip"`
	Source string `json:"source"`
	Ports  []int  `json:"ports,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	SSL    *SSLInfo `json:"ssl,omitempty"`
}

// SSLInfo holds SSL certificate information
type SSLInfo struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	SANs       []string `json:"sans"`
	NotAfter   string   `json:"not_after"`
	CommonName string   `json:"common_name"`
}

// Config holds application configuration
type Config struct {
	Domain      string
	Verbose     bool
	Timeout     time.Duration
	MaxWorkers  int
	OutputJSON  bool
	CheckPorts  bool
	CheckSSL    bool
	CheckSubdomains bool
}

func main() {
	var config Config

	flag.StringVar(&config.Domain, "d", "", "Target domain (required)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.DurationVar(&config.Timeout, "t", 10*time.Second, "Timeout duration")
	flag.IntVar(&config.MaxWorkers, "w", 50, "Maximum workers")
	flag.BoolVar(&config.OutputJSON, "json", false, "Output in JSON format")
	flag.BoolVar(&config.CheckPorts, "ports", false, "Check common ports")
	flag.BoolVar(&config.CheckSSL, "ssl", false, "Check SSL certificates")
	flag.BoolVar(&config.CheckSubdomains, "subs", false, "Check subdomains")
	flag.Parse()

	if config.Domain == "" {
		fmt.Println("Usage: realip -d <domain>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Clean domain
	config.Domain = strings.TrimPrefix(config.Domain, "http://")
	config.Domain = strings.TrimPrefix(config.Domain, "https://")
	config.Domain = strings.Split(config.Domain, "/")[0]

	discoverer := NewIPDiscoverer(config)
	results := discoverer.DiscoverRealIPs()

	if config.OutputJSON {
		outputJSON(results)
	} else {
		outputText(results, config.Verbose)
	}
}

// IPDiscoverer handles the IP discovery process
type IPDiscoverer struct {
	config  Config
	client  *http.Client
	dnsClient *dns.Client
	results []Result
	mu      sync.Mutex
}

func NewIPDiscoverer(config Config) *IPDiscoverer {
	return &IPDiscoverer{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		dnsClient: &dns.Client{Timeout: config.Timeout},
		results:   make([]Result, 0),
	}
}

func (d *IPDiscoverer) DiscoverRealIPs() []Result {
	var wg sync.WaitGroup

	// DNS Resolution Methods
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.checkDNSRecords()
	}()

	// Subdomain enumeration
	if d.config.CheckSubdomains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.checkSubdomains()
		}()
	}

	// HTTP header analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.analyzeHTTPHeaders()
	}()

	// Common port scanning on discovered IPs
	if d.config.CheckPorts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(2 * time.Second) // Wait for some IPs to be discovered
			d.scanCommonPorts()
		}()
	}

	wg.Wait()

	// Deduplicate and sort results
	return d.deduplicateResults()
}

func (d *IPDiscoverer) checkDNSRecords() {
	domain := dns.Fqdn(d.config.Domain)

	// Check A records
	d.queryDNS(domain, dns.TypeA, "DNS-A")

	// Check AAAA records  
	d.queryDNS(domain, dns.TypeAAAA, "DNS-AAAA")

	// Check MX records
	d.queryDNSMX(domain)

	// Check TXT records for potential IP leaks
	d.queryDNSTXT(domain)

	// Check NS records
	d.queryDNS(domain, dns.TypeNS, "DNS-NS")
}

func (d *IPDiscoverer) queryDNS(domain string, qtype uint16, source string) {
	m := new(dns.Msg)
	m.SetQuestion(domain, qtype)
	m.RecursionDesired = true

	// Try multiple DNS servers
	servers := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

	for _, server := range servers {
		r, _, err := d.dnsClient.Exchange(m, server)
		if err != nil {
			if d.config.Verbose {
				fmt.Printf("DNS query failed for %s: %v\n", server, err)
			}
			continue
		}

		for _, ans := range r.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				d.addResult(Result{
					IP:     rr.A.String(),
					Source: source + "-" + server,
				})
			case *dns.AAAA:
				d.addResult(Result{
					IP:     rr.AAAA.String(),
					Source: source + "-" + server,
				})
			case *dns.NS:
				// Resolve NS records to IPs
				d.queryDNS(rr.Ns, dns.TypeA, "DNS-NS-A")
			}
		}
	}
}

func (d *IPDiscoverer) queryDNSMX(domain string) {
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeMX)
	m.RecursionDesired = true

	r, _, err := d.dnsClient.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return
	}

	for _, ans := range r.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			// Resolve MX hostnames to IPs
			d.queryDNS(mx.Mx, dns.TypeA, "DNS-MX")
		}
	}
}

func (d *IPDiscoverer) queryDNSTXT(domain string) {
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := d.dnsClient.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return
	}

	// Look for IP addresses in TXT records
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			for _, str := range txt.Txt {
				ips := ipRegex.FindAllString(str, -1)
				for _, ip := range ips {
					if net.ParseIP(ip) != nil {
						d.addResult(Result{
							IP:     ip,
							Source: "DNS-TXT",
						})
					}
				}
			}
		}
	}
}

func (d *IPDiscoverer) checkSubdomains() {
	commonSubdomains := []string{
		"www", "mail", "ftp", "webmail", "admin", "dev", "test", "staging",
		"api", "blog", "shop", "secure", "support", "help", "docs", "cdn",
		"static", "img", "images", "media", "assets", "files", "download",
		"upload", "portal", "dashboard", "panel", "cpanel", "whm", "directadmin",
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.config.MaxWorkers)

	for _, sub := range commonSubdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fqdn := subdomain + "." + d.config.Domain
			d.queryDNS(dns.Fqdn(fqdn), dns.TypeA, "Subdomain-"+subdomain)
		}(sub)
	}

	wg.Wait()
}

func (d *IPDiscoverer) analyzeHTTPHeaders() {
	protocols := []string{"http", "https"}

	for _, proto := range protocols {
		url := fmt.Sprintf("%s://%s", proto, d.config.Domain)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		// Add headers that might reveal origin IP
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")

		resp, err := d.client.Do(req)
		if err != nil {
			if d.config.Verbose {
				fmt.Printf("HTTP request failed for %s: %v\n", url, err)
			}
			continue
		}
		defer resp.Body.Close()

		// Check response headers for IP leaks
		headers := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				headers[k] = v[0]

				// Look for IPs in various headers
				if strings.Contains(strings.ToLower(k), "server") || 
				   strings.Contains(strings.ToLower(k), "x-") ||
				   strings.Contains(strings.ToLower(k), "origin") {
					d.extractIPsFromString(v[0], "HTTP-Header-"+k)
				}
			}
		}

		// Read response body and look for IP patterns
		body, err := io.ReadAll(resp.Body)
		if err == nil && len(body) < 1024*1024 { // Limit to 1MB
			d.extractIPsFromString(string(body), "HTTP-Body")
		}

		// Check SSL certificate if HTTPS
		if proto == "https" && d.config.CheckSSL {
			d.analyzeSSLCertificate(d.config.Domain, headers)
		}
	}
}

func (d *IPDiscoverer) extractIPsFromString(text, source string) {
	// IPv4 regex
	ipv4Regex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ips := ipv4Regex.FindAllString(text, -1)

	for _, ip := range ips {
		if net.ParseIP(ip) != nil && !d.isPrivateIP(ip) && !d.isCDNIP(ip) {
			d.addResult(Result{
				IP:     ip,
				Source: source,
			})
		}
	}
}

func (d *IPDiscoverer) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsMulticast()
}

func (d *IPDiscoverer) isCDNIP(ip string) bool {
	// Simple check for common CDN ranges (Cloudflare, AWS CloudFront, etc.)
	cdnRanges := []string{
		"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
		"108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
		"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
		"197.234.240.0/22", "198.41.128.0/17",
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range cdnRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (d *IPDiscoverer) analyzeSSLCertificate(domain string, headers map[string]string) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		ServerName: domain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]

		sslInfo := &SSLInfo{
			Subject:    cert.Subject.String(),
			Issuer:     cert.Issuer.String(),
			SANs:       cert.DNSNames,
			NotAfter:   cert.NotAfter.Format(time.RFC3339),
			CommonName: cert.Subject.CommonName,
		}

		// Add certificate info to existing results or create new one
		d.mu.Lock()
		for i := range d.results {
			if d.results[i].Source == "SSL-Cert" {
				d.results[i].SSL = sslInfo
				d.mu.Unlock()
				return
			}
		}
		d.mu.Unlock()

		d.addResult(Result{
			IP:     "", // Will be filled if we can extract from cert
			Source: "SSL-Cert",
			SSL:    sslInfo,
		})
	}
}

func (d *IPDiscoverer) scanCommonPorts() {
	// Get unique IPs from current results
	ips := d.getUniqueIPs()

	commonPorts := []int{22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 2087, 2095, 2096}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.config.MaxWorkers)

	for _, ip := range ips {
		for _, port := range commonPorts {
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				if d.isPortOpen(ip, port) {
					d.addPortToResult(ip, port)
				}
			}(ip, port)
		}
	}

	wg.Wait()
}

func (d *IPDiscoverer) isPortOpen(ip string, port int) bool {
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func (d *IPDiscoverer) getUniqueIPs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	seen := make(map[string]bool)
	var ips []string

	for _, result := range d.results {
		if result.IP != "" && !seen[result.IP] {
			seen[result.IP] = true
			ips = append(ips, result.IP)
		}
	}

	return ips
}

func (d *IPDiscoverer) addResult(result Result) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.results = append(d.results, result)
}

func (d *IPDiscoverer) addPortToResult(ip string, port int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := range d.results {
		if d.results[i].IP == ip {
			d.results[i].Ports = append(d.results[i].Ports, port)
			return
		}
	}

	// If IP not found, create new result
	d.results = append(d.results, Result{
		IP:     ip,
		Source: "Port-Scan",
		Ports:  []int{port},
	})
}

func (d *IPDiscoverer) deduplicateResults() []Result {
	d.mu.Lock()
	defer d.mu.Unlock()

	ipMap := make(map[string]*Result)

	for _, result := range d.results {
		if result.IP == "" {
			continue
		}

		if existing, exists := ipMap[result.IP]; exists {
			// Merge results
			existing.Source += ", " + result.Source
			if result.Ports != nil {
				existing.Ports = append(existing.Ports, result.Ports...)
			}
			if result.Headers != nil {
				if existing.Headers == nil {
					existing.Headers = make(map[string]string)
				}
				for k, v := range result.Headers {
					existing.Headers[k] = v
				}
			}
			if result.SSL != nil {
				existing.SSL = result.SSL
			}
		} else {
			resultCopy := result
			ipMap[result.IP] = &resultCopy
		}
	}

	var finalResults []Result
	for _, result := range ipMap {
		// Deduplicate ports
		if result.Ports != nil {
			portMap := make(map[int]bool)
			var uniquePorts []int
			for _, port := range result.Ports {
				if !portMap[port] {
					portMap[port] = true
					uniquePorts = append(uniquePorts, port)
				}
			}
			sort.Ints(uniquePorts)
			result.Ports = uniquePorts
		}

		finalResults = append(finalResults, *result)
	}

	// Sort results by IP
	sort.Slice(finalResults, func(i, j int) bool {
		return finalResults[i].IP < finalResults[j].IP
	})

	return finalResults
}

func outputJSON(results []Result) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(results)
}

func outputText(results []Result, verbose bool) {
	if len(results) == 0 {
		fmt.Println("No real IPs found")
		return
	}

	for _, result := range results {
		if !verbose {
			// Simple output format for basic usage
			fmt.Println(result.IP)
		} else {
			// Detailed output for verbose mode
			fmt.Printf("IP: %s\n", result.IP)
			fmt.Printf("  Source: %s\n", result.Source)

			if len(result.Ports) > 0 {
				fmt.Printf("  Open Ports: %v\n", result.Ports)
			}

			if result.SSL != nil {
				fmt.Printf("  SSL Info:\n")
				fmt.Printf("    Common Name: %s\n", result.SSL.CommonName)
				if len(result.SSL.SANs) > 0 {
					fmt.Printf("    SANs: %v\n", result.SSL.SANs)
				}
			}

			if len(result.Headers) > 0 {
				fmt.Printf("  Headers: %v\n", result.Headers)
			}

			fmt.Println()
		}
	}
}
