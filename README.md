# RealIP - Advanced Origin IP Discovery Tool

A comprehensive Go-based tool for discovering the real IP addresses of domains behind CDNs, WAFs, and reverse proxies. This tool implements multiple reconnaissance techniques used in ethical security research and bug bounty hunting.

## Features

### Core Discovery Techniques
- **DNS Analysis**: Multiple record types (A, AAAA, MX, NS, TXT) across different resolvers
- **Subdomain Enumeration**: Common subdomain patterns that may leak origin IPs
- **HTTP Header Analysis**: Extracts IPs from response headers and body content
- **SSL Certificate Analysis**: Certificate metadata and SAN examination
- **Port Scanning**: Discovery of services on common ports
- **Multi-threaded Operations**: Concurrent execution for faster results

### Advanced Capabilities
- **CDN Detection**: Identifies and filters known CDN IP ranges (Cloudflare, AWS, etc.)
- **Private IP Filtering**: Excludes RFC 1918 addresses and localhost
- **Multiple Output Formats**: Simple text or detailed JSON output
- **Configurable Timeouts**: Adjustable for different network conditions
- **Verbose Logging**: Detailed information for debugging and analysis

## Installation

```bash
# Clone or download the realip.go file
# Initialize Go module
go mod init realip

# Install dependencies
go get github.com/miekg/dns

# Build the binary
go build -o realip realip.go
```

## Usage

### Basic Usage
```bash
# Simple IP discovery
./realip -d example.com

# Verbose output with detailed information
./realip -d example.com -v

# JSON output for programmatic use
./realip -d example.com -json
```

### Advanced Options
```bash
# Full reconnaissance with all features
./realip -d example.com -v -ports -ssl -subs -json

# Custom timeout and worker configuration
./realip -d example.com -t 30s -w 100

# Port scanning on discovered IPs
./realip -d example.com -ports -v
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Target domain (required) | - |
| `-v` | Verbose output | false |
| `-json` | Output in JSON format | false |
| `-ports` | Check common ports on discovered IPs | false |
| `-ssl` | Analyze SSL certificates | false |
| `-subs` | Check common subdomains | false |
| `-t` | Timeout duration | 10s |
| `-w` | Maximum concurrent workers | 50 |

## Discovery Techniques

### 1. DNS Record Analysis
- **A/AAAA Records**: Direct IPv4/IPv6 resolution
- **MX Records**: Mail server IP discovery
- **NS Records**: Name server resolution
- **TXT Records**: IP address extraction from text records
- **Multiple Resolvers**: Cross-validation using different DNS servers

### 2. Subdomain Enumeration
Common subdomains that may not be behind the CDN:
- Administrative: `admin`, `cpanel`, `whm`, `directadmin`
- Development: `dev`, `test`, `staging`
- Services: `mail`, `ftp`, `api`, `cdn`
- Static content: `static`, `img`, `media`, `assets`

### 3. HTTP Header Analysis
Examines response headers for IP disclosure:
- Server headers and custom X-headers
- Origin server information
- Load balancer configurations
- Response body content analysis

### 4. SSL Certificate Investigation
- Subject Alternative Names (SANs)
- Certificate issuer information  
- Common Name analysis
- Certificate chain examination

### 5. Port Discovery
Scans common ports on discovered IPs:
- Web services: 80, 443, 8080, 8443
- Administrative: 2087, 2095, 2096 (cPanel)
- Network services: 22 (SSH), 25 (SMTP), 53 (DNS)

## Output Formats

### Simple Text Output
```
192.168.1.100
10.0.0.50
203.0.113.42
```

### Verbose Text Output
```
IP: 192.168.1.100
  Source: DNS-A-8.8.8.8, Subdomain-dev
  Open Ports: [22, 80, 443]
  SSL Info:
    Common Name: *.example.com
    SANs: [example.com, www.example.com, dev.example.com]

IP: 203.0.113.42
  Source: HTTP-Header-Server
  Open Ports: [80, 8080]
```

### JSON Output
```json
[
  {
    "ip": "192.168.1.100",
    "source": "DNS-A-8.8.8.8, Subdomain-dev",
    "ports": [22, 80, 443],
    "ssl": {
      "subject": "CN=*.example.com,O=Example Inc",
      "issuer": "CN=Let's Encrypt Authority",
      "sans": ["example.com", "www.example.com"],
      "not_after": "2024-12-31T23:59:59Z",
      "common_name": "*.example.com"
    }
  }
]
```

## Security and Ethical Use

### Important Disclaimers
- **Scope Compliance**: Always verify target is within authorized scope
- **Legal Use Only**: Only use on domains you own or have explicit permission to test
- **Bug Bounty Programs**: Check program rules before testing discovered IPs
- **No Destructive Actions**: Tool performs passive reconnaissance only

### Bug Bounty Applications
When using discovered IPs in bug bounty programs:
1. **Verify Scope**: Confirm IPs belong to target organization
2. **Document Discovery**: Record how IP was found for reporting
3. **Test Safely**: Use non-destructive proof-of-concept methods
4. **Report Responsibly**: Include mitigation recommendations

## Technical Implementation

### Dependencies
- `github.com/miekg/dns`: DNS operations and queries
- Standard Go libraries: `net`, `http`, `crypto/tls`, `encoding/json`

### Architecture
- **Concurrent Processing**: Goroutines for parallel execution
- **Resource Management**: Semaphores for connection limiting
- **Error Handling**: Graceful failure recovery
- **Result Deduplication**: Intelligent merging of findings

### Performance Considerations
- **Connection Pooling**: Reuses HTTP connections
- **Timeout Management**: Prevents hanging operations  
- **Memory Efficiency**: Streaming processing for large responses
- **Rate Limiting**: Configurable worker limits

## Common Use Cases

### Bug Bounty Research
```bash
# Comprehensive reconnaissance
./realip -d target.com -v -ports -ssl -subs -json > results.json

# Quick IP check
./realip -d target.com
```

### Infrastructure Analysis
```bash
# Focus on services and certificates
./realip -d company.com -ssl -ports -v

# Subdomain investigation
./realip -d domain.com -subs -json
```

### CDN Bypass Validation
```bash
# Verify origin server discovery
./realip -d protected-site.com -v

# Port-based validation
./realip -d site.com -ports
```

## Mitigation Recommendations

For website operators to prevent IP disclosure:
- **Proper DNS Configuration**: Ensure all records point to CDN
- **Subdomain Protection**: Include all subdomains in CDN/WAF
- **Header Security**: Remove server identification headers
- **Certificate Management**: Use CDN-issued certificates
- **Port Filtering**: Block direct access to origin servers
- **IP Allowlisting**: Restrict origin access to CDN IP ranges

## Troubleshooting

### Common Issues
- **No Results**: Domain may be properly protected
- **Timeouts**: Increase timeout with `-t` flag
- **Rate Limiting**: Reduce workers with `-w` flag
- **DNS Failures**: Check network connectivity

### Debug Mode
```bash
# Enable verbose logging
./realip -d example.com -v

# Test specific techniques
./realip -d example.com -subs -v
./realip -d example.com -ssl -v
```

## Contributing

Contributions welcome for:
- Additional discovery techniques
- Performance improvements
- Bug fixes and error handling
- Documentation updates

## Disclaimer

This tool is intended for authorized security research, penetration testing, and bug bounty hunting only. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before use. The authors assume no liability for misuse or any damages resulting from the use of this tool.

## License

MIT License - See LICENSE file for details.
