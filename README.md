# Host Header Injection Scanner

A Python-based security testing tool designed to detect Host Header Injection vulnerabilities in web applications. This scanner tests various header combinations and payloads to identify potential security weaknesses.

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Only use this scanner on systems you own or have explicit permission to test. Unauthorized testing may be illegal in your jurisdiction.

## Features

- **Multiple Header Testing**: Tests various header types including `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, and more
- **Payload Generation**: Automatically generates variations of payloads based on attacker domain and wordlist
- **Detection Capabilities**: 
  - Reflection in response body
  - Reflection in response headers
  - Location header poisoning
  - Cache header analysis
- **Pretty Progress Mode**: Single-line updating progress display
- **Multi-threaded**: Concurrent scanning for improved performance
- **Flexible Configuration**: Support for custom headers, proxies, SSL options, and more
- **Output Options**: JSON-formatted results for easy parsing and analysis

## Requirements

- Python 3.6+
- Required packages:
  ```
  requests
  urllib3
  ```

## Installation

1. Clone or download the script
2. Install dependencies:
   ```bash
   pip install requests urllib3
   ```

## Usage

### Basic Usage

```bash
# Scan a single URL
python3 hostinject.py -u https://example.com -h header.txt -a attacker.com

# Scan multiple URLs from a file
python3 hostinject.py -l targets.txt -h header.txt -a attacker.com
```

### Command Line Options

#### Required Arguments

- `-u, --url URL`: Target URL to scan (single target)
- `-l, --list FILE`: File containing list of target URLs (one per line)
- `-h, --headers FILE`: Header wordlist file for payload generation
- `-a, --attacker DOMAIN`: Attacker-controlled domain for testing

#### Optional Arguments

**HTTP Options:**
- `-m, --method {GET,POST,HEAD}`: HTTP method (default: GET)
- `-b, --body DATA`: Request body for POST requests
- `-H, --extra-headers FILE`: Extra HTTP headers (JSON file or key:value lines)
- `-U, --user-agent STRING`: Custom User-Agent string
- `-r, --redirects`: Follow redirects
- `-s, --ssl`: Enable SSL certificate verification
- `--no-warn-ssl`: Suppress SSL warnings

**Performance:**
- `-t, --threads NUM`: Number of concurrent threads (default: 8)
- `-T, --timeout SECONDS`: Request timeout in seconds (default: 12.0)

**Progress Display:**
- `--pretty-progress`: Enable single-line updating progress display
- `--allow-concurrent-progress`: Allow threading with pretty progress (may cause output jitter)

**Network:**
- `-p, --proxy URL`: Proxy URL (e.g., http://127.0.0.1:8080)

**Output:**
- `-o, --output FILE`: Save findings to JSON file
- `-v, --verbose`: Enable verbose output

## Examples

### Basic Scan with Pretty Progress

```bash
python3 hostinject.py -u https://target.com -h header.txt -a evil.com --pretty-progress
```

### Scan with Custom Headers

```bash
python3 hostinject.py -u https://target.com -h header.txt -a evil.com -H headers.json
```

Example `headers.json`:
```json
{
  "Authorization": "Bearer token123",
  "X-Custom-Header": "value"
}
```

### Scan Through Proxy

```bash
python3 hostinject.py -u https://target.com -h header.txt -a evil.com -p http://127.0.0.1:8080
```

### Multi-threaded Scan with Output

```bash
python3 hostinject.py -l targets.txt -h header.txt -a evil.com -t 16 -o results.json
```

### POST Request with Body

```bash
python3 hostinject.py -u https://target.com -h header.txt -a evil.com -m POST -b '{"key":"value"}'
```

## Header Wordlist Format

Create a header wordlist file (`header.txt`) with subdomains or prefixes (one per line):

```
X-Forwarded
X-Forwarded-By
X-Forwarded-For
X-Forwarded-For-Original
X-Forwarded-Host
X-Forwarded-Port
X-Forwarded-Proto
X-Forwarded-Protocol
X-Forwarded-Scheme
X-Forwarded-Server
X-Forwarded-Ssl
X-Forwarded-Ssl 
X-Forwarder-For
X-Forward-For
X-Forward-Proto
```

Comments (lines starting with `#`) are ignored.

## Detection Signals

The scanner looks for the following indicators:

1. **Body Reflection**: Payload appears in response body
2. **Header Reflection**: Payload appears in response headers
3. **Location Poisoning**: Payload appears in `Location` header
4. **Cache Headers**: Presence of caching-related headers
5. **Interesting Headers**: Server identification and routing headers

## Output Format

Results are saved in JSON Lines format (one JSON object per line):

```json
{
  "url": "https://target.com",
  "header": "X-Forwarded-Host",
  "payload": "evil.com",
  "signals": {
    "status": 200,
    "reflected_in_body": true,
    "reflected_in_headers": ["Location"],
    "location_poison": false,
    "cache_headers": {},
    "interesting_headers": {},
    "content_length": 1234
  },
  "ts": 1699296000
}
```

## Headers Tested

The scanner tests the following headers:
- `Host`
- `X-Host`
- `X-Forwarded-Host`
- `X-Original-Host`
- `X-Forwarded-Server`
- `X-Forwarded-For`
- `Forwarded`

## Payload Generation

Payloads are automatically generated from your attacker domain and header wordlist:

- Base domain: `attacker.com`
- With ports: `attacker.com:80`, `attacker.com:443`
- With trailing dot: `attacker.com.`
- Subdomain variants: `word.attacker.com`
- Hyphenated variants: `word-attacker.com`, `attacker.com-word`

## Tips for Effective Testing

1. **Start Small**: Begin with a small header wordlist to understand the target's behavior
2. **Use Pretty Progress**: Enable `--pretty-progress` for cleaner output during testing
3. **Save Results**: Always use `-o` to save findings for later analysis
4. **Proxy Through Burp**: Use `-p` to route traffic through Burp Suite for detailed inspection
5. **Manual Validation**: Always manually verify findings before reporting

## Troubleshooting

**SSL Certificate Errors**:
```bash
# Disable SSL verification (use with caution)
python3 hostinject.py -u https://target.com -h header.txt -a evil.com --no-warn-ssl
```

**Connection Timeouts**:
```bash
# Increase timeout
python3 hostinject.py -u https://target.com -h header.txt -a evil.com -T 30
```

**Rate Limiting**:
```bash
# Reduce thread count
python3 hostinject.py -u https://target.com -h header.txt -a evil.com -t 2
```

## Security Considerations

- This tool generates network traffic that may trigger security alerts
- Always obtain written authorization before testing
- Be mindful of rate limits and terms of service
- Results should be manually validated before reporting as vulnerabilities
- Consider the legal and ethical implications in your jurisdiction

## Contributing

Contributions, bug reports, and feature requests are welcome. Please ensure any modifications maintain the security-focused nature of the tool.

## License

This tool is provided as-is for educational and authorized security testing purposes.

## Version

Current version: 1.2

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
