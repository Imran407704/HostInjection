# Host Header Injection Scanner

A Python-based security testing tool designed to detect Host Header Injection vulnerabilities in web applications. This scanner tests various header combinations and payloads to identify potential security weaknesses.

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Only use this scanner on systems you own or have explicit permission to test. Unauthorized testing may be illegal in your jurisdiction.

## Features

- **Multiple Header Testing**: Tests various header types including `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, and more
- **Payload Generation**: Automatically generates variations of payloads based on attacker domain and headers list
- **Detection Capabilities**: 
  - Reflection in response body
  - Reflection in response headers
  - Location header poisoning
  - Cache headers tracking
  - Interesting headers identification
- **Pretty Progress Mode**: Single-line updating progress display (ON by default)
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
# Scan a single URL (pretty progress ON by default)
python3 hostinject.py -u https://example.com --headers header.txt -a attacker.com

# Scan multiple URLs from a file
python3 hostinject.py -l targets.txt --headers header.txt -a attacker.com
```

### Command Line Options

#### Required Arguments

- `-u, --url URL`: Target URL to scan (single target)
- `-l, --list FILE`: File containing list of target URLs (one per line)
- `    --headers FILE`: Headers file for payload generation (e.g., header.txt)
- `-a, --attacker DOMAIN`: Attacker-controlled domain for testing

#### Optional Arguments

**HTTP Options:**
- `-m, --method {GET,POST,HEAD}`: HTTP method (default: GET)
- `-b, --body DATA`: Request body for POST/PUT requests
- `-H, --extra-headers FILE`: Extra static headers (JSON file or key:value lines)
- `-U, --user-agent STRING`: Custom User-Agent string
- `-r, --redirects`: Follow redirects
- `-s, --ssl`: Enable SSL certificate verification
- `--no-warn-ssl`: Suppress SSL warnings when SSL verify is off
- `--force-http`: For force http

**Performance:**
- `-t, --threads NUM`: Number of concurrent threads (default: 8)
- `-T, --timeout SECONDS`: Request timeout in seconds (default: 12.0)

**Progress Display:**
- `--no-pretty`: Disable single-line pretty progress (use standard per-attempt lines)
- `--allow-concurrent-progress`: Allow threading with pretty progress (output may jitter)

**Network:**
- `-p, --proxy URL`: Proxy URL (e.g., http://127.0.0.1:8080 or socks5://...)

**Output:**
- `-o, --output FILE`: Save findings to JSONL file
- `-v, --verbose`: Enable verbose output

## Examples

### Basic Scan (Pretty Progress ON by Default)

```bash
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com
```

### Scan Without Pretty Progress

```bash
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com --no-pretty
```
### Scan Through Proxy

```bash
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com -p http://127.0.0.1:8080
```

### Multi-threaded Scan with Output

```bash
python3 hostinject.py -l targets.txt --headers header.txt -a evil.com -t 16 -o results.json
```

### POST Request with Body

```bash
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com -m POST -b '{"key":"value"}'
```

## Detection Signals

The scanner looks for the following indicators:

1. **Body Reflection**: Payload appears in response body
2. **Header Reflection**: Payload appears in response headers
3. **Location Poisoning**: Payload appears in `Location` header
4. **Cache Headers**: Tracks cache-related headers (Cache-Control, Age, X-Cache, etc.)
5. **Interesting Headers**: Identifies server and routing headers (Server, Via, X-Varnish, etc.)

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
    "cache_headers": {
      "Cache-Control": "public, max-age=3600",
      "X-Cache": "HIT"
    },
    "interesting_headers": {
      "Server": "nginx/1.18.0",
      "Via": "1.1 varnish"
    },
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

**Given attacker domain:** `attacker.com`  
**Given header.txt entry:** `admin`

**Generated payloads:**
- Base domain: `attacker.com`
- With ports: `attacker.com:80`, `attacker.com:443`
- With trailing dot: `attacker.com.`
- Subdomain variants: `admin.attacker.com`
- Hyphenated variants: `admin-attacker.com`, `attacker.com-admin`

Each payload is then tested with all header types.

## Tips for Effective Testing

1. **Start Small**: Begin with a small header wordlist to understand the target's behavior
2. **Pretty Progress is Default**: The tool now has pretty progress ON by default for cleaner output
3. **Save Results**: Always use `-o` to save findings for later analysis
4. **Proxy Through Burp**: Use `-p` to route traffic through Burp Suite for detailed inspection
5. **Test Different Methods**: Try GET, POST, and HEAD methods
6. **Manual Validation**: Always manually verify findings before reporting
7. **Custom Headers**: Use `-H` to add authentication or other required headers
8. **Adjust Threads**: Lower thread count if you encounter rate limiting
9. **Check Cache Headers**: Review cache_headers in output for cache poisoning opportunities

## Troubleshooting

**SSL Certificate Errors**:
```bash
# Disable SSL verification (use with caution)
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com --no-warn-ssl
```

**Connection Timeouts**:
```bash
# Increase timeout to 30 seconds
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com -T 30
```

**Rate Limiting**:
```bash
# Reduce thread count to 2
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com -t 2
```

**Progress Display Issues**:
```bash
# Disable pretty progress if experiencing issues
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com --no-pretty

# Or allow concurrent with some jitter
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com --allow-concurrent-progress
```

## Common Use Cases

### Testing for Cache Poisoning

```bash
python3 hostinject.py -u https://target.com --headers header.txt -a evil.com -o cache-test.json
```

Look for responses with cache headers indicating the poisoned response was cached.

### Password Reset Poisoning

```bash
python3 hostinject.py -u https://target.com/reset-password --headers header.txt -a evil.com -m POST -b 'email=test@example.com'
```

Check if password reset emails contain links with your attacker domain.

### Web Cache Deception

```bash
python3 hostinject.py -u https://target.com/profile --headers header.txt -a evil.com
```

Test if sensitive pages can be cached with a malicious host header.

## Understanding Vulnerabilities

### Host Header Injection

Occurs when an application trusts the Host header value and uses it in:
- URL generation (password reset links, etc.)
- Access control decisions
- Cache keys
- Server-side request forgery (SSRF)

### Real-World Impact

- **Password Reset Poisoning**: Attacker receives password reset tokens
- **Web Cache Poisoning**: Serving malicious content to other users
- **SSRF**: Accessing internal resources
- **Business Logic Bypass**: Circumventing access controls

## Security Considerations

- This tool generates network traffic that may trigger security alerts
- Always obtain written authorization before testing
- Be mindful of rate limits and terms of service
- Results should be manually validated before reporting as vulnerabilities
- Consider the legal and ethical implications in your jurisdiction
- Do not use on production systems without proper authorization



## What's New in This Version

- **Pretty Progress by Default**: Clean single-line progress display is now enabled by default
- **Improved Error Handling**: Better SSL and request exception handling
- **Cache Headers Tracking**: Automatically tracks and reports cache-related headers
- **Interesting Headers**: Identifies server and routing headers for better analysis
- **Enhanced Detection**: More comprehensive reflection detection
- **User-Agent Update**: Default User-Agent changed to "HostInjection/1.0"

## Contributing

Contributions, bug reports, and feature requests are welcome. Please ensure any modifications maintain the security-focused nature of the tool.

## Version History

- **v1.0**: Original version by PikPikcU
- **v1.2**: Modified version with pretty progress by default, improved detection, and enhanced features

## Credits

- **Original Creator**: [PikPikcU](https://github.com/pikpikcu) - This is based on the original script at https://github.com/pikpikcu/hostinject
- **Modifications**: Enhanced with pretty progress by default, improved detection capabilities, cache header tracking, and better error handling

Full credit goes to PikPikcU for the original concept and implementation. This is a modified version with additional features.

## License

This tool is provided as-is for educational and authorized security testing purposes.

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
