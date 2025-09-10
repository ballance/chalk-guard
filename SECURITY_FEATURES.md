# Security Features Documentation

## Overview

ChalkGuard includes comprehensive security features to ensure safe and responsible scanning while preventing potential abuse. All security measures are enabled by default to protect both the scanner and target websites.

## Security Features

### 1. URL Validation & SSRF Prevention

The tool validates all URLs before scanning to prevent Server-Side Request Forgery (SSRF) attacks:

- **DNS Resolution**: Performs DNS lookups with clear error reporting for non-existent domains
- **Private IP Blocking**: Blocks scanning of private IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **Localhost Protection**: Prevents scanning of localhost, 127.0.0.1, and loopback addresses
- **Link-Local Blocking**: Blocks 169.254.0.0/16 addresses
- **Protocol Restrictions**: Only allows HTTP and HTTPS protocols

**Example blocked URLs:**
- `http://localhost/admin` - Localhost blocked
- `http://192.168.1.1/router` - Private IP blocked
- `ftp://example.com/files` - Unsupported protocol
- `file:///etc/passwd` - File protocol blocked

### 2. Rate Limiting

Prevents overwhelming target servers with requests:

- **Default Delay**: 0.5 seconds between requests
- **Configurable**: Use `--rate-limit` to adjust (in seconds)
- **Safe Mode**: Enforces minimum 1-second delay

**Usage:**
```bash
python supply.py https://example.com --rate-limit 1.0  # 1 second between requests
```

### 3. Robots.txt Compliance

Respects website robots.txt directives:

- **Automatic Checking**: Enabled by default
- **User-Agent Identification**: Uses "ChalkGuard/0.1 (NPM Security Scanner)"
- **Caching**: Caches robots.txt parsers to minimize requests
- **Override Option**: `--no-robots` flag (not recommended)

### 4. Redirect Security

Validates all HTTP redirects to prevent attacks:

- **Same-Domain Only**: Blocks cross-domain redirects by default
- **Validation**: Each redirect destination is validated
- **Chain Limit**: Maximum 3 redirects in a chain
- **Private IP Protection**: Blocks redirects to private IPs

**Example blocked redirects:**
- `example.com → evil.com` - Cross-domain blocked
- `public.com → 192.168.1.1` - Private IP blocked

### 5. Page Scan Limits

Prevents excessive scanning:

- **Default Limit**: Maximum 20 pages per scan
- **Configurable**: Use `--max-pages` to adjust
- **Safe Mode**: Limits to 10 pages maximum

**Usage:**
```bash
python supply.py https://example.com --max-pages 5  # Scan maximum 5 pages
```

### 6. Safe Mode

Conservative settings for maximum safety:

- **Rate Limit**: Minimum 1 second between requests
- **Page Limit**: Maximum 10 pages
- **Robots.txt**: Always enabled
- **All Validations**: Strictest settings

**Usage:**
```bash
python supply.py https://example.com --safe-mode
```

## Error Handling

The tool provides clear error messages for all blocked operations:

### DNS Resolution Errors
```
⚠️  ERROR: Site not found: Could not resolve hostname 'invalid-domain.com' (DNS lookup failed)
```

### Security Blocks
```
⚠️  ERROR: Cannot scan private IP address: 192.168.1.1 (security restriction)
⚠️  ERROR: Cannot scan localhost (security restriction)
⚠️  ERROR: Unsupported scheme: ftp
```

### Robot.txt Blocks
```
⚠️  WARNING: Robots.txt disallows scanning: https://example.com/admin
```

## Command Line Options

### Security-Related Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--rate-limit SECONDS` | Delay between requests | 0.5 |
| `--max-pages NUMBER` | Maximum pages to scan | 20 |
| `--no-robots` | Ignore robots.txt (not recommended) | False |
| `--no-redirects` | Don't follow HTTP redirects | False |
| `--safe-mode` | Enable all safety features | False |

## Best Practices

### Responsible Scanning

1. **Always obtain permission** before scanning websites
2. **Use appropriate rate limits** to avoid overwhelming servers
3. **Respect robots.txt** directives
4. **Monitor scan progress** and stop if issues arise
5. **Use safe mode** for unfamiliar targets

### Example Commands

**Conservative scan with all protections:**
```bash
python supply.py https://example.com --safe-mode --verbose
```

**Custom security settings:**
```bash
python supply.py https://example.com --rate-limit 2.0 --max-pages 5
```

**Batch scanning with safety limits:**
```bash
python supply.py --batch urls.txt --rate-limit 1.0 --max-pages 10
```

## Security Audit Trail

The tool maintains logs of all security events:

- **Blocked URLs**: Logged with reasons
- **DNS Failures**: Tracked in `error_sites.txt`
- **Rate Limiting**: Delays logged in verbose mode
- **Validation Failures**: Detailed error messages

## Compliance

ChalkGuard is designed for:
- **Authorized security testing only**
- **Defensive security purposes**
- **Incident response**
- **Vulnerability assessment with permission**

## Reporting Issues

If you encounter security issues or have suggestions:

1. **Do not publicly disclose vulnerabilities**
2. **Open a private issue on GitHub**
3. **Include details and reproduction steps**
4. **Allow time for fixes before disclosure**

---

**Remember**: This tool is for defensive security purposes only. Always ensure you have explicit permission to scan any website or network.