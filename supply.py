#!/usr/bin/env python3
"""
NPM Supply Chain Attack Detection Tool
Detects the September 2025 npm supply chain compromise (chalk, debug, and related packages)
Author: Chris Ballance
Version: 1.0.0
"""

import requests
import json
import re
import hashlib
import argparse
import sys
import ipaddress
import socket
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NPMAttackDetector:
    """Main detector class for identifying compromised npm packages in web applications"""
    
    def __init__(self, verbose: bool = False, rate_limit: float = 0.5, max_pages: int = 20, 
                 check_robots: bool = True, allow_redirects: bool = True):
        self.verbose = verbose
        self.rate_limit = rate_limit  # Delay between requests in seconds
        self.max_pages = max_pages  # Maximum number of pages to scan
        self.check_robots = check_robots  # Whether to check robots.txt
        self.allow_redirects = allow_redirects  # Whether to follow redirects
        self.pages_scanned = 0  # Counter for pages scanned
        self.last_request_time = 0  # Track last request time for rate limiting
        self.robots_cache = {}  # Cache for robots.txt parsers
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ChalkGuard/0.1 (NPM Security Scanner; +https://github.com/ballance/ChalkGuard)'
        })
        self.session.max_redirects = 3  # Limit redirect chains
        
        # Compromised packages and versions
        self.compromised_packages = {
            'ansi-regex': ['6.2.1'],
            'ansi-styles': ['6.2.2'],
            'backslash': ['0.2.1'],
            'chalk': ['5.6.1'],
            'chalk-template': ['1.1.1'],
            'color-convert': ['3.1.1'],
            'color-name': ['2.0.1'],
            'color-string': ['2.1.1'],
            'debug': ['4.4.2'],
            'error-ex': ['1.3.3'],
            'has-ansi': ['6.0.1'],
            'is-arrayish': ['0.3.3'],
            'simple-swizzle': ['0.2.3'],
            'slice-ansi': ['7.1.1'],
            'strip-ansi': ['7.1.1'],
            'supports-color': ['10.2.1'],
            'supports-hyperlinks': ['4.1.1'],
            'wrap-ansi': ['9.0.1'],
            # Additional compromised packages
            'duckdb': ['*'],
            '@duckdb/node-api': ['*'],
            '@duckdb/duckdb-wasm': ['*'],
            '@duckdb/node-bindings': ['*'],
            'proto-tinker-wc': ['*'],
            'prebid-universal-creative': ['*'],
            'prebid': ['*'],
            'prebid.js': ['*']
        }
        
        # Malicious code signatures - enhanced for Sept 8 attack patterns
        self.malware_signatures = [
            # Primary obfuscation patterns
            r'const\s+_0x[a-f0-9]+\s*=\s*_0x[a-f0-9]+',
            r'_0x112fa8',
            r'_0x180f',
            r'_0x[a-f0-9]{4,6}\([^)]*\)',  # Obfuscated function calls
            
            # Malicious function names and patterns
            r'checkethereumw',
            r'newdlocal',
            r'runmask',
            r'ethereumCheck',
            r'walletHijack',
            r'cryptoStealer',
            
            # Wallet hooking patterns
            r'window\.ethereum\s*=\s*new\s+Proxy',
            r'window\.web3\s*=\s*new\s+Proxy',
            r'window\.fetch\s*=\s*[^=]',
            r'XMLHttpRequest\.prototype\.(open|send)\s*=',
            r'ethereum\.request\s*=\s*function',
            r'eth_requestAccounts.*Proxy',
            r'eth_sendTransaction.*replace',
            
            # Known attacker addresses
            r'0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976',
            r'0x[Ff][Cc]4[Aa]4858[Bb][Aa][Ff][Ee][Ff]54[Dd]',  # Case variations
            
            # Malicious CDN domains
            r'static-mw-host\.b-cdn\.net',
            r'img-data-backup\.b-cdn\.net',
            r'websocket-api2\.publicvm\.com',
            r'cdn-remote\.b-cdn\.net',
            r'static-files\.publicvm\.com',
            r'ws://[^/]*publicvm\.com',
            r'wss://[^/]*publicvm\.com',
            
            # Browser and environment checks
            r'typeof\s+window\s*!==?\s*["\']undefined["\']',
            r'typeof\s+global\s*!==?\s*["\']undefined["\']',
            r'process\.browser\s*===?\s*true',
            
            # Address manipulation functions
            r'levenshtein|levenstein',
            r'similarityScore',
            r'addressReplace',
            r'swapAddress',
            
            # Obfuscation and encoding patterns
            r'atob\s*\(["\'][A-Za-z0-9+/]{50,}["\']',
            r'Buffer\.from\s*\(["\'][A-Za-z0-9+/]{50,}["\']\s*,\s*["\']base64["\']',
            r'eval\s*\(\s*String\.fromCharCode',
            r'Function\s*\(["\']return\s*',
            
            # Crypto wallet patterns
            r'0x[a-fA-F0-9]{40}',
            r'privateKey.*0x[a-fA-F0-9]{64}',
            r'mnemonic.*\b(?:word|seed|phrase)\b',
            
            # ERC-20 and transaction hijacking
            r'(approve|transfer|transferFrom)\s*\([^)]*0x[a-fA-F0-9]{40}',
            r'sendTransaction.*to\s*:\s*["\']0x',
            r'estimateGas.*replace',
            
            # WebSocket patterns for C2 communication
            r'new\s+WebSocket\s*\(["\'][^"\']*(publicvm|b-cdn)',
            r'socket\.emit\s*\(["\']wallet',
            r'socket\.on\s*\(["\']command'
        ]
        
        # CDN patterns that might host compromised files
        self.cdn_patterns = [
            r'unpkg\.com',
            r'cdnjs\.cloudflare\.com',
            r'jsdelivr\.(net|com)',
            r'jspm\.io',
            r'wzrd\.in',
            r'bundle\.run',
            r'runkit\.com',
            r'skypack\.dev',
            r'esm\.sh',
            r'cdn\.pika\.dev',
            r'ga\.jspm\.io',
            r'dev\.jspm\.io'
        ]
        
        # Known malicious file hashes (SHA256)
        self.malicious_hashes = {
            # Add known hashes of compromised package versions
            'a3b4c5d6e7f8g9h0': 'chalk@5.6.1',
            'b4c5d6e7f8g9h0i1': 'debug@4.4.2',
            # These are example hashes - real hashes would be added here
        }
        
        # Obfuscation patterns
        self.obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
            r'\\u[0-9a-fA-F]{4}',  # Unicode escape sequences
            r'String\.fromCharCode\s*\([0-9,\s]+\)',  # Character code arrays
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*\[[0-9,\s]{100,}\]',  # Large numeric arrays
            r'["\'][A-Za-z0-9+/]{100,}["\']',  # Long base64 strings
            r'["\']\\x[0-9a-fA-F\\]{100,}["\']',  # Long hex strings
        ]
        
        # Attack timeline
        self.attack_window = {
            'start': datetime(2025, 9, 8, 13, 16),  # UTC
            'end': datetime(2025, 9, 8, 19, 59)      # UTC
        }

    def _validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate URL to prevent SSRF attacks
        Returns: (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            
            # Check for supported schemes
            if parsed.scheme not in ['http', 'https']:
                msg = f"Unsupported scheme: {parsed.scheme}"
                logger.warning(msg)
                return False, msg
            
            # Get hostname
            hostname = parsed.hostname
            if not hostname:
                msg = "No hostname found in URL"
                logger.warning(msg)
                return False, msg
            
            # Block localhost and loopback addresses
            if hostname.lower() in ['localhost', 'localhost.localdomain']:
                msg = "Cannot scan localhost (security restriction)"
                logger.warning(msg)
                return False, msg
            
            # Resolve hostname to IP
            try:
                # First, try to resolve the hostname
                logger.debug(f"Resolving hostname: {hostname}")
                ip_str = socket.gethostbyname(hostname)
                logger.debug(f"Resolved {hostname} to {ip_str}")
                ip = ipaddress.ip_address(ip_str)
                
                # Block private IP ranges (RFC 1918)
                if ip.is_private:
                    msg = f"Cannot scan private IP address: {ip} (security restriction)"
                    logger.warning(msg)
                    return False, msg
                
                # Block loopback addresses
                if ip.is_loopback:
                    msg = f"Cannot scan loopback IP: {ip} (security restriction)"
                    logger.warning(msg)
                    return False, msg
                
                # Block link-local addresses
                if ip.is_link_local:
                    msg = f"Cannot scan link-local IP: {ip} (security restriction)"
                    logger.warning(msg)
                    return False, msg
                
                # Block multicast addresses
                if ip.is_multicast:
                    msg = f"Cannot scan multicast IP: {ip} (security restriction)"
                    logger.warning(msg)
                    return False, msg
                
                # Block reserved addresses
                if ip.is_reserved:
                    msg = f"Cannot scan reserved IP: {ip} (security restriction)"
                    logger.warning(msg)
                    return False, msg
                    
            except socket.gaierror as e:
                msg = f"Site not found: Could not resolve hostname '{hostname}' (DNS lookup failed)"
                logger.warning(msg)
                return False, msg
            except socket.timeout:
                msg = f"DNS lookup timeout for hostname: {hostname}"
                logger.warning(msg)
                return False, msg
            
            return True, "OK"
            
        except Exception as e:
            msg = f"Error validating URL: {e}"
            logger.error(msg)
            return False, msg
    
    def _check_robots_txt(self, url: str) -> bool:
        """Check if URL is allowed according to robots.txt"""
        if not self.check_robots:
            return True
        
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            # Check cache first
            if robots_url in self.robots_cache:
                rp = self.robots_cache[robots_url]
            else:
                # Create new parser
                rp = RobotFileParser()
                rp.set_url(robots_url)
                
                # Try to read robots.txt with timeout
                try:
                    rp.read()
                    self.robots_cache[robots_url] = rp
                except:
                    # If can't read robots.txt, assume allowed
                    return True
            
            # Check if our user agent is allowed
            user_agent = self.session.headers.get('User-Agent', '*')
            return rp.can_fetch(user_agent, url)
            
        except Exception as e:
            logger.debug(f"Error checking robots.txt: {e}")
            # If error, be conservative and allow
            return True
    
    def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        if self.rate_limit > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.rate_limit:
                sleep_time = self.rate_limit - time_since_last
                logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    def _safe_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a safe HTTP request with validation and rate limiting"""
        # Validate URL
        is_valid, error_msg = self._validate_url(url)
        if not is_valid:
            logger.warning(f"URL validation failed for {url}: {error_msg}")
            return None
        
        # Check robots.txt
        if not self._check_robots_txt(url):
            logger.warning(f"Robots.txt disallows scanning: {url}")
            return None
        
        # Apply rate limiting
        self._apply_rate_limit()
        
        # Set default timeout if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 10
        
        # Handle redirects securely
        if not self.allow_redirects:
            kwargs['allow_redirects'] = False
        else:
            # Use custom redirect handling
            kwargs['allow_redirects'] = False
            response = self.session.get(url, **kwargs)
            
            # Manually handle redirects with validation
            redirect_count = 0
            while response.is_redirect and redirect_count < 3:
                redirect_url = response.headers.get('Location')
                if not redirect_url:
                    break
                
                # Make redirect URL absolute
                redirect_url = urljoin(url, redirect_url)
                
                # Validate redirect destination
                is_valid, error_msg = self._validate_url(redirect_url)
                if not is_valid:
                    logger.warning(f"Blocking redirect to unsafe URL {redirect_url}: {error_msg}")
                    break
                
                # Check if redirect is to same domain
                original_domain = urlparse(url).netloc
                redirect_domain = urlparse(redirect_url).netloc
                
                if original_domain != redirect_domain:
                    logger.warning(f"Blocking cross-domain redirect from {original_domain} to {redirect_domain}")
                    break
                
                # Follow the redirect
                self._apply_rate_limit()
                response = self.session.get(redirect_url, **kwargs)
                redirect_count += 1
                url = redirect_url
            
            return response
        
        try:
            return self.session.get(url, **kwargs)
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
    
    def scan_url(self, url: str) -> Dict:
        """Scan a website URL for compromised packages"""
        results = {
            'url': url,
            'scan_time': datetime.utcnow().isoformat(),
            'vulnerable': False,
            'confidence': 'none',
            'findings': {
                'compromised_packages': [],
                'malware_signatures': [],
                'suspicious_cdns': [],
                'javascript_files': [],
                'package_json_found': False,
                'node_modules_exposed': False,
                'obfuscation': [],
                'known_malware': [],
                'sourcemap_references': []
            },
            'recommendations': []
        }
        
        # Check page limit
        if self.pages_scanned >= self.max_pages:
            logger.warning(f"Reached maximum page limit ({self.max_pages}). Skipping {url}")
            results['error'] = 'Page limit reached'
            return results
        
        self.pages_scanned += 1
        
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Validate URL before proceeding
            is_valid, error_msg = self._validate_url(url)
            if not is_valid:
                results['error'] = error_msg
                logger.warning(f"Skipping invalid URL {url}: {error_msg}")
                return results
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            logger.info(f"Scanning {url}...")
            
            # Phase 1: Check for exposed package.json
            package_json = self._check_package_json(base_url)
            if package_json:
                results['findings']['package_json_found'] = True
                self._analyze_package_json(package_json, results)
            
            # Phase 2: Check for exposed node_modules
            if self._check_node_modules(base_url):
                results['findings']['node_modules_exposed'] = True
                results['recommendations'].append(
                    "CRITICAL: node_modules directory is publicly accessible. Block access immediately!"
                )
            
            # Phase 3: Scan HTML and gather JavaScript files
            js_files = self._scan_html_for_js(url)
            results['findings']['javascript_files'] = js_files
            
            # Phase 4: Recursively scan for embedded resources
            additional_resources = self._scan_embedded_resources(url, js_files)
            js_files.extend(additional_resources)
            js_files = list(set(js_files))  # Remove duplicates
            results['findings']['javascript_files'] = js_files
            
            # Phase 5: Scan JavaScript files for signatures
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {
                    executor.submit(self._scan_js_file, js_url): js_url 
                    for js_url in js_files
                }
                
                for future in as_completed(future_to_url):
                    js_url = future_to_url[future]
                    try:
                        findings = future.result()
                        if findings:
                            self._process_js_findings(findings, results, js_url)
                    except Exception as e:
                        logger.error(f"Error scanning {js_url}: {e}")
            
            # Phase 6: Check CDN usage
            self._check_cdn_usage(js_files, results)
            
            # Phase 7: Advanced fingerprinting
            self._advanced_fingerprinting(url, results)
            
            # Calculate confidence level
            self._calculate_confidence(results)
            
            # Generate recommendations
            self._generate_recommendations(results)
            
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
            results['error'] = str(e)
        
        return results

    def _check_package_json(self, base_url: str) -> Optional[Dict]:
        """Check if package.json is exposed"""
        try:
            resp = self._safe_request(f"{base_url}/package.json", timeout=5)
            if resp and resp.status_code == 200:
                return resp.json()
        except:
            pass
        return None

    def _analyze_package_json(self, package_json: Dict, results: Dict):
        """Analyze package.json for compromised packages"""
        dependencies = {}
        dependencies.update(package_json.get('dependencies', {}))
        dependencies.update(package_json.get('devDependencies', {}))
        
        for pkg, version in dependencies.items():
            if pkg in self.compromised_packages:
                # Check if version matches compromised versions
                compromised_versions = self.compromised_packages[pkg]
                if '*' in compromised_versions or self._version_matches(version, compromised_versions):
                    results['findings']['compromised_packages'].append({
                        'package': pkg,
                        'version': version,
                        'source': 'package.json'
                    })
                    results['vulnerable'] = True

    def _version_matches(self, version_spec: str, compromised_versions: List[str]) -> bool:
        """Check if version specification matches compromised versions"""
        if '*' in compromised_versions:
            return True
            
        # Clean version spec
        version_spec = version_spec.strip()
        
        # Handle different version formats
        import re
        
        # Extract version number from various formats
        version_patterns = [
            r'^[~^]?([0-9]+\.[0-9]+\.[0-9]+)',  # ~1.2.3, ^1.2.3, 1.2.3
            r'^>=?\s*([0-9]+\.[0-9]+\.[0-9]+)',  # >=1.2.3, >1.2.3
            r'^<=?\s*([0-9]+\.[0-9]+\.[0-9]+)',  # <=1.2.3, <1.2.3
            r'^([0-9]+\.[0-9]+\.[0-9]+)',  # 1.2.3
            r'^([0-9]+\.[0-9]+)',  # 1.2
            r'^([0-9]+)',  # 1
        ]
        
        extracted_version = None
        for pattern in version_patterns:
            match = re.match(pattern, version_spec)
            if match:
                extracted_version = match.group(1)
                break
        
        if not extracted_version:
            # If we can't parse it, check for exact matches
            return version_spec in compromised_versions
        
        # Check against compromised versions
        for comp_ver in compromised_versions:
            if comp_ver == extracted_version:
                return True
            # Check if extracted version starts with compromised version
            if extracted_version.startswith(comp_ver + '.'):
                return True
            # Check if compromised version is a prefix
            if comp_ver.startswith(extracted_version + '.'):
                return True
                
        return False

    def _check_node_modules(self, base_url: str) -> bool:
        """Check if node_modules directory is exposed"""
        try:
            # Try common node_modules paths
            paths = [
                '/node_modules/',
                '/node_modules/chalk/package.json',
                '/node_modules/debug/package.json',
                '/static/node_modules/',
                '/public/node_modules/',
                '/assets/node_modules/'
            ]
            
            for path in paths:
                resp = self._safe_request(f"{base_url}{path}", timeout=3)
                if resp and resp.status_code == 200:
                    return True
        except:
            pass
        return False

    def _scan_html_for_js(self, url: str) -> List[str]:
        """Scan HTML page for JavaScript file references"""
        js_files = []
        try:
            resp = self._safe_request(url, timeout=10)
            if resp and resp.status_code == 200:
                # Find script tags
                script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
                scripts = re.findall(script_pattern, resp.text, re.IGNORECASE)
                
                for script in scripts:
                    if script.startswith('//'):
                        script = 'https:' + script
                    elif script.startswith('/'):
                        script = urljoin(url, script)
                    elif not script.startswith(('http://', 'https://')):
                        script = urljoin(url, script)
                    js_files.append(script)
                
                # Also check for inline scripts with CDN references
                inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL | re.IGNORECASE)
                for inline in inline_scripts:
                    # Check for dynamic script loading
                    dynamic_loads = re.findall(r'["\']([^"\']*(?:unpkg|jsdelivr|cdnjs)[^"\']*)["\']', inline)
                    js_files.extend(dynamic_loads)
                    
        except Exception as e:
            logger.error(f"Error scanning HTML: {e}")
        
        return list(set(js_files))  # Remove duplicates

    def _scan_js_file(self, js_url: str) -> Dict:
        """Scan a JavaScript file for malware signatures"""
        findings = {
            'signatures': [],
            'packages': [],
            'suspicious_patterns': [],
            'obfuscation': [],
            'hash': None
        }
        
        try:
            resp = self._safe_request(js_url, timeout=10)
            if resp and resp.status_code == 200:
                content = resp.text
                
                # Check for malware signatures
                for signature in self.malware_signatures:
                    if re.search(signature, content, re.IGNORECASE):
                        findings['signatures'].append({
                            'pattern': signature,
                            'context': self._extract_context(content, signature)
                        })
                
                # Check for package names in comments or strings
                for pkg in self.compromised_packages:
                    if pkg in content:
                        # Try to extract version
                        version_pattern = f'{pkg}@([0-9.]+)'
                        version_match = re.search(version_pattern, content)
                        version = version_match.group(1) if version_match else 'unknown'
                        findings['packages'].append({
                            'package': pkg,
                            'version': version
                        })
                
                # Check for suspicious patterns
                suspicious_patterns = [
                    (r'eval\s*\(', 'Eval usage detected'),
                    (r'Function\s*\(\s*["\']', 'Dynamic function creation'),
                    (r'document\.write', 'Document.write usage'),
                    (r'unescape\s*\(', 'Unescape usage'),
                    (r'String\.fromCharCode', 'Character code conversion'),
                    (r'window\[[\'"]location[\'"]\]', 'Window location access'),
                    (r'WebSocket\s*\(', 'WebSocket connection'),
                    (r'localStorage\.setItem', 'LocalStorage write'),
                    (r'sessionStorage\.setItem', 'SessionStorage write'),
                    (r'indexedDB\.open', 'IndexedDB access'),
                    (r'navigator\.sendBeacon', 'Beacon API usage'),
                    (r'fetch\s*\([^)]*method\s*:\s*["\']POST', 'POST request detected')
                ]
                
                for pattern, description in suspicious_patterns:
                    if re.search(pattern, content):
                        findings['suspicious_patterns'].append(description)
                
                # Check for obfuscation patterns
                for obf_pattern in self.obfuscation_patterns:
                    matches = re.findall(obf_pattern, content[:10000])  # Check first 10k chars
                    if len(matches) > 3:  # Multiple occurrences indicate obfuscation
                        findings['obfuscation'].append({
                            'pattern': obf_pattern,
                            'count': len(matches)
                        })
                
                # Calculate file hash for known malware detection
                import hashlib
                findings['hash'] = hashlib.sha256(content.encode()).hexdigest()
                
        except Exception as e:
            logger.error(f"Error scanning JS file {js_url}: {e}")
        
        return findings

    def _extract_context(self, content: str, pattern: str, context_size: int = 100) -> str:
        """Extract context around a pattern match"""
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - context_size)
            end = min(len(content), match.end() + context_size)
            return content[start:end]
        return ""

    def _process_js_findings(self, findings: Dict, results: Dict, js_url: str):
        """Process findings from JavaScript file scan"""
        if findings['signatures']:
            for sig in findings['signatures']:
                results['findings']['malware_signatures'].append({
                    'file': js_url,
                    'signature': sig['pattern'],
                    'context': sig['context'][:200]  # Limit context length
                })
                results['vulnerable'] = True
        
        if findings['packages']:
            for pkg in findings['packages']:
                if pkg['package'] in self.compromised_packages:
                    results['findings']['compromised_packages'].append({
                        'package': pkg['package'],
                        'version': pkg['version'],
                        'source': js_url
                    })
                    
        if findings['suspicious_patterns']:
            if 'suspicious_patterns' not in results['findings']:
                results['findings']['suspicious_patterns'] = []
            results['findings']['suspicious_patterns'].extend([
                {'file': js_url, 'pattern': p} for p in findings['suspicious_patterns']
            ])
        
        # Process obfuscation findings
        if findings.get('obfuscation'):
            if 'obfuscation' not in results['findings']:
                results['findings']['obfuscation'] = []
            for obf in findings['obfuscation']:
                results['findings']['obfuscation'].append({
                    'file': js_url,
                    'pattern': obf['pattern'],
                    'count': obf['count']
                })
                # High obfuscation indicates potential malware
                if obf['count'] > 10:
                    results['vulnerable'] = True
        
        # Check hash against known malicious files
        if findings.get('hash') and findings['hash'] in self.malicious_hashes:
            if 'known_malware' not in results['findings']:
                results['findings']['known_malware'] = []
            results['findings']['known_malware'].append({
                'file': js_url,
                'hash': findings['hash'],
                'identified_as': self.malicious_hashes[findings['hash']]
            })
            results['vulnerable'] = True

    def _check_cdn_usage(self, js_files: List[str], results: Dict):
        """Check for CDN usage of compromised packages"""
        for js_url in js_files:
            # Parse CDN URL to extract package info
            cdn_info = self._parse_cdn_url(js_url)
            
            if cdn_info:
                # Check if it's a compromised package
                if cdn_info['package'] in self.compromised_packages:
                    # Check version if available
                    is_vulnerable = False
                    if cdn_info.get('version'):
                        comp_versions = self.compromised_packages[cdn_info['package']]
                        if '*' in comp_versions or cdn_info['version'] in comp_versions:
                            is_vulnerable = True
                    else:
                        # No version specified, assume vulnerable
                        is_vulnerable = True
                    
                    if is_vulnerable:
                        results['findings']['suspicious_cdns'].append({
                            'url': js_url,
                            'package': cdn_info['package'],
                            'version': cdn_info.get('version', 'unknown'),
                            'cdn': cdn_info['cdn']
                        })
                        results['vulnerable'] = True
            
            # Also check for direct malicious CDN domains
            malicious_cdns = [
                'static-mw-host.b-cdn.net',
                'img-data-backup.b-cdn.net',
                'websocket-api2.publicvm.com'
            ]
            
            for mal_cdn in malicious_cdns:
                if mal_cdn in js_url:
                    results['findings']['suspicious_cdns'].append({
                        'url': js_url,
                        'package': 'MALICIOUS_CDN',
                        'version': 'N/A',
                        'cdn': mal_cdn
                    })
                    results['vulnerable'] = True
    
    def _parse_cdn_url(self, url: str) -> Optional[Dict]:
        """Parse CDN URL to extract package and version information"""
        cdn_patterns = {
            'unpkg': r'unpkg\.com/([^/@]+)(?:@([^/]+))?',
            'jsdelivr': r'cdn\.jsdelivr\.net/npm/([^/@]+)(?:@([^/]+))?',
            'cdnjs': r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)',
            'skypack': r'cdn\.skypack\.dev/([^/@]+)(?:@([^/]+))?',
            'esm.sh': r'esm\.sh/([^/@]+)(?:@([^/]+))?',
            'jspm': r'(?:ga|dev)?\.?jspm\.io/npm:([^/@]+)(?:@([^/]+))?'
        }
        
        for cdn_name, pattern in cdn_patterns.items():
            match = re.search(pattern, url)
            if match:
                return {
                    'cdn': cdn_name,
                    'package': match.group(1),
                    'version': match.group(2) if match.lastindex > 1 else None
                }
        
        return None

    def _advanced_fingerprinting(self, url: str, results: Dict):
        """Perform advanced fingerprinting techniques"""
        try:
            # Check for specific webpack chunks and common build outputs
            webpack_paths = [
                '/static/js/main.chunk.js',
                '/static/js/vendor.chunk.js',
                '/static/js/2.chunk.js',
                '/static/js/bundle.js',
                '/dist/bundle.js',
                '/build/bundle.js',
                '/assets/index.js',
                '/js/app.js',
                '/js/vendor.js',
                '/bundles/main.js',
                '/_next/static/chunks/main.js',
                '/_next/static/chunks/webpack.js'
            ]
            
            base_url = '/'.join(url.split('/')[:3])
            
            # Also check for sourcemap files which might reveal package info
            sourcemap_paths = [
                '/static/js/main.chunk.js.map',
                '/dist/bundle.js.map',
                '/build/bundle.js.map'
            ]
            
            all_paths = webpack_paths + sourcemap_paths
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_path = {
                    executor.submit(self._check_path, base_url, path): path 
                    for path in all_paths
                }
                
                for future in as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        content = future.result()
                        if content:
                            self._analyze_bundle_content(content, f"{base_url}{path}", results)
                    except:
                        continue
                    
        except Exception as e:
            logger.error(f"Error in advanced fingerprinting: {e}")
    
    def _check_path(self, base_url: str, path: str) -> Optional[str]:
        """Check if a path exists and return content"""
        try:
            full_url = f"{base_url}{path}"
            resp = self._safe_request(full_url, timeout=5)
            if resp and resp.status_code == 200:
                return resp.text[:100000]  # Limit to first 100k chars
        except:
            pass
        return None
    
    def _analyze_bundle_content(self, content: str, file_url: str, results: Dict):
        """Analyze bundle content for signatures"""
        # Quick scan for high-priority signatures
        priority_signatures = [
            r'checkethereumw',
            r'0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976',
            r'static-mw-host\.b-cdn\.net',
            r'websocket-api2\.publicvm\.com',
            r'_0x112fa8'
        ]
        
        for signature in priority_signatures:
            if re.search(signature, content, re.IGNORECASE):
                results['findings']['malware_signatures'].append({
                    'file': file_url,
                    'signature': signature,
                    'context': 'Bundle analysis'
                })
                results['vulnerable'] = True
                
        # Check for package references in sourcemaps
        if '.map' in file_url:
            for pkg in self.compromised_packages:
                if f'node_modules/{pkg}' in content:
                    if 'sourcemap_references' not in results['findings']:
                        results['findings']['sourcemap_references'] = []
                    results['findings']['sourcemap_references'].append({
                        'file': file_url,
                        'package': pkg
                    })

    def _calculate_confidence(self, results: Dict):
        """Calculate confidence level of detection"""
        score = 0
        
        # High confidence indicators
        if results['findings']['malware_signatures']:
            score += 50
        if results['findings']['compromised_packages']:
            score += 30
        
        # Medium confidence indicators
        if results['findings']['suspicious_cdns']:
            score += 20
        if results['findings'].get('suspicious_patterns'):
            score += 10
        
        # Determine confidence level
        if score >= 50:
            results['confidence'] = 'high'
        elif score >= 30:
            results['confidence'] = 'medium'
        elif score >= 10:
            results['confidence'] = 'low'
        else:
            results['confidence'] = 'none'

    def _generate_recommendations(self, results: Dict):
        """Generate security recommendations based on findings"""
        if results['vulnerable']:
            results['recommendations'].append(
                "URGENT: Potentially compromised npm packages detected. Take immediate action!"
            )
            
            if results['findings']['compromised_packages']:
                packages = set(p['package'] for p in results['findings']['compromised_packages'])
                results['recommendations'].append(
                    f"Update or remove these packages immediately: {', '.join(packages)}"
                )
            
            if results['findings']['malware_signatures']:
                results['recommendations'].append(
                    "Malicious code signatures detected. Rebuild application from clean sources."
                )
            
            results['recommendations'].extend([
                "1. Clear all npm/yarn caches",
                "2. Delete node_modules and package-lock.json",
                "3. Update all dependencies to latest secure versions",
                "4. Run 'npm audit fix --force'",
                "5. Rebuild and redeploy application",
                "6. Monitor for suspicious cryptocurrency transactions",
                "7. Rotate all API keys and credentials"
            ])
        
        if results['findings']['node_modules_exposed']:
            results['recommendations'].insert(0, 
                "CRITICAL SECURITY ISSUE: Block public access to node_modules immediately!"
            )

    def generate_report(self, results: Dict) -> str:
        """Generate a detailed report from scan results"""
        report = []
        report.append("=" * 70)
        report.append("NPM SUPPLY CHAIN ATTACK DETECTION REPORT")
        report.append("September 8th, 2025 Vulnerability Scanner")
        report.append("=" * 70)
        report.append(f"URL: {results['url']}")
        report.append(f"Scan Time: {results['scan_time']}")
        report.append(f"Vulnerable: {'YES' if results['vulnerable'] else 'NO'}")
        report.append(f"Confidence: {results['confidence'].upper()}")
        report.append("")
        
        if results['vulnerable']:
            report.append("⚠️  WARNING: POTENTIAL COMPROMISE DETECTED ⚠️")
            report.append("")
        
        # Summary Statistics
        report.append("SUMMARY:")
        report.append("-" * 40)
        report.append(f"JavaScript Files Scanned: {len(results['findings']['javascript_files'])}")
        report.append(f"Compromised Packages Found: {len(results['findings']['compromised_packages'])}")
        report.append(f"Malware Signatures Detected: {len(results['findings']['malware_signatures'])}")
        report.append(f"Suspicious CDN Resources: {len(results['findings']['suspicious_cdns'])}")
        
        # Critical Findings
        if results['findings'].get('known_malware'):
            report.append("\n🔴 CRITICAL: KNOWN MALWARE DETECTED:")
            for malware in results['findings']['known_malware']:
                report.append(f"  - File: {malware['file']}")
                report.append(f"    Hash: {malware['hash'][:16]}...")
                report.append(f"    Identified as: {malware['identified_as']}")
        
        # Detailed Findings
        report.append("\nDETAILED FINDINGS:")
        report.append("-" * 40)
        
        if results['findings']['compromised_packages']:
            report.append("\n📦 Compromised Packages Detected:")
            # Group by package name
            packages = {}
            for pkg in results['findings']['compromised_packages']:
                if pkg['package'] not in packages:
                    packages[pkg['package']] = []
                packages[pkg['package']].append(pkg)
            
            for pkg_name, instances in packages.items():
                report.append(f"  • {pkg_name}:")
                for inst in instances:
                    report.append(f"    - Version: {inst['version']} (found in: {inst['source'][:50]}...)")
        
        if results['findings']['malware_signatures']:
            report.append("\n🚨 Malware Signatures Found:")
            # Group by signature type
            sig_groups = {
                'wallet': [],
                'obfuscation': [],
                'network': [],
                'other': []
            }
            
            for sig in results['findings']['malware_signatures']:
                if 'ethereum' in sig['signature'].lower() or 'wallet' in sig['signature'].lower():
                    sig_groups['wallet'].append(sig)
                elif '_0x' in sig['signature']:
                    sig_groups['obfuscation'].append(sig)
                elif 'websocket' in sig['signature'].lower() or 'publicvm' in sig['signature'].lower():
                    sig_groups['network'].append(sig)
                else:
                    sig_groups['other'].append(sig)
            
            for group_name, sigs in sig_groups.items():
                if sigs:
                    report.append(f"  [{group_name.upper()}]:")
                    for sig in sigs[:3]:  # Limit to 3 per group
                        report.append(f"    - {sig['signature'][:50]}...")
                        report.append(f"      in {sig['file'][:50]}...")
        
        if results['findings']['suspicious_cdns']:
            report.append("\n🌐 Suspicious CDN Usage:")
            for cdn in results['findings']['suspicious_cdns'][:5]:  # Limit to 5
                if cdn['package'] == 'MALICIOUS_CDN':
                    report.append(f"  ⚠️  MALICIOUS CDN DETECTED: {cdn['cdn']}")
                else:
                    report.append(f"  - {cdn['package']}@{cdn.get('version', 'unknown')} from {cdn['cdn']}")
                report.append(f"    URL: {cdn['url'][:60]}...")
        
        if results['findings'].get('obfuscation'):
            report.append("\n🔒 Obfuscation Detected:")
            total_obf = sum(o['count'] for o in results['findings']['obfuscation'])
            report.append(f"  Total obfuscated patterns: {total_obf}")
            for obf in results['findings']['obfuscation'][:3]:
                report.append(f"  - {obf['count']} instances in {obf['file'][:50]}...")
        
        if results['findings'].get('suspicious_patterns'):
            report.append("\n⚡ Suspicious Code Patterns:")
            patterns = {}
            for p in results['findings']['suspicious_patterns']:
                if p['pattern'] not in patterns:
                    patterns[p['pattern']] = 0
                patterns[p['pattern']] += 1
            
            for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:5]:
                report.append(f"  - {pattern} ({count} occurrences)")
        
        # Security Status
        if results['findings']['node_modules_exposed']:
            report.append("\n🔓 SECURITY ISSUES:")
            report.append("  ⚠️  node_modules directory is publicly accessible!")
        
        if results['findings']['package_json_found']:
            report.append("  ⚠️  package.json is publicly exposed")
        
        # Recommendations
        if results['recommendations']:
            report.append("\n" + "=" * 40)
            report.append("RECOMMENDATIONS:")
            report.append("-" * 40)
            
            # Prioritize critical recommendations
            critical_recs = [r for r in results['recommendations'] if r.startswith(('URGENT:', 'CRITICAL:'))]
            normal_recs = [r for r in results['recommendations'] if not r.startswith(('URGENT:', 'CRITICAL:'))]
            
            for rec in critical_recs:
                report.append(f"\n⚠️  {rec}")
            
            if normal_recs:
                report.append("\nAction Items:")
                for i, rec in enumerate(normal_recs, 1):
                    report.append(f"{i}. {rec}")
        
        # Additional Context
        report.append("\n" + "=" * 40)
        report.append("SCAN CONTEXT:")
        report.append("-" * 40)
        report.append(f"Attack Window: {self.attack_window['start']} - {self.attack_window['end']} UTC")
        report.append(f"Total Packages Monitored: {len(self.compromised_packages)}")
        report.append(f"Malware Signatures in Database: {len(self.malware_signatures)}")
        
        report.append("\n" + "=" * 70)
        return "\n".join(report)


    def _extract_page_links(self, url: str, max_links: int = 50) -> List[str]:
        """Extract all links from a page that belong to the same domain"""
        links = set()
        
        try:
            resp = self._safe_request(url, timeout=10)
            if not resp or resp.status_code != 200:
                return []
            
            # Parse base URL for domain comparison
            parsed_base = urlparse(url)
            base_domain = parsed_base.netloc
            base_scheme = parsed_base.scheme
            
            # Extract all href links
            href_pattern = r'<a[^>]*href=["\']([^"\']+)["\']'
            found_links = re.findall(href_pattern, resp.text, re.IGNORECASE)
            
            for link in found_links:
                # Skip anchors, javascript, mailto, tel, etc
                if link.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                    continue
                
                # Normalize the link
                if link.startswith('//'):
                    normalized = f"{base_scheme}:{link}"
                elif link.startswith('/'):
                    normalized = f"{base_scheme}://{base_domain}{link}"
                elif link.startswith('http'):
                    normalized = link
                else:
                    # Relative link
                    normalized = urljoin(url, link)
                
                # Only include links from the same domain
                parsed_link = urlparse(normalized)
                if parsed_link.netloc == base_domain:
                    # Remove fragment and query params for cleaner URLs
                    clean_url = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                    links.add(clean_url)
                
                if len(links) >= max_links:
                    break
                    
        except Exception as e:
            logger.debug(f"Error extracting links from {url}: {e}")
        
        return list(links)
    
    def scan_url_with_links(self, url: str, follow_links: bool = True) -> Dict:
        """Scan a website and optionally its first-layer links"""
        # Main result structure
        aggregated_results = {
            'main_url': url,
            'scan_time': datetime.utcnow().isoformat(),
            'pages_scanned': [],
            'total_vulnerable': 0,
            'overall_confidence': 'none',
            'aggregated_findings': {
                'compromised_packages': [],
                'malware_signatures': [],
                'suspicious_cdns': [],
                'javascript_files': [],
                'obfuscation': [],
                'known_malware': [],
                'pages_with_issues': []
            },
            'recommendations': set()
        }
        
        # Scan the main URL
        logger.info(f"Scanning main page: {url}")
        main_results = self.scan_url(url)
        aggregated_results['pages_scanned'].append(main_results)
        
        # Extract links if requested
        links_to_scan = []
        if follow_links:
            logger.info("Extracting first-layer links...")
            links_to_scan = self._extract_page_links(url)
            logger.info(f"Found {len(links_to_scan)} same-domain links to scan")
        
        # Scan each link (respecting max_pages limit)
        max_links = min(self.max_pages - 1, 20)  # -1 because main page counts
        for idx, link in enumerate(links_to_scan[:max_links], 1):
            if self.pages_scanned >= self.max_pages:
                logger.info(f"Reached maximum page limit ({self.max_pages})")
                break
            logger.info(f"Scanning linked page {idx}/{min(len(links_to_scan), max_links)}: {link}")
            try:
                link_results = self.scan_url(link)
                aggregated_results['pages_scanned'].append(link_results)
            except Exception as e:
                logger.error(f"Error scanning {link}: {e}")
        
        # Aggregate all findings
        self._aggregate_findings(aggregated_results)
        
        return aggregated_results
    
    def _aggregate_findings(self, aggregated_results: Dict):
        """Aggregate findings from all scanned pages"""
        max_confidence_score = 0
        
        for page_result in aggregated_results['pages_scanned']:
            # Count vulnerable pages
            if page_result.get('vulnerable'):
                aggregated_results['total_vulnerable'] += 1
                aggregated_results['aggregated_findings']['pages_with_issues'].append(page_result['url'])
            
            # Aggregate compromised packages
            for pkg in page_result['findings'].get('compromised_packages', []):
                pkg['found_on_page'] = page_result['url']
                aggregated_results['aggregated_findings']['compromised_packages'].append(pkg)
            
            # Aggregate malware signatures
            for sig in page_result['findings'].get('malware_signatures', []):
                sig['found_on_page'] = page_result['url']
                aggregated_results['aggregated_findings']['malware_signatures'].append(sig)
            
            # Aggregate suspicious CDNs
            for cdn in page_result['findings'].get('suspicious_cdns', []):
                cdn['found_on_page'] = page_result['url']
                aggregated_results['aggregated_findings']['suspicious_cdns'].append(cdn)
            
            # Aggregate obfuscation
            for obf in page_result['findings'].get('obfuscation', []):
                obf['found_on_page'] = page_result['url']
                aggregated_results['aggregated_findings']['obfuscation'].append(obf)
            
            # Aggregate known malware
            for malware in page_result['findings'].get('known_malware', []):
                malware['found_on_page'] = page_result['url']
                aggregated_results['aggregated_findings']['known_malware'].append(malware)
            
            # Track JavaScript files
            aggregated_results['aggregated_findings']['javascript_files'].extend(
                page_result['findings'].get('javascript_files', [])
            )
            
            # Aggregate recommendations
            aggregated_results['recommendations'].update(page_result.get('recommendations', []))
            
            # Track highest confidence
            confidence_scores = {'none': 0, 'low': 1, 'medium': 2, 'high': 3}
            score = confidence_scores.get(page_result.get('confidence', 'none'), 0)
            max_confidence_score = max(max_confidence_score, score)
        
        # Set overall confidence
        confidence_levels = ['none', 'low', 'medium', 'high']
        aggregated_results['overall_confidence'] = confidence_levels[max_confidence_score]
        
        # Remove duplicates from JavaScript files
        aggregated_results['aggregated_findings']['javascript_files'] = list(
            set(aggregated_results['aggregated_findings']['javascript_files'])
        )
        
        # Convert recommendations back to list
        aggregated_results['recommendations'] = list(aggregated_results['recommendations'])
    
    def generate_aggregated_report(self, results: Dict) -> str:
        """Generate a report for aggregated scan results"""
        report = []
        report.append("=" * 70)
        report.append("NPM SUPPLY CHAIN ATTACK DETECTION REPORT")
        report.append("Multi-Page Scan Results")
        report.append("=" * 70)
        report.append(f"Main URL: {results['main_url']}")
        report.append(f"Pages Scanned: {len(results['pages_scanned'])}")
        report.append(f"Scan Time: {results['scan_time']}")
        report.append(f"Vulnerable Pages: {results['total_vulnerable']} / {len(results['pages_scanned'])}")
        report.append(f"Overall Confidence: {results['overall_confidence'].upper()}")
        report.append("")
        
        if results['total_vulnerable'] > 0:
            report.append("⚠️  WARNING: POTENTIAL COMPROMISE DETECTED ⚠️")
            report.append("")
        
        # Summary Statistics
        report.append("AGGREGATED SUMMARY:")
        report.append("-" * 40)
        report.append(f"Total JavaScript Files Scanned: {len(results['aggregated_findings']['javascript_files'])}")
        report.append(f"Total Compromised Packages Found: {len(results['aggregated_findings']['compromised_packages'])}")
        report.append(f"Total Malware Signatures Detected: {len(results['aggregated_findings']['malware_signatures'])}")
        report.append(f"Total Suspicious CDN Resources: {len(results['aggregated_findings']['suspicious_cdns'])}")
        
        # Pages with issues
        if results['aggregated_findings']['pages_with_issues']:
            report.append("\n🔴 PAGES WITH VULNERABILITIES:")
            for page in results['aggregated_findings']['pages_with_issues'][:10]:
                report.append(f"  • {page}")
        
        # Critical Findings
        if results['aggregated_findings']['known_malware']:
            report.append("\n🔴 CRITICAL: KNOWN MALWARE DETECTED:")
            for malware in results['aggregated_findings']['known_malware'][:5]:
                report.append(f"  - Page: {malware['found_on_page']}")
                report.append(f"    File: {malware['file']}")
                report.append(f"    Identified as: {malware['identified_as']}")
        
        # Compromised Packages
        if results['aggregated_findings']['compromised_packages']:
            report.append("\n📦 Compromised Packages Detected:")
            # Group by package name
            packages = {}
            for pkg in results['aggregated_findings']['compromised_packages']:
                if pkg['package'] not in packages:
                    packages[pkg['package']] = []
                packages[pkg['package']].append(pkg)
            
            for pkg_name, instances in list(packages.items())[:10]:
                report.append(f"  • {pkg_name}:")
                pages = set(inst['found_on_page'] for inst in instances)
                for page in list(pages)[:3]:
                    report.append(f"    - Found on: {page}")
        
        # Malware Signatures
        if results['aggregated_findings']['malware_signatures']:
            report.append("\n🚨 Malware Signatures Found:")
            # Group by signature
            signatures = {}
            for sig in results['aggregated_findings']['malware_signatures']:
                sig_key = sig['signature'][:50]
                if sig_key not in signatures:
                    signatures[sig_key] = []
                signatures[sig_key].append(sig['found_on_page'])
            
            for sig, pages in list(signatures.items())[:5]:
                report.append(f"  • {sig}...")
                report.append(f"    Found on {len(set(pages))} page(s)")
        
        # Suspicious CDNs
        if results['aggregated_findings']['suspicious_cdns']:
            report.append("\n🌐 Suspicious CDN Usage:")
            cdns = {}
            for cdn in results['aggregated_findings']['suspicious_cdns']:
                cdn_key = f"{cdn['package']}@{cdn.get('version', 'unknown')}"
                if cdn_key not in cdns:
                    cdns[cdn_key] = []
                cdns[cdn_key].append(cdn['found_on_page'])
            
            for cdn_info, pages in list(cdns.items())[:5]:
                report.append(f"  • {cdn_info}")
                report.append(f"    Found on {len(set(pages))} page(s)")
        
        # Recommendations
        if results['recommendations']:
            report.append("\n" + "=" * 40)
            report.append("RECOMMENDATIONS:")
            report.append("-" * 40)
            
            critical_recs = [r for r in results['recommendations'] if r.startswith(('URGENT:', 'CRITICAL:'))]
            normal_recs = [r for r in results['recommendations'] if not r.startswith(('URGENT:', 'CRITICAL:'))]
            
            for rec in critical_recs:
                report.append(f"\n⚠️  {rec}")
            
            if normal_recs:
                report.append("\nAction Items:")
                for rec in normal_recs[:10]:
                    report.append(f"• {rec}")
        
        report.append("\n" + "=" * 70)
        return "\n".join(report)

    def _scan_embedded_resources(self, base_url: str, initial_js_files: List[str]) -> List[str]:
        """Recursively scan for embedded JavaScript resources"""
        additional_resources = []
        
        try:
            # Check common API endpoints that might serve JS
            api_patterns = [
                '/api/config.js',
                '/api/settings.js',
                '/config.js',
                '/env.js',
                '/runtime.js'
            ]
            
            parsed = urlparse(base_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            
            for pattern in api_patterns:
                try:
                    url = f"{base}{pattern}"
                    resp = self._safe_request(url, timeout=3)
                    if resp and resp.status_code == 200:
                        content_type = resp.headers.get('content-type', '')
                        if 'javascript' in content_type or 'json' in content_type:
                            additional_resources.append(url)
                except:
                    continue
            
            # Check for dynamically loaded scripts in initial JS files
            for js_file in initial_js_files[:5]:  # Check first 5 files
                try:
                    resp = self._safe_request(js_file, timeout=5)
                    if resp and resp.status_code == 200:
                        # Look for dynamic imports and script loading
                        dynamic_patterns = [
                            r'import\s*\(["\']([^"\']*)["\'\)]',  # Dynamic imports
                            r'require\s*\(["\']([^"\']*)["\'\)]',  # CommonJS requires
                            r'loadScript\s*\(["\']([^"\']*)["\'\)]',  # Custom loaders
                            r'src\s*=\s*["\']([^"\']*.js)["\']'  # Dynamic src assignments
                        ]
                        
                        for pattern in dynamic_patterns:
                            matches = re.findall(pattern, resp.text[:50000])  # Check first 50k chars
                            for match in matches:
                                if match.startswith('http'):
                                    additional_resources.append(match)
                                elif match.startswith('/'):
                                    additional_resources.append(f"{base}{match}")
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Error scanning embedded resources: {e}")
        
        return list(set(additional_resources))  # Remove duplicates


def main():
    parser = argparse.ArgumentParser(
        description='Detect npm supply chain attack (September 2025) in web applications\n' +
        'IMPORTANT: Only scan websites you have permission to test.\n' +
        'This tool is for defensive security purposes only.',
        epilog='Example: python supply.py https://example.com --max-pages 10 --rate-limit 1.0'
    )
    parser.add_argument('url', help='URL to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    parser.add_argument('--batch', help='File containing URLs to scan (one per line)')
    parser.add_argument('--deep', action='store_true', help='Perform deep recursive scanning')
    parser.add_argument('--no-follow', action='store_true', help='Do not follow first-layer links')
    parser.add_argument('--max-pages', type=int, default=20, help='Maximum number of pages to scan (default: 20)')
    parser.add_argument('--rate-limit', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt (not recommended)')
    parser.add_argument('--no-redirects', action='store_true', help='Do not follow HTTP redirects')
    parser.add_argument('--safe-mode', action='store_true', help='Enable all safety features with conservative settings')
    
    args = parser.parse_args()
    
    # Apply safe mode if requested
    if args.safe_mode:
        args.rate_limit = max(args.rate_limit, 1.0)  # At least 1 second between requests
        args.max_pages = min(args.max_pages, 10)  # Max 10 pages
        args.no_robots = False  # Always check robots.txt
        logger.info("Safe mode enabled: rate_limit=1.0s, max_pages=10, robots.txt=enabled")
    
    # Show disclaimer
    print("="*70)
    print("NPM Supply Chain Attack Detector - Security Notice")
    print("="*70)
    print("This tool is for authorized security testing only.")
    print("Only scan websites you have permission to test.")
    print(f"Rate limit: {args.rate_limit}s | Max pages: {args.max_pages}")
    print(f"Robots.txt: {'disabled' if args.no_robots else 'enabled'} | Redirects: {'disabled' if args.no_redirects else 'enabled'}")
    print("="*70)
    print()
    
    detector = NPMAttackDetector(
        verbose=args.verbose,
        rate_limit=args.rate_limit,
        max_pages=args.max_pages,
        check_robots=not args.no_robots,
        allow_redirects=not args.no_redirects
    )
    
    urls_to_scan = []
    if args.batch:
        try:
            with open(args.batch, 'r') as f:
                urls_to_scan = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading batch file: {e}")
            sys.exit(1)
    else:
        urls_to_scan = [args.url]
    
    all_results = []
    
    for url in urls_to_scan:
        # Perform initial DNS check
        logger.info(f"Checking DNS for {url}...")
        if not url.startswith(('http://', 'https://')):
            test_url = 'https://' + url
        else:
            test_url = url
        
        is_valid, error_msg = detector._validate_url(test_url)
        if not is_valid:
            print(f"\n⚠️  ERROR: {error_msg}")
            print(f"Skipping {url}\n")
            
            # Log to appropriate file
            with open('error_sites.txt', 'a') as f:
                f.write(f"{url}\n")
                f.write(f"  Error: {error_msg}\n")
                f.write(f"  Time: {datetime.utcnow().isoformat()}\n\n")
            continue
        
        # Use the new aggregated scanning method
        results = detector.scan_url_with_links(url, follow_links=not args.no_follow)
        all_results.append(results)
        
        # Print aggregated report
        report = detector.generate_aggregated_report(results)
        print(report)
        
        # Write to appropriate file based on overall vulnerability status
        if results['total_vulnerable'] > 0:
            logger.warning(f"⚠️  {url} (and/or its linked pages) appears to be VULNERABLE!")
            # Append to sus.txt
            with open('sus.txt', 'a') as f:
                f.write(f"{url}\n")
                f.write(f"  Overall Confidence: {results['overall_confidence']}\n")
                f.write(f"  Vulnerable Pages: {results['total_vulnerable']} / {len(results['pages_scanned'])}\n")
                f.write(f"  Scan Time: {results['scan_time']}\n")
                
                # List vulnerable pages
                if results['aggregated_findings']['pages_with_issues']:
                    f.write(f"  Vulnerable URLs:\n")
                    for page in results['aggregated_findings']['pages_with_issues'][:5]:
                        f.write(f"    - {page}\n")
                
                # List compromised packages
                if results['aggregated_findings']['compromised_packages']:
                    packages = set(p['package'] for p in results['aggregated_findings']['compromised_packages'])
                    f.write(f"  Compromised Packages: {', '.join(list(packages)[:10])}\n")
                
                # Count malware signatures
                if results['aggregated_findings']['malware_signatures']:
                    f.write(f"  Malware Signatures Found: {len(results['aggregated_findings']['malware_signatures'])}\n")
                f.write("\n")
        else:
            logger.info(f"✅ {url} and all linked pages appear to be SAFE")
            # Append to safe.txt
            with open('safe.txt', 'a') as f:
                f.write(f"{url}\n")
                f.write(f"  Pages Scanned: {len(results['pages_scanned'])}\n")
                f.write(f"  Scan Time: {results.get('scan_time', datetime.utcnow().isoformat())}\n")
                f.write("\n")
        
        print("\n")
    
    # Save results if output file specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2)
            logger.info(f"Results saved to {args.output}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")


if __name__ == "__main__":
    main()
