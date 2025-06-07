#!/usr/bin/env python3
"""
HTTP/HTTPS Checker Module
Checks if subdomains are live and responding to HTTP/HTTPS requests
"""

import requests
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import socket
from threading import Lock
import time

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class HTTPChecker:
    def __init__(self, timeout=10, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.lock = Lock()
        self.results = {}
        
        # Setup session with retry strategy
        self.session = self.create_session()
    
    def create_session(self):
        """Create a requests session with optimal settings"""
        session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def check_http_status(self, subdomain):
        """Check HTTP and HTTPS status for a subdomain with detailed analysis"""
        protocols = ['https', 'http']
        results = {}
        
        for protocol in protocols:
            url = f"{protocol}://{subdomain}"
            
            try:
                # Use HEAD request first (faster)
                response = self.session.head(
                    url, 
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                results[protocol] = {
                    'status': True,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'url': response.url,
                    'redirect': response.url != url
                }
                
                # Get additional info for successful responses
                if response.status_code == 200:
                    try:
                        # Get content for comprehensive analysis
                        get_response = self.session.get(
                            url, 
                            timeout=10,
                            verify=False,
                            allow_redirects=True,
                            headers={
                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                                'Accept-Language': 'en-US,en;q=0.5'
                            }
                        )
                        
                        # Get proper encoding
                        content_type = get_response.headers.get('content-type', '')
                        if 'charset=' in content_type:
                            encoding = content_type.split('charset=')[1].split(';')[0].strip()
                        else:
                            encoding = get_response.apparent_encoding or 'utf-8'
                        
                        # Decode content properly
                        try:
                            html_content = get_response.content.decode(encoding, errors='ignore')
                        except:
                            html_content = get_response.content.decode('utf-8', errors='ignore')
                        
                        # Extract comprehensive information using enhanced methods
                        title = self.extract_title(html_content)
                        technologies = self.extract_technologies(html_content, response.headers)
                        cms_info = self.detect_cms_advanced(html_content, response.headers, response.url)
                        security_info = self.extract_security_info(response.headers)
                        
                        # Add to results
                        results[protocol].update({
                            'title': title,
                            'technologies': technologies,
                            'cms_info': cms_info,
                            'security_info': security_info,
                            'content_length': get_response.headers.get('content-length', 'Unknown'),
                            'content_type': get_response.headers.get('content-type', 'Unknown'),
                            'response_size': len(html_content),
                            'encoding': encoding
                        })
                        
                        get_response.close()
                        
                    except Exception as e:
                        # If detailed GET fails, try title-only extraction
                        try:
                            title = self.get_title_with_fallback(url)
                            results[protocol].update({
                                'title': title,
                                'technologies': self.extract_technologies('', response.headers),
                                'cms_info': {},
                                'security_info': self.extract_security_info(response.headers)
                            })
                        except:
                            results[protocol].update({
                                'title': 'Unable to fetch title',
                                'technologies': [],
                                'cms_info': {},
                                'security_info': self.extract_security_info(response.headers)
                            })
                
                # For non-200 responses, still try to get basic info
                else:
                    # Try to get title even for non-200 responses
                    title = f"HTTP {response.status_code}"
                    if response.status_code in [301, 302, 303, 307, 308]:
                        title = f"Redirect ({response.status_code})"
                        location = response.headers.get('location', '')
                        if location:
                            title += f" → {location[:50]}"
                    
                    results[protocol].update({
                        'title': title,
                        'technologies': self.extract_technologies('', response.headers),
                        'cms_info': {},
                        'security_info': self.extract_security_info(response.headers)
                    })
                
            except requests.exceptions.SSLError:
                results[protocol] = {
                    'status': False,
                    'error': 'SSL Error',
                    'details': 'SSL certificate issue or protocol mismatch'
                }
            except requests.exceptions.ConnectionError:
                results[protocol] = {
                    'status': False,
                    'error': 'Connection Error',
                    'details': 'Unable to establish connection'
                }
            except requests.exceptions.Timeout:
                results[protocol] = {
                    'status': False,
                    'error': 'Timeout',
                    'details': f'Request timed out after {self.timeout} seconds'
                }
            except Exception as e:
                results[protocol] = {
                    'status': False,
                    'error': 'Unknown Error',
                    'details': str(e)[:100]
                }
        
        return results
    
    def extract_title(self, html_content):
        """Extract title from HTML content using advanced methods like httpx"""
        if not html_content:
            return "No Title"
        
        try:
            import re
            
            # Method 1: Standard title tag (case-insensitive)
            title_patterns = [
                r'<title[^>]*>([^<]+)</title>',
                r'<title[^>]*>\s*([^<\n\r]+)\s*</title>',
                r'<title[^>]*>([^<]*?)</title>',
            ]
            
            for pattern in title_patterns:
                title_match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()
                    if title:
                        # Clean up title
                        title = self._clean_title(title)
                        if title and title.lower() not in ['', 'untitled', 'no title']:
                            return title
            
            # Method 2: Open Graph title
            og_title_match = re.search(r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
            if og_title_match:
                title = og_title_match.group(1).strip()
                if title:
                    return self._clean_title(title)
            
            # Method 3: Twitter title
            twitter_title_match = re.search(r'<meta[^>]*name=["\']twitter:title["\'][^>]*content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
            if twitter_title_match:
                title = twitter_title_match.group(1).strip()
                if title:
                    return self._clean_title(title)
            
            # Method 4: JSON-LD structured data
            jsonld_match = re.search(r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>([^<]+)</script>', html_content, re.IGNORECASE | re.DOTALL)
            if jsonld_match:
                try:
                    import json
                    jsonld_data = json.loads(jsonld_match.group(1))
                    if isinstance(jsonld_data, dict) and 'name' in jsonld_data:
                        return self._clean_title(jsonld_data['name'])
                    elif isinstance(jsonld_data, list) and len(jsonld_data) > 0 and 'name' in jsonld_data[0]:
                        return self._clean_title(jsonld_data[0]['name'])
                except:
                    pass
            
            # Method 5: H1 tag as fallback
            h1_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html_content, re.IGNORECASE)
            if h1_match:
                title = h1_match.group(1).strip()
                if title:
                    cleaned = self._clean_title(title)
                    if len(cleaned) <= 100:  # Only use H1 if reasonable length
                        return cleaned
            
            # Method 6: Check for specific CMS patterns
            cms_title = self._extract_cms_title(html_content)
            if cms_title:
                return cms_title
            
            # Method 7: Extract from first significant text content
            content_title = self._extract_content_title(html_content)
            if content_title:
                return content_title
            
        except Exception as e:
            # If all methods fail, return generic message
            pass
        
        return "No Title"
    
    def _clean_title(self, title):
        """Clean and normalize title text like httpx does"""
        if not title:
            return "No Title"
        
        import re
        
        # Decode HTML entities
        html_entities = {
            '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', 
            '&#39;': "'", '&apos;': "'", '&nbsp;': ' ', '&ndash;': '–',
            '&mdash;': '—', '&hellip;': '…', '&copy;': '©', '&reg;': '®',
            '&trade;': '™', '&times;': '×', '&divide;': '÷'
        }
        
        for entity, char in html_entities.items():
            title = title.replace(entity, char)
        
        # Decode numeric HTML entities
        title = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), title)
        title = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), title)
        
        # Remove extra whitespace
        title = re.sub(r'\s+', ' ', title).strip()
        
        # Remove common unwanted characters
        title = re.sub(r'[\r\n\t]', ' ', title)
        
        # Remove leading/trailing special characters
        title = re.sub(r'^[^\w\s]+|[^\w\s]+$', '', title)
    
    def extract_technologies(self, html_content, headers):
        """Extract technologies and frameworks from content and headers"""
        technologies = set()
        
        # Server detection from headers
        server = headers.get('Server', '').lower()
        if server:
            if 'nginx' in server:
                technologies.add(f"Nginx {self._extract_version(server, 'nginx')}")
            elif 'apache' in server:
                technologies.add(f"Apache {self._extract_version(server, 'apache')}")
            elif 'microsoft-iis' in server:
                technologies.add(f"IIS {self._extract_version(server, 'microsoft-iis')}")
            elif 'cloudflare' in server:
                technologies.add("Cloudflare")
            elif 'openresty' in server:
                technologies.add("OpenResty")
            elif 'litespeed' in server:
                technologies.add("LiteSpeed")
        
        # Framework detection from headers
        powered_by = headers.get('X-Powered-By', '').lower()
        if powered_by:
            if 'php' in powered_by:
                technologies.add(f"PHP {self._extract_version(powered_by, 'php')}")
            elif 'asp.net' in powered_by:
                technologies.add(f"ASP.NET {self._extract_version(powered_by, 'asp.net')}")
            elif 'express' in powered_by:
                technologies.add("Express.js")
            elif 'django' in powered_by:
                technologies.add("Django")
        
        # CDN detection
        if headers.get('CF-Ray') or headers.get('cf-ray'):
            technologies.add("Cloudflare CDN")
        if headers.get('X-Served-By'):
            technologies.add("Fastly CDN")
        if headers.get('X-Cache') and 'varnish' in headers.get('X-Cache', '').lower():
            technologies.add("Varnish Cache")
        if headers.get('X-Drupal-Cache'):
            technologies.add("Drupal")
        
        # CMS/Framework detection from HTML content
        if html_content:
            html_lower = html_content.lower()
            
            # WordPress detection
            if any(x in html_lower for x in ['wp-content', 'wordpress', 'wp-includes']):
                technologies.add("WordPress")
            
            # Joomla detection
            if any(x in html_lower for x in ['/joomla/', 'joomla!', 'com_content']):
                technologies.add("Joomla")
            
            # Drupal detection
            if any(x in html_lower for x in ['drupal', 'sites/default/files']):
                technologies.add("Drupal")
            
            # React detection
            if any(x in html_lower for x in ['react', '__react', 'reactjs']):
                technologies.add("React")
            
            # Vue.js detection
            if any(x in html_lower for x in ['vue.js', 'vuejs', '__vue__']):
                technologies.add("Vue.js")
            
            # Angular detection
            if any(x in html_lower for x in ['angular', 'ng-app', 'angularjs']):
                technologies.add("Angular")
            
            # jQuery detection
            if any(x in html_lower for x in ['jquery', 'jquery.min.js']):
                technologies.add("jQuery")
            
            # Bootstrap detection
            if any(x in html_lower for x in ['bootstrap', 'bootstrap.min.css']):
                technologies.add("Bootstrap")
            
            # Laravel detection
            if any(x in html_lower for x in ['laravel_session', 'laravel', '_token']):
                technologies.add("Laravel")
            
            # CodeIgniter detection
            if 'codeigniter' in html_lower or 'ci_session' in html_lower:
                technologies.add("CodeIgniter")
            
            # Magento detection
            if any(x in html_lower for x in ['magento', 'mage/', 'varien/']):
                technologies.add("Magento")
            
            # Shopify detection
            if any(x in html_lower for x in ['shopify', 'myshopify.com', 'shopify-features']):
                technologies.add("Shopify")
            
            # WooCommerce detection
            if any(x in html_lower for x in ['woocommerce', 'wc-', 'wp-content/plugins/woocommerce']):
                technologies.add("WooCommerce")
        
        # Technology detection from specific headers
        if headers.get('X-Generator'):
            generator = headers.get('X-Generator', '')
            technologies.add(f"Generated by: {generator}")
        
        if headers.get('X-Drupal-Dynamic-Cache'):
            technologies.add("Drupal 8+")
        
        if headers.get('X-Magento-Tags'):
            technologies.add("Magento")
        
        return list(technologies)
    
    def _extract_version(self, text, software):
        """Extract version number from server string"""
        import re
        pattern = rf'{software}[\/\s]+(\d+\.[\d\.]*\d*)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return f"v{match.group(1)}"
        return ""
    
    def detect_cms_advanced(self, html_content, headers, url):
        """Advanced CMS and technology detection"""
        cms_info = {}
        
        if not html_content:
            return cms_info
        
        # WordPress advanced detection
        wp_indicators = {
            'wp-content': 'WordPress',
            'wp-includes': 'WordPress',
            '/wp-json/': 'WordPress REST API',
            'wp-emoji-release.min.js': 'WordPress',
            'wp-block-library': 'WordPress Gutenberg'
        }
        
        for indicator, tech in wp_indicators.items():
            if indicator in html_content.lower():
                cms_info['CMS'] = tech
                # Try to detect WP version
                version_patterns = [
                    r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d\.]+)',
                    r'wordpress\.org.*?(\d+\.\d+\.?\d*)',
                    r'/wp-json/wp/v2.*?WordPress\s+([\d\.]+)'
                ]
                for pattern in version_patterns:
                    import re
                    match = re.search(pattern, html_content, re.IGNORECASE)
                    if match:
                        cms_info['Version'] = match.group(1)
                        break
                break
        
        # Check for admin panels
        admin_indicators = {
            '/admin': 'Admin Panel Detected',
            '/administrator': 'Joomla Admin',
            '/wp-admin': 'WordPress Admin',
            '/phpmyadmin': 'phpMyAdmin',
            '/cpanel': 'cPanel',
            '/plesk': 'Plesk Panel'
        }
        
        for path, desc in admin_indicators.items():
            if path in html_content.lower() or path in url.lower():
                cms_info['Admin Panel'] = desc
        
        return cms_info
    
    def extract_security_info(self, headers):
        """Extract security-related information"""
        security_info = {}
        
        # Security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS Enabled',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-XSS-Protection': 'XSS Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Content-Security-Policy': 'CSP Enabled',
            'X-Permitted-Cross-Domain-Policies': 'Cross Domain Policy',
            'Referrer-Policy': 'Referrer Policy Set',
            'Feature-Policy': 'Feature Policy Enabled',
            'Permissions-Policy': 'Permissions Policy Enabled'
        }
        
        for header, description in security_headers.items():
            if header in headers:
                security_info[description] = headers[header][:50]  # Limit length
        
        # WAF detection
        waf_headers = [
            'cf-ray', 'x-sucuri-id', 'x-blocked-by', 'x-denied-reason',
            'x-waf-event-info', 'x-firewall-protection', 'x-protected-by'
        ]
        
        for header in waf_headers:
            if header in [h.lower() for h in headers.keys()]:
                security_info['WAF'] = f"Detected via {header} header"
                break
        
        return security_info
    
    def is_subdomain_live(self, subdomain):
        """Check if subdomain is live (responds to HTTP or HTTPS)"""
        results = self.check_http_status(subdomain)
        
        # Check if either HTTP or HTTPS is working
        http_live = results.get('http', {}).get('status', False)
        https_live = results.get('https', {}).get('status', False)
        
        if http_live or https_live:
            return True, results
        else:
            return False, results
    
    def check_single(self, subdomain):
        """Check a single subdomain and return formatted result with enhanced info"""
        try:
            is_live, http_results = self.is_subdomain_live(subdomain)
            
            if is_live:
                # Format the result with comprehensive information
                result = {
                    'subdomain': subdomain,
                    'live': True,
                    'protocols': {}
                }
                
                for protocol, data in http_results.items():
                    if data.get('status'):
                        # Basic info
                        protocol_info = {
                            'status_code': data.get('status_code'),
                            'title': data.get('title', 'No Title'),
                            'url': data.get('url', f"{protocol}://{subdomain}"),
                            'redirect': data.get('redirect', False),
                            'server': data.get('headers', {}).get('Server', 'Unknown'),
                            'content_length': data.get('content_length', 'Unknown'),
                            'content_type': data.get('content_type', 'Unknown')
                        }
                        
                        # Enhanced info
                        if 'technologies' in data:
                            protocol_info['technologies'] = data['technologies']
                        if 'cms_info' in data:
                            protocol_info['cms_info'] = data['cms_info']
                        if 'security_info' in data:
                            protocol_info['security_info'] = data['security_info']
                        
                        result['protocols'][protocol] = protocol_info
                
                return subdomain, result
            else:
                return subdomain, None
                
        except Exception as e:
            return subdomain, None
    
    def check_multiple(self, subdomains):
        """Check multiple subdomains concurrently with enhanced title extraction"""
        live_results = {}
        total = len(subdomains)
        completed = 0
        found = 0
        start_time = time.time()
        
        print(f"Checking {total} subdomains for HTTP/HTTPS response...")
        
        def update_progress():
            elapsed = time.time() - start_time
            rate = completed / elapsed if elapsed > 0 else 0
            print(f"Progress: {completed}/{total} ({completed/total*100:.1f}%) - Live: {found} - Rate: {rate:.1f}/s", end='\r')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_subdomain = {
                executor.submit(self.check_single, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            # Process results
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    checked_subdomain, result = future.result()
                    completed += 1
                    
                    if result:
                        found += 1
                        live_results[checked_subdomain] = result
                        
                        # Enhanced display of found subdomains
                        protocols = list(result['protocols'].keys())
                        tech_info = []
                        
                        for protocol, info in result['protocols'].items():
                            # Collect technology info for display
                            if info.get('technologies'):
                                tech_info.extend(info['technologies'][:3])  # Show first 3 technologies
                            
                            # Show CMS info if available
                            if info.get('cms_info') and info['cms_info'].get('CMS'):
                                tech_info.append(info['cms_info']['CMS'])
                        
                        # Format display
                        tech_display = f" [{', '.join(tech_info[:4])}]" if tech_info else ""
                        title_display = ""
                        
                        # Get title from first available protocol
                        for protocol, info in result['protocols'].items():
                            title = info.get('title', '')
                            if title and title not in ['No Title', 'Unable to fetch title', 'Unable to fetch']:
                                # Show meaningful titles only
                                if not title.startswith('HTTP ') and not title.startswith('Redirect '):
                                    title_display = f' - "{title[:40]}"'
                                    break
                        
                        # Status code info
                        status_info = []
                        for protocol, info in result['protocols'].items():
                            status_code = info.get('status_code', 'N/A')
                            if status_code == 200:
                                status_info.append(f"{protocol.upper()}:200")
                            else:
                                status_info.append(f"{protocol.upper()}:{status_code}")
                        
                        status_display = f" ({', '.join(status_info)})" if status_info else ""
                        
                        print(f"\n[+] Live: {checked_subdomain} [{', '.join(protocols).upper()}]{tech_display}{title_display}{status_display}")
                    
                    # Update progress
                    if completed % 25 == 0 or completed == total:
                        update_progress()
                        
                except Exception as e:
                    completed += 1
                    # Continue on errors
                    pass
        
        elapsed = time.time() - start_time
        print(f"\nHTTP check completed: {found} live subdomains found in {elapsed:.2f} seconds")
        
        return live_results
    
    def get_subdomain_info(self, subdomain):
        """Get detailed information about a subdomain"""
        is_live, results = self.is_subdomain_live(subdomain)
        
        info = {
            'subdomain': subdomain,
            'live': is_live,
            'timestamp': time.time()
        }
        
        if is_live:
            info['protocols'] = results
            
            # Additional checks
            info['technologies'] = self.detect_technologies(results)
            info['security_headers'] = self.check_security_headers(results)
        
        return info
    
    def detect_technologies(self, http_results):
        """Detect technologies used by the web application"""
        technologies = []
        
        for protocol, data in http_results.items():
            if not data.get('status'):
                continue
                
            headers = data.get('headers', {})
            
            # Server detection
            server = headers.get('Server', '').lower()
            if 'nginx' in server:
                technologies.append('Nginx')
            elif 'apache' in server:
                technologies.append('Apache')
            elif 'cloudflare' in server:
                technologies.append('Cloudflare')
            elif 'iis' in server:
                technologies.append('IIS')
            
            # Framework detection
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            
            # CDN detection
            if headers.get('CF-Ray'):
                technologies.append('Cloudflare CDN')
            if headers.get('X-Served-By'):
                technologies.append('Fastly CDN')
        
        return list(set(technologies))
    
    def check_security_headers(self, http_results):
        """Check for security headers"""
        security_headers = {}
        
        headers_to_check = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'Referrer-Policy'
        ]
        
        for protocol, data in http_results.items():
            if not data.get('status'):
                continue
                
            headers = data.get('headers', {})
            protocol_security = {}
            
            for header in headers_to_check:
                if header in headers:
                    protocol_security[header] = headers[header]
            
            if protocol_security:
                security_headers[protocol] = protocol_security
        
        return security_headers
    
    def debug_title_extraction(self, url):
        """Debug method to test title extraction on specific URL"""
        print(f"Debug: Testing title extraction for {url}")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            print(f"Status Code: {response.status_code}")
            print(f"Content-Type: {response.headers.get('content-type')}")
            
            if response.status_code == 200:
                html_content = response.text
                print(f"Content Length: {len(html_content)}")
                
                # Test different extraction methods
                title = self.extract_title(html_content)
                print(f"Extracted Title: '{title}'")
                
                # Show first 500 chars of content for debugging
                print(f"Content Preview: {html_content[:500]}...")
                
                return title
            else:
                print(f"Non-200 response: {response.status_code}")
                return f"HTTP {response.status_code}"
                
        except Exception as e:
            print(f"Error: {e}")
            return f"Error fetching: {e} | Title: {title}".strip()
        
        # Limit length (like httpx does)
        if len(title) > 100:
            title = title[:97] + "..."
        
        return title if title else "No Title"
    
    def _extract_cms_title(self, html_content):
        """Extract title using CMS-specific patterns"""
        import re
        
        # WordPress specific
        wp_patterns = [
            r'<meta[^>]*property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']application-name["\'][^>]*content=["\']([^"\']+)["\']'
        ]
        
        for pattern in wp_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                title = match.group(1).strip()
                if title and 'wordpress' not in title.lower():
                    return self._clean_title(title)
        
        return None
    
    def _extract_content_title(self, html_content):
        """Extract title from main content as last resort"""
        import re
        
        # Look for meaningful text in common containers
        content_patterns = [
            r'<div[^>]*class=["\'][^"\']*header[^"\']*["\'][^>]*>([^<]+)',
            r'<div[^>]*class=["\'][^"\']*title[^"\']*["\'][^>]*>([^<]+)',
            r'<span[^>]*class=["\'][^"\']*title[^"\']*["\'][^>]*>([^<]+)',
            r'<p[^>]*class=["\'][^"\']*lead[^"\']*["\'][^>]*>([^<]+)'
        ]
        
        for pattern in content_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                content = match.group(1).strip()
                if content and len(content) < 80:
                    return self._clean_title(content)
        
        return None
    
    def get_title_with_fallback(self, url, session_response=None):
        """Get title with multiple fallback methods like httpx"""
        try:
            # If we already have response content, use it
            if session_response and hasattr(session_response, 'text'):
                return self.extract_title(session_response.text)
            
            # Make fresh request specifically for title extraction
            response = self.session.get(
                url,
                timeout=8,
                verify=False,
                allow_redirects=True,
                headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Cache-Control': 'no-cache'
                }
            )
            
            if response.status_code == 200:
                # Try to get encoding from headers first
                content_type = response.headers.get('content-type', '')
                if 'charset=' in content_type:
                    encoding = content_type.split('charset=')[1].split(';')[0].strip()
                else:
                    encoding = response.apparent_encoding or 'utf-8'
                
                # Decode content properly
                try:
                    html_content = response.content.decode(encoding, errors='ignore')
                except:
                    html_content = response.content.decode('utf-8', errors='ignore')
                
                return self.extract_title(html_content)
            else:
                return f"HTTP {response.status_code}"
                
        except Exception as e:
            return "Unable to fetch title"
    
    def extract_technologies(self, html_content, headers):
        """Extract technologies and frameworks from content and headers"""
        technologies = set()
        
        # Server detection from headers
        server = headers.get('Server', '').lower()
        if server:
            if 'nginx' in server:
                technologies.add(f"Nginx {self._extract_version(server, 'nginx')}")
            elif 'apache' in server:
                technologies.add(f"Apache {self._extract_version(server, 'apache')}")
            elif 'microsoft-iis' in server:
                technologies.add(f"IIS {self._extract_version(server, 'microsoft-iis')}")
            elif 'cloudflare' in server:
                technologies.add("Cloudflare")
            elif 'openresty' in server:
                technologies.add("OpenResty")
            elif 'litespeed' in server:
                technologies.add("LiteSpeed")
        
        # Framework detection from headers
        powered_by = headers.get('X-Powered-By', '').lower()
        if powered_by:
            if 'php' in powered_by:
                technologies.add(f"PHP {self._extract_version(powered_by, 'php')}")
            elif 'asp.net' in powered_by:
                technologies.add(f"ASP.NET {self._extract_version(powered_by, 'asp.net')}")
            elif 'express' in powered_by:
                technologies.add("Express.js")
            elif 'django' in powered_by:
                technologies.add("Django")
        
        # CDN detection
        if headers.get('CF-Ray') or headers.get('cf-ray'):
            technologies.add("Cloudflare CDN")
        if headers.get('X-Served-By'):
            technologies.add("Fastly CDN")
        if headers.get('X-Cache') and 'varnish' in headers.get('X-Cache', '').lower():
            technologies.add("Varnish Cache")
        if headers.get('X-Drupal-Cache'):
            technologies.add("Drupal")
        
        # CMS/Framework detection from HTML content
        if html_content:
            html_lower = html_content.lower()
            
            # WordPress detection
            if any(x in html_lower for x in ['wp-content', 'wordpress', 'wp-includes']):
                technologies.add("WordPress")
            
            # Joomla detection
            if any(x in html_lower for x in ['/joomla/', 'joomla!', 'com_content']):
                technologies.add("Joomla")
            
            # Drupal detection
            if any(x in html_lower for x in ['drupal', 'sites/default/files']):
                technologies.add("Drupal")
            
            # React detection
            if any(x in html_lower for x in ['react', '__react', 'reactjs']):
                technologies.add("React")
            
            # Vue.js detection
            if any(x in html_lower for x in ['vue.js', 'vuejs', '__vue__']):
                technologies.add("Vue.js")
            
            # Angular detection
            if any(x in html_lower for x in ['angular', 'ng-app', 'angularjs']):
                technologies.add("Angular")
            
            # jQuery detection
            if any(x in html_lower for x in ['jquery', 'jquery.min.js']):
                technologies.add("jQuery")
            
            # Bootstrap detection
            if any(x in html_lower for x in ['bootstrap', 'bootstrap.min.css']):
                technologies.add("Bootstrap")
            
            # Laravel detection
            if any(x in html_lower for x in ['laravel_session', 'laravel', '_token']):
                technologies.add("Laravel")
            
            # CodeIgniter detection
            if 'codeigniter' in html_lower or 'ci_session' in html_lower:
                technologies.add("CodeIgniter")
            
            # Magento detection
            if any(x in html_lower for x in ['magento', 'mage/', 'varien/']):
                technologies.add("Magento")
            
            # Shopify detection
            if any(x in html_lower for x in ['shopify', 'myshopify.com', 'shopify-features']):
                technologies.add("Shopify")
            
            # WooCommerce detection
            if any(x in html_lower for x in ['woocommerce', 'wc-', 'wp-content/plugins/woocommerce']):
                technologies.add("WooCommerce")
        
        # Technology detection from specific headers
        if headers.get('X-Generator'):
            generator = headers.get('X-Generator', '')
            technologies.add(f"Generated by: {generator}")
        
        if headers.get('X-Drupal-Dynamic-Cache'):
            technologies.add("Drupal 8+")
        
        if headers.get('X-Magento-Tags'):
            technologies.add("Magento")
        
        return list(technologies)
    
    def _extract_version(self, text, software):
        """Extract version number from server string"""
        import re
        pattern = rf'{software}[\/\s]+(\d+\.[\d\.]*\d*)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return f"v{match.group(1)}"
        return ""
    
    def detect_cms_advanced(self, html_content, headers, url):
        """Advanced CMS and technology detection"""
        cms_info = {}
        
        if not html_content:
            return cms_info
        
        # WordPress advanced detection
        wp_indicators = {
            'wp-content': 'WordPress',
            'wp-includes': 'WordPress',
            '/wp-json/': 'WordPress REST API',
            'wp-emoji-release.min.js': 'WordPress',
            'wp-block-library': 'WordPress Gutenberg'
        }
        
        for indicator, tech in wp_indicators.items():
            if indicator in html_content.lower():
                cms_info['CMS'] = tech
                # Try to detect WP version
                version_patterns = [
                    r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d\.]+)',
                    r'wordpress\.org.*?(\d+\.\d+\.?\d*)',
                    r'/wp-json/wp/v2.*?WordPress\s+([\d\.]+)'
                ]
                for pattern in version_patterns:
                    import re
                    match = re.search(pattern, html_content, re.IGNORECASE)
                    if match:
                        cms_info['Version'] = match.group(1)
                        break
                break
        
        # Check for admin panels
        admin_indicators = {
            '/admin': 'Admin Panel Detected',
            '/administrator': 'Joomla Admin',
            '/wp-admin': 'WordPress Admin',
            '/phpmyadmin': 'phpMyAdmin',
            '/cpanel': 'cPanel',
            '/plesk': 'Plesk Panel'
        }
        
        for path, desc in admin_indicators.items():
            if path in html_content.lower() or path in url.lower():
                cms_info['Admin Panel'] = desc
        
        return cms_info
    
    def extract_security_info(self, headers):
        """Extract security-related information"""
        security_info = {}
        
        # Security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS Enabled',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-XSS-Protection': 'XSS Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Content-Security-Policy': 'CSP Enabled',
            'X-Permitted-Cross-Domain-Policies': 'Cross Domain Policy',
            'Referrer-Policy': 'Referrer Policy Set',
            'Feature-Policy': 'Feature Policy Enabled',
            'Permissions-Policy': 'Permissions Policy Enabled'
        }
        
        for header, description in security_headers.items():
            if header in headers:
                security_info[description] = headers[header][:50]  # Limit length
        
        # WAF detection
        waf_headers = [
            'cf-ray', 'x-sucuri-id', 'x-blocked-by', 'x-denied-reason',
            'x-waf-event-info', 'x-firewall-protection', 'x-protected-by'
        ]
        
        for header in waf_headers:
            if header in [h.lower() for h in headers.keys()]:
                security_info['WAF'] = f"Detected via {header} header"
                break
        
        return security_info
    
    def is_subdomain_live(self, subdomain):
        """Check if subdomain is live (responds to HTTP or HTTPS)"""
        results = self.check_http_status(subdomain)
        
        # Check if either HTTP or HTTPS is working
        http_live = results.get('http', {}).get('status', False)
        https_live = results.get('https', {}).get('status', False)
        
        if http_live or https_live:
            return True, results
        else:
            return False, results
    
    def check_single(self, subdomain):
        """Check a single subdomain and return formatted result with enhanced info"""
        try:
            is_live, http_results = self.is_subdomain_live(subdomain)
            
            if is_live:
                # Format the result with comprehensive information
                result = {
                    'subdomain': subdomain,
                    'live': True,
                    'protocols': {}
                }
                
                for protocol, data in http_results.items():
                    if data.get('status'):
                        # Basic info
                        protocol_info = {
                            'status_code': data.get('status_code'),
                            'title': data.get('title', 'No Title'),
                            'url': data.get('url', f"{protocol}://{subdomain}"),
                            'redirect': data.get('redirect', False),
                            'server': data.get('headers', {}).get('Server', 'Unknown'),
                            'content_length': data.get('content_length', 'Unknown'),
                            'content_type': data.get('content_type', 'Unknown')
                        }
                        
                        # Enhanced info
                        if 'technologies' in data:
                            protocol_info['technologies'] = data['technologies']
                        if 'cms_info' in data:
                            protocol_info['cms_info'] = data['cms_info']
                        if 'security_info' in data:
                            protocol_info['security_info'] = data['security_info']
                        
                        result['protocols'][protocol] = protocol_info
                
                return subdomain, result
            else:
                return subdomain, None
                
        except Exception as e:
            return subdomain, None
    
    def check_multiple(self, subdomains):
        """Check multiple subdomains concurrently"""
        live_results = {}
        total = len(subdomains)
        completed = 0
        found = 0
        start_time = time.time()
        
        print(f"Checking {total} subdomains for HTTP/HTTPS response...")
        
        def update_progress():
            elapsed = time.time() - start_time
            rate = completed / elapsed if elapsed > 0 else 0
            print(f"Progress: {completed}/{total} ({completed/total*100:.1f}%) - Live: {found} - Rate: {rate:.1f}/s", end='\r')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_subdomain = {
                executor.submit(self.check_single, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            # Process results
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    checked_subdomain, result = future.result()
                    completed += 1
                    
                    if result:
                        found += 1
                        live_results[checked_subdomain] = result
                        
                        # Enhanced display of found subdomains
                        protocols = list(result['protocols'].keys())
                        tech_info = []
                        
                        for protocol, info in result['protocols'].items():
                            # Collect technology info for display
                            if info.get('technologies'):
                                tech_info.extend(info['technologies'][:3])  # Show first 3 technologies
                            
                            # Show CMS info if available
                            if info.get('cms_info') and info['cms_info'].get('CMS'):
                                tech_info.append(info['cms_info']['CMS'])
                        
                        # Format display
                        tech_display = f" [{', '.join(tech_info[:4])}]" if tech_info else ""
                        title_display = ""
                        
                        # Get title from first available protocol
                        for protocol, info in result['protocols'].items():
                            if info.get('title') and info['title'] != 'No Title':
                                title_display = f' - "{info["title"][:40]}"'
                                break
                        
                        print(f"\n[+] Live: {checked_subdomain} [{', '.join(protocols).upper()}]{tech_display}{title_display}")
                    
                    # Update progress
                    if completed % 25 == 0 or completed == total:
                        update_progress()
                        
                except Exception as e:
                    completed += 1
                    # Continue on errors
                    pass
        
        elapsed = time.time() - start_time
        print(f"\nHTTP check completed: {found} live subdomains found in {elapsed:.2f} seconds")
        
        return live_results
    
    def get_subdomain_info(self, subdomain):
        """Get detailed information about a subdomain"""
        is_live, results = self.is_subdomain_live(subdomain)
        
        info = {
            'subdomain': subdomain,
            'live': is_live,
            'timestamp': time.time()
        }
        
        if is_live:
            info['protocols'] = results
            
            # Additional checks
            info['technologies'] = self.detect_technologies(results)
            info['security_headers'] = self.check_security_headers(results)
        
        return info
    
    def detect_technologies(self, http_results):
        """Detect technologies used by the web application"""
        technologies = []
        
        for protocol, data in http_results.items():
            if not data.get('status'):
                continue
                
            headers = data.get('headers', {})
            
            # Server detection
            server = headers.get('Server', '').lower()
            if 'nginx' in server:
                technologies.append('Nginx')
            elif 'apache' in server:
                technologies.append('Apache')
            elif 'cloudflare' in server:
                technologies.append('Cloudflare')
            elif 'iis' in server:
                technologies.append('IIS')
            
            # Framework detection
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            
            # CDN detection
            if headers.get('CF-Ray'):
                technologies.append('Cloudflare CDN')
            if headers.get('X-Served-By'):
                technologies.append('Fastly CDN')
        
        return list(set(technologies))
    
    def check_security_headers(self, http_results):
        """Check for security headers"""
        security_headers = {}
        
        headers_to_check = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'Referrer-Policy'
        ]
        
        for protocol, data in http_results.items():
            if not data.get('status'):
                continue
                
            headers = data.get('headers', {})
            protocol_security = {}
            
            for header in headers_to_check:
                if header in headers:
                    protocol_security[header] = headers[header]
            
            if protocol_security:
                security_headers[protocol] = protocol_security
        
        return security_headers