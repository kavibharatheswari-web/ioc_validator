import requests
import re
import validators
import hashlib
from datetime import datetime, timedelta
from ai_analyzer import AIAnalyzer
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Try to import whois, make it optional
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: python-whois not installed. Domain age checking disabled.")

class IOCAnalyzer:
    def __init__(self, api_keys):
        self.api_keys = api_keys
        self.ai_analyzer = AIAnalyzer()
    
    def identify_ioc_type(self, ioc):
        """Identify the type of IOC"""
        ioc = ioc.strip()
        
        # IP Address
        if validators.ipv4(ioc) or validators.ipv6(ioc):
            return 'ip'
        
        # Domain
        if validators.domain(ioc):
            return 'domain'
        
        # URL
        if validators.url(ioc):
            return 'url'
        
        # Email
        if validators.email(ioc):
            return 'email'
        
        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return 'md5'
        if re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return 'sha1'
        if re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return 'sha256'
        
        # PowerShell command detection
        if any(keyword in ioc.lower() for keyword in ['powershell', 'invoke-', 'iex', 'downloadstring']):
            return 'powershell'
        
        # File extension
        if re.match(r'^\.[a-zA-Z0-9]+$', ioc):
            return 'extension'
        
        return 'unknown'
    
    def analyze(self, ioc):
        """Analyze an IOC using multiple services"""
        ioc_type = self.identify_ioc_type(ioc)
        
        results = {
            'ioc': ioc,
            'type': ioc_type,
            'threat_category': 'Unknown',
            'threat_score': 0,
            'threat_type': 'Unknown',
            'severity': 'Low',
            'details': {},
            'ai_summary': '',
            'ai_recommendation': ''
        }
        
        # Analyze based on type
        if ioc_type == 'ip':
            results['details'] = self.analyze_ip(ioc)
        elif ioc_type == 'domain':
            results['details'] = self.analyze_domain(ioc)
        elif ioc_type == 'url':
            results['details'] = self.analyze_url(ioc)
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            results['details'] = self.analyze_hash(ioc)
        elif ioc_type == 'email':
            results['details'] = self.analyze_email(ioc)
        elif ioc_type == 'powershell':
            results['details'] = self.analyze_powershell(ioc)
        
        # Calculate overall threat score and severity
        results = self.calculate_threat_metrics(results)
        
        # Get AI analysis
        ai_analysis = self.ai_analyzer.analyze(ioc, ioc_type, results['details'])
        results['ai_summary'] = ai_analysis['summary']
        results['ai_recommendation'] = ai_analysis['recommendation']
        
        return results
    
    def check_domain_age(self, domain):
        """Check domain age using WHOIS data"""
        if not WHOIS_AVAILABLE:
            return {
                'error': 'WHOIS module not available',
                'note': 'Install python-whois to enable domain age checking'
            }
        
        try:
            w = python_whois.whois(domain)
            
            # Get creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                # Calculate age
                age_days = (datetime.now() - creation_date).days
                age_years = age_days / 365.25
                
                # Determine risk level based on age
                if age_days < 30:
                    risk_level = "CRITICAL"
                    risk_note = "⚠️ NEWLY REGISTERED DOMAIN - High phishing/malware risk!"
                elif age_days < 90:
                    risk_level = "HIGH"
                    risk_note = "⚠️ Recently registered domain - Suspicious"
                elif age_days < 365:
                    risk_level = "MEDIUM"
                    risk_note = "Domain less than 1 year old - Monitor closely"
                else:
                    risk_level = "LOW"
                    risk_note = "Established domain"
                
                return {
                    'creation_date': creation_date.strftime('%Y-%m-%d'),
                    'age_days': age_days,
                    'age_years': round(age_years, 2),
                    'age_display': f"{age_years:.1f} years" if age_years >= 1 else f"{age_days} days",
                    'risk_level': risk_level,
                    'risk_note': risk_note,
                    'registrar': w.registrar if w.registrar else 'Unknown',
                    'status': 'Active' if w.status else 'Unknown'
                }
            else:
                return {
                    'error': 'Could not determine domain age',
                    'note': 'WHOIS data unavailable - Domain may be very new or privacy-protected'
                }
        except Exception as e:
            return {
                'error': str(e),
                'note': 'Domain not found in WHOIS database - May be newly registered or invalid'
            }
    
    def analyze_ip(self, ip):
        """Analyze IP address using multiple services"""
        details = {}
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            details['virustotal'] = self.check_virustotal_ip(ip)
        
        # AbuseIPDB
        if 'abuseipdb' in self.api_keys:
            details['abuseipdb'] = self.check_abuseipdb(ip)
        
        # IPVoid
        if 'ipvoid' in self.api_keys:
            details['ipvoid'] = self.check_ipvoid(ip)
        
        # Cisco Talos
        details['talos'] = {
            'link': f'https://talosintelligence.com/reputation_center/lookup?search={ip}',
            'note': 'Cisco Talos - Check IP reputation and threat intelligence'
        }
        
        # ViewDNS IP tools
        details['viewdns'] = {
            'reverse_dns': f'https://viewdns.info/reversedns/?ip={ip}',
            'ip_location': f'https://viewdns.info/iplocation/?ip={ip}',
            'port_scan': f'https://viewdns.info/portscan/?host={ip}',
            'note': 'ViewDNS - Check reverse DNS, location, and open ports'
        }
        
        # AlienVault OTX (Free, no API key needed)
        details['alienvault'] = self.check_alienvault_ip(ip)
        
        # ANY.RUN - Interactive Malware Analysis
        details['anyrun'] = self.check_anyrun(ip, 'ip')
        
        return details
    
    def analyze_domain(self, domain):
        """Analyze domain using multiple services"""
        details = {}
        
        # WHOIS - Domain Age Check (FIRST - Important for new domains)
        details['domain_age'] = self.check_domain_age(domain)
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            details['virustotal'] = self.check_virustotal_domain(domain)
        
        # URLVoid
        details['urlvoid'] = {
            'link': f'https://www.urlvoid.com/scan/{domain}/',
            'note': 'Manual check required - Check domain reputation'
        }
        
        # ViewDNS - Multiple checks
        details['viewdns'] = {
            'reverse_ip': f'https://viewdns.info/reverseip/?host={domain}',
            'dns_record': f'https://viewdns.info/dnsrecord/?domain={domain}',
            'whois': f'https://viewdns.info/whois/?domain={domain}',
            'ip_history': f'https://viewdns.info/iphistory/?domain={domain}',
            'note': 'ViewDNS - Check reverse IP, DNS records, WHOIS, and IP history'
        }
        
        # Palo Alto WildFire
        details['paloalto'] = {
            'link': f'https://urlfiltering.paloaltonetworks.com/',
            'search': domain,
            'note': 'Palo Alto URL Filtering - Check domain category and threat verdict',
            'action': 'Manual check: Enter domain to see category (e.g., malware, phishing, benign)'
        }
        
        # AlienVault OTX
        details['alienvault'] = self.check_alienvault_domain(domain)
        
        # ANY.RUN - Interactive Malware Analysis
        details['anyrun'] = self.check_anyrun(domain, 'domain')
        
        return details
    
    def analyze_url(self, url):
        """Analyze URL using multiple services"""
        details = {}
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            details['virustotal'] = self.check_virustotal_url(url)
        
        # URLScan.io (Free)
        details['urlscan'] = self.check_urlscan(url)
        
        # URLQuery - Redirections and Threat Analysis
        details['urlquery'] = self.check_urlquery(url)
        
        # ANY.RUN - Interactive Malware Analysis
        details['anyrun'] = self.check_anyrun(url, 'url')
        
        # Zscaler Content Analyzer
        details['zscaler_content'] = self.check_zscaler_content(url)
        
        # Zscaler Category Analyzer
        details['zscaler_category'] = self.check_zscaler_category(url)
        
        # Check Redirections
        details['redirections'] = self.check_redirections(url)
        
        # Zscaler URL Categorization (Manual)
        details['zscaler'] = {
            'link': f'https://sitereview.zscaler.com/',
            'url_to_check': url,
            'note': 'Zscaler - Check URL categorization and security rating',
            'action': 'Manual check: Enter URL to see category (e.g., Malicious Sites, Phishing, Adult Content, Business, etc.)'
        }
        
        # Palo Alto URL Filtering
        details['paloalto'] = {
            'link': f'https://urlfiltering.paloaltonetworks.com/',
            'url_to_check': url,
            'note': 'Palo Alto URL Filtering - Check URL category and threat verdict',
            'action': 'Manual check: Enter URL to see category (e.g., malware, phishing, command-and-control, benign)'
        }
        
        # Cisco Talos
        details['cisco_talos'] = {
            'link': f'https://talosintelligence.com/reputation_center/lookup?search={url}',
            'note': 'Cisco Talos - Check URL reputation and threat intelligence'
        }
        
        return details
    
    def analyze_hash(self, hash_value):
        """Analyze file hash using multiple services"""
        details = {}
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            details['virustotal'] = self.check_virustotal_hash(hash_value)
        
        # Hybrid Analysis
        if 'hybrid_analysis' in self.api_keys:
            details['hybrid_analysis'] = self.check_hybrid_analysis(hash_value)
        
        # MalwareBazaar (Free)
        details['malwarebazaar'] = self.check_malwarebazaar(hash_value)
        
        return details
    
    def analyze_email(self, email):
        """Analyze email address"""
        details = {}
        
        domain = email.split('@')[1] if '@' in email else ''
        
        details['email_info'] = {
            'email': email,
            'domain': domain
        }
        
        # Check domain reputation
        if domain:
            details['domain_check'] = self.analyze_domain(domain)
        
        return details
    
    def analyze_powershell(self, command):
        """Analyze PowerShell command for malicious patterns"""
        details = {}
        
        suspicious_patterns = [
            'invoke-expression', 'iex', 'downloadstring', 'downloadfile',
            'invoke-webrequest', 'invoke-restmethod', 'net.webclient',
            'bitstransfer', 'encoded', '-enc', 'frombase64string',
            'reflection.assembly', 'system.net.webclient'
        ]
        
        found_patterns = [p for p in suspicious_patterns if p in command.lower()]
        
        details['powershell_analysis'] = {
            'suspicious_patterns': found_patterns,
            'risk_level': 'High' if len(found_patterns) > 2 else 'Medium' if found_patterns else 'Low',
            'command_length': len(command),
            'contains_base64': 'base64' in command.lower() or re.search(r'[A-Za-z0-9+/]{20,}={0,2}', command) is not None
        }
        
        return details
    
    # API Integration Methods
    def check_virustotal_ip(self, ip):
        """Check IP on VirusTotal - Enhanced with detailed info"""
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'community_score': attributes.get('reputation', 0),
                    'link': f'https://www.virustotal.com/gui/ip-address/{ip}'
                }
                
                # Add IP-specific details
                if 'as_owner' in attributes:
                    result['isp'] = attributes['as_owner']
                if 'asn' in attributes:
                    result['asn'] = attributes['asn']
                if 'country' in attributes:
                    result['country'] = attributes['country']
                if 'continent' in attributes:
                    result['continent'] = attributes['continent']
                if 'network' in attributes:
                    result['network'] = attributes['network']
                
                # Check if it's a known CDN
                as_owner = attributes.get('as_owner', '').lower()
                cdn_keywords = ['cloudflare', 'akamai', 'fastly', 'amazon', 'google', 'microsoft', 'azure']
                result['is_cdn'] = any(cdn in as_owner for cdn in cdn_keywords)
                
                return result
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_virustotal_domain(self, domain):
        """Check domain on VirusTotal - Enhanced with detailed info"""
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'community_score': attributes.get('reputation', 0),
                    'link': f'https://www.virustotal.com/gui/domain/{domain}'
                }
                
                # Add domain-specific details
                if 'registrar' in attributes:
                    result['registrar'] = attributes['registrar']
                if 'creation_date' in attributes:
                    # Convert Unix timestamp to date
                    try:
                        from datetime import datetime
                        timestamp = attributes['creation_date']
                        result['created'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
                    except:
                        result['created'] = str(attributes['creation_date'])[:10]
                if 'last_update_date' in attributes:
                    # Convert Unix timestamp to date
                    try:
                        from datetime import datetime
                        timestamp = attributes['last_update_date']
                        result['updated'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
                    except:
                        result['updated'] = str(attributes['last_update_date'])[:10]
                if 'categories' in attributes:
                    cats = attributes['categories']
                    if cats:
                        result['categories'] = ', '.join(list(cats.values())[:3])
                if 'popularity_ranks' in attributes:
                    ranks = attributes['popularity_ranks']
                    if ranks:
                        result['popularity'] = f"Alexa: {ranks.get('Alexa', {}).get('rank', 'N/A')}"
                
                return result
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_virustotal_url(self, url):
        """Check URL on VirusTotal - Enhanced with detailed info"""
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            url_id = hashlib.sha256(url.encode()).hexdigest()
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'community_score': attributes.get('reputation', 0),
                    'link': f'https://www.virustotal.com/gui/url/{url_id}'
                }
                
                # Add URL-specific details
                if 'title' in attributes:
                    result['page_title'] = attributes['title'][:100]
                if 'last_final_url' in attributes:
                    result['final_url'] = attributes['last_final_url'][:100]
                if 'categories' in attributes:
                    cats = attributes['categories']
                    if cats:
                        result['categories'] = ', '.join(list(cats.values())[:3])
                if 'last_http_response_code' in attributes:
                    result['http_code'] = attributes['last_http_response_code']
                
                return result
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_virustotal_hash(self, hash_value):
        """Check file hash on VirusTotal - Enhanced with file details"""
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{hash_value}',
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'community_score': attributes.get('reputation', 0),
                    'link': f'https://www.virustotal.com/gui/file/{hash_value}'
                }
                
                # Add file-specific details
                if 'meaningful_name' in attributes:
                    result['file_name'] = attributes['meaningful_name']
                elif 'names' in attributes and attributes['names']:
                    result['file_name'] = attributes['names'][0]
                
                if 'size' in attributes:
                    size_bytes = attributes['size']
                    if size_bytes < 1024:
                        result['file_size'] = f"{size_bytes} B"
                    elif size_bytes < 1024*1024:
                        result['file_size'] = f"{size_bytes/1024:.2f} KB"
                    else:
                        result['file_size'] = f"{size_bytes/(1024*1024):.2f} MB"
                
                if 'type_description' in attributes:
                    result['file_type'] = attributes['type_description']
                
                if 'magic' in attributes:
                    result['file_magic'] = attributes['magic'][:50]
                
                if 'signature_info' in attributes:
                    sig_info = attributes['signature_info']
                    if 'product' in sig_info:
                        result['signed_by'] = sig_info['product']
                
                if 'popular_threat_classification' in attributes:
                    threat_class = attributes['popular_threat_classification']
                    if 'suggested_threat_label' in threat_class:
                        result['threat_label'] = threat_class['suggested_threat_label']
                
                return result
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_abuseipdb(self, ip):
        """Check IP on AbuseIPDB"""
        try:
            headers = {'Key': self.api_keys['abuseipdb'], 'Accept': 'application/json'}
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'link': f'https://www.abuseipdb.com/check/{ip}'
                }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_ipvoid(self, ip):
        """IPVoid check (requires API key)"""
        return {
            'link': f'https://www.ipvoid.com/ip-blacklist-check/',
            'note': 'Manual check required or API key needed'
        }
    
    def check_alienvault_ip(self, ip):
        """Check IP on AlienVault OTX (Free) - Essential data only"""
        try:
            # Get general info
            response = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                
                result = {
                    'pulse_count': pulse_info.get('count', 0),
                    'reputation': data.get('reputation', 0),
                    'link': f'https://otx.alienvault.com/indicator/ip/{ip}'
                }
                
                # Extract only essential threat intelligence
                pulses = pulse_info.get('pulses', [])
                if pulses and len(pulses) > 0:
                    # Get top 3 malware families
                    malware_families = set()
                    # Get top 3 campaigns
                    campaigns = []
                    # Get top 5 tags
                    tags = set()
                    
                    for pulse in pulses[:5]:  # Limit to first 5 pulses
                        # Extract malware families
                        if 'malware_families' in pulse:
                            for mf in pulse['malware_families']:
                                if isinstance(mf, dict):
                                    malware_families.add(mf.get('display_name', ''))
                                else:
                                    malware_families.add(str(mf))
                                if len(malware_families) >= 3:
                                    break
                        
                        # Extract campaign info (top 3)
                        if pulse.get('name') and len(campaigns) < 3:
                            campaigns.append({
                                'name': pulse['name'],
                                'created': pulse.get('created', '')[:10]
                            })
                        
                        # Extract tags (top 5)
                        if 'tags' in pulse:
                            for tag in pulse['tags']:
                                tags.add(tag)
                                if len(tags) >= 5:
                                    break
                    
                    # Add to result only if data exists
                    if malware_families:
                        result['malware_families'] = ', '.join(list(malware_families)[:3])
                    if campaigns:
                        result['top_campaigns'] = ', '.join([c['name'] for c in campaigns])
                    if tags:
                        result['tags'] = ', '.join(list(tags)[:5])
                
                return result
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_alienvault_domain(self, domain):
        """Check domain on AlienVault OTX (Free) - Essential data only"""
        try:
            response = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general',
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                
                result = {
                    'pulse_count': pulse_info.get('count', 0),
                    'link': f'https://otx.alienvault.com/indicator/domain/{domain}'
                }
                
                # Extract only essential threat intelligence
                pulses = pulse_info.get('pulses', [])
                if pulses and len(pulses) > 0:
                    malware_families = set()
                    campaigns = []
                    tags = set()
                    
                    for pulse in pulses[:5]:
                        if 'malware_families' in pulse:
                            for mf in pulse['malware_families']:
                                if isinstance(mf, dict):
                                    malware_families.add(mf.get('display_name', ''))
                                else:
                                    malware_families.add(str(mf))
                                if len(malware_families) >= 3:
                                    break
                        
                        if pulse.get('name') and len(campaigns) < 3:
                            campaigns.append({
                                'name': pulse['name'],
                                'created': pulse.get('created', '')[:10]
                            })
                        
                        if 'tags' in pulse:
                            for tag in pulse['tags']:
                                tags.add(tag)
                                if len(tags) >= 5:
                                    break
                    
                    if malware_families:
                        result['malware_families'] = ', '.join(list(malware_families)[:3])
                    if campaigns:
                        result['top_campaigns'] = ', '.join([c['name'] for c in campaigns])
                    if tags:
                        result['tags'] = ', '.join(list(tags)[:5])
                
                return result
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_urlscan(self, url):
        """Check URL on URLScan.io (Free)"""
        try:
            response = requests.post(
                'https://urlscan.io/api/v1/scan/',
                json={'url': url, 'visibility': 'public'},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'scan_id': data.get('uuid', ''),
                    'link': data.get('result', ''),
                    'note': 'Scan submitted, check link for results'
                }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_hybrid_analysis(self, hash_value):
        """Check hash on Hybrid Analysis"""
        try:
            headers = {'api-key': self.api_keys['hybrid_analysis'], 'user-agent': 'Falcon Sandbox'}
            response = requests.post(
                'https://www.hybrid-analysis.com/api/v2/search/hash',
                headers=headers,
                data={'hash': hash_value},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data:
                    return {
                        'verdict': data[0].get('verdict', 'Unknown'),
                        'threat_score': data[0].get('threat_score', 0),
                        'link': f'https://www.hybrid-analysis.com/sample/{hash_value}'
                    }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_malwarebazaar(self, hash_value):
        """Check hash on MalwareBazaar (Free)"""
        try:
            response = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data={'query': 'get_info', 'hash': hash_value},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    info = data.get('data', [{}])[0]
                    return {
                        'signature': info.get('signature', 'Unknown'),
                        'file_type': info.get('file_type', 'Unknown'),
                        'link': f'https://bazaar.abuse.ch/sample/{hash_value}/'
                    }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_urlquery(self, url):
        """Check URL on URLQuery for redirections and threat analysis"""
        try:
            # URLQuery API endpoint
            headers = {}
            if 'urlquery' in self.api_keys:
                headers['X-API-Key'] = self.api_keys['urlquery']
            
            response = requests.post(
                'https://urlquery.net/api/v1/submit',
                json={'url': url},
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    'status': data.get('status', 'Unknown'),
                    'redirects': [],
                    'http_referrer': None,
                    'final_url': None,
                    'link': f'https://urlquery.net/report/{data.get("id", "")}'
                }
                
                # Extract redirection chain
                if 'redirects' in data:
                    result['redirects'] = data['redirects'][:5]  # Top 5 redirects
                if 'http_referrer' in data:
                    result['http_referrer'] = data['http_referrer']
                if 'final_url' in data:
                    result['final_url'] = data['final_url']
                
                return result
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_anyrun(self, ioc, ioc_type):
        """Check IOC on ANY.RUN for interactive malware analysis"""
        try:
            if 'anyrun' not in self.api_keys:
                return {'error': 'API key required'}
            
            headers = {'Authorization': f'API-Key {self.api_keys["anyrun"]}'}
            
            # Search for IOC
            response = requests.get(
                'https://api.any.run/v1/analysis',
                headers=headers,
                params={'search': ioc, 'limit': 5},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                analyses = data.get('data', [])
                
                if analyses:
                    latest = analyses[0]
                    return {
                        'verdict': latest.get('verdict', 'Unknown'),
                        'threat_level': latest.get('threat_level', 'Unknown'),
                        'malware_families': latest.get('malware_families', []),
                        'tags': latest.get('tags', []),
                        'link': f'https://app.any.run/tasks/{latest.get("uuid", "")}'
                    }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_zscaler_content(self, url):
        """Check URL on Zscaler Content Analyzer"""
        try:
            if 'zscaler_content' not in self.api_keys:
                return {'error': 'API key required'}
            
            headers = {'Authorization': f'Bearer {self.api_keys["zscaler_content"]}'}
            
            response = requests.post(
                'https://api.zscaler.com/api/v1/urlLookup',
                headers=headers,
                json={'url': url},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'content_type': data.get('contentType', 'Unknown'),
                    'risk_score': data.get('riskScore', 0),
                    'threats': data.get('threats', []),
                    'categories': data.get('categories', []),
                    'link': 'https://admin.zscaler.com'
                }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_zscaler_category(self, url):
        """Check URL category on Zscaler Category Analyzer"""
        try:
            if 'zscaler_category' not in self.api_keys:
                return {'error': 'API key required'}
            
            headers = {'Authorization': f'Bearer {self.api_keys["zscaler_category"]}'}
            
            response = requests.post(
                'https://api.zscaler.com/api/v1/urlCategories',
                headers=headers,
                json={'urls': [url]},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 0:
                    url_data = data[0]
                    return {
                        'category': url_data.get('urlCategory', 'Unknown'),
                        'super_category': url_data.get('superCategory', 'Unknown'),
                        'risk_level': url_data.get('riskLevel', 'Unknown'),
                        'link': 'https://admin.zscaler.com'
                    }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def check_redirections(self, url):
        """Check URL redirections and HTTP referrers"""
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            redirects = []
            http_referrers = []
            
            # Follow redirects manually
            session = requests.Session()
            session.max_redirects = 10
            
            response = session.get(url, allow_redirects=True, timeout=5, verify=False)
            
            # Get redirect history
            for resp in response.history:
                redirects.append({
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'location': resp.headers.get('Location', '')
                })
            
            # Final URL
            final_url = response.url
            
            # Check for HTTP referrer
            if 'Referer' in response.request.headers:
                http_referrers.append(response.request.headers['Referer'])
            
            return {
                'redirect_count': len(redirects),
                'redirects': redirects[:5],  # Top 5
                'final_url': final_url,
                'http_referrers': http_referrers,
                'status_code': response.status_code
            }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'No data'}
    
    def calculate_threat_metrics(self, results):
        """Calculate overall threat score and severity based on tool detections"""
        details = results['details']
        ioc = results.get('ioc', '').lower()
        
        # Whitelist of known legitimate domains/sites
        legitimate_domains = [
            'google.com', 'amazon.com', 'microsoft.com', 'apple.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'youtube.com', 'netflix.com', 'adobe.com',
            'salesforce.com', 'oracle.com', 'ibm.com', 'cisco.com',
            'cloudflare.com', 'akamai.com', 'aws.amazon.com'
        ]
        
        # Check if this is a known legitimate domain
        is_legitimate = any(domain in ioc for domain in legitimate_domains)
        
        # Track different types of scores
        malicious_total = 0
        suspicious_total = 0
        abuse_scores = []
        tool_count = 0
        
        # Extract scores from various sources
        for service, data in details.items():
            if isinstance(data, dict) and not data.get('error'):
                tool_count += 1
                
                # VirusTotal detections
                if 'malicious' in data:
                    malicious_total += data.get('malicious', 0)
                if 'suspicious' in data:
                    suspicious_total += data.get('suspicious', 0)
                
                # AbuseIPDB score
                if 'abuse_confidence_score' in data:
                    abuse_scores.append(data['abuse_confidence_score'])
                
                # AlienVault pulse count (be more conservative)
                if 'pulse_count' in data and data.get('pulse_count', 0) > 0:
                    # Only count pulses if not a legitimate domain
                    if not is_legitimate:
                        # Each pulse adds to threat score (reduced weight)
                        malicious_total += min(data['pulse_count'] * 0.5, 3)  # Cap at 3, reduced weight
                
                # URLScan verdict
                if 'verdict' in data:
                    if data['verdict'] == 'malicious':
                        malicious_total += 10
                    elif data['verdict'] == 'suspicious':
                        suspicious_total += 5
                
                # MalwareBazaar
                if 'found' in data and data.get('found'):
                    malicious_total += 10
                
                # PowerShell risk
                if 'risk_level' in data:
                    risk = data.get('risk_level', 'Low')
                    if risk == 'High':
                        malicious_total += 8
                    elif risk == 'Medium':
                        suspicious_total += 5
        
        # Calculate weighted threat score
        # For legitimate domains, require stronger evidence
        if is_legitimate:
            # Legitimate domains need actual malicious detections (not just pulses)
            if malicious_total > 5:  # Require more than 5 malicious detections
                malicious_score = min((malicious_total - 5) * 8, 60)  # Reduced max
            else:
                malicious_score = 0
            suspicious_score = min(suspicious_total * 2, 20)  # Reduced weight
            abuse_score = 0  # Ignore abuse scores for legitimate domains
        else:
            # Normal scoring for unknown domains
            malicious_score = min(malicious_total * 8, 80)  # Max 80 from malicious
            suspicious_score = min(suspicious_total * 3, 30)  # Max 30 from suspicious
            abuse_score = max(abuse_scores) if abuse_scores else 0  # Take highest abuse score
        
        # Combine scores with weights
        if malicious_total > 0:
            # If any malicious detections, score is high
            threat_score = malicious_score + (suspicious_score * 0.3) + (abuse_score * 0.2)
        elif suspicious_total > 0:
            # If only suspicious, moderate score
            threat_score = suspicious_score + (abuse_score * 0.5)
        elif abuse_score > 0:
            # If only abuse score
            threat_score = abuse_score
        else:
            # Clean
            threat_score = 0
        
        # Cap at 100
        results['threat_score'] = min(round(threat_score, 2), 100)
        
        # Store detection counts for reference
        results['detection_summary'] = {
            'malicious_count': malicious_total,
            'suspicious_count': suspicious_total,
            'abuse_score': abuse_score,
            'tools_checked': tool_count
        }
        
        # Determine severity based on threat score and detection counts
        if results['threat_score'] >= 70 or malicious_total >= 5:
            results['severity'] = 'Critical'
            results['threat_category'] = 'Malicious'
        elif results['threat_score'] >= 50 or malicious_total >= 2:
            results['severity'] = 'High'
            results['threat_category'] = 'Suspicious'
        elif results['threat_score'] >= 30 or suspicious_total >= 3:
            results['severity'] = 'Medium'
            results['threat_category'] = 'Potentially Malicious'
        elif results['threat_score'] > 0 or suspicious_total > 0:
            results['severity'] = 'Low'
            results['threat_category'] = 'Suspicious Activity'
        else:
            results['severity'] = 'Info'
            results['threat_category'] = 'Clean'
        
        results['threat_type'] = self.determine_threat_type(results)
        
        # Extract IOC context for SOC investigation
        context_info = self.extract_ioc_context(results)
        results.update(context_info)
        
        return results
    
    def extract_ioc_context(self, results):
        """Extract IOC context information for SOC investigation"""
        details = results['details']
        
        context = {
            'ioc_context': '',
            'first_seen': None,
            'last_seen': None,
            'associated_malware': [],
            'campaign_info': [],
            'tags': []
        }
        
        # Extract from AlienVault
        if 'alienvault' in details and isinstance(details['alienvault'], dict):
            av_data = details['alienvault']
            
            # Malware families - handle both string and list
            if 'malware_families' in av_data:
                malware = av_data['malware_families']
                if isinstance(malware, str):
                    # Split comma-separated string
                    context['associated_malware'].extend([m.strip() for m in malware.split(',') if m.strip()])
                elif isinstance(malware, list):
                    context['associated_malware'].extend(malware)
            
            # Campaigns - handle both string and list
            if 'campaigns' in av_data:
                campaigns = av_data['campaigns']
                if isinstance(campaigns, str):
                    # Split comma-separated string and create simple campaign objects
                    campaign_names = [c.strip() for c in campaigns.split(',') if c.strip()]
                    context['campaign_info'] = [{'name': name, 'created': ''} for name in campaign_names]
                elif isinstance(campaigns, list):
                    context['campaign_info'] = campaigns
            
            # Top campaigns (from simplified AlienVault)
            if 'top_campaigns' in av_data:
                campaigns = av_data['top_campaigns']
                if isinstance(campaigns, str):
                    campaign_names = [c.strip() for c in campaigns.split(',') if c.strip()]
                    context['campaign_info'] = [{'name': name, 'created': ''} for name in campaign_names]
            
            # Tags - handle both string and list
            if 'tags' in av_data:
                tags = av_data['tags']
                if isinstance(tags, str):
                    # Split comma-separated string
                    context['tags'].extend([t.strip() for t in tags.split(',') if t.strip()])
                elif isinstance(tags, list):
                    context['tags'].extend(tags)
            
            # Adversaries
            if 'adversaries' in av_data:
                adversaries = av_data['adversaries']
                if isinstance(adversaries, str):
                    adv_list = [a.strip() for a in adversaries.split(',') if a.strip()]
                    context['tags'].extend([f"APT:{adv}" for adv in adv_list])
                elif isinstance(adversaries, list):
                    context['tags'].extend([f"APT:{adv}" for adv in adversaries])
        
        # Build context summary
        context_parts = []
        
        if context['associated_malware']:
            malware_str = ', '.join(context['associated_malware'][:5])
            context_parts.append(f"🦠 Associated Malware: {malware_str}")
        
        if context['campaign_info']:
            campaign_names = [c['name'] for c in context['campaign_info'][:3]]
            context_parts.append(f"🎯 Related Campaigns: {', '.join(campaign_names)}")
        
        if context['tags']:
            tags_str = ', '.join(context['tags'][:10])
            context_parts.append(f"🏷️ Tags: {tags_str}")
        
        # Get first/last seen from campaigns
        if context['campaign_info']:
            dates = [c.get('created', '') for c in context['campaign_info'] if c.get('created')]
            if dates:
                context['first_seen'] = min(dates)
                context['last_seen'] = max(dates)
        
        context['ioc_context'] = '\n'.join(context_parts) if context_parts else 'No additional context available'
        
        # Convert lists to JSON strings for storage
        import json
        context['associated_malware'] = json.dumps(context['associated_malware'])
        context['campaign_info'] = json.dumps(context['campaign_info'])
        context['tags'] = json.dumps(context['tags'])
        
        return context
    
    def determine_threat_type(self, results):
        """Determine the type of threat"""
        ioc_type = results['type']
        
        if ioc_type == 'powershell':
            return 'Malicious Script'
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            return 'Malware'
        elif ioc_type in ['ip', 'domain', 'url']:
            if results['threat_score'] > 50:
                return 'C&C Server / Phishing'
            else:
                return 'Network IOC'
        elif ioc_type == 'email':
            return 'Phishing / Spam'
        
        return 'Unknown'
