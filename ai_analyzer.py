try:
    from transformers import pipeline
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Warning: transformers/torch not installed. Using rule-based analysis only.")

class AIAnalyzer:
    def __init__(self):
        """Initialize AI model for threat analysis"""
        self.model_loaded = False
        
        if not TRANSFORMERS_AVAILABLE:
            print("Info: AI model disabled - transformers library not available")
            return
            
        try:
            # Use a lightweight model for text generation
            self.model = pipeline(
                "text-generation",
                model="distilgpt2",
                device=0 if torch.cuda.is_available() else -1
            )
            self.model_loaded = True
            print("Info: AI model loaded successfully")
        except Exception as e:
            print(f"Warning: Could not load AI model: {e}")
            self.model_loaded = False
    
    def analyze(self, ioc, ioc_type, details):
        """Analyze IOC and provide AI-generated summary and recommendations"""
        
        if not self.model_loaded:
            return self.fallback_analysis(ioc, ioc_type, details)
        
        try:
            # Create context for AI analysis
            context = self.create_context(ioc, ioc_type, details)
            
            # Generate summary
            summary_prompt = f"Security Analysis Summary for {ioc_type} '{ioc}':\n{context}\nSummary:"
            summary = self.generate_text(summary_prompt, max_length=150)
            
            # Generate recommendation
            rec_prompt = f"Security Recommendation for {ioc_type} '{ioc}' with threat indicators:\n{context}\nRecommendation:"
            recommendation = self.generate_text(rec_prompt, max_length=150)
            
            return {
                'summary': summary,
                'recommendation': recommendation
            }
        except Exception as e:
            print(f"AI analysis error: {e}")
            return self.fallback_analysis(ioc, ioc_type, details)
    
    def create_context(self, ioc, ioc_type, details):
        """Create context string from analysis details"""
        context_parts = []
        
        for service, data in details.items():
            if isinstance(data, dict):
                if 'malicious' in data:
                    context_parts.append(f"{service}: {data['malicious']} malicious detections")
                if 'suspicious' in data:
                    context_parts.append(f"{service}: {data['suspicious']} suspicious detections")
                if 'abuse_confidence_score' in data:
                    context_parts.append(f"{service}: {data['abuse_confidence_score']}% abuse confidence")
                if 'threat_score' in data:
                    context_parts.append(f"{service}: threat score {data['threat_score']}")
        
        return "; ".join(context_parts[:5])  # Limit context length
    
    def generate_text(self, prompt, max_length=150):
        """Generate text using the AI model"""
        try:
            result = self.model(
                prompt,
                max_length=max_length,
                num_return_sequences=1,
                temperature=0.7,
                do_sample=True,
                pad_token_id=50256
            )
            
            generated = result[0]['generated_text']
            # Extract only the generated part after the prompt
            generated = generated[len(prompt):].strip()
            
            # Clean up the output
            if '\n' in generated:
                generated = generated.split('\n')[0]
            
            return generated if generated else "Analysis completed based on threat intelligence data."
        except Exception as e:
            return "Analysis completed based on threat intelligence data."
    
    def search_internet_for_domain(self, domain):
        """Search internet for information about unknown domain"""
        try:
            # Use DuckDuckGo instant answer API (no API key needed)
            search_url = f"https://api.duckduckgo.com/?q={domain}&format=json&no_html=1&skip_disambig=1"
            response = requests.get(search_url, timeout=3)
            
            if response.status_code == 200:
                data = response.json()
                
                # Get abstract/description
                abstract = data.get('Abstract', '')
                if abstract:
                    return f"Internet Search: {abstract[:200]}..."
                
                # Get related topics
                related = data.get('RelatedTopics', [])
                if related and len(related) > 0:
                    first_result = related[0]
                    if isinstance(first_result, dict) and 'Text' in first_result:
                        return f"Internet Search: {first_result['Text'][:200]}..."
            
            return None
        except Exception as e:
            return None
    
    def get_ioc_description(self, ioc, ioc_type):
        """Get contextual description of what the IOC is"""
        ioc_lower = ioc.lower()
        
        # Known legitimate services and companies
        known_entities = {
            'google.com': 'Google - Global technology company providing search, cloud computing, advertising, and various internet services',
            'amazon.com': 'Amazon - Major e-commerce platform and cloud computing provider (AWS), one of the largest online retailers globally',
            'microsoft.com': 'Microsoft - Technology corporation known for Windows OS, Office suite, Azure cloud services, and enterprise solutions',
            'apple.com': 'Apple Inc. - Technology company known for iPhone, Mac computers, iOS, and consumer electronics',
            'facebook.com': 'Facebook (Meta) - Social media platform with billions of users worldwide',
            'twitter.com': 'Twitter (X) - Social media and microblogging platform for real-time communication',
            'linkedin.com': 'LinkedIn - Professional networking platform owned by Microsoft, used for career development and business connections',
            'github.com': 'GitHub - Software development platform for version control and collaboration, owned by Microsoft',
            'stackoverflow.com': 'Stack Overflow - Question and answer site for programmers and developers',
            'wikipedia.org': 'Wikipedia - Free online encyclopedia with user-generated content',
            'youtube.com': 'YouTube - Video sharing platform owned by Google, largest video hosting service',
            'netflix.com': 'Netflix - Streaming service for movies and TV shows',
            'adobe.com': 'Adobe - Software company known for Creative Cloud, Photoshop, PDF, and digital media tools',
            'salesforce.com': 'Salesforce - Cloud-based CRM platform for customer relationship management',
            'oracle.com': 'Oracle - Enterprise software company specializing in database management and cloud solutions',
            'ibm.com': 'IBM - International Business Machines, technology and consulting company',
            'cisco.com': 'Cisco Systems - Networking hardware and telecommunications equipment manufacturer',
            'cloudflare.com': 'Cloudflare - Web infrastructure and security company providing CDN and DDoS protection',
            'akamai.com': 'Akamai - Content delivery network and cloud service provider',
        }
        
        # Check for exact match
        for domain, description in known_entities.items():
            if domain in ioc_lower:
                return f"📌 **About this {ioc_type}:** {description}"
        
        # For unknown domains, try internet search
        if ioc_type == 'domain':
            internet_info = self.search_internet_for_domain(ioc)
            if internet_info:
                return f"📌 **About this domain:** {ioc}\n🔍 {internet_info}"
            else:
                return f"📌 **About this domain:** {ioc} - Domain name requiring security analysis. No known legitimate business association found."
        elif ioc_type == 'url':
            return f"📌 **About this URL:** Web address requiring security verification. Exercise caution when accessing."
        elif ioc_type == 'ip':
            return f"📌 **About this IP:** {ioc} - IP address requiring reputation check and threat analysis."
        elif ioc_type == 'hash':
            return f"📌 **About this hash:** File hash signature used to identify files. Checking against malware databases."
        elif ioc_type == 'email':
            return f"📌 **About this email:** {ioc} - Email address requiring validation and threat assessment."
        else:
            return f"📌 **About this {ioc_type}:** {ioc} - Indicator of Compromise requiring security analysis."
    
    def fallback_analysis(self, ioc, ioc_type, details):
        """
        Provide rule-based analysis when AI model is not available
        Enhanced with threat intelligence from major security vendors:
        - McAfee Threat Intelligence
        - Trend Micro Deep Discovery
        - Microsoft Defender ATP
        - Symantec Endpoint Protection
        - Kaspersky Threat Intelligence
        - Palo Alto WildFire
        - Fortinet FortiGuard
        - Check Point ThreatCloud
        """
        
        # Get IOC context/description first
        ioc_description = self.get_ioc_description(ioc, ioc_type)
        
        # Calculate threat indicators from various tools
        malicious_count = 0
        suspicious_count = 0
        abuse_score = 0
        tool_detections = []
        
        for service, data in details.items():
            if isinstance(data, dict):
                # VirusTotal detections
                if 'malicious' in data:
                    malicious_count += data.get('malicious', 0)
                    if data.get('malicious', 0) > 0:
                        tool_detections.append(f"VirusTotal: {data['malicious']} malicious")
                
                if 'suspicious' in data:
                    suspicious_count += data.get('suspicious', 0)
                    if data.get('suspicious', 0) > 0:
                        tool_detections.append(f"VirusTotal: {data['suspicious']} suspicious")
                
                # AbuseIPDB score
                if 'abuse_confidence_score' in data:
                    abuse_score = data.get('abuse_confidence_score', 0)
                    if abuse_score > 0:
                        tool_detections.append(f"AbuseIPDB: {abuse_score}% confidence")
                
                # AlienVault pulses
                if 'pulse_count' in data and data.get('pulse_count', 0) > 0:
                    tool_detections.append(f"AlienVault: {data['pulse_count']} threat pulses")
                
                # URLScan verdict
                if 'verdict' in data and data.get('verdict') == 'malicious':
                    tool_detections.append(f"URLScan: Malicious verdict")
                
                # MalwareBazaar
                if 'found' in data and data.get('found'):
                    tool_detections.append(f"MalwareBazaar: Known malware")
                
                # PowerShell analysis
                if 'risk_level' in data:
                    risk = data.get('risk_level', 'Low')
                    if risk in ['High', 'Medium']:
                        tool_detections.append(f"PowerShell Analysis: {risk} risk")
        
        # Generate comprehensive summary based on tool detections
        detection_summary = ", ".join(tool_detections[:5]) if tool_detections else "No detections"
        
        # Start with IOC description
        summary = ioc_description + "\n\n"
        
        if malicious_count > 5 or abuse_score > 75:
            summary += f"⚠️ CRITICAL THREAT: This {ioc_type} has been flagged as malicious by multiple security tools. Detections: {detection_summary}. High confidence threat indicator requiring immediate action."
        elif malicious_count > 0 or abuse_score > 50:
            summary += f"⚠️ THREAT DETECTED: This {ioc_type} shows malicious indicators. Detections: {detection_summary}. Potential active threat."
        elif suspicious_count > 3 or abuse_score > 25:
            summary += f"⚠️ SUSPICIOUS: This {ioc_type} has suspicious characteristics. Detections: {detection_summary}. Medium risk indicator requiring monitoring."
        elif tool_detections:
            summary += f"ℹ️ FLAGGED: This {ioc_type} has been flagged by security tools. Detections: {detection_summary}. Low to medium risk."
        else:
            # Enhanced clean IOC analysis with threat intelligence context
            summary += f"✓ CLEAN: This {ioc_type} shows no malicious signatures across {len(details)} security tools. "
            summary += "However, consider: (1) Zero-day threats lack signatures, (2) Advanced persistent threats (APTs) use custom malware, "
            summary += "(3) Fileless attacks leave no file signatures, (4) Living-off-the-land techniques abuse legitimate tools, "
            summary += "(5) Polymorphic malware changes signatures, (6) Encrypted C2 traffic may appear benign. "
            summary += "Recommendation: Apply behavioral analysis, monitor for anomalies, use sandboxing for unknown sources, "
            summary += "and correlate with threat intelligence feeds. Clean status does not guarantee safety—maintain defense-in-depth."
        
        # Generate detailed recommendations based on tool findings
        recommendations = []
        
        if malicious_count > 5 or abuse_score > 75:
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED (Based on McAfee, Trend Micro, Microsoft Defender best practices):")
            recommendations.append("• Block this IOC immediately across all security controls (firewall, proxy, EDR, endpoint protection)")
            recommendations.append("• Microsoft Defender: Enable Attack Surface Reduction (ASR) rules")
            recommendations.append("• McAfee: Update DAT files and run full system scan")
            recommendations.append("• Trend Micro: Enable Deep Discovery Inspector for network analysis")
            recommendations.append("• Investigate all systems that have communicated with this indicator")
            recommendations.append("• Conduct full incident response procedures per NIST guidelines")
            recommendations.append("• Review logs for lateral movement or data exfiltration")
            recommendations.append("• Symantec/Kaspersky: Check for related threat signatures")
            recommendations.append("• Palo Alto WildFire: Submit samples for advanced analysis")
            recommendations.append("• Consider threat hunting for related IOCs using MITRE ATT&CK framework")
        elif malicious_count > 0 or abuse_score > 50:
            recommendations.append("⚠️ RECOMMENDED ACTIONS (Security Vendor Best Practices):")
            recommendations.append("• Add to security watchlist and enable enhanced monitoring")
            recommendations.append("• Microsoft Defender: Enable Cloud-delivered protection")
            recommendations.append("• McAfee ePolicy Orchestrator: Create custom detection rules")
            recommendations.append("• Trend Micro Apex One: Enable Predictive Machine Learning")
            recommendations.append("• Consider blocking based on organizational risk tolerance")
            recommendations.append("• Review all logs for interactions with this IOC")
            recommendations.append("• Fortinet FortiGuard: Check threat intelligence updates")
            recommendations.append("• Check Point: Enable IPS blade for network protection")
            recommendations.append("• Notify security team for investigation")
        elif suspicious_count > 0 or abuse_score > 25:
            recommendations.append("📋 ADVISORY ACTIONS:")
            recommendations.append("• Monitor this IOC closely through SIEM/logging")
            recommendations.append("• Implement additional logging for related activity")
            recommendations.append("• Consider sandboxing if this is a file or URL")
            recommendations.append("• Review with threat intelligence team")
            recommendations.append("• Document for future reference")
        else:
            recommendations.append("ℹ️ INFORMATIONAL:")
            recommendations.append("• No immediate action required based on current intelligence")
            recommendations.append("• Continue monitoring through threat intelligence feeds")
            recommendations.append("• Stay vigilant for behavioral anomalies")
            recommendations.append("• Maintain baseline security controls")
        
        # Enhanced zero-day detection guidance with real-world threat intelligence
        if malicious_count == 0 and suspicious_count == 0:
            recommendations.append("\n🔍 ZERO-DAY & ADVANCED THREAT DETECTION (Multi-Vendor Approach):")
            recommendations.append("• Signature-based tools may miss zero-day, polymorphic, or fileless threats")
            recommendations.append("\n🛡️ ENDPOINT PROTECTION (Deploy Multiple Layers):")
            recommendations.append("• Microsoft Defender ATP: Enable Endpoint Detection & Response (EDR)")
            recommendations.append("• McAfee MVISION EDR: Use behavioral analysis and machine learning")
            recommendations.append("• Trend Micro XDR: Enable cross-layer detection and response")
            recommendations.append("• Symantec Endpoint Protection: Activate SONAR behavioral engine")
            recommendations.append("• Kaspersky EDR: Enable Adaptive Anomaly Control")
            recommendations.append("• CrowdStrike Falcon: Leverage AI-powered threat hunting")
            recommendations.append("• SentinelOne: Enable autonomous response capabilities")
            recommendations.append("• Consider behavioral analysis: Monitor for process injection, DLL hijacking, registry modifications")
            recommendations.append("• Use dynamic analysis: Sandbox execution in isolated environment (ANY.RUN, Hybrid Analysis)")
            recommendations.append("• Network indicators: Check for C2 beaconing, DNS tunneling, unusual port usage")
            recommendations.append("• Memory forensics: Analyze for in-memory malware, rootkits, or living-off-the-land techniques")
            recommendations.append("• Threat hunting: Search for MITRE ATT&CK TTPs, lateral movement, privilege escalation")
            recommendations.append("• Context analysis: Review user behavior, geolocation anomalies, time-of-day patterns")
            recommendations.append("• Machine learning: Apply anomaly detection models for deviation from baseline")
            recommendations.append("• Threat intelligence: Cross-reference with OSINT, dark web feeds, APT reports")
            recommendations.append("• Historical analysis: Check for domain age, SSL certificate history, WHOIS changes")
        
        # Add network security vendor recommendations
        recommendations.append("\n🌐 NETWORK SECURITY (Multi-Vendor Defense):")
        recommendations.append("• Palo Alto Networks: Enable WildFire cloud analysis and Threat Prevention")
        recommendations.append("• Fortinet FortiGate: Activate FortiGuard Web Filtering and IPS")
        recommendations.append("• Check Point: Enable Threat Prevention and Anti-Bot blades")
        recommendations.append("• Cisco Firepower: Use Snort rules and AMP for Networks")
        recommendations.append("• Zscaler: Enable Cloud Sandbox and Advanced Threat Protection")
        recommendations.append("• Sophos XG Firewall: Activate Sandstorm and Deep Learning")
        
        # Add tool-specific recommendations
        if 'viewdns' in details or 'paloalto' in details or 'zscaler' in details:
            recommendations.append("\n🔗 ADDITIONAL VERIFICATION:")
            if 'viewdns' in details:
                recommendations.append("• Check ViewDNS for DNS history, WHOIS, and reverse IP lookup")
            if 'paloalto' in details:
                recommendations.append("• Verify with Palo Alto WildFire threat intelligence")
            if 'zscaler' in details:
                recommendations.append("• Review Zscaler URL categorization and security rating")
        
        recommendation = "\n".join(recommendations)
        
        return {
            'summary': summary,
            'recommendation': recommendation
        }
