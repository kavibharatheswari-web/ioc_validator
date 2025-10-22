# IOC Validator - Advanced Threat Intelligence Platform

A comprehensive web-based tool for analyzing Indicators of Compromise (IOCs) including IPs, domains, URLs, file hashes, emails, malicious code, PowerShell commands, and more.

## Features

### 🔍 Multi-IOC Analysis
- **IP Addresses** - IPv4 and IPv6 support
- **Domains & URLs** - Reputation and threat analysis
- **File Hashes** - MD5, SHA1, SHA256 malware detection
- **Email Addresses** - Phishing and spam detection
- **PowerShell Commands** - Malicious script detection
- **File Extensions & Packages** - Risk assessment

### 🛡️ Security Tool Integration
- **VirusTotal** - Comprehensive malware scanning
- **AbuseIPDB** - IP reputation and abuse reports
- **AlienVault OTX** - Open threat intelligence (Free)
- **URLScan.io** - URL analysis and screenshots (Free)
- **MalwareBazaar** - Malware sample database (Free)
- **Hybrid Analysis** - Advanced malware analysis
- **Cisco Talos** - Threat intelligence
- **IPVoid** - IP blacklist checking
- **ViewDNS** - DNS and domain tools
- **Zscaler & Palo Alto** - Enterprise security integration

### 🤖 AI-Powered Analysis
- **Zero-Day Detection** - AI model for unknown threats
- **Threat Summarization** - Automated analysis summaries
- **Smart Recommendations** - Actionable security advice
- **Behavioral Analysis** - Pattern recognition using Hugging Face models

### 📊 Advanced Features
- **User Authentication** - Secure login and registration
- **API Key Management** - Personal API key storage
- **Batch Analysis** - Upload files or paste multiple IOCs
- **Detailed Reports** - Comprehensive threat intelligence
- **PDF Export** - Download analysis reports with timestamps
- **Analysis History** - Track all previous scans
- **Real-time Dashboard** - Threat statistics and metrics
- **Severity Scoring** - Critical, High, Medium, Low classifications

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- 2GB RAM minimum (4GB recommended for AI models)

### Setup Instructions

1. **Clone or download the project**
```bash
cd windsurf-project-8
```

2. **Create a virtual environment (recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env and set your SECRET_KEY
```

5. **Initialize the database**
```bash
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

6. **Run the application**
```bash
python app.py
```

7. **Access the application**
Open your browser and navigate to: `http://localhost:5000`

## Usage Guide

### 1. Register an Account
- Click "Register" on the login page
- Enter your username, email, and password
- Click "Register" to create your account

### 2. Configure API Keys (Optional but Recommended)
- Navigate to "Settings" after logging in
- Add API keys for various security tools:
  - **VirusTotal**: Get free API key at https://www.virustotal.com/gui/join-us
  - **AbuseIPDB**: Register at https://www.abuseipdb.com/register
  - **Hybrid Analysis**: Sign up at https://www.hybrid-analysis.com/signup
- Note: Some tools work without API keys (AlienVault OTX, URLScan.io, MalwareBazaar)

### 3. Analyze IOCs

#### Text Input Method:
1. Go to "Analyze" section
2. Select "Text Input" tab
3. Enter IOCs (one per line):
   ```
   192.168.1.1
   malicious-domain.com
   http://suspicious-url.com
   5d41402abc4b2a76b9719d911017c592
   ```
4. Click "Analyze"

#### File Upload Method:
1. Go to "Analyze" section
2. Select "File Upload" tab
3. Upload a .txt or .csv file containing IOCs (one per line)
4. Click "Analyze File"

### 4. View Results
- **Summary Table**: Shows IOC, type, threat score, severity, and category
- **Detailed Report**: Click "View Details" for comprehensive analysis
- **Tool Results**: See results from each security tool
- **AI Analysis**: View AI-generated summary and recommendations
- **Export PDF**: Download complete report with timestamp

### 5. Review History
- Navigate to "History" section
- View all previous analyses
- Click "View" to see detailed reports
- Track threat trends over time

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### API Key Management
- `GET /api/keys` - Get user's API keys
- `POST /api/keys` - Add/update API key
- `DELETE /api/keys/<id>` - Delete API key

### IOC Analysis
- `POST /api/analyze` - Analyze IOCs (text or file)
- `GET /api/history` - Get analysis history
- `GET /api/report/<id>` - Get detailed report
- `POST /api/export/pdf` - Export reports as PDF

## Security Features

### Data Protection
- Password hashing using Werkzeug
- JWT token-based authentication
- Encrypted API key storage
- Secure session management

### Privacy
- User data isolation
- No IOC data sharing
- Local database storage
- Optional API key usage

## AI Model Information

The application uses the following AI capabilities:

### Primary Model
- **DistilGPT2** - Lightweight text generation model from Hugging Face
- Used for threat summarization and recommendations
- Runs locally without external API calls
- Automatic fallback to rule-based analysis if model unavailable

### Zero-Day Detection
- Pattern recognition for unknown threats
- Behavioral analysis of suspicious indicators
- Confidence scoring for novel threats
- Continuous learning from threat intelligence feeds

## Troubleshooting

### Common Issues

**1. AI Model Loading Error**
```
Warning: Could not load AI model
```
- Solution: The app will use rule-based analysis instead
- Optional: Install torch with CUDA support for GPU acceleration

**2. API Rate Limits**
- Free API keys have rate limits
- Solution: Wait before making more requests or upgrade to paid plans

**3. Database Locked Error**
- Solution: Ensure only one instance of the app is running
- Delete `ioc_validator.db` and restart to reset database

**4. Port Already in Use**
- Solution: Change port in `app.py`: `app.run(port=5001)`

## Performance Optimization

### For Better Performance:
1. **GPU Acceleration**: Install CUDA-enabled PyTorch for faster AI analysis
2. **API Keys**: Configure API keys for more comprehensive results
3. **Batch Size**: Analyze IOCs in batches of 10-20 for optimal speed
4. **Caching**: Results are cached in database to avoid redundant API calls

## Contributing

Contributions are welcome! Areas for improvement:
- Additional security tool integrations
- Enhanced AI models
- UI/UX improvements
- Performance optimizations
- Additional IOC types

## License

This project is open source and available for educational and commercial use.

## Disclaimer

This tool is for security research and threat intelligence purposes. Users are responsible for:
- Obtaining necessary API keys
- Complying with API terms of service
- Using the tool ethically and legally
- Verifying results before taking action

## Support

For issues, questions, or feature requests:
1. Check the troubleshooting section
2. Review API documentation for integrated tools
3. Ensure all dependencies are properly installed

## Version History

### v1.0.0 (Current)
- Initial release
- Multi-IOC type support
- 10+ security tool integrations
- AI-powered analysis
- PDF export functionality
- User authentication and API key management

## Roadmap

### Planned Features:
- [ ] Bulk file analysis (ZIP archives)
- [ ] Scheduled scans
- [ ] Email notifications
- [ ] API webhooks
- [ ] Team collaboration features
- [ ] Custom threat intelligence feeds
- [ ] Advanced visualization dashboards
- [ ] Mobile responsive design improvements
