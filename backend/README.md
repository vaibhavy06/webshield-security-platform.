# WebShield: Website Security Scanner & Risk Intelligence Engine

WebShield is a production-grade backend system designed to analyze the security posture of websites. It performs multi-layered scans (Headers, SSL, Content, Ports) and integrates with threat intelligence services to provide a comprehensive risk score and actionable recommendations.

## 🚀 Features

- **Modular Scanners**: Independently testable modules for different security layers.
- **Parallel Execution**: Uses `asyncio` for high-performance concurrent scanning.
- **Risk Intelligence**: Proprietary scoring engine based on industry best practices.
- **Threat Integration**: Built-in support for VirusTotal and OWASP ZAP.
- **Dockerized**: Easy deployment with Docker and Docker Compose.

## 🛠️ Tech Stack

- **Framework**: FastAPI (Python 3.10+)
- **Analysis**: BeautifulSoup4, Python-nmap, SSL/TLS inspection
- **Integrations**: VirusTotal API, zapv2 (OWASP ZAP)
- **Infrastructure**: Redis, PostgreSQL (optional for reporting history)

## 📦 Setup Instructions

1.  **Clone the repository**
2.  **Create a `.env` file** in the root directory:
    ```env
    VIRUSTOTAL_API_KEY=your_key_here
    ZAP_API_KEY=your_zap_key_here
    DATABASE_URL=postgresql://postgres:postgres@db:5432/webshield
    REDIS_URL=redis://redis:6379/0
    ```
3.  **Run with Docker Compose**:
    ```bash
    docker-compose up --build
    ```
4.  **Access the API**:
    - API: `http://localhost:8000`
    - Documentation (Swagger): `http://localhost:8000/docs`

## 🔍 API Usage

### Start a Scan
**POST** `/api/v1/scan`

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "timestamp": "2024-05-04T10:00:00.000Z",
  "summary": "Security analysis for https://example.com completed.",
  "security": {
    "https": true,
    "ssl": { "valid": true, "expires_in_days": 120, "issuer": "Let's Encrypt" },
    "headers": { "present": ["X-Frame-Options"], "missing": ["Content-Security-Policy"] }
  },
  "risk_score": 75,
  "risk_level": "MODERATE",
  "recommendations": [
    "Implement Content-Security-Policy to prevent XSS attacks."
  ]
}
```

## ⚖️ Legal Disclaimer

This tool is for educational and authorized security testing purposes only. The developers are not responsible for any misuse or illegal activities performed using this software. Only scan targets you own or have explicit permission to test.
