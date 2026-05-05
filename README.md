# WebShield Security Platform

WebShield is a production-grade, full-stack website security scanner and risk intelligence engine. It performs multi-layered scans (Headers, SSL, Content, Ports) and integrates with threat intelligence services to provide a comprehensive risk score and actionable recommendations.

This repository contains both the frontend and backend components in a monorepo structure.

## 🚀 Features

- **Comprehensive Security Scanning**: Analyzes HTTPS/SSL configurations, HTTP security headers, and open ports.
- **Risk Intelligence**: Proprietary scoring engine based on industry best practices for evaluating website security posture.
- **Threat Integration**: Built-in support for VirusTotal and OWASP ZAP.
- **Modern User Interface**: A dynamic, interactive frontend built with React, Vite, and Framer Motion for a premium user experience.
- **High-Performance Backend**: Fast and scalable backend powered by FastAPI (Python) using asynchronous execution (`asyncio`).

## 📁 Repository Structure

- `/backend`: Contains the FastAPI python application.
- `/frontend`: Contains the React/Vite web application.

## 🛠️ Tech Stack

### Frontend
- **Framework**: React, Vite
- **Styling**: Vanilla CSS, Framer Motion (for animations)
- **Icons**: Lucide React

### Backend
- **Framework**: FastAPI (Python 3.10+)
- **Analysis**: BeautifulSoup4, Python-nmap, SSL/TLS inspection
- **Integrations**: VirusTotal API, zapv2 (OWASP ZAP)

## 📦 Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/vaibhavy06/webshield-security-platform..git
cd webshield-security-platform.
```

### 2. Backend Setup
Navigate to the backend directory:
```bash
cd backend
```
Create a `.env` file based on `.env.example`:
```env
VIRUSTOTAL_API_KEY=your_key_here
ZAP_API_KEY=your_zap_key_here
```
Run with Docker Compose (if applicable) or locally using Python:
```bash
pip install -r requirements.txt
uvicorn demo_working:app --reload
```
The API documentation (Swagger) will be available at `http://localhost:8000/docs`.

### 3. Frontend Setup
Navigate to the frontend directory:
```bash
cd frontend
```
Install dependencies and run the development server:
```bash
npm install
npm run dev
```
The web application will be accessible at `http://localhost:5173`.

## 🔍 API Usage Example

**POST** `/api/v1/scan`
**Request:**
```json
{
  "url": "https://example.com"
}
```

## ⚖️ Legal Disclaimer

This tool is for educational and authorized security testing purposes only. The developers are not responsible for any misuse or illegal activities performed using this software. Only scan targets you own or have explicit permission to test.