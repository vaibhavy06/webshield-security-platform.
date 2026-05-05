from typing import Any, Dict, List

class RiskEngine:
    def calculate_score(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        score = 100
        recommendations = []
        
        # 1. HTTPS missing (if target was http)
        target_url = scan_results.get('url', '')
        if target_url.startswith('http://'):
            score -= 30
            recommendations.append("Implement HTTPS to encrypt traffic and improve SEO.")

        # 2. SSL Scanner results
        ssl_data = scan_results.get('scanners', {}).get('ssl_scanner', {})
        if ssl_data.get('status') == 'success':
            if not ssl_data.get('valid'):
                score -= 25
                recommendations.append("The SSL certificate is invalid, expired, or self-signed.")
            elif ssl_data.get('expires_in_days', 99) < 15:
                recommendations.append("SSL certificate expires soon. Renew it immediately.")

        # 3. Header Scanner results
        header_data = scan_results.get('scanners', {}).get('header_scanner', {})
        if header_data.get('status') == 'success':
            missing_headers = header_data.get('missing_headers', [])
            score -= (len(missing_headers) * 10)
            for header in missing_headers:
                recommendations.append(f"Missing security header: {header}. Configure it to harden your server.")

        # 4. Content Scanner results
        content_data = scan_results.get('scanners', {}).get('content_scanner', {})
        if content_data.get('status') == 'success':
            if content_data.get('has_suspicious_content'):
                score -= 15
                recommendations.append("Detected a high volume of inline scripts. Consider using external files and a strict CSP.")
            if len(content_data.get('suspicious_iframes', [])) > 0:
                recommendations.append("Detected iframes which can be used for clickjacking or loading malicious content.")

        # 5. Port Scanner results
        port_data = scan_results.get('scanners', {}).get('port_scanner', {})
        if port_data.get('status') == 'success':
            open_ports = port_data.get('open_ports', [])
            risky_ports = [21, 22]
            for p in open_ports:
                if p['port'] in risky_ports:
                    score -= 20
                    recommendations.append(f"Risky port {p['port']} ({p['name']}) is open. Close it if not essential.")

        # 6. Malware (VirusTotal)
        vt_data = scan_results.get('integrations', {}).get('virustotal', {})
        if vt_data.get('status') == 'success':
            if vt_data.get('malicious_count', 0) > 0:
                score -= 50
                recommendations.append("Domain is flagged as malicious by VirusTotal. Investigate immediately.")

        # Clamp score
        score = max(0, min(100, score))
        
        # Determine risk level
        if score >= 80:
            level = "SAFE"
        elif score >= 50:
            level = "MODERATE"
        else:
            level = "HIGH RISK"

        return {
            "risk_score": score,
            "risk_level": level,
            "recommendations": recommendations
        }
