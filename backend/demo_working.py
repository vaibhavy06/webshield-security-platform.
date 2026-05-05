import asyncio
import json
from app.core.orchestrator import ScanOrchestrator

async def demo_scan():
    orchestrator = ScanOrchestrator()
    target_url = "https://www.google.com"
    
    print(f"[*] Initiating Live Scan for: {target_url}...")
    print("-" * 50)
    
    try:
        report = await orchestrator.run_scan(target_url)
        
        # Displaying key parts of the report
        print(f"[+] Scan Status: Completed")
        print(f"[!] Risk Score: {report['risk_score']}/100")
        print(f"[!] Risk Level: {report['risk_level']}")
        
        print("\n[#] Security Analysis:")
        print(f"  - HTTPS: {'Enabled' if report['security']['https'] else 'Disabled'}")
        
        ssl = report['security']['ssl']
        if ssl and ssl.get('status') == 'success':
            print(f"  - SSL Issuer: {ssl.get('issuer')}")
            print(f"  - SSL Expiry: {ssl.get('expires_in_days')} days")
        
        print("\n[!] Findings:")
        headers = report['security']['headers']
        if headers:
            print(f"  - Missing Headers: {len(headers.get('missing_headers', []))}")
        
        ports = report['findings']['ports']
        if ports:
            print(f"  - Open Ports: {[p['port'] for p in ports]}")
        
        print("\n[>] Recommendations:")
        for rec in report['recommendations'][:3]: # Show top 3
            print(f"  - {rec}")
            
        print("-" * 50)
        # print("\nFull JSON Report Sample (Truncated):")
        # print(json.dumps(report, indent=2)[:500] + "...")

    except Exception as e:
        print(f"❌ Scan Failed: {str(e)}")

if __name__ == "__main__":
    asyncio.run(demo_scan())
