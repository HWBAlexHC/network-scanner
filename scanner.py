import nmap
from datetime import datetime

FINDINGS = {
    21:  {"severity": "HIGH",   "name": "FTP",     "description": "FTP transfers data unencrypted, including passwords. Use SFTP instead."},
    22:  {"severity": "INFO",   "name": "SSH",     "description": "SSH is generally secure but ensure password authentication is disabled in favor of key-based auth."},
    23:  {"severity": "HIGH",   "name": "Telnet",  "description": "Telnet transmits all data including passwords in plaintext. Disable immediately and replace with SSH."},
    25:  {"severity": "MEDIUM", "name": "SMTP",    "description": "Mail server exposed. Ensure it is not an open relay and requires authentication."},
    53:  {"severity": "INFO",   "name": "DNS",     "description": "DNS service running. Ensure it is not configured as an open resolver."},
    80:  {"severity": "INFO",   "name": "HTTP",    "description": "Unencrypted web traffic. Consider enforcing HTTPS."},
    111: {"severity": "MEDIUM", "name": "RPCBind", "description": "RPCBind can expose sensitive network services. Should not be publicly accessible."},
    139: {"severity": "MEDIUM", "name": "NetBIOS", "description": "NetBIOS can leak system information. Should not be exposed outside internal network."},
    445: {"severity": "HIGH",   "name": "SMB",     "description": "SMB has a history of critical vulnerabilities (e.g. WannaCry). Should not be publicly exposed."},
    512: {"severity": "HIGH",   "name": "Exec",    "description": "Remote exec service is insecure and outdated. Disable immediately."},
    513: {"severity": "HIGH",   "name": "Login",   "description": "Remote login service is insecure and outdated. Disable immediately."},
    514: {"severity": "HIGH",   "name": "Shell",   "description": "Remote shell service is insecure and outdated. Disable immediately."},
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
SEVERITY_COLOR = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "INFO": "#3498db"}
SEVERITY_BG    = {"HIGH": "#fdf0f0", "MEDIUM": "#fdf6e3", "INFO": "#eaf4fb"}

def scan_target(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target}...")
    scanner.scan(target, '1-1024')

    all_findings = []

    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            for port in sorted(scanner[host][protocol].keys()):
                state = scanner[host][protocol][port]['state']
                if state == 'open':
                    if port in FINDINGS:
                        all_findings.append((port, protocol, FINDINGS[port]))
                    else:
                        all_findings.append((port, protocol, {
                            "severity": "INFO",
                            "name": scanner[host][protocol][port]['name'],
                            "description": "No specific rule for this port. Investigate if unexpected."
                        }))

    all_findings.sort(key=lambda x: SEVERITY_ORDER[x[2]['severity']])

    high   = sum(1 for _,_,f in all_findings if f['severity'] == 'HIGH')
    medium = sum(1 for _,_,f in all_findings if f['severity'] == 'MEDIUM')
    info   = sum(1 for _,_,f in all_findings if f['severity'] == 'INFO')

    # Build findings HTML
    findings_html = ""
    for port, protocol, finding in all_findings:
        color = SEVERITY_COLOR[finding['severity']]
        bg    = SEVERITY_BG[finding['severity']]
        findings_html += f"""
        <div style="background:{bg}; border-left: 5px solid {color}; padding: 16px; margin-bottom: 16px; border-radius: 4px;">
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">
                <span style="background:{color}; color:white; padding:3px 10px; border-radius:12px; font-size:13px; font-weight:bold;">{finding['severity']}</span>
                <strong style="font-size:16px;">Port {port}/{protocol} — {finding['name']}</strong>
            </div>
            <p style="margin:0; color:#444;">{finding['description']}</p>
        </div>
        """

    # Build full HTML report
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Report — {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 860px; margin: 40px auto; padding: 0 20px; color: #222; }}
        h1 {{ font-size: 26px; margin-bottom: 4px; }}
        .meta {{ color: #666; font-size: 14px; margin-bottom: 32px; }}
        .summary {{ display: flex; gap: 16px; margin-bottom: 32px; }}
        .summary-box {{ flex: 1; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-box .count {{ font-size: 36px; font-weight: bold; }}
        .summary-box .label {{ font-size: 13px; margin-top: 4px; }}
        h2 {{ font-size: 20px; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Network Security Report</h1>
    <div class="meta">
        Target: <strong>{target}</strong> &nbsp;|&nbsp; 
        Scan date: <strong>{datetime.now().strftime('%B %d, %Y %H:%M')}</strong> &nbsp;|&nbsp;
        Port range: <strong>1–1024</strong>
    </div>

    <h2>Summary</h2>
    <div class="summary">
        <div class="summary-box" style="background:#fdf0f0;">
            <div class="count" style="color:#e74c3c;">{high}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-box" style="background:#fdf6e3;">
            <div class="count" style="color:#f39c12;">{medium}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-box" style="background:#eaf4fb;">
            <div class="count" style="color:#3498db;">{info}</div>
            <div class="label">Info</div>
        </div>
    </div>

    <h2>Findings</h2>
    {findings_html}

    <p style="color:#aaa; font-size:13px; margin-top:40px;">Generated by  Network Scanner · {datetime.now().strftime('%Y')}</p>
</body>
</html>"""

    filename = f"report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w') as f:
        f.write(html)

    print(f"\nReport saved: {filename}")
    print(f"Summary: {high} High | {medium} Medium | {info} Info")
    return filename

scan_target('192.168.56.101')