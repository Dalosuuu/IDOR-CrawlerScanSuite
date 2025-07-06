"""
Reporting module for generating IDOR vulnerability reports
"""
import json
import csv
import html as html_module
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

class Reporter:
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize reporter
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
    def generate_report(self, findings: List[Dict[str, Any]], 
                       scan_info: Dict[str, Any],
                       format_type: str = "html") -> str:
        """
        Generate vulnerability report in specified format
        
        Args:
            findings: List of IDOR findings
            scan_info: Information about the scan
            format_type: Output format ('html', 'json', 'csv', 'txt')
            
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"idor_report_{timestamp}"
        
        if format_type.lower() == "html":
            return self._generate_html_report(findings, scan_info, base_filename)
        elif format_type.lower() == "json":
            return self._generate_json_report(findings, scan_info, base_filename)
        elif format_type.lower() == "csv":
            return self._generate_csv_report(findings, scan_info, base_filename)
        elif format_type.lower() == "txt":
            return self._generate_txt_report(findings, scan_info, base_filename)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_html_report(self, findings: List[Dict[str, Any]], 
                             scan_info: Dict[str, Any], 
                             base_filename: str) -> str:
        """Generate HTML report"""
        filepath = self.output_dir / f"{base_filename}.html"
        
        # Categorize findings by risk level
        high_risk = [f for f in findings if f['risk_level'] == 'HIGH']
        medium_risk = [f for f in findings if f['risk_level'] == 'MEDIUM']
        low_risk = [f for f in findings if f['risk_level'] == 'LOW']
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDOR Vulnerability Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .summary {{
            padding: 30px;
            background: #fff;
            border-bottom: 1px solid #eee;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #007bff;
        }}
        .summary-card.high {{ border-left-color: #dc3545; }}
        .summary-card.medium {{ border-left-color: #fd7e14; }}
        .summary-card.low {{ border-left-color: #28a745; }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 2em;
            color: #333;
        }}
        .risk-section {{
            margin: 30px;
        }}
        .risk-title {{
            font-size: 1.5em;
            margin-bottom: 20px;
            padding: 10px 0;
            border-bottom: 2px solid;
        }}
        .risk-title.high {{ color: #dc3545; border-color: #dc3545; }}
        .risk-title.medium {{ color: #fd7e14; border-color: #fd7e14; }}
        .risk-title.low {{ color: #28a745; border-color: #28a745; }}
        .finding {{
            background: #f8f9fa;
            margin: 15px 0;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #dee2e6;
        }}
        .finding-header {{
            background: #e9ecef;
            padding: 15px 20px;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .finding-header:hover {{
            background: #dee2e6;
        }}
        .finding-content {{
            padding: 20px;
            display: none;
        }}
        .finding-content.expanded {{
            display: block;
        }}
        .finding-detail {{
            margin: 10px 0;
        }}
        .finding-detail strong {{
            color: #495057;
        }}
        .code {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            margin: 5px 0;
        }}
        .reasons {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
        }}
        .reasons ul {{
            margin: 5px 0;
            padding-left: 20px;
        }}
        .toggle-icon {{
            transition: transform 0.3s ease;
        }}
        .toggle-icon.expanded {{
            transform: rotate(90deg);
        }}
        .footer {{
            background: #343a40;
            color: white;
            padding: 20px;
            text-align: center;
        }}
    </style>
    <script>
        function toggleFinding(element) {{
            const content = element.nextElementSibling;
            const icon = element.querySelector('.toggle-icon');
            
            if (content.classList.contains('expanded')) {{
                content.classList.remove('expanded');
                icon.classList.remove('expanded');
            }} else {{
                content.classList.add('expanded');
                icon.classList.add('expanded');
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IDOR Vulnerability Report</h1>
            <p>Automated Insecure Direct Object Reference Detection</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>{scan_info.get('target_url', 'N/A')}</h3>
                    <p>Target URL</p>
                </div>
                <div class="summary-card">
                    <h3>{scan_info.get('total_urls', 0)}</h3>
                    <p>URLs Scanned</p>
                </div>
                <div class="summary-card">
                    <h3>{scan_info.get('total_parameters', 0)}</h3>
                    <p>Parameters Tested</p>
                </div>
                <div class="summary-card">
                    <h3>{len(findings)}</h3>
                    <p>Total Findings</p>
                </div>
                <div class="summary-card high">
                    <h3>{len(high_risk)}</h3>
                    <p>High Risk</p>
                </div>
                <div class="summary-card medium">
                    <h3>{len(medium_risk)}</h3>
                    <p>Medium Risk</p>
                </div>
                <div class="summary-card low">
                    <h3>{len(low_risk)}</h3>
                    <p>Low Risk</p>
                </div>
            </div>
            <p><strong>Scan Date:</strong> {scan_info.get('scan_date', 'N/A')}</p>
            <p><strong>Duration:</strong> {scan_info.get('duration', 'N/A')}</p>
        </div>
        
        {self._generate_findings_html(high_risk, "HIGH", "high")}
        {self._generate_findings_html(medium_risk, "MEDIUM", "medium")}
        {self._generate_findings_html(low_risk, "LOW", "low")}
        
        <div class="footer">
            <p>Generated by IDOR Scanner v1.0 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {filepath}")
        return str(filepath)
    
    def _generate_findings_html(self, findings: List[Dict[str, Any]], 
                               risk_level: str, css_class: str) -> str:
        """Generate HTML for findings of a specific risk level"""
        if not findings:
            return ""
        
        html = f'''
        <div class="risk-section">
            <h2 class="risk-title {css_class}">{risk_level} Risk Findings ({len(findings)})</h2>
'''
        
        for i, finding in enumerate(findings):
            reasons_html = "<ul>" + "".join(f"<li>{html_module.escape(reason)}</li>" for reason in finding.get('reasons', [])) + "</ul>"
            
            html += f'''
            <div class="finding">
                <div class="finding-header" onclick="toggleFinding(this)">
                    <span>{html_module.escape(finding.get('parameter', 'Unknown Parameter'))} - {html_module.escape(finding.get('url', 'Unknown URL'))}</span>
                    <span class="toggle-icon">▶</span>
                </div>
                <div class="finding-content">
                    <div class="finding-detail">
                        <strong>Parameter:</strong> {html_module.escape(finding.get('parameter', 'N/A'))}
                    </div>
                    <div class="finding-detail">
                        <strong>Original Value:</strong> 
                        <div class="code">{html_module.escape(finding.get('original_value', 'N/A'))}</div>
                    </div>
                    <div class="finding-detail">
                        <strong>Test Value:</strong> 
                        <div class="code">{html_module.escape(finding.get('test_value', 'N/A'))}</div>
                    </div>
                    <div class="finding-detail">
                        <strong>Vulnerable URL:</strong> 
                        <div class="code">{html_module.escape(finding.get('url', 'N/A'))}</div>
                    </div>
                    <div class="finding-detail">
                        <strong>Confidence Score:</strong> {finding.get('confidence', 0)}/10
                    </div>
                    <div class="finding-detail">
                        <strong>Response Status:</strong> {finding.get('original_status', 'N/A')} → {finding.get('test_status', 'N/A')}
                    </div>
                    <div class="finding-detail">
                        <strong>Content Similarity:</strong> {finding.get('content_similarity', 0):.2f}
                    </div>
                    <div class="reasons">
                        <strong>Evidence:</strong>
                        {reasons_html}
                    </div>
                </div>
            </div>
'''
        
        html += "</div>"
        return html
    
    def _generate_json_report(self, findings: List[Dict[str, Any]], 
                             scan_info: Dict[str, Any], 
                             base_filename: str) -> str:
        """Generate JSON report"""
        filepath = self.output_dir / f"{base_filename}.json"
        
        report_data = {
            "scan_info": scan_info,
            "summary": {
                "total_findings": len(findings),
                "high_risk": len([f for f in findings if f['risk_level'] == 'HIGH']),
                "medium_risk": len([f for f in findings if f['risk_level'] == 'MEDIUM']),
                "low_risk": len([f for f in findings if f['risk_level'] == 'LOW'])
            },
            "findings": findings,
            "generated_at": datetime.now().isoformat()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"JSON report generated: {filepath}")
        return str(filepath)
    
    def _generate_csv_report(self, findings: List[Dict[str, Any]], 
                            scan_info: Dict[str, Any], 
                            base_filename: str) -> str:
        """Generate CSV report"""
        filepath = self.output_dir / f"{base_filename}.csv"
        
        fieldnames = [
            'parameter', 'original_value', 'test_value', 'url', 'original_url',
            'risk_level', 'confidence', 'original_status', 'test_status',
            'content_similarity', 'reasons'
        ]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in findings:
                row = {}
                for field in fieldnames:
                    value = finding.get(field, '')
                    if field == 'reasons' and isinstance(value, list):
                        value = '; '.join(value)
                    row[field] = value
                writer.writerow(row)
        
        self.logger.info(f"CSV report generated: {filepath}")
        return str(filepath)
    
    def _generate_txt_report(self, findings: List[Dict[str, Any]], 
                            scan_info: Dict[str, Any], 
                            base_filename: str) -> str:
        """Generate text report"""
        filepath = self.output_dir / f"{base_filename}.txt"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\\n")
            f.write("IDOR VULNERABILITY REPORT\\n")
            f.write("=" * 80 + "\\n\\n")
            
            f.write("SCAN SUMMARY:\\n")
            f.write("-" * 40 + "\\n")
            f.write(f"Target URL: {scan_info.get('target_url', 'N/A')}\\n")
            f.write(f"Scan Date: {scan_info.get('scan_date', 'N/A')}\\n")
            f.write(f"Duration: {scan_info.get('duration', 'N/A')}\\n")
            f.write(f"URLs Scanned: {scan_info.get('total_urls', 0)}\\n")
            f.write(f"Parameters Tested: {scan_info.get('total_parameters', 0)}\\n")
            f.write(f"Total Findings: {len(findings)}\\n\\n")
            
            # Group by risk level
            for risk_level in ['HIGH', 'MEDIUM', 'LOW']:
                risk_findings = [f for f in findings if f['risk_level'] == risk_level]
                if risk_findings:
                    f.write(f"{risk_level} RISK FINDINGS ({len(risk_findings)}):\\n")
                    f.write("-" * 40 + "\\n")
                    
                    for i, finding in enumerate(risk_findings, 1):
                        f.write(f"\\n{i}. {finding.get('parameter', 'Unknown Parameter')}\\n")
                        f.write(f"   URL: {finding.get('url', 'N/A')}\\n")
                        f.write(f"   Original Value: {finding.get('original_value', 'N/A')}\\n")
                        f.write(f"   Test Value: {finding.get('test_value', 'N/A')}\\n")
                        f.write(f"   Confidence: {finding.get('confidence', 0)}/10\\n")
                        f.write(f"   Status: {finding.get('original_status', 'N/A')} → {finding.get('test_status', 'N/A')}\\n")
                        f.write(f"   Evidence:\\n")
                        for reason in finding.get('reasons', []):
                            f.write(f"     - {reason}\\n")
                    f.write("\\n")
            
            f.write("=" * 80 + "\\n")
            f.write(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
        
        self.logger.info(f"Text report generated: {filepath}")
        return str(filepath)
    
    def print_summary(self, findings: List[Dict[str, Any]]) -> None:
        """Print a summary of findings to console"""
        if not findings:
            print("No IDOR vulnerabilities found!")
            return
        
        high_risk = [f for f in findings if f['risk_level'] == 'HIGH']
        medium_risk = [f for f in findings if f['risk_level'] == 'MEDIUM']
        low_risk = [f for f in findings if f['risk_level'] == 'LOW']
        
        print(f"\\nIDOR Scan Results:")
        print(f"{'='*50}")
        print(f"Total Findings: {len(findings)}")
        print(f"🔴 High Risk: {len(high_risk)}")
        print(f"🟡 Medium Risk: {len(medium_risk)}")
        print(f"🟢 Low Risk: {len(low_risk)}")
        print(f"{'='*50}")
        
        # Show top findings
        if high_risk:
            print(f"🔴 High Risk Findings:")
            for finding in high_risk[:3]:  # Show top 3
                print(f"  • {finding.get('parameter', 'Unknown')} in {finding.get('url', 'Unknown URL')}")
                print(f"    Confidence: {finding.get('confidence', 0)}/10")
        
        if medium_risk and len(high_risk) < 3:
            print(f"🟡 Medium Risk Findings:")
            remaining_slots = 3 - len(high_risk)
            for finding in medium_risk[:remaining_slots]:
                print(f"  • {finding.get('parameter', 'Unknown')} in {finding.get('url', 'Unknown URL')}")
                print(f"    Confidence: {finding.get('confidence', 0)}/10")
