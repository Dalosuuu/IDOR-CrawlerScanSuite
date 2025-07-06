#!/usr/bin/env python3
"""
Enhanced IDOR (Insecure Direct Object Reference) Vulnerability Scanner
A comprehensive tool for discovering IDOR vulnerabilities in web applications.

Developed for security research and penetration testing.
Version: 2.0
"""

import argparse
import logging
import sys
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Import our modules
from .crawler import WebCrawler
from .parameter_identifier import ParameterIdentifier
from .idor_tester import IDORTester
from .session_manager import SessionManager
from .reporter import Reporter

class IDORScanner:
    def __init__(self, target_url: str, **kwargs):
        """
        Initialize the IDOR scanner
        
        Args:
            target_url: Target website URL
            **kwargs: Additional configuration options
        """
        self.target_url = target_url
        self.config = kwargs
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.session_manager = SessionManager(rate_limit=self.config.get('rate_limit', 1.0))
        self.crawler = WebCrawler(
            self.session_manager.get_session(),
            rate_limit=self.config.get('rate_limit', 1.0),
            max_depth=self.config.get('max_depth', 3)
        )
        self.parameter_identifier = ParameterIdentifier()
        self.idor_tester = IDORTester(
            self.session_manager.get_session(),
            rate_limit=self.config.get('rate_limit', 1.0)
        )
        self.reporter = Reporter(output_dir=self.config.get('output_dir', 'reports'))
        
        # Scan statistics
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'urls_crawled': 0,
            'forms_found': 0,
            'parameters_tested': 0,
            'findings': []
        }
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('idor_scanner.log')
            ]
        )
    
    def authenticate(self, login_url: str, username: str, password: str, 
                    username_field: str = 'username', password_field: str = 'password',
                    extra_fields: Optional[Dict[str, str]] = None) -> bool:
        """
        Authenticate with the target application
        
        Args:
            login_url: URL of the login page
            username: Username for authentication
            password: Password for authentication
            username_field: Name of the username field (default: 'username')
            password_field: Name of the password field (default: 'password')
            extra_fields: Additional form fields required
            
        Returns:
            True if authentication successful
        """
        self.logger.info("Starting authentication...")
        return self.session_manager.login(
            login_url, username, password, 
            username_field, password_field, extra_fields
        )
    
    def set_cookies(self, cookies: Dict[str, str]) -> bool:
        """
        Set authentication cookies directly
        
        Args:
            cookies: Dictionary of cookie name-value pairs
            
        Returns:
            True if cookies set successfully
        """
        return self.session_manager.login_with_cookies(cookies)
    
    def set_headers(self, headers: Dict[str, str]) -> None:
        """
        Set additional headers for requests
        
        Args:
            headers: Dictionary of header name-value pairs
        """
        self.session_manager.set_headers(headers)
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Perform comprehensive IDOR vulnerability scan
        
        Returns:
            List of discovered IDOR vulnerabilities
        """
        self.scan_stats['start_time'] = datetime.now()
        self.logger.info(f"Starting IDOR scan of {self.target_url}")
        
        try:
            # Phase 1: Crawl the website
            self.logger.info("Phase 1: Crawling website...")
            discovered_urls, discovered_forms = self.crawler.crawl(self.target_url)
            
            self.scan_stats['urls_crawled'] = len(discovered_urls)
            self.scan_stats['forms_found'] = len(discovered_forms)
            
            self.logger.info(f"Discovered {len(discovered_urls)} URLs and {len(discovered_forms)} forms")
            
            # Phase 2: Identify potentially vulnerable parameters
            self.logger.info("Phase 2: Identifying potentially vulnerable parameters...")
            all_parameters = []
            
            # Analyze URL parameters
            for url in discovered_urls:
                parameters = self.parameter_identifier.identify_parameters(url)
                all_parameters.extend(parameters)
            
            # Analyze form parameters
            for form in discovered_forms:
                parameters = self.parameter_identifier.identify_parameters(
                    form['source_url'], form
                )
                all_parameters.extend(parameters)
            
            # Filter parameters by suspicion score
            suspicious_parameters = self.parameter_identifier.filter_parameters(
                all_parameters, min_score=self.config.get('min_suspicion_score', 2)
            )
            
            self.scan_stats['parameters_tested'] = len(suspicious_parameters)
            self.logger.info(f"Found {len(suspicious_parameters)} potentially vulnerable parameters")
            
            # Phase 3: Test for IDOR vulnerabilities
            self.logger.info("Phase 3: Testing for IDOR vulnerabilities...")
            all_findings = []
            
            for param_info in suspicious_parameters:
                self.logger.debug(f"Testing parameter: {param_info['name']} = {param_info['value']}")
                
                if param_info['source'] == 'url':
                    # Test URL parameter
                    findings = self.idor_tester.test_url_parameter(
                        param_info['source_url'], param_info
                    )
                elif param_info['source'] == 'form':
                    # Find the form data for this parameter
                    form_data = next(
                        (form for form in discovered_forms 
                         if form.get('action') == param_info.get('form_action')), 
                        None
                    )
                    if form_data:
                        findings = self.idor_tester.test_form_parameter(form_data, param_info)
                    else:
                        findings = []
                
                all_findings.extend(findings)
                
                # Progress update
                if len(all_findings) > 0:
                    self.logger.info(f"Found {len(all_findings)} potential vulnerabilities so far...")
            
            self.scan_stats['findings'] = all_findings
            self.scan_stats['end_time'] = datetime.now()
            
            self.logger.info(f"Scan completed! Found {len(all_findings)} potential IDOR vulnerabilities")
            
            return all_findings
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            return []
        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            return []
    
    def generate_report(self, findings: List[Dict[str, Any]], 
                       format_type: str = 'html') -> str:
        """
        Generate vulnerability report
        
        Args:
            findings: List of IDOR findings
            format_type: Report format ('html', 'json', 'csv', 'txt')
            
        Returns:
            Path to generated report
        """
        scan_info = {
            'target_url': self.target_url,
            'scan_date': self.scan_stats['start_time'].strftime('%Y-%m-%d %H:%M:%S') if self.scan_stats['start_time'] else 'N/A',
            'duration': str(self.scan_stats['end_time'] - self.scan_stats['start_time']) if self.scan_stats['start_time'] and self.scan_stats['end_time'] else 'N/A',
            'total_urls': self.scan_stats['urls_crawled'],
            'total_forms': self.scan_stats['forms_found'],
            'total_parameters': self.scan_stats['parameters_tested'],
            'scanner_version': '2.0'
        }
        
        return self.reporter.generate_report(findings, scan_info, format_type)
    
    def print_summary(self, findings: List[Dict[str, Any]]) -> None:
        """Print scan summary to console"""
        self.reporter.print_summary(findings)


def main():
    """Main function to run the IDOR scanner"""
    parser = argparse.ArgumentParser(
        description="Enhanced IDOR Vulnerability Scanner for Bug Bounty Hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python main.py -u https://example.com
  
  # Authenticated scan with login
  python main.py -u https://example.com --login-url https://example.com/login \\
                 --username user@example.com --password password123
  
  # Scan with custom headers and cookies
  python main.py -u https://example.com --headers "Authorization: Bearer token123" \\
                 --cookies "session=abc123;csrf=xyz789"
  
  # Generate multiple report formats
  python main.py -u https://example.com --reports html,json,csv
  
  # Adjust scan parameters
  python main.py -u https://example.com --max-depth 5 --rate-limit 0.5 \\
                 --min-score 3 --output-dir ./my_reports
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL to scan')
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument('--login-url',
                           help='URL of the login page')
    auth_group.add_argument('--username',
                           help='Username for authentication')
    auth_group.add_argument('--password',
                           help='Password for authentication')
    auth_group.add_argument('--username-field', default='username',
                           help='Name of the username field (default: username)')
    auth_group.add_argument('--password-field', default='password',
                           help='Name of the password field (default: password)')
    auth_group.add_argument('--cookies',
                           help='Authentication cookies in format "name1=value1;name2=value2"')
    auth_group.add_argument('--headers',
                           help='Additional headers in format "Header1: value1;Header2: value2"')
    
    # Scan configuration
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('--max-depth', type=int, default=3,
                           help='Maximum crawling depth (default: 3)')
    scan_group.add_argument('--rate-limit', type=float, default=1.0,
                           help='Delay between requests in seconds (default: 1.0)')
    scan_group.add_argument('--min-score', type=int, default=2,
                           help='Minimum suspicion score for parameters (default: 2)')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output-dir', default='reports',
                             help='Directory to save reports (default: reports)')
    output_group.add_argument('--reports', default='html',
                             help='Report formats: html,json,csv,txt (default: html)')
    output_group.add_argument('--log-level', default='INFO',
                             choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                             help='Logging level (default: INFO)')
    output_group.add_argument('--no-summary', action='store_true',
                             help='Don\'t print summary to console')
    
    args = parser.parse_args()
    
    # Validate URL
    parsed_url = urlparse(args.url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print("Error: Invalid URL provided. Must include scheme (http/https)")
        sys.exit(1)
    
    # Initialize scanner
    scanner = IDORScanner(
        args.url,
        max_depth=args.max_depth,
        rate_limit=args.rate_limit,
        min_suspicion_score=args.min_score,
        output_dir=args.output_dir,
        log_level=args.log_level
    )
    
    # Setup authentication if provided
    if args.login_url and args.username and args.password:
        success = scanner.authenticate(
            args.login_url, args.username, args.password,
            args.username_field, args.password_field
        )
        if not success:
            print("Error: Authentication failed")
            sys.exit(1)
    
    # Set cookies if provided
    if args.cookies:
        cookies = {}
        for cookie_pair in args.cookies.split(';'):
            if '=' in cookie_pair:
                name, value = cookie_pair.strip().split('=', 1)
                cookies[name] = value
        scanner.set_cookies(cookies)
    
    # Set headers if provided
    if args.headers:
        headers = {}
        for header_pair in args.headers.split(';'):
            if ':' in header_pair:
                name, value = header_pair.strip().split(':', 1)
                headers[name] = value.strip()
        scanner.set_headers(headers)
    
    # Perform scan
    print(f"Starting IDOR scan of {args.url}")
    print(f"Configuration: max_depth={args.max_depth}, rate_limit={args.rate_limit}s")
    print("-" * 60)
    
    findings = scanner.scan()
    
    # Generate reports
    report_formats = [fmt.strip() for fmt in args.reports.split(',')]
    generated_reports = []
    
    for format_type in report_formats:
        try:
            report_path = scanner.generate_report(findings, format_type)
            generated_reports.append(report_path)
            print(f"Report generated ({format_type.upper()}): {report_path}")
        except Exception as e:
            print(f"Error generating {format_type} report: {e}")
    
    # Print summary
    if not args.no_summary:
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        scanner.print_summary(findings)
    
    # Final message
    if findings:
        high_risk_count = len([f for f in findings if f['risk_level'] == 'HIGH'])
        if high_risk_count > 0:
            print(f"\nFound {high_risk_count} HIGH risk IDOR vulnerabilities!")
            print("These should be prioritized for manual verification.")
        else:
            print(f"\nFound {len(findings)} potential IDOR vulnerabilities to investigate.")
    else:
        print("\nNo IDOR vulnerabilities detected in this scan.")
    
    print("\nScan completed successfully.")


if __name__ == "__main__":
    main()
