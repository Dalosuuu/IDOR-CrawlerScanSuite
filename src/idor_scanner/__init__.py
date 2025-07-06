"""
IDOR-CrawlerScanSuite - Advanced Web Security Testing Suite

A powerful web security testing suite that combines intelligent web crawling 
with sophisticated IDOR vulnerability detection for security professionals 
and bug bounty hunters, featuring multi-format professional reporting.
"""

__version__ = "2.0.0"
__author__ = "Security Research Team"

from .main import IDORScanner, main
from .crawler import WebCrawler
from .parameter_identifier import ParameterIdentifier
from .idor_tester import IDORTester
from .session_manager import SessionManager
from .reporter import Reporter

__all__ = [
    'IDORScanner',
    'WebCrawler', 
    'ParameterIdentifier',
    'IDORTester',
    'SessionManager',
    'Reporter',
    'main'
]
