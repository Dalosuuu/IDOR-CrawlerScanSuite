"""
Session management module for handling authentication and CSRF tokens
"""
import requests
from bs4 import BeautifulSoup, Tag
import re
from typing import Dict, Optional, Any
import logging

class SessionManager:
    def __init__(self, rate_limit: float = 1.0):
        """
        Initialize session manager
        
        Args:
            rate_limit: Delay between requests in seconds
        """
        self.session = requests.Session()
        self.rate_limit = rate_limit
        self.logger = logging.getLogger(__name__)
        self.csrf_token = None
        self.csrf_token_name = None
        self.authenticated = False
        
        # Common CSRF token names
        self.csrf_names = [
            'csrf_token', 'csrftoken', '_token', 'authenticity_token',
            'csrf', '_csrf', 'csrf_param', 'csrf_value', 'token',
            '_wpnonce', 'security', '__RequestVerificationToken'
        ]
        
        # Set common headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def login(self, login_url: str, username: str, password: str, 
              username_field: str = 'username', password_field: str = 'password',
              extra_fields: Optional[Dict[str, str]] = None) -> bool:
        """
        Attempt to log in to the application
        
        Args:
            login_url: URL of the login page/endpoint
            username: Username for authentication
            password: Password for authentication
            username_field: Name of the username field
            password_field: Name of the password field
            extra_fields: Additional form fields required for login
            
        Returns:
            True if login successful, False otherwise
        """
        try:
            # First, get the login page to extract CSRF tokens and form details
            self.logger.info(f"Getting login page: {login_url}")
            response = self.session.get(login_url, timeout=10)
            response.raise_for_status()
            
            # Extract CSRF token
            self._extract_csrf_token(response.text)
            
            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }
            
            # Add CSRF token if found
            if self.csrf_token and self.csrf_token_name:
                login_data[self.csrf_token_name] = self.csrf_token
                self.logger.info(f"Added CSRF token: {self.csrf_token_name}")
            
            # Add extra fields
            if extra_fields:
                login_data.update(extra_fields)
            
            # Attempt login
            self.logger.info("Attempting login...")
            login_response = self.session.post(login_url, data=login_data, timeout=10)
            
            # Check if login was successful
            self.authenticated = self._check_authentication_success(login_response)
            
            if self.authenticated:
                self.logger.info("Login successful!")
                return True
            else:
                self.logger.warning("Login failed - checking response for errors")
                self._log_login_failure(login_response)
                return False
                
        except Exception as e:
            self.logger.error(f"Error during login: {e}")
            return False
    
    def login_with_cookies(self, cookies: Dict[str, str]) -> bool:
        """
        Set authentication cookies directly
        
        Args:
            cookies: Dictionary of cookie name-value pairs
            
        Returns:
            True if cookies set successfully
        """
        try:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
            
            self.authenticated = True
            self.logger.info("Authentication cookies set successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting cookies: {e}")
            return False
    
    def set_headers(self, headers: Dict[str, str]) -> None:
        """
        Set additional headers for requests
        
        Args:
            headers: Dictionary of header name-value pairs
        """
        self.session.headers.update(headers)
        self.logger.info(f"Updated headers: {list(headers.keys())}")
    
    def get_session(self) -> requests.Session:
        """Get the configured session object"""
        return self.session
    
    def refresh_csrf_token(self, url: str) -> bool:
        """
        Refresh CSRF token from a page
        
        Args:
            url: URL to get fresh CSRF token from
            
        Returns:
            True if token refreshed successfully
        """
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            old_token = self.csrf_token
            self._extract_csrf_token(response.text)
            
            if self.csrf_token != old_token:
                self.logger.info("CSRF token refreshed")
                return True
            else:
                self.logger.warning("CSRF token not found or unchanged")
                return False
                
        except Exception as e:
            self.logger.error(f"Error refreshing CSRF token: {e}")
            return False
    
    def _extract_csrf_token(self, html_content: str) -> None:
        """Extract CSRF token from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for CSRF tokens in meta tags
        for meta in soup.find_all('meta'):
            if isinstance(meta, Tag):
                name = str(meta.get('name', '')).lower()
                if any(csrf_name in name for csrf_name in self.csrf_names):
                    self.csrf_token = str(meta.get('content', ''))
                    self.csrf_token_name = name
                    self.logger.info(f"Found CSRF token in meta tag: {name}")
                    return
        
        # Look for CSRF tokens in hidden input fields
        for input_tag in soup.find_all('input', type='hidden'):
            if isinstance(input_tag, Tag):
                name = str(input_tag.get('name', '')).lower()
                if any(csrf_name in name for csrf_name in self.csrf_names):
                    self.csrf_token = str(input_tag.get('value', ''))
                    self.csrf_token_name = str(input_tag.get('name', ''))
                    self.logger.info(f"Found CSRF token in hidden input: {name}")
                    return
        
        # Look for CSRF tokens in script tags or inline JavaScript
        for script in soup.find_all('script'):
            if isinstance(script, Tag) and script.string:
                script_content = script.string
                for csrf_name in self.csrf_names:
                    # Look for patterns like: csrf_token: "value" or csrf_token = "value"
                    pattern = rf'{csrf_name}[\'"\s]*[:=][\'"\s]*([^\'"\s,}}]+)'
                    match = re.search(pattern, script_content, re.IGNORECASE)
                    if match:
                        self.csrf_token = match.group(1)
                        self.csrf_token_name = csrf_name
                        self.logger.info(f"Found CSRF token in script: {csrf_name}")
                        return
    
    def _check_authentication_success(self, response: requests.Response) -> bool:
        """
        Check if authentication was successful based on response
        
        Args:
            response: Login response
            
        Returns:
            True if authentication appears successful
        """
        # Check for redirect (common after successful login)
        if response.history:
            self.logger.info("Login response contained redirects (potential success)")
            
        # Check response content for success/failure indicators
        content = response.text.lower()
        
        # Success indicators
        success_indicators = [
            'dashboard', 'welcome', 'logout', 'profile', 'settings',
            'account', 'logged in', 'successful', 'success'
        ]
        
        # Failure indicators
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error', 'wrong',
            'authentication failed', 'login failed', 'bad credentials'
        ]
        
        success_count = sum(1 for indicator in success_indicators if indicator in content)
        failure_count = sum(1 for indicator in failure_indicators if indicator in content)
        
        # Check for authentication cookies
        auth_cookies = ['session', 'auth', 'token', 'login', 'user']
        has_auth_cookies = any(
            any(cookie_name in cookie.name.lower() for cookie_name in auth_cookies)
            for cookie in self.session.cookies
        )
        
        # Decision logic
        if failure_count > 0:
            return False
        elif success_count > 0 or has_auth_cookies or response.history:
            return True
        elif response.status_code == 200 and 'login' not in content:
            # If we're not on a login page anymore, might be successful
            return True
        else:
            return False
    
    def _log_login_failure(self, response: requests.Response) -> None:
        """Log details about login failure for debugging"""
        self.logger.warning(f"Login failed with status: {response.status_code}")
        
        # Look for error messages in response
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Common error message containers
        error_selectors = [
            '.error', '.alert', '.message', '.notification',
            '#error', '#alert', '#message'
        ]
        
        for selector in error_selectors:
            elements = soup.select(selector)
            for element in elements:
                if isinstance(element, Tag):
                    error_text = element.get_text(strip=True)
                    if error_text:
                        self.logger.warning(f"Error message found: {error_text}")
    
    def is_authenticated(self) -> bool:
        """Check if session is authenticated"""
        return self.authenticated
    
    def test_authentication(self, test_url: str) -> bool:
        """
        Test if current session is still authenticated
        
        Args:
            test_url: URL to test authentication against
            
        Returns:
            True if still authenticated
        """
        try:
            response = self.session.get(test_url, timeout=10)
            
            # Check if we're redirected to login page
            if 'login' in response.url.lower():
                self.authenticated = False
                return False
            
            # Check for authentication indicators in content
            content = response.text.lower()
            if 'login' in content and 'logout' not in content:
                self.authenticated = False
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error testing authentication: {e}")
            return False
