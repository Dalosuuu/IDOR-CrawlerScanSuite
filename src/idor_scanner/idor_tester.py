"""
IDOR testing module for detecting access control vulnerabilities
"""
import requests
import time
import difflib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional, Tuple
import logging
import hashlib
import re

class IDORTester:
    def __init__(self, session: requests.Session, rate_limit: float = 1.0):
        """
        Initialize IDOR tester
        
        Args:
            session: Authenticated requests session
            rate_limit: Delay between requests in seconds
        """
        self.session = session
        self.rate_limit = rate_limit
        self.logger = logging.getLogger(__name__)
        
        # Patterns that might indicate successful unauthorized access
        self.success_indicators = [
            r'user\s*:\s*\w+',
            r'email\s*:\s*[\w@.-]+',
            r'profile',
            r'dashboard',
            r'account',
            r'"id"\s*:\s*\d+',
            r'"user_id"\s*:\s*\d+',
            r'welcome\s+\w+',
            r'logged\s+in',
            r'member\s+since'
        ]
        
        # Patterns that indicate access denied
        self.denied_indicators = [
            r'access\s+denied',
            r'unauthorized',
            r'forbidden',
            r'permission\s+denied',
            r'not\s+allowed',
            r'restricted',
            r'error\s*:\s*403',
            r'error\s*:\s*401'
        ]
    
    def test_url_parameter(self, url: str, param_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Test URL parameter for IDOR vulnerability
        
        Args:
            url: Original URL
            param_info: Parameter information from identifier
            
        Returns:
            List of potential IDOR findings
        """
        findings = []
        param_name = param_info['name']
        original_value = param_info['value']
        test_values = param_info['test_values']
        
        # Get original response for comparison
        try:
            time.sleep(self.rate_limit)
            original_response = self.session.get(url, timeout=10)
            original_content = original_response.text
            original_status = original_response.status_code
            
        except Exception as e:
            self.logger.error(f"Error getting original response for {url}: {e}")
            return findings
        
        # Test each generated value
        for test_value in test_values:
            try:
                time.sleep(self.rate_limit)
                
                # Modify URL parameter
                modified_url = self._modify_url_parameter(url, param_name, test_value)
                
                # Send request with modified parameter
                test_response = self.session.get(modified_url, timeout=10)
                
                # Analyze response for potential IDOR
                finding = self._analyze_response(
                    original_url=url,
                    modified_url=modified_url,
                    param_name=param_name,
                    original_value=original_value,
                    test_value=test_value,
                    original_response=original_response,
                    test_response=test_response,
                    param_info=param_info
                )
                
                if finding:
                    findings.append(finding)
                    
            except Exception as e:
                self.logger.error(f"Error testing parameter {param_name}={test_value}: {e}")
                continue
        
        return findings
    
    def test_form_parameter(self, form_data: Dict[str, Any], param_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Test form parameter for IDOR vulnerability
        
        Args:
            form_data: Form information
            param_info: Parameter information from identifier
            
        Returns:
            List of potential IDOR findings
        """
        findings = []
        param_name = param_info['name']
        original_value = param_info['value']
        test_values = param_info['test_values']
        
        # Prepare form data
        form_action = form_data['action']
        form_method = form_data['method'].lower()
        
        # Build form payload
        form_payload = {}
        for input_field in form_data['inputs']:
            field_name = input_field.get('name', '')
            if field_name:
                if field_name == param_name:
                    form_payload[field_name] = original_value
                else:
                    # Use default values for other fields
                    field_type = input_field.get('type', 'text')
                    if field_type == 'hidden':
                        form_payload[field_name] = input_field.get('value', '')
                    elif field_type == 'select':
                        options = input_field.get('options', [])
                        if options:
                            form_payload[field_name] = options[0]
                    else:
                        form_payload[field_name] = input_field.get('value', 'test')
        
        # Get original response
        try:
            time.sleep(self.rate_limit)
            if form_method == 'post':
                original_response = self.session.post(form_action, data=form_payload, timeout=10)
            else:
                original_response = self.session.get(form_action, params=form_payload, timeout=10)
                
        except Exception as e:
            self.logger.error(f"Error getting original form response: {e}")
            return findings
        
        # Test each value
        for test_value in test_values:
            try:
                time.sleep(self.rate_limit)
                
                # Modify form payload
                test_payload = form_payload.copy()
                test_payload[param_name] = test_value
                
                # Send request with modified parameter
                if form_method == 'post':
                    test_response = self.session.post(form_action, data=test_payload, timeout=10)
                    modified_url = f"{form_action} (POST)"
                else:
                    test_response = self.session.get(form_action, params=test_payload, timeout=10)
                    modified_url = f"{form_action}?{urlencode(test_payload)}"
                
                # Analyze response
                finding = self._analyze_response(
                    original_url=form_action,
                    modified_url=modified_url,
                    param_name=param_name,
                    original_value=original_value,
                    test_value=test_value,
                    original_response=original_response,
                    test_response=test_response,
                    param_info=param_info
                )
                
                if finding:
                    findings.append(finding)
                    
            except Exception as e:
                self.logger.error(f"Error testing form parameter {param_name}={test_value}: {e}")
                continue
        
        return findings
    
    def _modify_url_parameter(self, url: str, param_name: str, new_value: str) -> str:
        """Modify a specific parameter in a URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param_name] = [new_value]
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def _analyze_response(self, original_url: str, modified_url: str, param_name: str, 
                         original_value: str, test_value: str, 
                         original_response: requests.Response, test_response: requests.Response,
                         param_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze responses to detect potential IDOR vulnerabilities
        
        Returns:
            Finding dictionary if potential IDOR detected, None otherwise
        """
        original_status = original_response.status_code
        test_status = test_response.status_code
        original_content = original_response.text
        test_content = test_response.text
        
        # Skip if test request failed
        if test_status >= 500:
            return None
        
        # Calculate content similarity
        similarity = self._calculate_similarity(original_content, test_content)
        
        # Different analysis strategies based on response codes
        finding_confidence = 0
        finding_reasons = []
        
        # Strategy 1: Both responses successful but different content
        if original_status == 200 and test_status == 200:
            if similarity < 0.9:  # Significantly different content
                finding_confidence += 3
                finding_reasons.append(f"Different content returned (similarity: {similarity:.2f})")
                
                # Check for success indicators in new content
                success_matches = self._check_indicators(test_content, self.success_indicators)
                if success_matches:
                    finding_confidence += 2
                    finding_reasons.append(f"Success indicators found: {success_matches}")
        
        # Strategy 2: Original forbidden/not found, but test succeeds
        elif original_status in [403, 404, 401] and test_status == 200:
            finding_confidence += 4
            finding_reasons.append(f"Access granted where originally denied (was {original_status}, now 200)")
            
            # Check for success indicators
            success_matches = self._check_indicators(test_content, self.success_indicators)
            if success_matches:
                finding_confidence += 2
                finding_reasons.append(f"Success indicators found: {success_matches}")
        
        # Strategy 3: Different status codes (both not errors)
        elif original_status != test_status and test_status < 400 and original_status < 500:
            finding_confidence += 2
            finding_reasons.append(f"Different response codes: {original_status} -> {test_status}")
        
        # Strategy 4: Content length differences
        original_length = len(original_content)
        test_length = len(test_content)
        length_diff_ratio = abs(original_length - test_length) / max(original_length, 1)
        
        if length_diff_ratio > 0.3:  # Significant length difference
            finding_confidence += 1
            finding_reasons.append(f"Significant content length difference: {original_length} -> {test_length}")
        
        # Strategy 5: Check for access denied indicators in original but not in test
        original_denied = self._check_indicators(original_content, self.denied_indicators)
        test_denied = self._check_indicators(test_content, self.denied_indicators)
        
        if original_denied and not test_denied:
            finding_confidence += 3
            finding_reasons.append("Access denied indicators removed")
        
        # Strategy 6: Headers analysis
        original_headers = original_response.headers
        test_headers = test_response.headers
        
        # Check for different content types
        original_ct = original_headers.get('content-type', '')
        test_ct = test_headers.get('content-type', '')
        if original_ct != test_ct and 'json' in test_ct.lower():
            finding_confidence += 1
            finding_reasons.append(f"Content type changed to JSON: {original_ct} -> {test_ct}")
        
        # Determine if this is a finding
        if finding_confidence >= 3:
            risk_level = self._calculate_risk_level(finding_confidence, param_info)
            
            return {
                'url': modified_url,
                'original_url': original_url,
                'parameter': param_name,
                'original_value': original_value,
                'test_value': test_value,
                'confidence': finding_confidence,
                'risk_level': risk_level,
                'reasons': finding_reasons,
                'original_status': original_status,
                'test_status': test_status,
                'content_similarity': similarity,
                'parameter_info': param_info,
                'response_hashes': {
                    'original': self._hash_content(original_content),
                    'test': self._hash_content(test_content)
                }
            }
        
        return None
    
    def _calculate_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity between two content strings"""
        if not content1 and not content2:
            return 1.0
        if not content1 or not content2:
            return 0.0
        
        # Use difflib for similarity calculation
        return difflib.SequenceMatcher(None, content1, content2).ratio()
    
    def _check_indicators(self, content: str, indicators: List[str]) -> List[str]:
        """Check for indicator patterns in content"""
        matches = []
        for indicator in indicators:
            if re.search(indicator, content, re.IGNORECASE):
                matches.append(indicator)
        return matches
    
    def _hash_content(self, content: str) -> str:
        """Generate hash of content for comparison"""
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def _calculate_risk_level(self, confidence: int, param_info: Dict[str, Any]) -> str:
        """Calculate risk level based on confidence and parameter info"""
        risk_score = confidence + param_info['suspicion_score']
        
        if risk_score >= 8:
            return "HIGH"
        elif risk_score >= 5:
            return "MEDIUM"
        else:
            return "LOW"
