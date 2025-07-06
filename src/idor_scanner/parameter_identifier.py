"""
Parameter identification module for detecting potential IDOR parameters
"""
import re
import uuid
import logging
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Set, Any, Optional

class ParameterIdentifier:
    def __init__(self):
        """Initialize parameter identifier with various patterns"""
        self.logger = logging.getLogger(__name__)
        # Patterns for different types of identifiers
        self.patterns = {
            'numeric_id': re.compile(r'^\d+$'),
            'uuid': re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$', re.IGNORECASE),
            'hex_id': re.compile(r'^[a-f0-9]{8,}$', re.IGNORECASE),
            'base64_like': re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$'),
            'filename': re.compile(r'^[\w\-_.]+\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|txt|csv|zip|rar)$', re.IGNORECASE),
            'username': re.compile(r'^[a-zA-Z0-9_.-]{3,}$'),
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'date': re.compile(r'^\d{4}-\d{2}-\d{2}$|^\d{2}/\d{2}/\d{4}$|^\d{2}-\d{2}-\d{4}$'),
            'hash': re.compile(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', re.IGNORECASE)
        }
        
        # Parameter names that commonly contain object references
        self.suspicious_names = {
            'id', 'user_id', 'userid', 'uid', 'user', 'account_id', 'account',
            'profile_id', 'profile', 'document_id', 'doc_id', 'file_id', 'file',
            'post_id', 'postid', 'message_id', 'msg_id', 'order_id', 'orderid',
            'invoice_id', 'payment_id', 'transaction_id', 'ticket_id', 'session_id',
            'token', 'key', 'ref', 'reference', 'slug', 'name', 'username',
            'email', 'path', 'filename', 'resource', 'object', 'item_id', 'item',
            'product_id', 'customer_id', 'client_id', 'project_id', 'task_id',
            'company_id', 'org_id', 'organization_id', 'group_id', 'team_id',
            'conversation_id', 'chat_id', 'room_id', 'channel_id', 'thread_id',
            'comment_id', 'reply_id', 'photo_id', 'image_id', 'video_id',
            'album_id', 'gallery_id', 'folder_id', 'directory_id', 'category_id',
            'tag_id', 'label_id', 'status_id', 'type_id', 'role_id', 'permission_id',
            'page_id', 'section_id', 'module_id', 'component_id', 'widget_id',
            'report_id', 'log_id', 'entry_id', 'record_id', 'row_id', 'pk',
            'primary_key', 'foreign_key', 'fk', 'uuid', 'guid', 'hash', 'code',
            'oid', 'objectid', 'entity_id', 'model_id', 'instance_id', 'node_id',
            'doc', 'document'
        }
    
    def identify_parameters(self, url: str, form_data: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """
        Identify potentially vulnerable parameters from URL and form data
        
        Args:
            url: The URL to analyze
            form_data: Optional form data dictionary
            
        Returns:
            List of parameter dictionaries with metadata
        """
        parameters = []
        
        # Analyze URL parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        self.logger.debug(f"Analyzing URL: {url}")
        self.logger.debug(f"Query params found: {query_params}")
        
        for param_name, param_values in query_params.items():
            if param_values:  # Skip empty parameters
                param_info = self._analyze_parameter(param_name, param_values[0], 'url')
                if param_info:
                    param_info['source_url'] = url
                    parameters.append(param_info)
                    self.logger.debug(f"Added URL parameter: {param_name} = {param_values[0]} (score: {param_info['suspicion_score']})")
        
        # Analyze form parameters
        if form_data:
            self.logger.debug(f"Analyzing form data: {form_data}")
            for input_field in form_data.get('inputs', []):
                param_name = input_field.get('name', '')
                param_value = input_field.get('value', '')
                
                if param_name and param_value:
                    param_info = self._analyze_parameter(param_name, param_value, 'form')
                    if param_info:
                        param_info['form_action'] = form_data.get('action', '')
                        param_info['form_method'] = form_data.get('method', 'get')
                        param_info['input_type'] = input_field.get('type', 'text')
                        parameters.append(param_info)
                        self.logger.debug(f"Added form parameter: {param_name} = {param_value} (score: {param_info['suspicion_score']})")
        
        return parameters
    
    def _analyze_parameter(self, name: str, value: str, source: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a single parameter to determine if it's potentially vulnerable
        
        Args:
            name: Parameter name
            value: Parameter value
            source: Source of parameter ('url' or 'form')
            
        Returns:
            Parameter info dict if potentially vulnerable, None otherwise
        """
        # Skip empty values
        if not value or not name:
            return None
        
        name_lower = name.lower()
        
        # Check if parameter name is suspicious
        name_suspicious = any(suspicious in name_lower for suspicious in self.suspicious_names)
        
        # Identify value type and calculate suspicion score
        value_types = []
        suspicion_score = 0
        
        for pattern_name, pattern in self.patterns.items():
            if pattern.match(value):
                value_types.append(pattern_name)
                
                # Assign suspicion scores based on pattern type
                if pattern_name in ['numeric_id', 'uuid', 'hex_id']:
                    suspicion_score += 3
                elif pattern_name in ['hash', 'base64_like']:
                    suspicion_score += 2
                elif pattern_name in ['filename', 'username', 'email']:
                    suspicion_score += 2
                else:
                    suspicion_score += 1
        
        # Boost score for suspicious parameter names
        if name_suspicious:
            suspicion_score += 2
        
        # Add minimal score for any parameter that has a value
        # This makes the scanner more aggressive for bug bounty hunting
        if suspicion_score == 0 and value:
            suspicion_score = 1
        
        # Only consider parameters with some suspicion (lowered threshold)
        if suspicion_score < 1:
            return None
        
        return {
            'name': name,
            'value': value,
            'source': source,
            'value_types': value_types,
            'suspicion_score': suspicion_score,
            'name_suspicious': name_suspicious,
            'test_values': self._generate_test_values(value, value_types)
        }
    
    def _generate_test_values(self, original_value: str, value_types: List[str]) -> List[str]:
        """
        Generate test values for IDOR testing based on the original value type
        
        Args:
            original_value: The original parameter value
            value_types: List of detected value types
            
        Returns:
            List of test values to try
        """
        test_values = []
        
        # Numeric ID testing
        if 'numeric_id' in value_types:
            try:
                num_val = int(original_value)
                test_values.extend([
                    str(num_val + 1),
                    str(num_val - 1),
                    str(num_val + 10),
                    str(num_val - 10),
                    '1',
                    '0',
                    '999999',
                    str(num_val * 2),
                    str(max(1, num_val // 2))
                ])
            except ValueError:
                pass
        
        # UUID testing
        if 'uuid' in value_types:
            # Generate some random UUIDs
            for _ in range(3):
                test_values.append(str(uuid.uuid4()))
            
            # Try common UUID patterns
            test_values.extend([
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            ])
        
        # Hex ID testing
        if 'hex_id' in value_types:
            try:
                hex_val = int(original_value, 16)
                test_values.extend([
                    format(hex_val + 1, 'x'),
                    format(hex_val - 1, 'x'),
                    format(hex_val + 10, 'x'),
                    '0',
                    'ffffffff',
                    'deadbeef'
                ])
            except ValueError:
                pass
        
        # Username/string testing
        if 'username' in value_types:
            test_values.extend([
                'admin',
                'administrator',
                'user',
                'test',
                'guest',
                'root',
                'user1',
                'user2',
                original_value + '1',
                original_value.replace(original_value[-1], str(int(original_value[-1]) + 1)) if original_value[-1].isdigit() else original_value + '1'
            ])
        
        # Filename testing
        if 'filename' in value_types:
            base_name, ext = original_value.rsplit('.', 1) if '.' in original_value else (original_value, '')
            test_values.extend([
                f"{base_name}1.{ext}" if ext else f"{base_name}1",
                f"{base_name}2.{ext}" if ext else f"{base_name}2",
                f"admin.{ext}" if ext else "admin",
                f"config.{ext}" if ext else "config",
                f"backup.{ext}" if ext else "backup"
            ])
        
        # Email testing
        if 'email' in value_types:
            domain = original_value.split('@')[1] if '@' in original_value else 'example.com'
            test_values.extend([
                f"admin@{domain}",
                f"test@{domain}",
                f"user@{domain}",
                f"root@{domain}"
            ])
        
        # Remove duplicates and original value
        test_values = list(set(test_values))
        if original_value in test_values:
            test_values.remove(original_value)
        
        return test_values[:10]  # Limit to 10 test values to avoid excessive requests
    
    def filter_parameters(self, parameters: List[Dict[str, Any]], min_score: int = 2) -> List[Dict[str, Any]]:
        """
        Filter parameters based on suspicion score
        
        Args:
            parameters: List of parameter dictionaries
            min_score: Minimum suspicion score to include
            
        Returns:
            Filtered list of parameters
        """
        return [p for p in parameters if p['suspicion_score'] >= min_score]
