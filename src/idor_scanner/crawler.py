"""
Web crawler module for discovering pages and forms
"""
import requests
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List, Dict, Tuple, Union
import time
import logging

class WebCrawler:
    def __init__(self, session: requests.Session, rate_limit: float = 1.0, max_depth: int = 3):
        """
        Initialize the web crawler
        
        Args:
            session: Authenticated requests session
            rate_limit: Delay between requests in seconds
            max_depth: Maximum crawling depth
        """
        self.session = session
        self.rate_limit = rate_limit
        self.max_depth = max_depth
        self.visited = set()
        self.logger = logging.getLogger(__name__)
        
    def get_links(self, url: str) -> Set[str]:
        """Extract all same-domain links from a page"""
        try:
            time.sleep(self.rate_limit)  # Rate limiting
            resp = self.session.get(url, timeout=10)
            resp.raise_for_status()
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()
            base_netloc = urlparse(url).netloc
            
            for a in soup.find_all('a', href=True):
                if isinstance(a, Tag) and a.get('href'):
                    link = urljoin(url, str(a.get('href')))
                    parsed_link = urlparse(link)
                    
                    # Only include same-domain links and filter out fragments
                    if (parsed_link.netloc == base_netloc and 
                        not link.endswith('#') and 
                        '#' not in parsed_link.path):
                        # Remove fragment from URL
                        clean_link = link.split('#')[0]
                        links.add(clean_link)
                    
            return links
            
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
            return set()
    
    def get_forms(self, url: str) -> List[Dict]:
        """Extract all forms from a page with their details"""
        try:
            time.sleep(self.rate_limit)
            resp = self.session.get(url, timeout=10)
            resp.raise_for_status()
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                if not isinstance(form, Tag):
                    continue
                    
                form_data = {
                    'action': urljoin(url, str(form.get('action', ''))),
                    'method': str(form.get('method', 'get')).lower(),
                    'inputs': [],
                    'source_url': url
                }
                
                # Extract all input fields
                for input_tag in form.find_all(['input', 'select', 'textarea']):
                    if not isinstance(input_tag, Tag):
                        continue
                        
                    if input_tag.name == 'input':
                        input_data = {
                            'name': str(input_tag.get('name', '')),
                            'type': str(input_tag.get('type', 'text')),
                            'value': str(input_tag.get('value', '')),
                            'required': input_tag.has_attr('required')
                        }
                    elif input_tag.name == 'select':
                        options = []
                        for opt in input_tag.find_all('option'):
                            if isinstance(opt, Tag):
                                option_value = str(opt.get('value', opt.get_text()))
                                options.append(option_value)
                        input_data = {
                            'name': str(input_tag.get('name', '')),
                            'type': 'select',
                            'options': options,
                            'required': input_tag.has_attr('required')
                        }
                    elif input_tag.name == 'textarea':
                        input_data = {
                            'name': str(input_tag.get('name', '')),
                            'type': 'textarea',
                            'value': input_tag.get_text(),
                            'required': input_tag.has_attr('required')
                        }
                    
                    if input_data['name']:  # Only add inputs with names
                        form_data['inputs'].append(input_data)
                
                forms.append(form_data)
            
            return forms
            
        except Exception as e:
            self.logger.error(f"Error extracting forms from {url}: {e}")
            return []
    
    def crawl(self, start_url: str) -> Tuple[Set[str], List[Dict]]:
        """
        Crawl website starting from start_url
        
        Returns:
            Tuple of (discovered_urls, discovered_forms)
        """
        to_visit = [(start_url, 0)]  # (url, depth)
        all_forms = []
        
        while to_visit:
            url, depth = to_visit.pop(0)
            
            if url in self.visited or depth > self.max_depth:
                continue
                
            self.visited.add(url)
            self.logger.info(f"Crawling: {url} (depth: {depth})")
            
            # Get forms from current page
            forms = self.get_forms(url)
            all_forms.extend(forms)
            
            # Get links for further crawling
            if depth < self.max_depth:
                links = self.get_links(url)
                for link in links:
                    if link not in self.visited:
                        to_visit.append((link, depth + 1))
        
        return self.visited, all_forms
