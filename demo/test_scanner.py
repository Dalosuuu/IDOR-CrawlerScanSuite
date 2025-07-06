#!/usr/bin/env python3
"""
Test script to debug what parameters are being found
"""
import sys
import os
import logging

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.idor_scanner.parameter_identifier import ParameterIdentifier

def test_parameter_detection():
    """Test parameter detection with some sample URLs"""
    
    # Setup logging to see debug output
    logging.basicConfig(level=logging.DEBUG)
    
    identifier = ParameterIdentifier()
    
    test_urls = [
        "https://example.com/profile?id=123",
        "https://example.com/user?user_id=456&name=john",
        "https://example.com/order?order_id=789&status=pending",
        "https://example.com/document?doc=private.pdf",
        "https://example.com/api/user?uuid=550e8400-e29b-41d4-a716-446655440000",
        "https://indrive.com/legal?doc=privacyPolicy",  # From your actual scan
    ]
    
    print("Testing parameter detection:")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        parameters = identifier.identify_parameters(url)
        print(f"Found {len(parameters)} parameters:")
        for param in parameters:
            print(f"  - {param['name']} = {param['value']} (score: {param['suspicion_score']}, types: {param['value_types']})")
    
    print("\n" + "=" * 50)
    print("Testing with min_score filtering:")
    
    for min_score in [1, 2, 3]:
        print(f"\nMin score {min_score}:")
        total_params = 0
        for url in test_urls:
            parameters = identifier.identify_parameters(url)
            filtered = identifier.filter_parameters(parameters, min_score)
            total_params += len(filtered)
        print(f"  Total parameters that pass: {total_params}")

if __name__ == "__main__":
    test_parameter_detection()
