#!/bin/bash
# IDOR Scanner Usage Examples
# Comprehensive examples for security professionals and bug bounty hunters

echo "IDOR Vulnerability Scanner - Usage Examples"
echo "==========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running with test parameter
if [ "$1" = "test" ]; then
    echo -e "${GREEN}Quick Test Mode${NC}"
    echo "Starting test server..."
    uv run python demo/test_server.py &
    SERVER_PID=$!
    
    sleep 3
    echo -e "${BLUE}Testing IDOR scanner...${NC}"
    uv run ./idor_scanner -u http://localhost:5000 \
        --min-score 1 \
        --max-depth 2 \
        --rate-limit 0.3 \
        --reports html,json
    
    echo -e "${GREEN}Stopping test server...${NC}"
    kill $SERVER_PID
    exit 0
fi

echo -e "${BLUE}Available Examples:${NC}"
echo "1. Basic scan"
echo "2. Authenticated scan with login"
echo "3. Scan with API token authentication"
echo "4. Scan with custom cookies"
echo "5. Aggressive scan with low threshold"
echo "6. Multi-format report generation"
echo "7. Test with local vulnerable server"
echo

# Example 1: Basic scan
echo -e "${GREEN}Example 1: Basic Website Scan${NC}"
echo "./idor_scanner -u https://example.com"
echo

# Example 2: Authenticated scan
echo -e "${GREEN}Example 2: Authenticated Scan with Login Form${NC}"
echo "./idor_scanner -u https://target.com \\"
echo "    --login-url https://target.com/login \\"
echo "    --username your_email@example.com \\"
echo "    --password your_password \\"
echo "    --max-depth 4 \\"
echo "    --rate-limit 0.8"
echo

# Example 3: API token authentication
echo -e "${GREEN}Example 3: API Token Authentication${NC}"
echo "./idor_scanner -u https://api.target.com \\"
echo "    --headers \"Authorization: Bearer eyJhbGc...\" \\"
echo "    --max-depth 3 \\"
echo "    --reports html,json"
echo

# Example 4: Cookie-based authentication
echo -e "${GREEN}Example 4: Cookie-based Authentication${NC}"
echo "./idor_scanner -u https://app.example.com \\"
echo "    --cookies \"session_id=abc123;csrf_token=xyz789\" \\"
echo "    --max-depth 5 \\"
echo "    --reports html,csv"
echo

# Example 5: Aggressive scan
echo -e "${GREEN}Example 5: Aggressive Scan (Low Threshold)${NC}"
echo "./idor_scanner -u https://target.com \\"
echo "    --min-score 1 \\"
echo "    --max-depth 5 \\"
echo "    --rate-limit 0.5 \\"
echo "    --log-level DEBUG"
echo

# Example 6: Multi-format reports
echo -e "${GREEN}Example 6: Generate Multiple Report Formats${NC}"
echo "./idor_scanner -u https://target.com \\"
echo "    --reports html,json,csv,txt \\"
echo "    --output-dir ./my_reports \\"
echo "    --min-score 2"
echo

# Example 7: Test server
echo -e "${GREEN}Example 7: Test with Local Vulnerable Server${NC}"
echo -e "${YELLOW}First, start the test server in one terminal:${NC}"
echo "uv run python demo/test_server.py"
echo
echo -e "${YELLOW}Then, in another terminal, scan it:${NC}"
echo "./idor_scanner -u http://localhost:5000 \\"
echo "    --min-score 1 \\"
echo "    --max-depth 2 \\"
echo "    --rate-limit 0.3 \\"
echo "    --reports html,json"
echo

# Bug bounty specific example
echo -e "${GREEN}Example 8: Bug Bounty Scanning${NC}"
echo -e "${YELLOW}Note: Always ensure you have permission before scanning!${NC}"
echo "./idor_scanner -u https://target.com \\"
echo "    --min-score 1 \\"
echo "    --max-depth 3 \\"
echo "    --rate-limit 1.0 \\"
echo "    --reports html,json \\"
echo "    --log-level INFO"
echo

echo -e "${BLUE}Best Practices:${NC}"
echo "- Always get explicit permission before scanning"
echo "- Respect rate limits to avoid being blocked"
echo "- Lower min-score finds more parameters but may have false positives"
echo "- Higher max-depth takes longer but finds more pages"
echo "- Use DEBUG log level for troubleshooting"
echo
echo -e "${RED}Security Considerations:${NC}"
echo "- Focus on authenticated areas for better results"
echo "- Test user profile, order, and payment endpoints"
echo "- Look for numeric IDs, UUIDs, and object references"
echo "- Always manually verify findings before reporting"
echo

echo -e "${BLUE}Quick Test:${NC}"
echo "To quickly test the scanner, run:"
echo -e "${GREEN}./examples.sh test${NC}"
