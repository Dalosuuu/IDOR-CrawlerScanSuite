# IDOR Scanner Configuration Examples

## Basic Configuration
The scanner can be configured through command-line arguments or by modifying the default values in the code.

### Scan Parameters
- `max_depth`: Maximum depth for crawling (default: 3)
- `rate_limit`: Delay between requests in seconds (default: 1.0)
- `min_suspicion_score`: Minimum score for parameter testing (default: 2)

### Authentication Methods
1. **Username/Password Login**
2. **Cookie-based Authentication**
3. **Header-based Authentication (API keys, tokens)**

### Parameter Detection
The scanner identifies potentially vulnerable parameters based on:
- Parameter names (id, user_id, account_id, etc.)
- Parameter values (numeric IDs, UUIDs, hashes, etc.)
- Context (URL parameters vs form fields)

### Suspicion Scoring
Parameters are scored based on:
- Name patterns: +2 points for suspicious names
- Value types: +3 for numeric/UUID, +2 for hashes/filenames
- Combined score determines testing priority

### IDOR Detection Methods
1. **Response Code Analysis**: 403/404 → 200 transitions
2. **Content Comparison**: Significant content differences
3. **Success Indicators**: Presence of user data, dashboards
4. **Access Control Bypass**: Removal of "access denied" messages

### Risk Levels
- **HIGH**: Strong evidence of IDOR (confidence + suspicion ≥ 8)
- **MEDIUM**: Moderate evidence (confidence + suspicion ≥ 5)
- **LOW**: Potential IDOR (confidence + suspicion < 5)

## Report Formats
- **HTML**: Interactive report with collapsible findings
- **JSON**: Machine-readable format for integration
- **CSV**: Spreadsheet-compatible format
- **TXT**: Plain text summary report
