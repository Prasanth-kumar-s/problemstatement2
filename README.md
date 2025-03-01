# CTI Extractor

This tool analyzes unstructured cyber threat intelligence (CTI) reports and extracts ATT&CK Tactics and Techniques in a structured JSON format.

## Setup

1. Install Python 3.x if not already installed.
2. Install the required Python packages:
   ```bash
   pip install nltk
   ```
3. Download the `nltk` stopwords resource:
   ```python
   import nltk
   nltk.download('stopwords')
   ```

## Usage

1. Place your CTI reports in the `reports` directory (create it if it doesn't exist).
2. Run the script:
   ```bash
   python cti_extractor.py
   ```
3. The script will output the structured JSON data to the console.

## Example

```python
from cti_extractor import CTIExtractor

extractor = CTIExtractor()
report_text = """
The attackers used spear-phishing emails with malicious attachments. 
A PowerShell script was executed to download additional payloads from 192.168.1.100.
The malware hash is a3b8e9f4d...
"""
iocs, attacks, interpretive_analysis = extractor.parse_report(report_text)
json_output = extractor.generate_json_output("XYZ-2025-001", iocs, attacks, interpretive_analysis)
print(json.dumps(json_output, indent=2))
```

## Output Format

The script outputs JSON data in the following format:
```json
{
  "report_id": "XYZ-2025-001",
  "attacks": [
    {
      "tactic": "Initial Access",
      "technique": "Phishing (T1566)",
      "confidence": "High",
      "source_text": "The attackers used spear-phishing emails with malicious attachments."
    }
  ],
  "indicators_of_compromise": [
    {
      "type": "IP Address",
      "value": "192.168.1.100"
    }
  ],
  "interpretive_analysis": "The attack suggests an APT-style campaign leveraging social engineering."
}
```

## Dependencies

- Python 3.x
- `nltk` library
