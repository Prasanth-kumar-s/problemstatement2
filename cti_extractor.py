import re
import json
from openai import OpenAI
import os

class CTIExtractor:
    def __init__(self, api_key: str):
        """Initialize the CTIExtractor with an OpenAI API key."""
        self.api_key = api_key

    def parse_report(self, report_text: str) -> dict:
        """Parse the CTI report and extract relevant information."""
        iocs = self.extract_iocs(report_text)
        attacks, interpretive_analysis = self.extract_attacks_and_analysis(report_text)
        return {
            "report_id": "XYZ-2025-001",
            "attacks": attacks,
            "indicators_of_compromise": self.generate_iocs_list(iocs),
            "interpretive_analysis": interpretive_analysis
        }

    def extract_iocs(self, report_text: str) -> dict:
        """Extract indicators of compromise (IOCs) from the report using regex."""
        iocs = {
            'ip_addresses': re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', report_text),
            'hashes': re.findall(r'\b[a-fA-F0-9]{32,128}\b', report_text),
            'domains': re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', report_text)
        }
        return iocs

    def extract_attacks_and_analysis(self, report_text: str) -> tuple:
        """Use a large language model to extract ATT&CK Tactics, Techniques, and interpretive analysis."""
        try:
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst."},
                    {"role": "user", "content": self.generate_prompt(report_text)}
                ],
                max_tokens=1000,
                temperature=0.5
            )
            response_text = response.choices[0].message.content.strip()
            try:
                data = json.loads(response_text)
                return data["tactics_and_techniques"], data["interpretive_analysis"]
            except json.JSONDecodeError:
                return [], "Could not parse the model's response."
        except Exception as e:
            return [], f"Error: {str(e)}"

    def generate_prompt(self, report_text: str) -> str:
        """Generate the prompt for the OpenAI API request."""
        return f"""
        Analyze the following cyber threat intelligence report and extract the MITRE ATT&CK Tactics and Techniques mentioned. For each technique, provide the tactic it belongs to, the technique ID and name, a confidence level (High, Medium, Low), and the relevant excerpt from the report that supports this technique. Also, provide an interpretive analysis of the adversary's behavior based on the report.

        Report:
        {report_text}

        Output the results in JSON format with the following structure:
        {{
            "tactics_and_techniques": [
