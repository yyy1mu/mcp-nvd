"""
Test suite for the MCP-NVD server implementation.

This script provides unit tests for the MCP-NVD server tools (get_cve and search_cve) using mocked HTTP
responses to simulate interactions with the NVD API. It tests various scenarios including successful CVE retrieval,
search functionality, and error handling.
How to Run:
  1. Ensure dependencies are installed: `pip install httpx python-dotenv`.
  2. Place this script in the `tests/` directory alongside `mcp-nvd/server.py` in the parent directory structure:
     cybersec-agent/mcp-servers/mcp-nvd/
       ├── mcp-nvd/
       │   └── server.py
       └── tests/
           └── test_tools.py
  3. From the `tests/` directory, run the tests with one of these commands:
     - `python test_tools.py` (direct execution)
     - `python -m test_tools` (run as a module)
  4. For verbose output, add the `-v` flag: `python test_tools.py -v`.

Dependencies: unittest, unittest.mock, asyncio, httpx, dotenv

Copyright (c) 2025 Graziano Labs Corp.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
import asyncio
from unittest.mock import patch, AsyncMock
from dotenv import load_dotenv

from mcp_nvd.server import get_cve, search_cve, make_nvd_request, format_cve

load_dotenv()

# Sample CVE data for mocking
SAMPLE_CVE = {
    "id": "CVE-2023-1234",
    "sourceIdentifier": "nvd@nist.gov",
    "published": "2023-01-01T00:00:00",
    "lastModified": "2023-01-02T00:00:00",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "Test CVE description"}],
    "metrics": {
        "cvssMetricV31": [{
            "type": "Primary",
            "cvssData": {
                "baseScore": 7.5,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            },
            "exploitabilityScore": 3.9,
            "impactScore": 3.6
        }],
        "cvssMetricV2": [{
            "type": "Primary",
            "cvssData": {
                "baseScore": 5.0,
                "baseSeverity": "MEDIUM",
                "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"
            }
        }]
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
    "references": [{"url": "https://example.com", "tags": ["Patch"]}],
    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:test:1.0"}]}]}]
}

class TestMCPNVDServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the environment before tests."""
        if not os.getenv("NVD_API_KEY"):
            os.environ["NVD_API_KEY"] = "test-api-key"

    @classmethod
    def tearDownClass(cls):
        """Clean up the environment after tests."""
        pass

    async def async_mock_nvd_request(self, url):
        """Helper to mock NVD API responses based on URL."""
        if "cveId=CVE-2023-1234" in url:
            return {"vulnerabilities": [{"cve": SAMPLE_CVE}]}
        elif "keywordSearch=test" in url:
            return {"vulnerabilities": [{"cve": SAMPLE_CVE}], "totalResults": 1}
        elif "keywordSearch=nonexistent" in url:
            return {"vulnerabilities": []}
        return None

    def setUp(self):
        """Set up mocks for each test."""
        self.patcher = patch('mcp_nvd.server.make_nvd_request', new_callable=AsyncMock)
        self.mock_nvd_request = self.patcher.start()
        self.mock_nvd_request.side_effect = self.async_mock_nvd_request

    def tearDown(self):
        """Stop mocks after each test."""
        self.patcher.stop()

    def test_format_cve(self):
        """Test the format_cve helper function."""
        formatted = format_cve(SAMPLE_CVE, concise=False)
        self.assertIn("CVE ID: CVE-2023-1234", formatted)
        self.assertIn("Description: Test CVE description", formatted)
        self.assertIn("CVSS v3.1 Score: 7.5 (HIGH)", formatted)
        self.assertIn("Weaknesses (CWE): CWE-79", formatted)

    def test_format_cve_concise(self):
        """Test the format_cve helper function with concise output."""
        formatted = format_cve(SAMPLE_CVE, concise=True)
        self.assertIn("CVE ID: CVE-2023-1234", formatted)
        self.assertIn("Description: Test CVE description", formatted)
        self.assertIn("CVSS v3.1 Score: 7.5 (HIGH)", formatted)
        self.assertNotIn("Weaknesses (CWE)", formatted)

    def test_get_cve_success(self):
        """Test get_cve tool with a successful response."""
        result = asyncio.run(get_cve("CVE-2023-1234"))
        self.assertIn("CVE ID: CVE-2023-1234", result)
        self.assertIn("Test CVE description", result)
        self.assertIn("CVSS v3.1 Score: 7.5 (HIGH)", result)

    def test_get_cve_not_found(self):
        """Test get_cve tool when CVE is not found."""
        result = asyncio.run(get_cve("CVE-9999-9999"))
        self.assertEqual(result, "No data found for CVE ID: CVE-9999-9999")

    def test_search_cve_success(self):
        """Test search_cve tool with a successful response."""
        result = asyncio.run(search_cve("test", exact_match=False, results=10))
        self.assertIn("Found 1 of 1 CVEs for keyword 'test'", result)
        self.assertIn("CVE ID: CVE-2023-1234", result)
        self.assertIn("Test CVE description", result)

    def test_search_cve_no_results(self):
        """Test search_cve tool when no CVEs are found."""
        result = asyncio.run(search_cve("nonexistent", exact_match=False, results=10))
        self.assertEqual(result, "No CVEs found for keyword: nonexistent (exact_match: False)")

    def test_search_cve_exact_match(self):
        """Test search_cve tool with exact match enabled."""
        result = asyncio.run(search_cve("test", exact_match=True, results=10))
        self.assertIn("Found 1 of 1 CVEs for keyword 'test'", result)
        self.assertIn("(exact_match: True, results requested: 10)", result)

if __name__ == "__main__":
    unittest.main()