"""
MCP-NVD Server Implementation

This script implements an asynchronous FastMCP server for querying the NVD (National Vulnerability Database) 
API to retrieve and search CVE (Common Vulnerabilities and Exposures) data. It defines two tools: get_cve for fetching 
a specific CVE by ID and search_cve for keyword-based CVE searches. The server uses an API key for authentication 
and provides detailed formatting of CVE data including CVSS scores, weaknesses, references, and configurations.

Key Features:
- Asynchronous HTTP requests to the NVD API using httpx with error handling
- Environment variable loading for NVD_API_KEY using python-dotenv
- Detailed CVE formatting with support for concise output (format_cve helper function)
- Logging for debugging and error tracking
- Two exposed tools: get_cve (single CVE lookup) and search_cve (keyword search with exact match and result limits)
- Configurable via environment variables and FastMCP framework

Copyright (c) 2025 Graziano Labs Corp.
"""

import logging
import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
import os
from typing import Dict, Any

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")
if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY environment variable not set")

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {
    "apiKey": NVD_API_KEY,
    "Content-Type": "application/json"
}

MCP_SERVER_NAME = "mcp-nvd"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(MCP_SERVER_NAME)

deps = ["starlette", "python-dotenv", "uvicorn", "httpx"]
mcp = FastMCP(MCP_SERVER_NAME, dependencies=deps)

async def make_nvd_request(url: str) -> Dict[str, Any] | None:
    """Make a request to the NVD API with proper error handling."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=HEADERS, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
            return None
        except httpx.RequestError as e:
            logger.error(f"Request error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None

def format_cve(cve: Dict[str, Any], concise: bool = False) -> str:
    """Helper function to format a single CVE entry, shared by get_cve and search_cve."""
    try:
        cve_id = cve["id"]
        source_identifier = cve["sourceIdentifier"]
        published = cve["published"]
        last_modified = cve["lastModified"]
        vuln_status = cve["vulnStatus"]
        description = next(
            (desc["value"] for desc in cve["descriptions"] if desc["lang"] == "en"),
            "No English description available",
        )

        # Extract CVSS v3.1 metrics
        cvss_v31_metric = next(
            (metric for metric in cve.get("metrics", {}).get("cvssMetricV31", []) if metric["type"] == "Primary"),
            None,
        )
        cvss_v31_data = cvss_v31_metric["cvssData"] if cvss_v31_metric else None
        cvss_v31_score = cvss_v31_data.get("baseScore", "N/A") if cvss_v31_data else "N/A"
        cvss_v31_severity = cvss_v31_data.get("baseSeverity", "N/A") if cvss_v31_data else "N/A"
        cvss_v31_vector = cvss_v31_data.get("vectorString", "N/A") if cvss_v31_data else "N/A"
        cvss_v31_exploitability = cvss_v31_metric.get("exploitabilityScore", "N/A") if cvss_v31_metric else "N/A"
        cvss_v31_impact = cvss_v31_metric.get("impactScore", "N/A") if cvss_v31_metric else "N/A"

        # Extract CVSS v2.0 metrics
        cvss_v2 = next(
            (metric["cvssData"] for metric in cve.get("metrics", {}).get("cvssMetricV2", []) if metric["type"] == "Primary"),
            None,
        )
        cvss_v2_score = cvss_v2.get("baseScore", "N/A") if cvss_v2 else "N/A"
        cvss_v2_severity = cvss_v2.get("baseSeverity", "N/A") if cvss_v2 else "N/A"
        cvss_v2_vector = cvss_v2.get("vectorString", "N/A") if cvss_v2 else "N/A"

        # Extract weaknesses (CWE IDs)
        weaknesses = [
            desc["value"] for weak in cve.get("weaknesses", []) for desc in weak["description"] if desc["lang"] == "en"
        ]
        weaknesses_str = ", ".join(weaknesses) if weaknesses else "None listed"

        # Extract references with tags
        references = [f"{ref['url']} ({', '.join(ref.get('tags', []))})" for ref in cve.get("references", [])]
        references_str = "\n  - " + "\n  - ".join(references) if references else "None listed"

        # Extract configurations (CPEs)
        cpe_matches = []
        for node in cve.get("configurations", [{}])[0].get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    cpe_matches.append(match["criteria"])
        configurations_str = "\n  - " + "\n  - ".join(cpe_matches) if cpe_matches else "None listed"

        # Format output
        if concise:
            return (
                f"CVE ID: {cve_id}\n"
                f"Description: {description}\n"
                f"CVSS v3.1 Score: {cvss_v31_score} ({cvss_v31_severity})"
            )
        else:
            return (
                f"CVE ID: {cve_id}\n"
                f"Source Identifier: {source_identifier}\n"
                f"Published: {published}\n"
                f"Last Modified: {last_modified}\n"
                f"Vulnerability Status: {vuln_status}\n"
                f"Description: {description}\n"
                f"CVSS v3.1 Score: {cvss_v31_score} ({cvss_v31_severity})\n"
                f"CVSS v3.1 Vector: {cvss_v31_vector}\n"
                f"CVSS v3.1 Exploitability Score: {cvss_v31_exploitability}\n"
                f"CVSS v3.1 Impact Score: {cvss_v31_impact}\n"
                f"CVSS v2.0 Score: {cvss_v2_score} ({cvss_v2_severity})\n"
                f"CVSS v2.0 Vector: {cvss_v2_vector}\n"
                f"Weaknesses (CWE): {weaknesses_str}\n"
                f"References:\n{references_str}\n"
                f"Affected Configurations (CPE):\n{configurations_str}"
            )
    except Exception as e:
        logger.error(f"Error formatting CVE {cve.get('id', 'unknown')}: {str(e)}")
        return f"Error processing CVE: {str(e)}"

@mcp.tool()
async def get_cve(cve_id: str, concise: bool = False) -> str:
    """Get a CVE based on the ID and return a formatted string with detailed attributes."""
    url = f"{BASE_URL}?cveId={cve_id}"
    data = await make_nvd_request(url)

    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        return f"No data found for CVE ID: {cve_id}"

    cve = data["vulnerabilities"][0]["cve"]
    logger.info(f"Processing CVE: {cve_id}")
    return format_cve(cve, concise)

@mcp.tool()
async def search_cve(keyword: str, exact_match: bool = False, concise: bool = False, results: int = 10) -> str:
    """Search CVEs by keyword and return formatted results matching the get_cve format."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results  # Use the results parameter here
    }
    if exact_match:
        params["keywordExactMatch"] = ""  # Presence of the param enables exact match, no value needed

    url = f"{BASE_URL}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
    data = await make_nvd_request(url)

    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        return f"No CVEs found for keyword: {keyword} (exact_match: {exact_match})"

    logger.info(f"Searching CVEs with keyword: {keyword}, exact_match: {exact_match}, results: {results}")
    results_list = []
    for cve in data["vulnerabilities"]:
        formatted_cve = format_cve(cve["cve"], concise)
        results_list.append(formatted_cve)

    total_results = data.get("totalResults", 0)
    result_str = f"Found {len(results_list)} of {total_results} CVEs for keyword '{keyword}' (exact_match: {exact_match}, results requested: {results}):\n\n"
    result_str += "\n\n---\n\n".join(results_list)
    logger.info(f"Completed search for keyword: {keyword}, found {len(results_list)} results")
    return result_str

@mcp.tool()
async def search_cve_by_publication_date(start_date: str, end_date: str, concise: bool = False, max_results: int = 1000,
                                         page_size: int = 100) -> str:
    """
    Search for ALL CVEs by PUBLICATION date within a specific range, using automated pagination.
    The date range cannot exceed 120 days.
    Dates must be in extended ISO-8601 format: YYYY-MM-DDTHH:MM:SSZ.
    Example: '2025-01-01T00:00:00Z'
    """
    # --- 1. Validate inputs ---
    try:
        start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
    except ValueError:
        return "Error: Invalid date format. Please use the extended ISO-8601 format (e.g., '2025-01-20T14:00:00Z')."

    if (end_dt - start_dt) > timedelta(days=120):
        return "Error: The date range cannot exceed 120 consecutive days."

    if start_dt > end_dt:
        return "Error: The start date cannot be after the end date."

    if not (1 <= page_size <= 2000):
        return "Error: page_size must be between 1 and 2000."

    # --- 2. Perform paginated search ---
    all_vulnerabilities: List[Dict[str, Any]] = []
    start_index = 0
    total_results = 0

    logger.info(f"Initiating paginated search for CVEs published between {start_date} and {end_date}.")

    while True:
        params = {
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "resultsPerPage": page_size,
            "startIndex": start_index
        }
        url = f"{BASE_URL}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
        data = await make_nvd_request(url)

        # Stop if there's an API error or no more results
        if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
            if start_index == 0:  # If it fails on the very first request
                return f"No CVEs found published between {start_date} and {end_date}."
            logger.info("No more results found or API error occurred. Concluding search.")
            break

        if total_results == 0:  # Get total results only on the first successful call
            total_results = data.get("totalResults", 0)

        current_page_vulnerabilities = data["vulnerabilities"]
        all_vulnerabilities.extend(current_page_vulnerabilities)

        logger.info(f"Fetched {len(all_vulnerabilities)} of {total_results} total CVEs.")

        # Stop if we have all results or have reached the user-defined max
        if len(all_vulnerabilities) >= total_results or len(all_vulnerabilities) >= max_results:
            break

        # Prepare for the next page
        start_index += page_size

    # --- 3. Format and return the final results ---
    if not all_vulnerabilities:
        return f"No CVEs found published between {start_date} and {end_date} after a full search."

    # Trim results if we exceeded max_results
    if len(all_vulnerabilities) > max_results:
        all_vulnerabilities = all_vulnerabilities[:max_results]

    results_list = []
    for cve_item in all_vulnerabilities:
        cve_item = cve_item["cve"]
        formatted_cve = format_cve(cve_item, concise)
        results_list.append(formatted_cve)

    summary = f"Displaying {len(results_list)} of {total_results} total CVEs found published between {start_date} and {end_date} (max_results cap: {max_results}):\n\n"
    final_output = summary + "\n\n---\n\n".join(results_list)

    logger.info(f"Completed paginated search. Returning {len(results_list)} CVEs.")
    return final_output