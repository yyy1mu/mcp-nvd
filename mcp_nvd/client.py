"""
Client Implementation for the MCP-NVD Server.

Description: This script defines an asynchronous client (MCPNVDClient) for interacting with an MCP-NVD server 
using Server-Sent Events (SSE) transport. It provides methods to connect to the server, list available tools, 
retrieve specific CVE data by ID, search CVEs by keyword, and clean up resources. The client uses the 
mcp library for session management and supports command-line arguments for flexible operation.
Key Features:
- Asynchronous connection to an SSE server with initialization and tool listing
- Method to fetch a specific CVE by ID (test_get_cve)
- Method to search CVEs by keyword with options for exact match and result limits (test_search_cve)
- Resource cleanup using AsyncExitStack for proper session and stream management
- Command-line interface for specifying server URL and CVE ID or search parameters

Usage: python client.py <server_url> <cve_id or search:keyword[:exact][:results]>


Copyright (c) 2025 Graziano Labs Corp.
"""

import asyncio
from typing import Optional
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.sse import sse_client

class MCPNVDClient:
    def __init__(self):
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()

    async def connect_to_sse_server(self, server_url: str):
        """Connect to the MCP-NVD server running with SSE transport."""
        self._streams_context = sse_client(url=server_url)
        streams = await self._streams_context.__aenter__()
        self._session_context = ClientSession(*streams)
        self.session: ClientSession = await self._session_context.__aenter__()
        await self.session.initialize()
        print("Initialized SSE client...")
        print("Listing tools...")
        response = await self.session.list_tools()
        tools = [tool.name for tool in response.tools]
        print(f"Connected to server with tools: {tools}")

    async def cleanup(self):
        """Clean up the session and streams."""
        if self._session_context:
            await self._session_context.__aexit__(None, None, None)
        if self._streams_context:
            await self._streams_context.__aexit__(None, None, None)

    async def test_get_cve(self, cve_id: str):
        if not self.session:
            print("Error: Not connected to the server.")
            return
        print(f"\nTesting get_cve with CVE ID: {cve_id}")
        try:
            response = await self.session.call_tool("get_cve", {"cve_id": cve_id})
            print("\nResponse from get_cve:")
            print(response.content)
        except Exception as e:
            print(f"Error calling get_cve: {str(e)}")

    async def test_search_cve(self, keyword: str, exact_match: bool = False, results: int = 10):
        if not self.session:
            print("Error: Not connected to the server.")
            return
        print(f"\nTesting search_cve with keyword: {keyword}, exact_match: {exact_match}, results: {results}")
        try:
            # Always include all parameters in the arguments dictionary
            response = await self.session.call_tool(
                "search_cve",
                {"keyword": keyword, "exact_match": exact_match, "results": results}
            )
            print("\nResponse from search_cve:")
            print(response.content)
        except Exception as e:
            print(f"Error calling search_cve: {str(e)}")

async def main():
    import sys
    if len(sys.argv) < 3:
        print("Usage: python client.py <URL> <CVE_ID or search:keyword[:exact][:results]>")
        sys.exit(1)

    server_url = sys.argv[1]
    arg = sys.argv[2]

    client = MCPNVDClient()
    try:
        await client.connect_to_sse_server(server_url=server_url)
        if arg.startswith("search:"):
            parts = arg.split(":")
            keyword = parts[1]
            exact_match = len(parts) > 2 and parts[2] == "exact"
            results = int(parts[3]) if len(parts) > 3 else 10  # Default to 10 if not specified
            await client.test_search_cve(keyword, exact_match, results)
        else:
            await client.test_get_cve(arg)
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(main())