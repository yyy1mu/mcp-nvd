# NVD Database MCP Server


A [Model Context Protocol](https://modelcontextprotocol.io/) server implementation to query the NIST National Vulnerability Database (NVD) via its API. [https://nvd.nist.gov/](https://nvd.nist.gov/)

As a prerequisite an NVD API key is required.  ([Request here](https://nvd.nist.gov/developers/request-an-api-key)).

## Status

Works with Claude Desktop app and other MCP compliant hosts and clients using both the `stdio` and `sse` transports.

## Features
- Query specific CVEs by ID with detailed vulnerability data.
- Search the NVD database by keyword with customizable result options.
- Supports Server-Sent Events (SSE) transport for real-time communication.
- Compatible with MCP-compliant clients like Claude Desktop.

### Tools

The server implements the following tools to query the NVD Database:

- **`get_cve`**:
  - **Description**: Retrieves a CVE record by its ID.
  - **Parameters**:
    - `cve_id` (str): The CVE ID (e.g., `CVE-2019-1010218`).
    - `concise` (bool, default `False`): If `True`, returns a shorter format.
  - **Returns**: Detailed CVE info including scores, weaknesses, and references.

- **`search_cve`**:
  - **Description**: Searches the NVD database by keyword.
  - **Parameters**:
    - `keyword` (str): Search term (e.g., `Red Hat`).
    - `exact_match` (bool, default `False`): If `True`, requires an exact phrase match.
    - `concise` (bool, default `False`): If `True`, returns shorter CVE records.
    - `results` (int, default `10`): Maximum number of CVE records (1-2000).
  - **Returns**: List of matching CVEs with total count.


## Configuration

1. Create or edit the Claude Desktop configuration file located at:
   - On macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - On Windows: `%APPDATA%/Claude/claude_desktop_config.json`

2. Add the following:

```json
{
  "mcpServers": {
    "mcp-nvd": {
      "command": "/path/to/uv",
      "args": ["run", "mcp-nvd"],
      "env": {
        "NVD_API_KEY": "your-api-key"
      }
    }
  }
}
```

3. Replace `/path/to/uv` with the absolute path to the `uv` executable. Find the path with `which uv` command in a terminal. This ensures that the correct version of `uv` is used when starting the server.

4. Restart Claude Desktop to apply the changes.

## Development

### Setup

1. **Prerequisites**:
   - Python 3.10 or higher.
   - An NVD API key ([request here](https://nvd.nist.gov/developers/request-an-api-key)).
   - `uv` package manager ([installation](https://docs.astral.sh/uv/)).

2. **Clone the Repository**:
```bash
git clone https://github.com/marcoeg/mcp-nvd
cd mcp-nvd
```

3. **Set Environment Variables**:
   - Create a `.env` file in the project root:
     ```
     NVD_API_KEY=your-api-key
     ```
   - Replace `your-api-key` with your NVD API key.

4. **Install Dependencies**:
```bash
uv sync
uv pip install -e .
```

### Run with the MCP Inspector
```bash
cd /path/to/the/repo
source .env

npx @modelcontextprotocol/inspector uv \
    --directory /path/to/repo/mcp-nvd run mcp-nvd
 ```

Then open the browser to the URL indicated by the MCP Inspector, typically `http://localhost:8077?proxyPort=8078`

> Switch freely between `stdio` and `sse` transport types in the inspector.

### Testing with the SSE Client

#### Run the Server:
```bash
cd /path/to/the/repo
source .env

uv run mcp-nvd --transport sse --port 9090
```
- Runs with SSE transport on port `9090` by default.

#### Run the Client:
Test `get_cve`:
```bash
uv run client.py http://localhost:9090/sse CVE-2019-1010218
```

Test `search_cve` (default 10 results):
```bash
uv run client.py http://localhost:9090/sse "search:Red Hat"
```

Test `search_cve` (exact match, 5 results):
```bash
uv run client.py http://localhost:9090/sse "search:Microsoft Windows:exact:5"
```

## Docker Setup

### Build
```bash
docker build -t mcp-nvd:latest .
```

### Run
With `.env`:
```bash
docker run -d -p 9090:9090 -v /path/to/.env:/app/.env mcp-nvd:latest
```

With env var:
```bash
docker run -d -p 9090:9090 -e NVD_API_KEY="your-key" mcp-nvd:latest
```

Custom port:
```bash
docker run -d -p 8080:8080 -v /path/to/.env:/app/.env mcp-nvd:latest uv run mcp-nvd --transport sse --port 8080 --host 0.0.0.0
```

### Verify
```bash
docker logs <container_id>
# Expect: INFO: Uvicorn running on http://0.0.0.0:9090
```

Test:
```bash
uv run client.py http://localhost:9090/sse CVE-2019-1010218
```

### Notes
- Ensure `.env` has `NVD_API_KEY=your-key` or use `-e`.
- Default port: `9090`.

---

Here’s the summary formatted as Markdown comments within a code block, suitable for inclusion in a file like `docker-compose.yaml` or `README.md`:

### Using Docker Compose for Testing

This `docker-compose.yaml`, located in the `tests/` directory, defines a service for testing the MCP-NVD server using a pre-built Docker image. It’s designed for a testing use case, similar to a standalone service like `clickhouse`, and assumes the image is built beforehand rather than rebuilt each time.

#### Assumptions
- **Pre-built Image**: The service uses a pre-built image tagged as `mcp-nvd:test`, available locally or in a registry. The image is based on the `Dockerfile` in the parent directory, which sets up the MCP-NVD server with `uv` and runs it in SSE mode on port 9090.

#### How to Build the Image
To create the `mcp-nvd:test` image:
1. Navigate to the project root:
   ```bash
   cd ./mcp-nvd
   ```
2. Build the image using the Dockerfile:
   ```bash
   docker build -t mcp-nvd:test .
   ```
   - This builds the image with all dependencies from `pyproject.toml` and the `mcp_nvd/` module, setting the default command to run the server.

#### Running the Service
From the `tests/` directory:
```bash
cd tests
docker-compose up
```
- **Access**: The server runs at `http://localhost:9090`.
- **Stop**: `docker-compose down`.
- **Environment**: Ensure `NVD_API_KEY` is in `../.env` or use `docker-compose --env-file ../.env up`.

#### Running `test_tools.py` in the Docker Compose Scenario
To run the unit tests (`test_tools.py`) within the Docker environment:
1. **Start the Service**: Ensure the `mcp-nvd` service is running via `docker-compose up`.
2. **Exec into the Container**:
   - Identify the container name (e.g., `mcp-nvd-mcp-nvd-1`) with:
     ```bash
     docker ps
     ```
   - Run the tests inside the container:
     ```bash
     docker exec -it mcp-nvd-mcp-nvd-1 python /app/tests/test_tools.py
     ```
   - **Note**: Assumes `test_tools.py` is copied into the image at `/app/tests/`. If not, modify the Dockerfile to include:
     ```dockerfile
     COPY tests/ ./tests/
     ```
     Then rebuild the image with `docker build -t mcp-nvd:test .` from the root.
3. **Alternative**: Run tests locally against the containerized service:
   ```bash
   cd tests
   python test_tools.py
   ```
   - This tests against `http://localhost:9090` while the service runs.

#### Key Details
- **Port**: 9090 is exposed for SSE access.
- **Logs**: Stored in a `log-data` volume (optional).
- **Image**: Must be built once and tagged as `mcp-nvd:test` before running `docker-compose`.


---

Credits to [@sidharthrajaram](https://github.com/sidharthrajaram/) for its working pattern for SSE-based MCP clients and servers: [https://github.com/sidharthrajaram/mcp-sse](https://github.com/sidharthrajaram/mcp-sse)