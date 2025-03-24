# Use an official Python runtime as the base image
FROM python:3.10-slim

# Set working directory in the container
WORKDIR /app

# Install system dependencies (e.g., for uv)
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv explicitly and ensure it's in PATH in one RUN command
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && /root/.local/bin/uv --version \
    && echo "UV installed at: $(/root/.local/bin/uv --version)"

# Ensure uv is in PATH for subsequent commands and runtime
ENV PATH="/root/.local/bin:$PATH"

# Copy project files
COPY pyproject.toml README.md ./
COPY mcp_nvd/ ./mcp_nvd/

# Install dependencies and the project in editable mode using uv
RUN uv pip install --system -e .

# Expose the port the server will run on
EXPOSE 9090

# Set environment variable for real-time logging
ENV PYTHONUNBUFFERED=1

# Command to run the server with SSE transport on port 9090
CMD ["uv", "run", "mcp-nvd", "--transport", "sse", "--port", "9090", "--host", "0.0.0.0"]