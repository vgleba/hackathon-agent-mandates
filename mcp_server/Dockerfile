FROM public.ecr.aws/docker/library/python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /uvx /bin/

# Set the working directory
WORKDIR /app

# Install project dependencies using uv
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --extra fastapi

# Copy minimal structure needed for installation
COPY mcp_server mcp_server
COPY shared_utils shared_utils




# Create non-root user, own the app directory
RUN useradd --create-home --shell /bin/bash appuser \
    && mkdir -p /app/mcp_server/data/writes \
    && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 8080

HEALTHCHECK CMD curl --fail http://localhost:8080/api/healthcheck

# Command to run the FastAPI app using Uvicorn
CMD ["/app/.venv/bin/uvicorn", "mcp_server.main:app", "--host", "0.0.0.0", "--port", "8080"]
