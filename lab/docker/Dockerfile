# Simulation-only MCP attack lab. Build context is the repository root.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Non-root process; compose additionally disables all networking.
RUN useradd --create-home --uid 10001 labuser && chown -R labuser:labuser /app
USER labuser
CMD ["python", "mcp_lab/vulnerable_server.py"]
