FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PORT=8091
WORKDIR /app
COPY src/ /app/src/
RUN useradd -m -u 10001 fwuser && mkdir -p /app/data && chown -R fwuser:fwuser /app
USER fwuser
EXPOSE 8091
CMD ["python", "-m", "mcp_firewall.server", "--host", "0.0.0.0"]
