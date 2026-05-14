# access-ai-agent — Phase 4 A2A skill server.
#
# Built on the standard library so the runtime image is just the
# python:3.12-slim base + the requirements.txt deps (pytest is
# excluded from the runtime install).
FROM python:3.12-slim AS runtime

# Run as a non-root user — the agent does not need root in any
# code path and the cluster security policy rejects root containers.
RUN useradd --create-home --shell /usr/sbin/nologin agent
WORKDIR /app

COPY main.py ./main.py
COPY skills ./skills

# Drop pytest at install time so it is not in the runtime image.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER agent

# Container listens on 8090 to match docker-compose.yml and the
# ACCESS_AI_AGENT_BASE_URL ztna-api wires (`http://access-ai-agent:8090`).
# Standalone dev runs (`python main.py`) still default to 8765 per
# cmd/access-ai-agent/README.md — the port is only fixed here because
# the image runs inside the compose stack.
EXPOSE 8090

# Healthcheck the dispatcher's GET /healthz route. 5s timeout is a
# loose bound — the agent serves /healthz from a stdlib handler with
# no I/O.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=5).status==200 else 1)"

CMD ["python", "main.py", "--host", "0.0.0.0", "--port", "8090"]
