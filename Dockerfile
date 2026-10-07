# ---- Build stage: resolve and install dependencies into an isolated prefix ----
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install --no-deps .

# ---- Runtime stage: slim, non-root ----
FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --home /app shield && mkdir -p /data && chown shield /data
COPY --from=build /install /usr/local
WORKDIR /app
USER shield
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "agent_shield.main:app", "--host", "0.0.0.0", "--port", "8000"]
