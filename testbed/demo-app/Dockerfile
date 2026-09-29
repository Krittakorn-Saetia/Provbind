# PROVBIND demo app (Role 1). Two stages: the builder compiles the harmless test payload and
# embeds it into requestz-helper; the final image installs that package and runs the app.
#
# Pin the base image by digest before the final demo, so the envelope is stable between runs:
#   docker pull python:3.11-slim
#   docker image inspect --format '{{index .RepoDigests 0}}' python:3.11-slim
# then replace both FROM lines with python:3.11-slim@sha256:<digest>.

# --- builder: compile x9.c and embed it as base64 into requestz_helper/_payload.py ---
FROM python:3.11-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY x9.c gen_payload.sh ./
COPY requestz-helper ./requestz-helper
RUN bash gen_payload.sh

# --- final image ---
FROM python:3.11-slim
WORKDIR /app
# curl is used by the scenarios to hit the app's own endpoints from inside the pod.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
# Install the test package from local source only (never from PyPI); it carries the embedded payload.
COPY --from=builder /build/requestz-helper ./requestz-helper
RUN pip install --no-cache-dir --no-index ./requestz-helper
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
