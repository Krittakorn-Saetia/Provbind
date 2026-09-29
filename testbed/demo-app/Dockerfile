# PROVBIND demo app (Role 1). Two stages: the builder compiles the harmless test payload and
# embeds it into requestz-helper; the final image installs that package and runs the app.
#
# Both stages are pinned to the stand-in's base image digest (testbed/standin-app/Dockerfile), so the
# envelope is stable between runs. gen_provenance.py records the FIRST FROM as the base image, which
# is only right because both lines name the same digest: change them together.

# --- builder: compile x9.c and embed it as base64 into requestz_helper/_payload.py ---
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY x9.c gen_payload.sh ./
COPY requestz-helper ./requestz-helper
RUN bash gen_payload.sh

# --- final image ---
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
WORKDIR /app
# No curl in the image: the scenarios reach the app through kubectl port-forward, so a trigger never
# executes anything inside the container (it would add its own detection to the scenario's window).
# Install the test package from local source only (never from PyPI); it carries the embedded payload.
COPY --from=builder /build/requestz-helper ./requestz-helper
RUN pip install --no-cache-dir --no-index --no-build-isolation ./requestz-helper
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
