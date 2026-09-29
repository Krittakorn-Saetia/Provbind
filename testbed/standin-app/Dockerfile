# Stand-in for Role 1's demo app: same shape, no malicious package.
# The base image is pinned by digest, so every build starts from the same layers. The digest is the
# python:3.11-slim image index the stand-in was first built and attested from (27 September 2026;
# see its provenance). To move to a newer base, replace it with the output of
#   crane digest python:3.11-slim
# and keep the demo app (testbed/demo-app/Dockerfile) on the same digest.
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
