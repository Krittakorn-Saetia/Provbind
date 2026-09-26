# Stand-in for Role 1's demo app: same shape, no malicious package.
# Before the final demo, pin the base image by digest:
#   docker pull python:3.11-slim
#   docker image inspect --format '{{index .RepoDigests 0}}' python:3.11-slim
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
