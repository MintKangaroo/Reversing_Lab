FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system rlab \
    && useradd --system --gid rlab --create-home rlab

WORKDIR /workspace/backend
COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements.txt -r requirements-dev.txt
COPY . .
RUN mkdir -p /var/lib/rlab/binaries \
    && chmod 755 /workspace/backend/docker-entrypoint.sh \
    && chown -R rlab:rlab /workspace/backend /var/lib/rlab

USER rlab
EXPOSE 8000
CMD ["sh", "docker-entrypoint.sh"]
