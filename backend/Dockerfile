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
    && chown -R rlab:rlab /workspace/backend /var/lib/rlab

USER rlab
EXPOSE 8000
CMD ["uvicorn", "reversing_lab.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
