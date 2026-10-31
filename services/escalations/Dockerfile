FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir "psycopg[binary]>=3.2"
COPY app/ ./app/
USER nobody
CMD ["python", "-u", "app/bridge.py"]
