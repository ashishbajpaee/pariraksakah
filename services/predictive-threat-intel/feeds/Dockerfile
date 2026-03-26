FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY feed_integration.py .
EXPOSE 8041
CMD ["uvicorn", "feed_integration:app", "--host", "0.0.0.0", "--port", "8041"]
