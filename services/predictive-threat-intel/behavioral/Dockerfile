FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ueba_engine.py .
EXPOSE 8042
CMD ["uvicorn", "ueba_engine:app", "--host", "0.0.0.0", "--port", "8042"]
