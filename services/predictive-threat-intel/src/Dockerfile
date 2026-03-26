FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY prediction_engine.py .
RUN mkdir -p /models
EXPOSE 8040
CMD ["uvicorn", "prediction_engine:app", "--host", "0.0.0.0", "--port", "8040"]
