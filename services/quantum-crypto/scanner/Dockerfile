FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY cbom_scanner.py .
EXPOSE 8030
CMD ["uvicorn", "cbom_scanner:app", "--host", "0.0.0.0", "--port", "8030"]
