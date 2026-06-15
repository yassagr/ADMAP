FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY admap_m4/ ./admap_m4/

EXPOSE 8003
CMD ["uvicorn", "admap_m4.main:app", "--host", "0.0.0.0", "--port", "8003"]
