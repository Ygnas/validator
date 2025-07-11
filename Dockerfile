FROM python:3.11-slim

RUN pip install fastapi uvicorn PyJWT requests kubernetes httpx

COPY . /app
WORKDIR /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

