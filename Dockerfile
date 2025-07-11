FROM python:3.13-alpine

RUN pip --no-cache-dir install fastapi uvicorn httpx

COPY . /app
WORKDIR /app

CMD ["uvicorn", "validate:app", "--host", "0.0.0.0", "--port", "8080"]
