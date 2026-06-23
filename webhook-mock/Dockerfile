FROM python:3.13-alpine
WORKDIR /app
COPY webhook_server.py .
EXPOSE 9000
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/health')"
CMD ["python", "webhook_server.py"]
