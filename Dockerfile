FROM python:3.12-slim
WORKDIR /app
COPY main.py ./
COPY README.md ABOUT.txt ./
CMD ["python", "main.py"]
