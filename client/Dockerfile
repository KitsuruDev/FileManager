FROM python:3.12-slim

RUN useradd -m -u 1000 cliuser
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY client.py .

USER cliuser
CMD ["python", "client.py"]