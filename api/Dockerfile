FROM python:3.12-slim

# Непривилегированный пользователь
RUN useradd -m -u 1000 appuser

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /storage && chown -R appuser:appuser /storage
USER appuser

EXPOSE 5000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app.wsgi:app"]