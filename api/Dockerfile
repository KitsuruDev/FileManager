# ==========================================
# Стадия 1: Сборка зависимостей (builder)
# ==========================================
FROM python:3.12-slim AS builder

WORKDIR /srv
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /srv/wheels -r requirements.txt


# ==========================================
# Стадия 2: Финальный образ (runtime)
# ==========================================
FROM python:3.12-slim

# непривилегированный пользователь
RUN useradd -m -u 1000 appuser

WORKDIR /srv

# копирование wheel-файлов и установка их зависимостей
COPY --from=builder /srv/wheels /wheels
COPY --from=builder /srv/requirements.txt .
RUN pip install --no-cache /wheels/* && rm -rf /wheels

# копирование исходного кода
COPY app ./app

# папка для файлов
RUN mkdir -p /storage && chown -R appuser:appuser /storage

# переключение на непривилегированного пользователя
USER appuser

EXPOSE 5000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app.wsgi:app"]