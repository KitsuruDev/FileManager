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
RUN useradd -m -u 1000 cliuser

WORKDIR /srv

# копирование wheel-файлов и установка их зависимостей
COPY --from=builder /srv/wheels /wheels
COPY --from=builder /srv/requirements.txt .
RUN pip install --no-cache /wheels/* && rm -rf /wheels

# копирование исходного кода
COPY client.py .

# переключение на непривилегированного пользователя
USER cliuser

CMD ["python", "client.py"]