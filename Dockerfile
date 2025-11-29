FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

RUN apt update -y && \
    apt install -y python3-dev \
    gcc \
    musl-dev

ADD pyproject.toml /app

RUN pip install --upgrade pip
RUN pip install poetry

RUN poetry config virtualenvs.create false
RUN poetry install --no-root --no-interaction --no-ansi

COPY . .

RUN mkdir -p logs

# Проверяем, что proto файлы сгенерированы (если нет - генерируем)
RUN if [ ! -f "grpc_generated/auth_pb2.py" ]; then \
    pip install grpcio-tools \
    && python -m grpc_tools.protoc \
    -I./proto \
    --python_out=./grpc_generated \
    --grpc_python_out=./grpc_generated \
    ./proto/auth.proto; \
    fi

# Проверяем структуру проекта
RUN echo "Project structure:" && find . -name "*.py" -type f | head -20

# Порт gRPC сервера
EXPOSE 50051

# Запускаем приложение
CMD ["python", "main.py"]