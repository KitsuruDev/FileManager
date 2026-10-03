-- Users: пароль только в виде bcrypt-хеша (CWE-916 закрыт)
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    failed_count  INT          NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ
);

-- Files: метаданные файлов
CREATE TABLE IF NOT EXISTS files (
    id         SERIAL PRIMARY KEY,
    filename   VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    size       BIGINT,
    location   VARCHAR(512) NOT NULL,
    owner_id   INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

-- Sessions: Bearer-токены (FK -> users, поэтому после users)
CREATE TABLE IF NOT EXISTS api_sessions (
    token      TEXT PRIMARY KEY,
    user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Operations: журнал аудита
CREATE TABLE IF NOT EXISTS operations (
    id             SERIAL PRIMARY KEY,
    timestamp      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    operation_type VARCHAR(20) NOT NULL
                   CHECK (operation_type IN ('create','modify','delete','read','login','logout','zip','unzip')),
    file_id        INT REFERENCES files(id) ON DELETE SET NULL,
    user_id        INT REFERENCES users(id) ON DELETE SET NULL,
    details        TEXT
);

CREATE INDEX IF NOT EXISTS idx_operations_user ON operations(user_id);
CREATE INDEX IF NOT EXISTS idx_operations_file ON operations(file_id);
CREATE INDEX IF NOT EXISTS idx_files_owner     ON files(owner_id);