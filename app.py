"""
Secure REST API with OWASP Top 10 protection
"""

import os
import sqlite3
from datetime import timedelta

from flask import Flask, jsonify, request
from markupsafe import escape
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Конфигурация JWT
app.config["JWT_SECRET_KEY"] = os.environ.get(
    "JWT_SECRET_KEY", "your-secret-key-change-in-production"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

jwt = JWTManager(app)

# Инициализация базы данных
DATABASE = "users.db"


def init_db():
    """Инициализация базы данных с параметризованными запросами"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Используем параметризованные запросы для защиты от SQLi
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    """
    )

    conn.commit()
    conn.close()


def get_db_connection():
    """Получение соединения с БД"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def sanitize_input(data):
    """Санитизация пользовательских данных для защиты от XSS"""
    if isinstance(data, str):
        return escape(data)
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    return data


@app.route("/auth/login", methods=["POST"])
def login():
    """
    Аутентификация пользователя
    Принимает логин и пароль, возвращает JWT токен
    """
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return (
            jsonify({"error": "Username and password are required"}),
            400,
        )

    username = data["username"]
    password = data["password"]

    # Санитизация входных данных
    username = sanitize_input(username)

    conn = get_db_connection()

    # Параметризованный запрос для защиты от SQLi
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    )
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        # Создание JWT токена
        access_token = create_access_token(identity=user["id"])
        return (
            jsonify({"access_token": access_token, "token_type": "Bearer"}),  # nosec B105: 'Bearer' — имя схемы авторизации, а не секрет
            200,
        )
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/data", methods=["GET"])
@jwt_required()
def get_data():
    """
    Получение списка постов
    Доступ только для аутентифицированных пользователей
    """
    conn = get_db_connection()

    # Параметризованный запрос для защиты от SQLi
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT p.id, p.title, p.content, u.username as author
        FROM posts p
        JOIN users u ON p.author_id = u.id
        ORDER BY p.id DESC
    """
    )
    posts = cursor.fetchall()
    conn.close()

    # Санитизация данных перед отправкой (защита от XSS)
    result = []
    for post in posts:
        result.append(
            {
                "id": post["id"],
                "title": sanitize_input(post["title"]),
                "content": sanitize_input(post["content"]),
                "author": sanitize_input(post["author"]),
            }
        )

    return jsonify({"posts": result}), 200


@app.route("/api/posts", methods=["POST"])
@jwt_required()
def create_post():
    """
    Создание нового поста
    Третий эндпоинт - создание поста
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()

    if not data or "title" not in data or "content" not in data:
        return (
            jsonify({"error": "Title and content are required"}),
            400,
        )

    title = sanitize_input(data["title"])
    content = sanitize_input(data["content"])

    conn = get_db_connection()

    # Параметризованный запрос для защиты от SQLi
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO posts (title, content, author_id)
        VALUES (?, ?, ?)
    """,
        (title, content, current_user_id),
    )

    conn.commit()
    post_id = cursor.lastrowid
    conn.close()

    return (
        jsonify(
            {
                "id": post_id,
                "title": title,
                "content": content,
                "message": "Post created successfully",
            }
        ),
        201,
    )


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    init_db()
    # Безопасный режим по умолчанию: debug выключен, слушаем только localhost.
    # Для локальной разработки можно включить FLASK_DEBUG=1, тогда включится debug и bind на 0.0.0.0.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = "127.0.0.1"
    if debug_mode:
        host = "0.0.0.0"
    app.run(debug=debug_mode, host=host, port=5000)
