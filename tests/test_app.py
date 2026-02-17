"""
Тесты для приложения Flask
"""

import os

import pytest

from app import app
import app as app_module


@pytest.fixture
def client():
    """Создание тестового клиента"""
    app.config["TESTING"] = True
    app.config["JWT_SECRET_KEY"] = "test-secret-key-longer-than-32-bytes-for-sha256"

    # Используем тестовую БД
    test_db = "test_users.db"
    original_db = app_module.DATABASE
    app_module.DATABASE = test_db
    
    if os.path.exists(test_db):
        os.remove(test_db)

    with app.test_client() as client:
        with app.app_context():
            # Инициализация тестовой БД
            import sqlite3

            from werkzeug.security import generate_password_hash

            conn = sqlite3.connect(test_db)
            cursor = conn.cursor()
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

            # Создание тестового пользователя
            password_hash = generate_password_hash("testpass")
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("testuser", password_hash),
            )
            conn.commit()
            conn.close()

        yield client

        # Восстанавливаем оригинальную БД
        app_module.DATABASE = original_db

        # Удаляем тестовую БД
        if os.path.exists(test_db):
            os.remove(test_db)


def test_health_endpoint(client):
    """Тест health check эндпоинта"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}


def test_login_success(client):
    """Тест успешной аутентификации"""
    response = client.post(
        "/auth/login", json={"username": "testuser", "password": "testpass"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json
    assert response.json["token_type"] == "Bearer"


def test_login_failure(client):
    """Тест неудачной аутентификации"""
    response = client.post(
        "/auth/login", json={"username": "testuser", "password": "wrongpass"}
    )
    assert response.status_code == 401
    assert "error" in response.json


def test_login_missing_credentials(client):
    """Тест логина без учетных данных"""
    response = client.post("/auth/login", json={})
    assert response.status_code == 400
    assert "error" in response.json


def test_get_data_without_token(client):
    """Тест доступа к защищенному эндпоинту без токена"""
    response = client.get("/api/data")
    assert response.status_code == 401


def test_get_data_with_token(client):
    """Тест доступа к защищенному эндпоинту с токеном"""
    # Сначала получаем токен
    login_response = client.post(
        "/auth/login", json={"username": "testuser", "password": "testpass"}
    )
    token = login_response.json["access_token"]

    # Затем получаем данные
    response = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert "posts" in response.json


def test_create_post_with_token(client):
    """Тест создания поста с токеном"""
    # Получаем токен
    login_response = client.post(
        "/auth/login", json={"username": "testuser", "password": "testpass"}
    )
    token = login_response.json["access_token"]

    # Создаем пост
    response = client.post(
        "/api/posts",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Test Post", "content": "Test content"},
    )
    assert response.status_code == 201
    assert "id" in response.json
    assert response.json["title"] == "Test Post"


def test_create_post_without_token(client):
    """Тест создания поста без токена"""
    response = client.post(
        "/api/posts",
        json={"title": "Test Post", "content": "Test content"},
    )
    assert response.status_code == 401
