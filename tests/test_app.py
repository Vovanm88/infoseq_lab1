"""
Тесты для приложения Flask
"""

import pytest

from app import app


@pytest.fixture
def client():
    """Создание тестового клиента"""
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Тест health check эндпоинта"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "ok"}
