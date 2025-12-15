# Secure REST API

Защищенное REST API с интеграцией в CI/CD и защитой от OWASP Top 10.

## Описание проекта

Проект представляет собой простое, но защищенное веб-API на Flask с реализацией базовых мер безопасности согласно OWASP Top 10. API включает аутентификацию через JWT, защиту от SQL-инъекций, XSS и других распространенных уязвимостей.

## Технологический стек

- **Python 3.9+**
- **Flask** - веб-фреймворк
- **Flask-JWT-Extended** - JWT аутентификация
- **bcrypt** - хэширование паролей
- **SQLite** - база данных
- **Poetry** - менеджер пакетов

## Установка и запуск

### Требования

- Python 3.9 или выше
- Poetry (или uv)

### Установка зависимостей

```bash
# С использованием Poetry
poetry install

# Или с использованием uv
uv pip install -r requirements.txt
```

### Инициализация базы данных

```bash
poetry run python init_db.py
```

### Запуск приложения

```bash
poetry run python app.py
```

Приложение будет доступно по адресу: `http://localhost:5000`

## API Эндпоинты

### 1. POST /auth/login

Аутентификация пользователя и получение JWT токена.

**Запрос:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Ответ (успех):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer"
}
```

**Ответ (ошибка):**
```json
{
  "error": "Invalid credentials"
}
```

**Пример с curl:**
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### 2. GET /api/data

Получение списка постов. Требует аутентификации.

**Заголовки:**
```
Authorization: Bearer <access_token>
```

**Ответ:**
```json
{
  "posts": [
    {
      "id": 1,
      "title": "Welcome Post",
      "content": "This is a welcome post",
      "author": "admin"
    }
  ]
}
```

**Пример с curl:**
```bash
curl -X GET http://localhost:5000/api/data \
  -H "Authorization: Bearer <your_token>"
```

### 3. POST /api/posts

Создание нового поста. Требует аутентификации.

**Заголовки:**
```
Authorization: Bearer <access_token>
```

**Запрос:**
```json
{
  "title": "New Post",
  "content": "Post content here"
}
```

**Ответ:**
```json
{
  "id": 4,
  "title": "New Post",
  "content": "Post content here",
  "message": "Post created successfully"
}
```

**Пример с curl:**
```bash
curl -X POST http://localhost:5000/api/posts \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{"title": "New Post", "content": "Post content"}'
```

### 4. GET /health

Health check эндпоинт (не требует аутентификации).

**Ответ:**
```json
{
  "status": "ok"
}
```

## Реализованные меры защиты

### 1. Защита от SQL-инъекций (SQLi)

**Проблема:** Конкатенация строк в SQL-запросах позволяет злоумышленникам выполнять произвольный SQL-код.

**Решение:** Использование параметризованных запросов (Prepared Statements) во всех местах работы с базой данных.

**Пример реализации:**
```python
# НЕПРАВИЛЬНО (уязвимо к SQLi):
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# ПРАВИЛЬНО (защищено):
cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
```

**Где реализовано:**
- `app.py`: Все SQL-запросы используют параметризованные запросы с плейсхолдерами `?`
- Функции `login()`, `get_data()`, `create_post()` - все используют параметризованные запросы

### 2. Защита от XSS (Cross-Site Scripting)

**Проблема:** Пользовательские данные, возвращаемые в ответах API без санитизации, могут содержать вредоносный JavaScript-код.

**Решение:** Санитизация всех пользовательских данных перед отправкой в ответах API с помощью функции `escape()` из Flask.

**Пример реализации:**
```python
def sanitize_input(data):
    """Санитизация пользовательских данных для защиты от XSS"""
    if isinstance(data, str):
        return escape(data)
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    return data
```

**Где реализовано:**
- Функция `sanitize_input()` в `app.py`
- Все данные из базы данных санитизируются перед отправкой в `get_data()`
- Все входные данные санитизируются в `create_post()`

### 3. Защита от Broken Authentication

**Проблема:** Неправильная реализация аутентификации может привести к компрометации учетных записей.

**Решение:** Комплексная защита аутентификации:

#### 3.1. JWT токены
- Использование JWT (JSON Web Tokens) для аутентификации
- Токены имеют срок действия (1 час)
- Middleware `@jwt_required()` защищает все приватные эндпоинты

**Реализация:**
```python
from flask_jwt_extended import jwt_required, create_access_token

@app.route('/api/data', methods=['GET'])
@jwt_required()
def get_data():
    current_user_id = get_jwt_identity()
    # ...
```

#### 3.2. Хэширование паролей
- Пароли никогда не хранятся в открытом виде
- Использование `werkzeug.security.generate_password_hash()` и `check_password_hash()`
- Алгоритм хэширования: PBKDF2 с SHA-256

**Реализация:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# При создании пользователя:
password_hash = generate_password_hash(password)

# При проверке пароля:
if check_password_hash(user['password_hash'], password):
    # аутентификация успешна
```

**Где реализовано:**
- `init_db.py`: Пароли хэшируются при создании пользователей
- `app.py`: Пароли проверяются через `check_password_hash()` в функции `login()`

## CI/CD Pipeline с Security-сканерами

### Настройка GitHub Actions

В проекте настроен CI/CD pipeline в файле `.github/workflows/ci.yml`, который автоматически запускается при каждом push или создании pull request.

### SAST (Static Application Security Testing)

**Bandit** - статический анализатор безопасности для Python кода.

Проверяет:
- Использование небезопасных функций
- Потенциальные SQL-инъекции
- Хардкод паролей и секретов
- Использование устаревших криптографических функций

**Запуск вручную:**
```bash
poetry run bandit -r .
```

### SCA (Software Composition Analysis)

**Safety** - проверка зависимостей на известные уязвимости.

Проверяет:
- Уязвимости в установленных пакетах
- Устаревшие версии библиотек с известными CVE

**Запуск вручную:**
```bash
poetry run safety check
```

**OWASP Dependency-Check** - комплексный анализ зависимостей.

Проверяет:
- Известные уязвимости в зависимостях
- Лицензионные проблемы
- Устаревшие библиотеки

### Отчеты безопасности

После каждого запуска pipeline создаются отчеты:
- `bandit-report.json` - отчет Bandit в JSON формате
- `safety-report.json` - отчет Safety в JSON формате
- `dependency-check-report.json` - отчет OWASP Dependency-Check в JSON формате
- `dependency-check-report.html` - HTML отчет OWASP Dependency-Check

Все отчеты сохраняются как артефакты GitHub Actions и доступны в разделе "Actions" репозитория.

## Тестирование API

### Тестовые пользователи

После инициализации базы данных доступны следующие тестовые пользователи:

- `admin` / `admin123`
- `user1` / `password123`
- `testuser` / `testpass`

### Примеры использования

1. **Получение токена:**
```bash
TOKEN=$(curl -s -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' \
  | jq -r '.access_token')
```

2. **Получение списка постов:**
```bash
curl -X GET http://localhost:5000/api/data \
  -H "Authorization: Bearer $TOKEN"
```

3. **Создание нового поста:**
```bash
curl -X POST http://localhost:5000/api/posts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "My Post", "content": "Post content"}'
```

## Структура проекта

```
lab1/
├── app.py                 # Основное приложение Flask
├── init_db.py            # Инициализация БД с тестовыми данными
├── pyproject.toml        # Конфигурация Poetry
├── README.md             # Документация проекта
├── .gitignore            # Игнорируемые файлы
└── .github/
    └── workflows/
        └── ci.yml        # CI/CD pipeline с security-сканерами
```

## Ссылки

- [GitHub Repository](https://github.com/Vovanm88/infoseq_lab1)
- [CI/CD Pipeline](https://github.com/Vovanm88/infoseq_lab1/actions/runs/20221859348)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## Скриншоты отчетов безопасности

### Bandit SAST Report
![Bandit Report](screenshots/bandit-report.png)

### Safety SCA Report
![Safety Report](screenshots/safety-report.png)

### OWASP Dependency-Check Report
![Dependency-Check Report](screenshots/dependency-check-report.png)

*Примечание: Скриншоты отчетов должны быть добавлены после успешного запуска pipeline в GitHub Actions.*

