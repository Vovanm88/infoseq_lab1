"""
Скрипт для инициализации базы данных с тестовыми данными
"""
import sqlite3
from werkzeug.security import generate_password_hash

def init_test_data():
    """Создание тестовых пользователей и постов"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Создание таблиц
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')
    
    # Создание тестовых пользователей
    test_users = [
        ('admin', 'admin123'),
        ('user1', 'password123'),
        ('testuser', 'testpass')
    ]
    
    for username, password in test_users:
        password_hash = generate_password_hash(password)
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
        except sqlite3.IntegrityError:
            print(f"User {username} already exists")
    
    # Создание тестовых постов
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    admin_id = cursor.fetchone()[0]
    
    test_posts = [
        ('Welcome Post', 'This is a welcome post to our secure API'),
        ('Security Best Practices', 'Always use parameterized queries and hash passwords'),
        ('API Documentation', 'Check README.md for API documentation')
    ]
    
    for title, content in test_posts:
        cursor.execute(
            'INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
            (title, content, admin_id)
        )
    
    conn.commit()
    conn.close()
    print("Database initialized with test data")

if __name__ == '__main__':
    init_test_data()

