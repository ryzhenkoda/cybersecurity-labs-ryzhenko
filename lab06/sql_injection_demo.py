"""
Лабораторна робота №6. Етичний хакінг власного застосунку
Дисципліна: «Захист інформації»
Демонстрація SQL-ін'єкції (SQLi) та захисту від неї на прикладі системи
пошуку студентів і авторизації. Реалізовано дві версії однакового
функціоналу:
  - вразлива - пряме підставлення користувацького вводу в SQL-запит;
  - захищена - параметризовані запити (prepared statements).

Студент: Риженко Данило Євгенович
Група: 6.04.122.010.D.22.1
"""

import hashlib
import re
import sqlite3

DB_PATH = "students.db"


# 1. ХЕШУВАННЯ ПАРОЛІВ (для реалістичності - паролі не зберігаються у відкритому вигляді)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# 2. СТВОРЕННЯ ТЕСТОВОЇ БАЗИ ДАНИХ З ПЕРСОНАЛЬНОЮ ІНФОРМАЦІЄЮ

def setup_database(path: str = DB_PATH) -> None:
    """Створює тестову БД: таблиця students (публічно доступна через пошук)
    і таблиця secrets (адміністративна, ніколи не повинна бути доступною
    через функціонал пошуку студентів)."""
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS students;
        DROP TABLE IF EXISTS secrets;

        CREATE TABLE students (
            id INTEGER PRIMARY KEY,
            full_name TEXT NOT NULL,
            group_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY,
            note TEXT NOT NULL
        );
        """
    )

    students = [
        ("Риженко Данило Євгенович", "6.04.122.010.D.22.1", "ryzhenko509@gmail.com", "TestPass2026"),
        ("Коваленко Олена Ігорівна", "6.04.122.010.D.22.1", "kovalenko.o@example.com", "OlenaPass1"),
        ("Мельник Тарас Петрович", "6.04.122.010.D.22.2", "melnyk.t@example.com", "TarasSecure7"),
        ("Бондаренко Софія Андріївна", "6.04.122.010.D.22.2", "bondarenko.s@example.com", "Sofia_2005"),
    ]
    cur.executemany(
        "INSERT INTO students (full_name, group_name, email, password_hash) VALUES (?, ?, ?, ?)",
        [(name, group, email, hash_password(pwd)) for name, group, email, pwd in students],
    )

    cur.execute(
        "INSERT INTO secrets (note) VALUES (?)",
        ("CONFIDENTIAL: адміністративний пароль деканату - Adm1nP@ss2026",),
    )

    conn.commit()
    conn.close()


# 3. ЛОГУВАННЯ СПРОБ АТАК (заохочувана бонусна можливість)

ATTACK_PATTERNS = [r"'", r"--", r"\bUNION\b", r"\bOR\b", r";"]
attack_log = []


def log_if_suspicious(source: str, user_input: str) -> None:
    """Евристично перевіряє ввід на характерні для SQL-ін'єкції символи й
    записує підозрілі спроби в журнал. Це проста ілюстративна перевірка
    для логування, а НЕ повноцінний WAF і НЕ засіб захисту - вона нічого
    не блокує, лише фіксує факт підозрілого вводу."""
    matched = [p for p in ATTACK_PATTERNS if re.search(p, user_input, re.IGNORECASE)]
    if matched:
        attack_log.append({"source": source, "input": user_input, "matched_patterns": matched})


# 4. ВРАЗЛИВА ВЕРСІЯ - пряме підставлення вводу в SQL-запит

def login_vulnerable(email: str, password: str, path: str = DB_PATH):
    log_if_suspicious("login_vulnerable.email", email)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    query = f"SELECT full_name, group_name, email FROM students WHERE email = '{email}' AND password_hash = '{hash_password(password)}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows, query


def search_vulnerable(name_query: str, path: str = DB_PATH):
    log_if_suspicious("search_vulnerable.name_query", name_query)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    query = f"SELECT full_name, group_name, email FROM students WHERE full_name LIKE '%{name_query}%'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows, query


# 5. ЗАХИЩЕНА ВЕРСІЯ - параметризовані запити (prepared statements)

def login_secure(email: str, password: str, path: str = DB_PATH):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    query = "SELECT full_name, group_name, email FROM students WHERE email = ? AND password_hash = ?"
    cur.execute(query, (email, hash_password(password)))
    rows = cur.fetchall()
    conn.close()
    return rows, query


def search_secure(name_query: str, path: str = DB_PATH):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    query = "SELECT full_name, group_name, email FROM students WHERE full_name LIKE ?"
    cur.execute(query, (f"%{name_query}%",))
    rows = cur.fetchall()
    conn.close()
    return rows, query


# 6. ДЕМОНСТРАЦІЯ

def print_rows(rows):
    if not rows:
        print("   (порожній результат)")
    for row in rows:
        print("  ", row)


if __name__ == "__main__":
    setup_database()

    print("=" * 70)
    print("КРОК 1. ЗВИЧАЙНЕ ВИКОРИСТАННЯ (легітимний ввід) - обидві версії")
    print("=" * 70)
    print("Пошук за ім'ям 'Данило' (вразлива версія):")
    normal_rows_vuln, q = search_vulnerable("Данило")
    print(f"  SQL: {q}")
    print_rows(normal_rows_vuln)
    print("Пошук за ім'ям 'Данило' (захищена версія):")
    normal_rows_secure, q = search_secure("Данило")
    print(f"  SQL: {q}  parameters=('%Данило%',)")
    print_rows(normal_rows_secure)

    print("\n" + "=" * 70)
    print("КРОК 2. АТАКА 1 - ОБХІД АВТОРИЗАЦІЇ (SQL injection в email)")
    print("=" * 70)
    attack_email = "x' OR '1'='1' -- "
    attack_password = "будь-який, не має значення"
    print(f"Payload (email): {attack_email!r}")

    print("\n-- Вразлива версія --")
    auth_rows_vuln, q = login_vulnerable(attack_email, attack_password)
    print(f"  SQL: {q}")
    print(f"  Результат: {'УСПІШНИЙ ВХІД БЕЗ ПАРОЛЯ (' + str(len(auth_rows_vuln)) + ' обліковий(і) запис(и))' if auth_rows_vuln else 'відмовлено'}")
    print_rows(auth_rows_vuln)

    print("\n-- Захищена версія --")
    auth_rows_secure, q = login_secure(attack_email, attack_password)
    print(f"  SQL: {q}  parameters=({attack_email!r}, <hash>)")
    print(f"  Результат: {'вхід виконано (!!)' if auth_rows_secure else 'ВІДМОВЛЕНО - авторизація не пройдена'}")
    print_rows(auth_rows_secure)

    print("\n" + "=" * 70)
    print("КРОК 3. АТАКА 2 - ВИТІК ДАНИХ ЧЕРЕЗ UNION (пошук)")
    print("=" * 70)
    attack_search = "%' UNION SELECT note, 'LEAK', 'LEAK' FROM secrets -- "
    print(f"Payload (пошук): {attack_search!r}")

    print("\n-- Вразлива версія --")
    union_rows_vuln, q = search_vulnerable(attack_search)
    print(f"  SQL: {q}")
    leaked_vuln = [r for r in union_rows_vuln if r[1] == "LEAK"]
    print(f"  Результат: {'ВИТІК ' + str(len(leaked_vuln)) + ' запис(ів) з таблиці secrets' if leaked_vuln else 'витоку немає'}")
    print_rows(union_rows_vuln)

    print("\n-- Захищена версія --")
    union_rows_secure, q = search_secure(attack_search)
    print(f"  SQL: {q}  parameters=('%{attack_search}%',)")
    leaked_secure = [r for r in union_rows_secure if r[1] == "LEAK"]
    print(f"  Результат: {'витік стався (!!)' if leaked_secure else 'витоку немає - payload опрацьовано як звичайний текст пошуку'}")
    print_rows(union_rows_secure)

    print("\n" + "=" * 70)
    print("КРОК 4. ЖУРНАЛ ПІДОЗРІЛИХ СПРОБ (лише вразлива версія веде лог)")
    print("=" * 70)
    for entry in attack_log:
        print(f"  [{entry['source']}] ввід={entry['input']!r} -> патерни: {entry['matched_patterns']}")
    print(f"Усього зафіксовано підозрілих спроб: {len(attack_log)}")

    import json

    results = {
        "normal_search_vulnerable_count": len(normal_rows_vuln),
        "normal_search_secure_count": len(normal_rows_secure),
        "auth_bypass_vulnerable_rows": len(auth_rows_vuln),
        "auth_bypass_secure_rows": len(auth_rows_secure),
        "union_leak_vulnerable_rows": len(leaked_vuln),
        "union_leak_secure_rows": len(leaked_secure),
        "attack_log_entries": len(attack_log),
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("\n[Результати збережено у results.json]")
