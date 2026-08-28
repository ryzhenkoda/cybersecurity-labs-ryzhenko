"""
Лабораторна робота №1. Аудит власної цифрової безпеки
Дисципліна: «Захист інформації»
Програма аналізу надійності паролів з урахуванням персональних даних користувача.

Студент: Риженко Данило Євгенович
Група: 6.04.122.010.D.22.1
"""

import re

# ============================================================
# 1. ПЕРСОНАЛЬНІ ДАНІ СТУДЕНТА (для генерації тестових даних)
# ============================================================
PERSONAL_DATA = {
    "first_name_ua": "Данило",
    "last_name_ua": "Риженко",
    "patronymic_ua": "Євгенович",
    "first_name_en": "danylo",
    "last_name_en": "ryzhenko",
    "birth_date": "25.02.2005",   # ДД.ММ.РРРР
    "birth_day": "25",
    "birth_month": "02",
    "birth_year": "2005",
}

# Невеликі довідкові списки для демонстрації словникової перевірки
# та перевірки на найпоширеніші паролі (для реального проєкту варто
# підключати повноцінні списки, напр. rockyou.txt)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "qwertyuiop", "letmein", "monkey", "admin",
    "football", "iloveyou", "welcome", "abc123", "000000",
}

COMMON_WORDS = {
    "password", "qwerty", "admin", "welcome", "dragon", "monkey",
    "football", "master", "love", "sunshine", "princess",
    "пароль", "привіт", "любов", "сонце", "качка",
}


def get_personal_fragments(data: dict) -> set:
    """Генерує набір фрагментів особистих даних, які часто потрапляють у паролі."""
    fragments = {
        data["first_name_en"],
        data["first_name_en"][:4],
        data["last_name_en"],
        data["last_name_en"][:4],
        data["birth_year"],
        data["birth_day"] + data["birth_month"],          # 2502
        data["birth_month"] + data["birth_day"],           # 0225
        data["birth_date"].replace(".", ""),                # 25022005
    }
    # прибираємо надто короткі фрагменти (шум/хибні спрацювання)
    return {f for f in fragments if len(f) >= 3}


def dedupe_substrings(found: list) -> list:
    """Якщо один знайдений фрагмент є підрядком іншого - лишаємо довший."""
    found_sorted = sorted(found, key=len, reverse=True)
    result = []
    for frag in found_sorted:
        if not any(frag != other and frag in other for other in result):
            result.append(frag)
    return result


def check_personal_data_leak(password: str, data: dict) -> list:
    """Перевіряє, чи містить пароль фрагменти особистих даних користувача."""
    pwd_lower = password.lower()
    found = [frag for frag in get_personal_fragments(data) if frag in pwd_lower]
    return dedupe_substrings(found)


def check_character_diversity(password: str) -> dict:
    return {
        "has_lower": bool(re.search(r"[a-zа-яіїєё]", password.lower())),
        "has_upper": bool(re.search(r"[A-ZА-ЯІЇЄЁ]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[^a-zA-Zа-яА-ЯіІїЇєЄёЁ0-9]", password)),
    }


def check_dictionary_word(password: str) -> list:
    pwd_lower = password.lower()
    return [w for w in COMMON_WORDS if w in pwd_lower]


def score_password(password: str, personal_data: dict):
    """Оцінює пароль за шкалою 1-10, повертає (оцінку, список зауважень)."""
    score = 10
    details = []

    length = len(password)
    if length < 6:
        score -= 4
        details.append(f"Дуже короткий пароль ({length} символів)")
    elif length < 8:
        score -= 2
        details.append(f"Короткий пароль ({length} символів)")
    elif length >= 12:
        details.append(f"Хороша довжина пароля ({length} символів)")

    diversity = check_character_diversity(password)
    diversity_count = sum(diversity.values())
    if diversity_count <= 1:
        score -= 3
        details.append("Використано лише один тип символів")
    elif diversity_count == 2:
        score -= 1
        details.append("Використано лише два типи символів")
    else:
        details.append(f"Різноманітність символів: {diversity_count}/4 типи")

    personal_leaks = check_personal_data_leak(password, personal_data)
    if personal_leaks:
        penalty = min(6, 3 * len(personal_leaks))
        score -= penalty
        details.append(
            "Знайдено фрагменти особистих даних у паролі: " + ", ".join(personal_leaks)
        )

    dict_words = check_dictionary_word(password)
    if dict_words:
        score -= 2
        details.append("Знайдено словникові слова: " + ", ".join(dict_words))

    if password.lower() in COMMON_PASSWORDS:
        score -= 5
        details.append("Пароль входить до списку найпоширеніших скомпрометованих паролів")

    score = max(1, min(10, score))
    return score, details


def generate_recommendations(password: str, details: list) -> list:
    recs = []
    diversity = check_character_diversity(password)

    if any("особистих даних" in d for d in details):
        recs.append("Уникайте використання імені, прізвища чи дати народження у паролі.")
    if len(password) < 12:
        recs.append("Збільште довжину пароля щонайменше до 12-16 символів.")
    if not diversity["has_special"]:
        recs.append("Додайте спеціальні символи (!, @, #, $ тощо).")
    if not diversity["has_upper"]:
        recs.append("Додайте великі літери.")
    if not diversity["has_digit"]:
        recs.append("Додайте цифри.")
    if any("словникові" in d for d in details):
        recs.append("Не використовуйте звичайні слова зі словника - краще випадкову фразу з кількох слів.")
    if any("скомпрометованих" in d for d in details):
        recs.append("Цей пароль відомий зловмисникам - негайно замініть його на будь-яких сервісах.")
    if not recs:
        recs.append("Пароль виглядає надійним. Використовуйте менеджер паролів та унікальний пароль для кожного сервісу.")
    return recs


def analyze_password(password: str, personal_data: dict) -> dict:
    score, details = score_password(password, personal_data)
    recs = generate_recommendations(password, details)
    return {"password": password, "score": score, "details": details, "recommendations": recs}


def print_report(result: dict) -> None:
    print(f"\nПароль: {result['password']}")
    print(f"Оцінка надійності: {result['score']}/10")
    print("Деталі аналізу:")
    for d in result["details"]:
        print(f"  - {d}")
    print("Рекомендації:")
    for r in result["recommendations"]:
        print(f"  -> {r}")


if __name__ == "__main__":
    # 5 тестових паролів на основі комбінацій власного імені та дати народження
    test_passwords = [
        "danylo2005",
        "Ryzhenko25",
        "dan250205",
        "Danylo_Ryzhenko",
        "R!zh2502#05",
    ]

    print("=" * 64)
    print("АНАЛІЗ НАДІЙНОСТІ ПАРОЛІВ")
    print(
        f"Персональні дані для перевірки: "
        f"{PERSONAL_DATA['last_name_ua']} {PERSONAL_DATA['first_name_ua']}, "
        f"д.н. {PERSONAL_DATA['birth_date']}"
    )
    print("=" * 64)

    for pwd in test_passwords:
        print_report(analyze_password(pwd, PERSONAL_DATA))

    print("\n" + "=" * 64)
    print("Інтерактивна перевірка (введіть 'exit' для виходу)")
    print("=" * 64)
    while True:
        try:
            user_pwd = input("\nВведіть пароль для перевірки: ").strip()
        except EOFError:
            break
        if user_pwd.lower() == "exit" or not user_pwd:
            break
        print_report(analyze_password(user_pwd, PERSONAL_DATA))
