"""
Лабораторна робота №2. Захист особистих повідомлень
Дисципліна: «Захист інформації»
Порівняльний аналіз класичних шифрів (Цезар, Віженер) з ключами,
згенерованими на основі персональних даних користувача.

Студент: Риженко Данило 
Група: 6.04.122.010.D.22.1
"""

from collections import Counter

# ============================================================
# 1. ПЕРСОНАЛЬНІ ДАНІ ТА АЛФАВІТ
# ============================================================
PERSONAL_DATA = {
    "last_name_ua": "Риженко",
    "birth_date": "25.02.2005",  # ДД.ММ.РРРР
}

# Український алфавіт (33 літери, без ъ/ы/э - вони не використовуються в укр. мові)
UA_LOWER = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
UA_UPPER = UA_LOWER.upper()
ALPHABET_SIZE = len(UA_LOWER)  # 33


def caesar_shift_from_birthdate(date_str: str) -> int:
    """Ключ шифру Цезаря = сума цифр дати народження."""
    return sum(int(ch) for ch in date_str if ch.isdigit())


# ============================================================
# 2. ШИФР ЦЕЗАРЯ
# ============================================================
def _caesar_transform(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch in UA_LOWER:
            idx = (UA_LOWER.index(ch) + shift) % ALPHABET_SIZE
            result.append(UA_LOWER[idx])
        elif ch in UA_UPPER:
            idx = (UA_UPPER.index(ch) + shift) % ALPHABET_SIZE
            result.append(UA_UPPER[idx])
        else:
            result.append(ch)  # пробіли, розділові знаки - без змін
    return "".join(result)


def caesar_encrypt(text: str, shift: int) -> str:
    return _caesar_transform(text, shift)


def caesar_decrypt(text: str, shift: int) -> str:
    return _caesar_transform(text, -shift)


# ============================================================
# 3. ШИФР ВІЖЕНЕРА
# ============================================================
def _vigenere_transform(text: str, key: str, encrypt: bool) -> str:
    key = key.lower()
    key_shifts = [UA_LOWER.index(k) for k in key if k in UA_LOWER]
    if not key_shifts:
        raise ValueError("Ключ має містити хоча б одну українську літеру")

    result = []
    ki = 0
    for ch in text:
        is_lower = ch in UA_LOWER
        is_upper = ch in UA_UPPER
        if is_lower or is_upper:
            base = UA_LOWER if is_lower else UA_UPPER
            shift = key_shifts[ki % len(key_shifts)]
            if not encrypt:
                shift = -shift
            idx = (base.index(ch) + shift) % ALPHABET_SIZE
            result.append(base[idx])
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_encrypt(text: str, key: str) -> str:
    return _vigenere_transform(text, key, encrypt=True)


def vigenere_decrypt(text: str, key: str) -> str:
    return _vigenere_transform(text, key, encrypt=False)


# ============================================================
# 3б. ШИФР АТБАШ (додатковий - для порівняльного дослідження)
# ============================================================
def atbash_transform(text: str) -> str:
    """Атбаш - дзеркальна заміна: перша літера алфавіту <-> остання, і т.д.
    Самооберненний шифр: та сама функція шифрує і розшифровує."""
    result = []
    for ch in text:
        if ch in UA_LOWER:
            idx = UA_LOWER.index(ch)
            result.append(UA_LOWER[ALPHABET_SIZE - 1 - idx])
        elif ch in UA_UPPER:
            idx = UA_UPPER.index(ch)
            result.append(UA_UPPER[ALPHABET_SIZE - 1 - idx])
        else:
            result.append(ch)
    return "".join(result)


# ============================================================
# 4. КРИПТОАНАЛІЗ: BRUTE FORCE ДЛЯ ШИФРУ ЦЕЗАРЯ
# ============================================================
def brute_force_caesar(ciphertext: str) -> list:
    """Перебирає всі можливі зсуви (1..32) і повертає список (зсув, текст)."""
    return [(shift, caesar_decrypt(ciphertext, shift)) for shift in range(1, ALPHABET_SIZE)]


# ============================================================
# 5. ЧАСТОТНИЙ АНАЛІЗ (додатково)
# ============================================================
def letter_frequency(text: str) -> list:
    """Повертає список (літера, частка) за спаданням частоти."""
    letters = [ch.lower() for ch in text if ch.lower() in UA_LOWER]
    total = len(letters)
    if total == 0:
        return []
    counts = Counter(letters)
    return [(letter, count / total) for letter, count in counts.most_common()]


# ============================================================
# 6. ДЕМОНСТРАЦІЯ
# ============================================================
if __name__ == "__main__":
    text = (
        "Розробка ігор поєднує програмування, дизайн та мистецтво "
        "в один цілісний продукт для гравців."
    )

    caesar_shift = caesar_shift_from_birthdate(PERSONAL_DATA["birth_date"])
    vigenere_key = PERSONAL_DATA["last_name_ua"]

    print("=" * 70)
    print("ПОРІВНЯЛЬНИЙ АНАЛІЗ ШИФРІВ")
    print(f"Текст: {text}")
    print(f"Ключ Цезаря (сума цифр дати народження {PERSONAL_DATA['birth_date']}): {caesar_shift}")
    print(f"Ключ Віженера (прізвище): {vigenere_key}")
    print("=" * 70)

    caesar_cipher = caesar_encrypt(text, caesar_shift)
    vigenere_cipher = vigenere_encrypt(text, vigenere_key)
    atbash_cipher = atbash_transform(text)

    print("\n--- ШИФР ЦЕЗАРЯ ---")
    print(f"Зашифровано: {caesar_cipher}")
    print(f"Розшифровано: {caesar_decrypt(caesar_cipher, caesar_shift)}")
    assert caesar_decrypt(caesar_cipher, caesar_shift) == text

    print("\n--- ШИФР ВІЖЕНЕРА ---")
    print(f"Зашифровано: {vigenere_cipher}")
    print(f"Розшифровано: {vigenere_decrypt(vigenere_cipher, vigenere_key)}")
    assert vigenere_decrypt(vigenere_cipher, vigenere_key) == text

    print("\n--- ШИФР АТБАШ (додатковий) ---")
    print(f"Зашифровано: {atbash_cipher}")
    print(f"Розшифровано: {atbash_transform(atbash_cipher)}")
    assert atbash_transform(atbash_cipher) == text

    print("\n--- ПОРІВНЯННЯ ---")
    print(f"{'Метод':<12}{'Довжина':<10}{'Ключ':<15}{'Приклад результату'}")
    print(f"{'Цезар':<12}{len(caesar_cipher):<10}{str(caesar_shift):<15}{caesar_cipher[:40]}...")
    print(f"{'Віженер':<12}{len(vigenere_cipher):<10}{vigenere_key:<15}{vigenere_cipher[:40]}...")
    print(f"{'Атбаш':<12}{len(atbash_cipher):<10}{'(без ключа)':<15}{atbash_cipher[:40]}...")

    print("\n--- ЧАСТОТНИЙ АНАЛІЗ (топ-5 літер) ---")
    print("Оригінал:", letter_frequency(text)[:5])
    print("Цезар:   ", letter_frequency(caesar_cipher)[:5])
    print("Віженер: ", letter_frequency(vigenere_cipher)[:5])
    print("Атбаш:   ", letter_frequency(atbash_cipher)[:5])

    print("\n--- КРИПТОАНАЛІЗ: BRUTE FORCE ШИФРУ ЦЕЗАРЯ ---")
    print(f"Зашифрований текст: {caesar_cipher}\n")
    for shift, candidate in brute_force_caesar(caesar_cipher):
        marker = "  <-- правильний зсув" if shift == caesar_shift else ""
        print(f"Зсув {shift:2d}: {candidate[:55]}{marker}")
