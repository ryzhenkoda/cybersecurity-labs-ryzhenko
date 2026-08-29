"""
Лабораторна робота №4. Особистий цифровий підпис
Дисципліна: «Захист інформації»
Навчальна реалізація асиметричного (RSA-подібного) цифрового підпису на
основі персональних даних. Приватний ключ реально підписує хеш документа,
а публічний ключ реально перевіряє підпис - без спільного секрету між
підписанням і перевіркою.

УВАГА: розмір ключа (1024 біт) обраний для навчальної демонстрації і
швидкості виконання. Для промислового використання RSA застосовують
модулі від 2048 біт і схеми доповнення (padding), яких тут навмисно
немає - це спрощена, а не криптографічно стійка для реального
використання реалізація.

Студент: Риженко Данило
Група: 6.04.122.010.D.22.1
"""

import hashlib
import json
import random
import sys

RSA_MODULUS_BITS = 1024   # довжина модуля n; кожен з простих p, q - вдвічі коротший
PUBLIC_EXPONENT = 65537   # стандартне значення e, що використовується і в реальному RSA


# 1. ПРОСТІ ЧИСЛА ТА МОДУЛЬНА АРИФМЕТИКА (без готових бібліотек RSA)

def is_probable_prime(n: int, rng: random.Random, rounds: int = 20) -> bool:
    """Ймовірнісний тест Міллера-Рабіна на простоту числа n."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rng: random.Random) -> int:
    """Генерує ймовірно просте число заданої довжини, використовуючи rng."""
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rng):
            return candidate


def egcd(a: int, b: int):
    """Розширений алгоритм Евкліда: повертає (gcd, x, y), де a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def modinv(a: int, m: int) -> int:
    """Обернений елемент a за модулем m (розширений Евклід)."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("Обернений елемент не існує - a і m не взаємно прості")
    return x % m


# 2. ГЕНЕРАЦІЯ ПАРИ КЛЮЧІВ НА ОСНОВІ ПЕРСОНАЛЬНИХ ДАНИХ

def generate_keys(full_name: str, birth_date: str, secret_word: str):
    """
    Генерує навчальну пару RSA-ключів на основі персональних даних.

    ПІБ, дата народження і секретне слово хешуються (SHA-256), і результат
    використовується як seed для детермінованого генератора випадкових
    чисел (random.Random). Це означає: той самий студент з тим самим
    секретним словом завжди отримає ту саму пару ключів, а стороння
    особа, яка не знає секретного слова, не зможе відтворити приватний
    ключ, навіть знаючи ПІБ і дату народження.

    Повертає:
        private_key = (d, n) - показник підписання; тримається в таємниці
        public_key  = (e, n) - показник перевірки; може бути опублікований
    """
    seed_material = f"{full_name}|{birth_date}|{secret_word}".encode("utf-8")
    seed = int.from_bytes(hashlib.sha256(seed_material).digest(), "big")
    rng = random.Random(seed)

    half_bits = RSA_MODULUS_BITS // 2
    p = generate_prime(half_bits, rng)
    q = generate_prime(half_bits, rng)
    while q == p:
        q = generate_prime(half_bits, rng)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = PUBLIC_EXPONENT
    while egcd(e, phi)[0] != 1:
        e += 2

    d = modinv(e, phi)

    private_key = (d, n)
    public_key = (e, n)
    return private_key, public_key


# 3. ХЕШУВАННЯ, ПІДПИСАННЯ, ПЕРЕВІРКА

def hash_document(file_path: str) -> int:
    """Обчислює SHA-256 хеш вмісту файлу і повертає його як велике ціле число."""
    with open(file_path, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big")


def sign_document(file_path: str, private_key) -> int:
    """
    Підписує документ приватним ключем: підпис = хеш^d mod n.

    Це справжня RSA-операція піднесення до степеня за модулем - той самий
    принцип, що використовується в реальних цифрових підписах (без
    додаткової схеми доповнення (padding), яку застосовують промислові
    реалізації для додаткового захисту).
    """
    d, n = private_key
    h = hash_document(file_path)
    if h >= n:
        raise ValueError("Хеш документа виявився більшим за модуль n - зменшіть RSA_MODULUS_BITS")
    return pow(h, d, n)


def verify_signature(file_path: str, signature: int, public_key):
    """
    Перевіряє підпис публічним ключем: підпис^e mod n має збігатися з
    поточним SHA-256 хешем файлу.

    Правильний результат отримати можна лише тим e, що математично
    пов'язаний із d, яким документ підписували, - тобто перевірка
    виконується виключно публічним ключем, без доступу до приватного.
    """
    e, n = public_key
    recovered_hash = pow(signature, e, n)
    current_hash = hash_document(file_path)
    return recovered_hash == current_hash, current_hash, recovered_hash


# 4. ДЕМОНСТРАЦІЯ

if __name__ == "__main__":
    FULL_NAME = "Риженко Данило Євгенович"
    BIRTH_DATE = "25.02.2005"
    DOCUMENT = "test_document.txt"
    TAMPERED_DOCUMENT = "test_document_tampered.txt"

    # Секретне слово запитується під час запуску і ніде не зберігається.
    # Для відтворюваного автоматизованого запуску його можна передати
    # першим аргументом командного рядка: python3 digital_signature.py <слово>
    if len(sys.argv) > 1:
        secret_word = sys.argv[1]
    else:
        secret_word = input("Введіть секретне слово для генерації ключів: ").strip()
    if not secret_word:
        raise SystemExit("Секретне слово не може бути порожнім.")

    print("=" * 70)
    print("КРОК 1. ГЕНЕРАЦІЯ ПАРИ RSA-КЛЮЧІВ НА ОСНОВІ ПЕРСОНАЛЬНИХ ДАНИХ")
    print("=" * 70)
    private_key, public_key = generate_keys(FULL_NAME, BIRTH_DATE, secret_word)
    e, n = public_key
    print(f"Вхідні дані: «{FULL_NAME}» + «{BIRTH_DATE}» + секретне слово (не виводиться)")
    print(f"Розмір модуля n: {n.bit_length()} біт")
    print(f"Публічний ключ:  e = {e}")
    print(f"                 n = {n}")
    print("Приватний ключ (d) згенеровано і залишається лише в пам'яті процесу -")
    print("не виводиться на екран і не зберігається в жодному файлі.")

    print("\n" + "=" * 70)
    print("КРОК 2. ПІДПИСАННЯ ДОКУМЕНТА")
    print("=" * 70)
    print(f"Документ: {DOCUMENT}")
    original_hash = hash_document(DOCUMENT)
    signature = sign_document(DOCUMENT, private_key)
    print(f"SHA-256 хеш документа (як число): {original_hash}")
    print(f"Цифровий підпис (хеш^d mod n):     {signature}")

    with open("public_key.txt", "w", encoding="utf-8") as f:
        f.write("-----BEGIN EDUCATIONAL RSA PUBLIC KEY-----\n")
        f.write(f"owner={FULL_NAME}\n")
        f.write(f"e={e}\n")
        f.write(f"n={n}\n")
        f.write("-----END EDUCATIONAL RSA PUBLIC KEY-----\n")
    with open("signature.sig", "w", encoding="utf-8") as f:
        f.write(f"document={DOCUMENT}\n")
        f.write("hash_algorithm=SHA-256\n")
        f.write(f"signature={signature}\n")
    print("Публічний ключ збережено -> public_key.txt")
    print("Підпис збережено          -> signature.sig")

    print("\n" + "=" * 70)
    print("КРОК 3. ПЕРЕВІРКА ПІДПИСУ НА НЕЗМІНЕНОМУ ДОКУМЕНТІ")
    print("=" * 70)
    is_valid, current_hash, recovered_hash = verify_signature(DOCUMENT, signature, public_key)
    print(f"Розшифрований підпис (підпис^e mod n): {recovered_hash}")
    print(f"Поточний хеш документа:                {current_hash}")
    print(f"Результат: {'ПІДПИС ДІЙСНИЙ' if is_valid else 'ПІДПИС НЕДІЙСНИЙ'}")

    print("\n" + "=" * 70)
    print("КРОК 4. ТЕСТУВАННЯ ПІДРОБКИ - МОДИФІКАЦІЯ ДОКУМЕНТА")
    print("=" * 70)
    with open(DOCUMENT, "rb") as f:
        original_bytes = f.read()
    tampered_bytes = original_bytes.replace(
        "Данило".encode("utf-8"), "Данила".encode("utf-8"), 1
    )
    if tampered_bytes == original_bytes:
        tampered_bytes = original_bytes + b" "
    with open(TAMPERED_DOCUMENT, "wb") as f:
        f.write(tampered_bytes)
    print(f"Створено підроблену копію: {TAMPERED_DOCUMENT} (1 символ відрізняється від оригіналу)")

    is_valid_t, current_hash_t, recovered_hash_t = verify_signature(
        TAMPERED_DOCUMENT, signature, public_key
    )
    print(f"Розшифрований підпис (той самий підпис):     {recovered_hash_t}")
    print(f"Поточний хеш підробленого документа:         {current_hash_t}")
    print(f"Результат: {'ПІДПИС ДІЙСНИЙ' if is_valid_t else 'ПІДПИС НЕДІЙСНИЙ'}")

    print("\n" + "=" * 70)
    print("ЧОМУ ПІДПИС НЕМОЖЛИВО ПІДРОБИТИ БЕЗ ПРИВАТНОГО КЛЮЧА")
    print("=" * 70)
    print(
        "Щоб підробити підпис, потрібно обчислити d, знаючи лише публічний\n"
        "ключ (e, n). Це вимагає розкладання n на множники p і q (n = p*q).\n"
        "Для реальних розмірів RSA (2048+ біт) задача факторизації великих\n"
        "чисел обчислювально нездійсненна за розумний час; саме її складність,\n"
        "а не секретність самого алгоритму, забезпечує стійкість RSA. У цій\n"
        f"навчальній реалізації n має {n.bit_length()} біт - для промислового\n"
        "застосування довжину модуля збільшують до 2048+ біт."
    )

    results = {
        "full_name": FULL_NAME,
        "birth_date": BIRTH_DATE,
        "document": DOCUMENT,
        "tampered_document": TAMPERED_DOCUMENT,
        "modulus_bits": n.bit_length(),
        "public_key": {"e": e, "n": str(n)},
        "document_hash": str(original_hash),
        "signature": str(signature),
        "verify_original_valid": is_valid,
        "verify_original_current_hash": str(current_hash),
        "verify_original_recovered_hash": str(recovered_hash),
        "tampered_current_hash": str(current_hash_t),
        "tampered_recovered_hash": str(recovered_hash_t),
        "verify_tampered_valid": is_valid_t,
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("\n[Результати (без секретного слова і без приватного ключа) збережено у results.json]")
