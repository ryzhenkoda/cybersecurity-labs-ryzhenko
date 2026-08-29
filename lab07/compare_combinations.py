"""
Лабораторна робота №7. Крок 2 методички - порівняльний аналіз комбінацій
compare_combinations.py

Застосовує три різні комбінації методів захисту з попередніх
лабораторних робіт до одного й того самого тестового файлу:
  Комбінація А: шифрування (ЛР5) + стеганографія (ЛР3)
  Комбінація Б: цифровий підпис (ЛР4) + шифрування (ЛР5)
  Комбінація В: стеганографія (ЛР3) + цифровий підпис (ЛР4)

Кожна комбінація вимірюється за часом обробки та розміром результату,
щоб дати реальні (а не оцінені "на око") дані для порівняльної таблиці.

Студент: Риженко Данило
Група: 6.04.122.010.D.22.1
"""

import base64
import json
import os
import time

import crypto_toolkit as ck

FULL_NAME = "Риженко Данило Євгенович"
BIRTH_DATE = "25.02.2005"
SEPARATOR = "|SIG|"

FILE_PATH = "personal_project.txt"
COVER_IMAGE = "cover_image.png"


def combo_a_encrypt_then_stego(secret_word: str):
    """Комбінація А: шифрування + стеганографія (без підпису - без перевірки цілісності)."""
    passphrase = ck.generate_key_material(FULL_NAME, BIRTH_DATE, secret_word)
    with open(FILE_PATH, "rb") as f:
        data = f.read()

    t0 = time.perf_counter()
    ciphertext_b64 = ck.encrypt_bytes(data, passphrase)
    t1 = time.perf_counter()
    ck.hide_message(COVER_IMAGE, ciphertext_b64, "combo_a_stego.png")
    t2 = time.perf_counter()

    return {
        "processing_time_sec": round(t2 - t0, 6),
        "result_size_bytes": os.path.getsize("combo_a_stego.png"),
        "provides_confidentiality": True,
        "provides_obscurity": True,
        "provides_integrity_check": False,
    }


def combo_b_sign_then_encrypt(secret_word: str):
    """Комбінація Б: підпис + шифрування (без приховування - файл видимий, але захищений)."""
    private_key, public_key = ck.generate_keys(FULL_NAME, BIRTH_DATE, secret_word)
    passphrase = ck.generate_key_material(FULL_NAME, BIRTH_DATE, secret_word)
    with open(FILE_PATH, "rb") as f:
        data = f.read()

    t0 = time.perf_counter()
    signature = ck.sign_bytes(data, private_key)
    package = base64.b64encode(data).decode("ascii") + SEPARATOR + str(signature)
    t1 = time.perf_counter()
    ciphertext_b64 = ck.encrypt_bytes(package.encode("utf-8"), passphrase)
    t2 = time.perf_counter()

    with open("combo_b_protected.txt", "w", encoding="utf-8") as f:
        f.write(ciphertext_b64)

    # перевірка (щоб підтвердити, що цілісність справді перевіряється)
    recovered_package = ck.decrypt_bytes(ciphertext_b64, passphrase).decode("utf-8")
    content_b64, sig_str = recovered_package.split(SEPARATOR)
    verify_ok = ck.verify_bytes(base64.b64decode(content_b64), int(sig_str), public_key)

    return {
        "processing_time_sec": round(t2 - t0, 6),
        "result_size_bytes": os.path.getsize("combo_b_protected.txt"),
        "provides_confidentiality": True,
        "provides_obscurity": False,
        "provides_integrity_check": True,
        "integrity_verified_in_test": verify_ok,
    }


def combo_c_stego_then_sign(secret_word: str):
    """Комбінація В: стеганографія + підпис (без шифрування - вміст не приховано криптографічно,
    лише в зображенні; підпис забезпечує автентичність, але НЕ конфіденційність)."""
    private_key, public_key = ck.generate_keys(FULL_NAME, BIRTH_DATE, secret_word)
    with open(FILE_PATH, "rb") as f:
        data = f.read()

    t0 = time.perf_counter()
    signature = ck.sign_bytes(data, private_key)
    package = base64.b64encode(data).decode("ascii") + SEPARATOR + str(signature)
    t1 = time.perf_counter()
    ck.hide_message(COVER_IMAGE, package, "combo_c_stego.png")
    t2 = time.perf_counter()

    # перевірка
    extracted = ck.extract_message("combo_c_stego.png")
    content_b64, sig_str = extracted.split(SEPARATOR)
    verify_ok = ck.verify_bytes(base64.b64decode(content_b64), int(sig_str), public_key)
    # ключова відмінність від А і Б: вміст можна прочитати одразу після витягнення,
    # без жодного ключа - це лише base64, а не шифрування
    content_readable_without_key = base64.b64decode(content_b64) == data

    return {
        "processing_time_sec": round(t2 - t0, 6),
        "result_size_bytes": os.path.getsize("combo_c_stego.png"),
        "provides_confidentiality": False,
        "provides_obscurity": True,
        "provides_integrity_check": True,
        "integrity_verified_in_test": verify_ok,
        "content_readable_without_any_key": content_readable_without_key,
    }


if __name__ == "__main__":
    import sys

    secret_word = sys.argv[1] if len(sys.argv) > 1 else input("Введіть секретне слово: ").strip()

    print("=" * 70)
    print("КОМБІНАЦІЯ А: ШИФРУВАННЯ + СТЕГАНОГРАФІЯ")
    print("=" * 70)
    result_a = combo_a_encrypt_then_stego(secret_word)
    for k, v in result_a.items():
        print(f"  {k}: {v}")

    print("\n" + "=" * 70)
    print("КОМБІНАЦІЯ Б: ЦИФРОВИЙ ПІДПИС + ШИФРУВАННЯ")
    print("=" * 70)
    result_b = combo_b_sign_then_encrypt(secret_word)
    for k, v in result_b.items():
        print(f"  {k}: {v}")

    print("\n" + "=" * 70)
    print("КОМБІНАЦІЯ В: СТЕГАНОГРАФІЯ + ЦИФРОВИЙ ПІДПИС")
    print("=" * 70)
    result_c = combo_c_stego_then_sign(secret_word)
    for k, v in result_c.items():
        print(f"  {k}: {v}")

    with open(FILE_PATH, "rb") as f:
        original_size = len(f.read())

    all_results = {
        "original_file_size_bytes": original_size,
        "combo_a": result_a,
        "combo_b": result_b,
        "combo_c": result_c,
    }
    with open("compare_results.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print("\n[Результати порівняння збережено у compare_results.json]")
