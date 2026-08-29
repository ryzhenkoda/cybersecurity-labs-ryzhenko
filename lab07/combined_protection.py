"""
Лабораторна робота №7. Комплексний захист особистого проекту
combined_protection.py

Триетапна система захисту особистого файлу, що поєднує три методи з
попередніх лабораторних робіт (вимога методички - два або більше):
  Етап 1 (цілісність і автентичність) - RSA-подібний цифровий підпис (ЛР4);
  Етап 2 (конфіденційність)           - AES-128-CBC шифрування (ЛР5);
  Етап 3 (прихованість)               - LSB-стеганографія (ЛР3).

Порядок захисту: підписати -> запакувати (вміст+підпис) -> зашифрувати
пакет -> приховати шифротекст у зображенні. Порядок відновлення -
дзеркальний, і останній крок - перевірка підпису, що виявляє будь-яку
підробку відновленого вмісту.

Студент: Риженко Данило Євгенович
Група: 6.04.122.010.D.22.1
"""

import base64
import os
import time

import crypto_toolkit as ck

SEPARATOR = "|SIG|"
FULL_NAME = "Риженко Данило Євгенович"
BIRTH_DATE = "25.02.2005"


# 1. ЗАХИСТ (усі три етапи послідовно)

def protect(file_path: str, cover_image_path: str, output_stego_path: str, secret_word: str):
    analytics = {}

    with open(file_path, "rb") as f:
        original_bytes = f.read()
    analytics["original_file_size_bytes"] = len(original_bytes)

    private_key, public_key = ck.generate_keys(FULL_NAME, BIRTH_DATE, secret_word)
    passphrase = ck.generate_key_material(FULL_NAME, BIRTH_DATE, secret_word)

    t0 = time.perf_counter()
    signature = ck.sign_bytes(original_bytes, private_key)
    t1 = time.perf_counter()
    analytics["stage1_sign_time_sec"] = round(t1 - t0, 6)

    package_str = base64.b64encode(original_bytes).decode("ascii") + SEPARATOR + str(signature)
    analytics["package_size_bytes"] = len(package_str.encode("utf-8"))

    t1b = time.perf_counter()
    ciphertext_b64 = ck.encrypt_bytes(package_str.encode("utf-8"), passphrase)
    t2 = time.perf_counter()
    analytics["stage2_encrypt_time_sec"] = round(t2 - t1b, 6)
    analytics["ciphertext_size_bytes"] = len(ciphertext_b64.encode("utf-8"))

    analytics["cover_image_size_bytes"] = os.path.getsize(cover_image_path)
    t2b = time.perf_counter()
    ck.hide_message(cover_image_path, ciphertext_b64, output_stego_path)
    t3 = time.perf_counter()
    analytics["stage3_hide_time_sec"] = round(t3 - t2b, 6)
    analytics["stego_image_size_bytes"] = os.path.getsize(output_stego_path)

    analytics["total_protect_time_sec"] = round(t3 - t0, 6)
    return analytics, public_key


# 2. ВІДНОВЛЕННЯ (дзеркальний порядок + перевірка підпису)

def recover(stego_image_path: str, secret_word: str):
    analytics = {}
    passphrase = ck.generate_key_material(FULL_NAME, BIRTH_DATE, secret_word)
    _, public_key = ck.generate_keys(FULL_NAME, BIRTH_DATE, secret_word)

    t0 = time.perf_counter()
    ciphertext_b64 = ck.extract_message(stego_image_path)
    t1 = time.perf_counter()
    analytics["stage1_extract_time_sec"] = round(t1 - t0, 6)

    package_bytes = ck.decrypt_bytes(ciphertext_b64, passphrase)
    t2 = time.perf_counter()
    analytics["stage2_decrypt_time_sec"] = round(t2 - t1, 6)

    package_str = package_bytes.decode("utf-8")
    content_b64, signature_str = package_str.split(SEPARATOR)
    recovered_bytes = base64.b64decode(content_b64)
    signature = int(signature_str)

    signature_valid = ck.verify_bytes(recovered_bytes, signature, public_key)
    analytics["total_recover_time_sec"] = round(t2 - t0, 6)

    return recovered_bytes, signature_valid, analytics


# 3. ДЕМОНСТРАЦІЯ

if __name__ == "__main__":
    import sys
    import json

    SECRET_WORD = sys.argv[1] if len(sys.argv) > 1 else input("Введіть секретне слово: ").strip()

    FILE_PATH = "personal_project.txt"
    COVER_IMAGE = "cover_image.png"
    STEGO_IMAGE = "stego_image.png"
    TAMPERED_STEGO_IMAGE = "stego_image_tampered.png"

    print("=" * 70)
    print("КРОК 1. ПОВНИЙ ЦИКЛ: ЗАХИСТ -> ВІДНОВЛЕННЯ")
    print("=" * 70)
    protect_analytics, public_key = protect(FILE_PATH, COVER_IMAGE, STEGO_IMAGE, SECRET_WORD)
    print("Аналітика захисту:")
    for k, v in protect_analytics.items():
        print(f"  {k}: {v}")

    recovered_bytes, sig_valid, recover_analytics = recover(STEGO_IMAGE, SECRET_WORD)
    with open(FILE_PATH, "rb") as f:
        original_bytes = f.read()
    roundtrip_ok = recovered_bytes == original_bytes
    print("\nАналітика відновлення:")
    for k, v in recover_analytics.items():
        print(f"  {k}: {v}")
    print(f"\nВідновлений файл ідентичний оригіналу: {roundtrip_ok}")
    print(f"Підпис дійсний: {sig_valid}")

    print("\n" + "=" * 70)
    print("КРОК 2. АТАКА 1 - Є ЗОБРАЖЕННЯ, НЕМАЄ СЕКРЕТНОГО СЛОВА")
    print("=" * 70)
    wrong_word = "wrong_secret"
    try:
        extracted = ck.extract_message(STEGO_IMAGE)
        wrong_passphrase = ck.generate_key_material(FULL_NAME, BIRTH_DATE, wrong_word)
        ck.decrypt_bytes(extracted, wrong_passphrase)
        attack1_blocked = False
        print("Розшифровано (неочікувано) - атака НЕ заблокована")
    except Exception as exc:
        attack1_blocked = True
        print(f"Приховані дані витягнуто, але розшифрувати не вдалося: {type(exc).__name__}: {exc}")
    print(f"Результат: {'дані недоступні без правильного секретного слова' if attack1_blocked else 'ПРОБЛЕМА'}")

    print("\n" + "=" * 70)
    print("КРОК 3. АТАКА 2 - Є СЕКРЕТНЕ СЛОВО, НЕМАЄ СТЕГО-ЗОБРАЖЕННЯ")
    print("=" * 70)
    try:
        garbage = ck.extract_message(COVER_IMAGE)  # оригінал без прихованих даних
        attack2_blocked = False
        print(f"Із чистого зображення \"витягнуто\" щось (неочікувано): {garbage[:50]!r}")
    except Exception as exc:
        attack2_blocked = True
        print(f"Спроба витягти дані з зображення без прихованого повідомлення провалилася: {type(exc).__name__}: {exc}")
    print(f"Результат: {'без доступу до правильного стего-зображення дані недоступні' if attack2_blocked else 'ПРОБЛЕМА'}")

    print("\n" + "=" * 70)
    print("КРОК 4. ТЕСТ ПІДРОБКИ - ЗМІНА ОДНОГО ПІКСЕЛЯ СТЕГО-ЗОБРАЖЕННЯ")
    print("=" * 70)
    from PIL import Image as _Image

    tamper_img = _Image.open(STEGO_IMAGE).convert("RGB")
    width, height = tamper_img.size
    pixels = list(tamper_img.getdata())
    # Змінюємо LSB одного пікселя десь у середині даних повідомлення
    # (пропускаємо перші кілька пікселів - там 32-бітний заголовок довжини,
    # його краще не займати, щоб перевірити саме шифр/підпис, а не тільки
    # коректність довжини повідомлення)
    target_index = 500
    r, g, b = pixels[target_index]
    pixels[target_index] = (r ^ 1, g, b)  # інвертуємо молодший біт каналу R
    tampered_img = _Image.new("RGB", (width, height))
    tampered_img.putdata(pixels)
    tampered_img.save(TAMPERED_STEGO_IMAGE)
    print(f"Інвертовано молодший біт каналу R пікселя №{target_index} "
          f"({r} -> {r ^ 1}) і збережено як новий коректний PNG-файл.")

    tamper_detected = False
    tamper_stage = None
    try:
        rec_bytes, sig_ok, _ = recover(TAMPERED_STEGO_IMAGE, SECRET_WORD)
        if not sig_ok:
            tamper_detected = True
            tamper_stage = "перевірка підпису (RSA) виявила невідповідність"
        elif rec_bytes != original_bytes:
            tamper_detected = True
            tamper_stage = "вміст відрізняється, хоча підпис пройшов (не мало б статись)"
        else:
            tamper_stage = "підробку НЕ виявлено"
    except Exception as exc:
        tamper_detected = True
        tamper_stage = f"{type(exc).__name__} на етапі розшифрування/розпакування: {exc}"
    print(f"Підробку виявлено: {tamper_detected}")
    print(f"Етап виявлення: {tamper_stage}")

    print("\n" + "=" * 70)
    print("КРОК 5. СТЕГАНОАНАЛІЗ - НАСКІЛЬКИ ПОМІТНІ ЗМІНИ В ЗОБРАЖЕННІ")
    print("=" * 70)
    img_diff = ck.compare_images(COVER_IMAGE, STEGO_IMAGE)
    for k, v in img_diff.items():
        print(f"  {k}: {v}")

    results = {
        "protect_analytics": protect_analytics,
        "recover_analytics": recover_analytics,
        "roundtrip_ok": roundtrip_ok,
        "signature_valid": sig_valid,
        "attack1_blocked_no_password": attack1_blocked,
        "attack2_blocked_no_image": attack2_blocked,
        "tamper_detected": tamper_detected,
        "tamper_detection_stage": tamper_stage,
        "image_comparison": img_diff,
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("\n[Результати (без секретного слова і без приватного ключа) збережено у results.json]")
