"""
Лабораторна робота №5. Захищена електронна пошта
Дисципліна: «Захист інформації»
Симетричне шифрування email-повідомлень: повна реалізація AES-128 "з нуля"
(без готових бібліотек шифрування - лише hashlib для похідної функції ключа
та os для генерації випадкової солі), у режимі CBC з PKCS7-доповненням.

Формат виводу відтворює структуру класичної OpenSSL/CryptoJS схеми
"Salted__" (саме такий вигляд - префікс "U2FsdGVkX1..." - має приклад
зашифрованих даних у методичці: це base64 від "Salted__" + сіль): пароль
і сіль перетворюються на ключ і IV функцією EVP_BytesToKey (ітеративний
MD5), після чого "Salted__" + сіль + шифротекст кодуються в base64.
Збіг стосується структури контейнера й алгоритму виведення ключа;
пряму сумісність із конкретним зовнішнім інструментом (наприклад,
розшифрування реальним CryptoJS.AES.decrypt() з тим самим паролем)
окремо не перевірено.

Студент: Риженко Данило Євгенович
Група: 6.04.122.010.D.22.1
"""

import base64
import hashlib
import os
import sys

BLOCK_SIZE = 16  # AES працює з 16-байтовими блоками незалежно від довжини ключа


# 1. КОНСТАНТИ AES (стандартні таблиці з специфікації FIPS-197)

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# 2. АРИФМЕТИКА В ПОЛІ GF(2^8) (потрібна для MixColumns)

def xtime(a: int) -> int:
    """Множення на x (тобто на 2) у полі GF(2^8) за модулем x^8+x^4+x^3+x+1."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a: int, b: int) -> int:
    """Множення двох байтів у полі GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result & 0xFF


# 3. РОЗГОРТАННЯ КЛЮЧА (Key Expansion / Key Schedule)

def key_expansion(key: bytes) -> list:
    """Розгортає 16-байтовий ключ AES-128 у 11 раундових ключів по 16 байт."""
    Nk, Nb, Nr = 4, 4, 10
    words = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = list(words[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]                       # RotWord
            temp = [SBOX[b] for b in temp]                    # SubWord
            temp[0] ^= RCON[i // Nk - 1]
        words.append([a ^ b for a, b in zip(words[i - Nk], temp)])

    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for w in words[4 * r:4 * r + 4]:
            rk.extend(w)
        round_keys.append(bytes(rk))
    return round_keys


# 4. ПЕРЕТВОРЕННЯ СТАНУ (4x4 матриця байтів, стовпцями)

def bytes_to_state(block: bytes):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def sub_bytes(state, box=SBOX):
    return [[box[b] for b in row] for row in state]


def shift_rows(state):
    return [row[r:] + row[:r] for r, row in enumerate(state)]


def inv_shift_rows(state):
    return [row[-r:] + row[:-r] if r else row[:] for r, row in enumerate(state)]


def mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        new_state[1][c] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        new_state[2][c] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        new_state[3][c] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)
    return new_state


def inv_mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9)
        new_state[1][c] = gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13)
        new_state[2][c] = gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11)
        new_state[3][c] = gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14)
    return new_state


def add_round_key(state, round_key: bytes):
    rk = bytes_to_state(round_key)
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


# 5. ШИФРУВАННЯ/РОЗШИФРУВАННЯ ОДНОГО БЛОКА (10 раундів AES-128)

def aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def aes_decrypt_block(block: bytes, round_keys: list) -> bytes:
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = sub_bytes(state, box=INV_SBOX)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = sub_bytes(state, box=INV_SBOX)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)


# 6. ДОПОВНЕННЯ (PKCS7) ТА РЕЖИМ CBC

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Некоректне доповнення PKCS7 - імовірно, невірний пароль або пошкоджені дані")
    return data[:-pad_len]


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext)
    ciphertext = b""
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = aes_encrypt_block(xored, round_keys)
        ciphertext += enc
        prev = enc
    return ciphertext


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    round_keys = key_expansion(key)
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = aes_decrypt_block(block, round_keys)
        xored = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += xored
        prev = block
    return pkcs7_unpad(plaintext)


# 7. ПОХІДНА ФУНКЦІЯ КЛЮЧА (OpenSSL-сумісна EVP_BytesToKey, ітеративний MD5)

def derive_key_and_iv(passphrase: bytes, salt: bytes, key_len: int = 16, iv_len: int = 16):
    """
    Класична схема EVP_BytesToKey, яку історично використовує "openssl enc"
    і за замовчуванням CryptoJS.AES.encrypt(). Саме через неї зашифровані
    дані з прикладу методички мають вигляд "U2FsdGVkX1..." (base64 від
    "Salted__" + сіль): "Salted__" - це 8-байтовий магічний префікс формату,
    після нього йде 8-байтова сіль, а решта - шифротекст.

    D_1 = MD5(passphrase + salt)
    D_2 = MD5(D_1 + passphrase + salt)
    ... доки не назбирається потрібна кількість байтів для ключа й IV.

    Це історичний і сьогодні застарілий підхід (сучасні системи
    використовують PBKDF2/scrypt/Argon2 із багатьма ітераціями) - тут він
    застосований свідомо, щоб відтворити точний формат прикладу з методички.
    """
    material = b""
    prev = b""
    while len(material) < key_len + iv_len:
        prev = hashlib.md5(prev + passphrase + salt).digest()
        material += prev
    return material[:key_len], material[key_len:key_len + iv_len]


def generate_key_material(full_name: str, birth_date: str, secret_word: str) -> bytes:
    """
    Формує парольну фразу (passphrase) на основі персональних даних
    користувача, аналогічно прикладу методички (хеш від "IvanPetrenko1995"),
    але з додаванням секретного слова: саме ім'я та дата народження часто
    є публічно відомими, тому без секретного слова пароль був би вгадуваним.
    """
    return f"{full_name}{birth_date}{secret_word}".encode("utf-8")


# 8. ШИФРУВАННЯ/РОЗШИФРУВАННЯ ПОВІДОМЛЕННЯ (публічний інтерфейс)

def encrypt_message(plaintext: str, passphrase: bytes) -> str:
    """Шифрує текстове повідомлення і повертає результат у форматі 'Salted__'+сіль+шифротекст, закодований у base64."""
    salt = os.urandom(8)
    key, iv = derive_key_and_iv(passphrase, salt)
    ciphertext = cbc_encrypt(plaintext.encode("utf-8"), key, iv)
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode("ascii")


def decrypt_message(encoded: str, passphrase: bytes) -> str:
    """Розшифровує повідомлення, отримане функцією encrypt_message()."""
    raw = base64.b64decode(encoded)
    if raw[:8] != b"Salted__":
        raise ValueError("Невірний формат: відсутній магічний префікс 'Salted__'")
    salt, ciphertext = raw[8:16], raw[16:]
    key, iv = derive_key_and_iv(passphrase, salt)
    plaintext = cbc_decrypt(ciphertext, key, iv)
    return plaintext.decode("utf-8")


# 9. САМОПЕРЕВІРКА AES ЗА ОФІЦІЙНИМ ТЕСТОВИМ ВЕКТОРОМ FIPS-197

def self_test_aes_block_cipher() -> bool:
    """
    Перевіряє власну реалізацію блочного AES-128 за офіційним тестовим
    вектором з додатку C.1 специфікації FIPS-197 - це гарантує, що
    реалізація S-box, розгортання ключа, ShiftRows і MixColumns коректна,
    а не просто "виглядає правильно".
    """
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    round_keys = key_expansion(key)
    actual_ciphertext = aes_encrypt_block(plaintext, round_keys)
    decrypted_back = aes_decrypt_block(actual_ciphertext, round_keys)

    return actual_ciphertext == expected_ciphertext and decrypted_back == plaintext


# 10. ДЕМОНСТРАЦІЯ

if __name__ == "__main__":
    FULL_NAME = "Риженко Данило Євгенович"
    BIRTH_DATE = "25.02.2005"

    print("=" * 70)
    print("КРОК 0. САМОПЕРЕВІРКА AES-128 ЗА ОФІЦІЙНИМ ТЕСТОВИМ ВЕКТОРОМ FIPS-197")
    print("=" * 70)
    ok = self_test_aes_block_cipher()
    print(f"Тестовий вектор (ключ 000102...0e0f, блок 001122...ddeeff) -> "
          f"очікується 69c4e0d86a7b0430d8cdb78070b4c55a")
    print(f"Результат самоперевірки: {'ПРОЙДЕНО' if ok else 'ПОМИЛКА РЕАЛІЗАЦІЇ'}")
    if not ok:
        raise SystemExit("Власна реалізація AES не пройшла офіційний тест - зупинка.")

    if len(sys.argv) > 1:
        secret_word = sys.argv[1]
    else:
        secret_word = input("\nВведіть секретне слово для генерації ключа шифрування: ").strip()
    if not secret_word:
        raise SystemExit("Секретне слово не може бути порожнім.")

    if len(sys.argv) > 2:
        message = sys.argv[2]
    else:
        message = input("Введіть повідомлення для шифрування: ").strip()
    if not message:
        raise SystemExit("Повідомлення не може бути порожнім.")

    print("\n" + "=" * 70)
    print("КРОК 1. ГЕНЕРАЦІЯ КЛЮЧА НА ОСНОВІ ПЕРСОНАЛЬНИХ ДАНИХ")
    print("=" * 70)
    passphrase = generate_key_material(FULL_NAME, BIRTH_DATE, secret_word)
    print(f"Парольна фраза складена як ПІБ + дата народження + секретне слово; "
          f"сама фраза не виводиться і нікуди не зберігається.")
    print(f"Довжина парольної фрази: {len(passphrase)} байт")

    print("\n" + "=" * 70)
    print("КРОК 2. ШИФРУВАННЯ ПОВІДОМЛЕННЯ (AES-128-CBC)")
    print("=" * 70)
    print(f"Повідомлення: «{message}»")
    encrypted = encrypt_message(message, passphrase)
    print(f"Зашифровані дані (base64, формат Salted__): {encrypted}")

    print("\n" + "=" * 70)
    print("КРОК 3. РОЗШИФРУВАННЯ У ОТРИМУВАЧА (той самий пароль)")
    print("=" * 70)
    decrypted = decrypt_message(encrypted, passphrase)
    print(f"Розшифроване повідомлення: «{decrypted}»")
    print(f"Результат: {'СПІВПАДАЄ З ОРИГІНАЛОМ' if decrypted == message else 'ПОМИЛКА'}")
    assert decrypted == message

    print("\n" + "=" * 70)
    print("КРОК 4. СПРОБА РОЗШИФРУВАННЯ З НЕВІРНИМ ПАРОЛЕМ")
    print("=" * 70)
    wrong_passphrase = generate_key_material(FULL_NAME, BIRTH_DATE, "wrong_word")
    wrong_password_rejected = False
    try:
        wrong_result = decrypt_message(encrypted, wrong_passphrase)
        print(f"Розшифровано (неочікувано): «{wrong_result}»")
    except (ValueError, UnicodeDecodeError) as exc:
        print(f"Розшифрування не вдалося, як і очікувалось: {exc}")
        wrong_password_rejected = True

    print("\n[Демонстрація завершена. Секретне слово і парольна фраза ніде не збережені.]")

    with open("encrypted_email.txt", "w", encoding="utf-8") as f:
        f.write(encrypted + "\n")

    import json
    results = {
        "full_name": FULL_NAME,
        "birth_date": BIRTH_DATE,
        "message": message,
        "passphrase_length_bytes": len(passphrase),
        "encrypted_message": encrypted,
        "decrypted_message": decrypted,
        "roundtrip_ok": decrypted == message,
        "wrong_password_rejected": wrong_password_rejected,
        "aes_self_test_passed": ok,
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("[Результати (без секретного слова і без парольної фрази) збережено у results.json]")
    print("[Зашифроване повідомлення збережено у encrypted_email.txt]")
