"""
Допоміжний скрипт перевірки (не є обов'язковою частиною завдання).

Звіряє власну реалізацію AES-128 (email_cipher.py) з незалежною
бібліотекою `cryptography`, щоб підтвердити коректність реалізації, а не
лише зовнішню схожість результату. Використовує три перевірки:

1. Один блок AES-128 у режимі ECB (щоб ізолювати саме блоковий шифр).
2. Повний режим CBC з власним PKCS7-доповненням.
3. Похідна функція ключа derive_key_and_iv() (EVP_BytesToKey, MD5).

Потребує пакет `cryptography` (не входить у стандартну бібліотеку -
використовується лише для цієї перевірки, сама програма email_cipher.py
його не імпортує): pip install cryptography
"""

import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from email_cipher import (
    aes_encrypt_block,
    aes_decrypt_block,
    cbc_encrypt,
    cbc_decrypt,
    pkcs7_pad,
    derive_key_and_iv,
    key_expansion,
)


def check(name: str, condition: bool) -> bool:
    print(f"[{'OK' if condition else 'FAIL'}] {name}")
    return condition


def main():
    all_ok = True

    # 1. Один блок AES-128, режим ECB (ізолює сам блоковий шифр)
    key = os.urandom(16)
    plaintext_block = os.urandom(16)
    round_keys = key_expansion(key)
    mine_ct = aes_encrypt_block(plaintext_block, round_keys)

    ref_cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = ref_cipher.encryptor()
    ref_ct = encryptor.update(plaintext_block) + encryptor.finalize()

    all_ok &= check("Один блок AES-128 (ECB) збігається з cryptography", mine_ct == ref_ct)
    mine_pt = aes_decrypt_block(mine_ct, round_keys)
    all_ok &= check("Розшифрування блока повертає оригінал", mine_pt == plaintext_block)

    # 2. Повний режим CBC з власним PKCS7-доповненням
    key2 = os.urandom(16)
    iv2 = os.urandom(16)
    message = b"Ich mache das um 3 Uhr, genau wie besprochen wurde gestern Abend!"
    padded = pkcs7_pad(message)

    ref_cipher2 = Cipher(algorithms.AES(key2), modes.CBC(iv2))
    encryptor2 = ref_cipher2.encryptor()
    ref_cbc_ct = encryptor2.update(padded) + encryptor2.finalize()

    mine_cbc_ct = cbc_encrypt(message, key2, iv2)
    all_ok &= check("Режим CBC (з PKCS7) збігається з cryptography", mine_cbc_ct == ref_cbc_ct)

    mine_cbc_pt = cbc_decrypt(mine_cbc_ct, key2, iv2)
    all_ok &= check("Розшифрування CBC повертає оригінальне повідомлення", mine_cbc_pt == message)

    # 3. Похідна функція ключа derive_key_and_iv() (EVP_BytesToKey, MD5)
    passphrase = b"test-passphrase-for-verification"
    salt = os.urandom(8)
    key3, iv3 = derive_key_and_iv(passphrase, salt)

    d1 = hashlib.md5(passphrase + salt).digest()
    d2 = hashlib.md5(d1 + passphrase + salt).digest()
    expected_key, expected_iv = (d1 + d2)[:16], (d1 + d2)[16:32]

    all_ok &= check("derive_key_and_iv() відповідає ручному обчисленню EVP_BytesToKey (ключ)", key3 == expected_key)
    all_ok &= check("derive_key_and_iv() відповідає ручному обчисленню EVP_BytesToKey (IV)", iv3 == expected_iv)

    print()
    print("ЗАГАЛЬНИЙ РЕЗУЛЬТАТ:", "усі перевірки пройдено" if all_ok else "Є РОЗБІЖНОСТІ")
    return all_ok


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
