"""
Лабораторна робота №3. Невидимі дані у власних файлах
Дисципліна: «Захист інформації»
Власна реалізація LSB-стеганографії (без готових бібліотек стеганографії) +
аналіз змін у зображенні та робота з EXIF-метаданими.

Студент: Риженко Данило
Група: 6.04.122.010.D.22.1
"""

from PIL import Image
from PIL.ExifTags import TAGS

# ============================================================
# 1. ПЕРЕТВОРЕННЯ ТЕКСТУ В ДВІЙКОВИЙ ФОРМАТ
# ============================================================
LENGTH_HEADER_BITS = 32  # скільки бітів відводимо під заголовок довжини повідомлення


def text_to_bits(text: str) -> str:
    """Перетворює текст (UTF-8) на рядок з бітів '0'/'1'."""
    data = text.encode("utf-8")
    length_header = format(len(data), f"0{LENGTH_HEADER_BITS}b")
    message_bits = "".join(format(byte, "08b") for byte in data)
    return length_header + message_bits


def bits_to_text(bits: str) -> str:
    """Збирає байти з рядка бітів і декодує їх як UTF-8 текст."""
    byte_chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    data = bytes(int(chunk, 2) for chunk in byte_chunks)
    return data.decode("utf-8")


# ============================================================
# 2. ПРИХОВУВАННЯ ПОВІДОМЛЕННЯ (LSB - молодші біти)
# ============================================================
def hide_message(image_path: str, message: str, output_path: str) -> None:
    """
    Приховує текстове повідомлення в зображенні методом LSB.

    Принцип: у кожному каналі (R, G, B) кожного пікселя молодший біт (LSB)
    замінюється на черговий біт повідомлення. Молодший біт впливає на
    значення каналу щонайбільше на 1 з 255 - зміна кольору настільки мала,
    що людське око її не помічає, а сумарна ємність зображення (кількість
    пікселів × 3 канали) зазвичай значно перевищує розмір короткого
    текстового повідомлення.

    Перші 32 біти зберігають довжину повідомлення в байтах - це дозволяє
    під час витягування точно знати, скільки бітів читати, без потреби
    шукати спеціальний маркер кінця в самих даних.
    """
    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    pixels = list(img.getdata())

    bits = text_to_bits(message)
    capacity_bits = width * height * 3
    if len(bits) > capacity_bits:
        raise ValueError(
            f"Повідомлення завелике: потрібно {len(bits)} бітів, "
            f"а місткість зображення - {capacity_bits} бітів."
        )

    bit_iter = iter(bits)
    new_pixels = []
    for pixel in pixels:
        new_channels = []
        for channel in pixel:
            try:
                bit = next(bit_iter)
                new_channels.append((channel & ~1) | int(bit))  # обнулити LSB, підставити біт
            except StopIteration:
                new_channels.append(channel)  # більше бітів немає - канал без змін
        new_pixels.append(tuple(new_channels))

    stego_img = Image.new("RGB", (width, height))
    stego_img.putdata(new_pixels)
    stego_img.save(output_path)  # обов'язково без втрат (PNG) - JPEG знищить молодші біти


def extract_message(image_path: str) -> str:
    """Витягує повідомлення, приховане функцією hide_message()."""
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    all_bits = "".join(str(channel & 1) for pixel in pixels for channel in pixel)

    length_bits = all_bits[:LENGTH_HEADER_BITS]
    message_byte_length = int(length_bits, 2)
    message_bits = all_bits[LENGTH_HEADER_BITS:LENGTH_HEADER_BITS + message_byte_length * 8]

    return bits_to_text(message_bits)


# ============================================================
# 3. АНАЛІЗ ЗМІН МІЖ ОРИГІНАЛОМ ТА СТЕГО-КОНТЕЙНЕРОМ
# ============================================================
def compare_images(original_path: str, stego_path: str) -> dict:
    """Порівнює оригінал і стего-контейнер: скільки пікселів/каналів змінилось."""
    orig = Image.open(original_path).convert("RGB")
    stego = Image.open(stego_path).convert("RGB")
    if orig.size != stego.size:
        raise ValueError("Зображення мають різний розмір")

    orig_data = list(orig.getdata())
    stego_data = list(stego.getdata())

    total_channels = len(orig_data) * 3
    changed_channels = 0
    changed_pixels = 0
    max_diff = 0

    for p1, p2 in zip(orig_data, stego_data):
        pixel_changed = False
        for c1, c2 in zip(p1, p2):
            diff = abs(c1 - c2)
            if diff != 0:
                changed_channels += 1
                pixel_changed = True
            max_diff = max(max_diff, diff)
        if pixel_changed:
            changed_pixels += 1

    return {
        "total_pixels": len(orig_data),
        "changed_pixels": changed_pixels,
        "changed_pixels_pct": round(100 * changed_pixels / len(orig_data), 2),
        "changed_channels_pct": round(100 * changed_channels / total_channels, 4),
        "max_channel_difference": max_diff,  # максимум 1 - це і є суть LSB-методу
    }


# ============================================================
# 4. РОБОТА З EXIF-МЕТАДАНИМИ (крок 4 практичної частини)
# ============================================================
def read_exif(image_path: str) -> dict:
    """Читає EXIF-метадані фотографії (якщо вони є)."""
    img = Image.open(image_path)
    exif_data = img.getexif()
    if not exif_data:
        return {}
    return {TAGS.get(tag_id, tag_id): value for tag_id, value in exif_data.items()}


def strip_exif(image_path: str, output_path: str) -> None:
    """Зберігає копію зображення без жодних EXIF-метаданих (для публікації)."""
    img = Image.open(image_path)
    data = list(img.getdata())
    clean_img = Image.new(img.mode, img.size)
    clean_img.putdata(data)
    clean_img.save(output_path)


# ============================================================
# 5. ДЕМОНСТРАЦІЯ
# ============================================================
if __name__ == "__main__":
    SECRET_MESSAGE = "Риженко Данило Євгенович, 25.02.2005"

    print("=" * 70)
    print("LSB-СТЕГАНОГРАФІЯ: ПРИХОВУВАННЯ ТА ВИТЯГУВАННЯ ПОВІДОМЛЕННЯ")
    print("=" * 70)
    print(f"Повідомлення: «{SECRET_MESSAGE}»")
    print(f"Довжина повідомлення: {len(SECRET_MESSAGE.encode('utf-8'))} байт")

    hide_message("cover_image.png", SECRET_MESSAGE, "stego_image.png")
    print("\nПовідомлення приховано -> stego_image.png")

    extracted = extract_message("stego_image.png")
    print(f"Витягнуте повідомлення: «{extracted}»")
    assert extracted == SECRET_MESSAGE, "Помилка: витягнутий текст не збігається з оригіналом!"
    print("Перевірка пройдена: витягнутий текст ідентичний оригіналу.")

    print("\n" + "=" * 70)
    print("ПОРІВНЯЛЬНИЙ АНАЛІЗ ОРИГІНАЛУ ТА СТЕГО-КОНТЕЙНЕРА")
    print("=" * 70)
    stats = compare_images("cover_image.png", "stego_image.png")
    for key, value in stats.items():
        print(f"{key}: {value}")

    img_size = Image.open("cover_image.png").size
    capacity_bytes = (img_size[0] * img_size[1] * 3) // 8
    print(f"\nРозмір зображення: {img_size[0]}x{img_size[1]}")
    print(f"Максимальна місткість (усі LSB): ~{capacity_bytes} байт тексту")
    print(f"Використано для повідомлення: {LENGTH_HEADER_BITS // 8 + len(SECRET_MESSAGE.encode('utf-8'))} байт")
