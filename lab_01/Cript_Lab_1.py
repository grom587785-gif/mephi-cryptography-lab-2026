# Лабораторная работа №1
# Шифрование методом перестановки

DEFAULT_KEY = [3, 5, 2, 6, 1, 4]


def encrypt_block(block, python_key):
    """Шифрует один блок согласно ключу перестановки."""
    encrypted_block = []

    for source_index in python_key:
        encrypted_block.append(block[source_index])

    return encrypted_block


def decrypt_block(encrypted_block, python_key):
    """Восстанавливает исходный порядок элементов одного блока."""
    decrypted_block = [0] * len(python_key)

    for encrypted_index, source_index in enumerate(python_key):
        decrypted_block[source_index] = encrypted_block[encrypted_index]

    return decrypted_block


def parse_key(key_input):
    """Преобразует введённый ключ в список чисел и проверяет его."""
    if not key_input.strip():
        return DEFAULT_KEY.copy()

    # Разрешаем ввод ключа через пробелы или запятые.
    key_input = key_input.replace(',', ' ')
    key_parts = key_input.split()

    key = []

    for item in key_parts:
        if not item.isdigit():
            raise ValueError(
                'ключ должен содержать только целые положительные числа'
            )

        key.append(int(item))

    if not key:
        raise ValueError('ключ не может быть пустым')

    # Корректный ключ длины n должен содержать
    # все числа от 1 до n без повторений.
    for number in range(1, len(key) + 1):
        if number not in key:
            raise ValueError('некорректный ключ перестановки')

    return key


def main():
    """Выполняет шифрование и обратное преобразование текста."""
    text = input('Введите исходный текст: ')

    if not text:
        raise ValueError('исходный текст не может быть пустым')

    if not text.isascii():
        raise ValueError(
            'исходный текст должен содержать только ASCII-символы'
        )

    key_input = input(
        'Введите ключ перестановки '
        '[по умолчанию 3,5,2,6,1,4]: '
    )

    key = parse_key(key_input)
    block_size = len(key)

    # Перевод ключа из нумерации 1, 2, 3...
    # в индексы Python 0, 1, 2...
    python_key = []

    for item in key:
        python_key.append(item - 1)

    # Преобразование исходного текста в ASCII-коды.
    ascii_codes = []

    for letter in text:
        ascii_codes.append(ord(letter))

    original_ascii = ascii_codes.copy()

    # Дополнение последнего блока пробелами.
    whitespace = ord(' ')
    remainder = len(ascii_codes) % block_size
    padding_count = 0

    if remainder != 0:
        padding_count = block_size - remainder

        for _ in range(padding_count):
            ascii_codes.append(whitespace)

    # Разбиение данных на блоки.
    blocks = []

    for start in range(0, len(ascii_codes), block_size):
        block = ascii_codes[start:start + block_size]
        blocks.append(block)

    # Шифрование всех блоков.
    encrypted_blocks = []

    for block in blocks:
        encrypted_block = encrypt_block(block, python_key)
        encrypted_blocks.append(encrypted_block)

    # Формирование единой криптограммы.
    cryptogram = []

    for encrypted_block in encrypted_blocks:
        cryptogram.extend(encrypted_block)

    cryptogram_chars = []

    for code in cryptogram:
        cryptogram_chars.append(chr(code))

    cryptogram_text = ''.join(cryptogram_chars)

    # Расшифрование всех блоков.
    decrypted_blocks = []

    for encrypted_block in encrypted_blocks:
        decrypted_block = decrypt_block(
            encrypted_block,
            python_key
        )
        decrypted_blocks.append(decrypted_block)

    # Объединение расшифрованных блоков.
    decrypted_ascii = []

    for decrypted_block in decrypted_blocks:
        decrypted_ascii.extend(decrypted_block)

    # Удаление только тех пробелов,
    # которые были добавлены перед шифрованием.
    if padding_count > 0:
        decrypted_ascii = decrypted_ascii[:-padding_count]

    # Обратное преобразование ASCII-кодов в текст.
    decrypted_chars = []

    for code in decrypted_ascii:
        decrypted_chars.append(chr(code))

    decrypted_text = ''.join(decrypted_chars)

    # Итоговый вывод.
    print('\n--- Результат ---')
    print('Исходный текст:', text)
    print('Исходный текст ASCII:', original_ascii)
    print('Ключ перестановки:', key)
    print('Криптограмма ASCII:', cryptogram)
    print('Криптограмма:', cryptogram_text)
    print('Расшифрованный текст:', decrypted_text)

    if decrypted_text == text:
        print('Проверка: расшифрование выполнено успешно.')
    else:
        print('Проверка: ошибка расшифрования.')


try:
    main()
except ValueError as error:
    print(f'\nОшибка: {error}.')
