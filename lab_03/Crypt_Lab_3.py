import secrets


def hash_message(message):
    """Вычисляет контрольную сумму сообщения по варианту №3."""

    # Преобразуем строку в последовательность байтов UTF-8.
    utf_text = message.encode('utf-8')

    # Определяем количество байтов в последнем неполном блоке.
    remainder = len(utf_text) % 4

    if remainder != 0:
        padding = 4 - remainder
    else:
        padding = 0

    # Дополняем последний блок нулевыми байтами до 4 байт (32 бит).
    padding_bytes = b'\x00' * padding
    padded_text = utf_text + padding_bytes

    # Начальное значение контрольной суммы.
    h = 0

    # Обрабатываем сообщение блоками по 4 байта (32 бита).
    for i in range(0, len(padded_text), 4):
        block = padded_text[i:i + 4]

        # Преобразуем четыре байта в одно 32-битное целое число.
        block_number = int.from_bytes(block, 'big')

        # Сложение блоков по модулю 2 — операция XOR.
        h = h ^ block_number

    return h


def is_prime(number, rounds=40):
    """Проверяет число на простоту тестом Миллера — Рабина."""

    if number < 2:
        return False

    # Сначала проверяем делимость на небольшие простые числа.
    small_primes = (
        2, 3, 5, 7, 11, 13,
        17, 19, 23, 29, 31, 37
    )

    for prime in small_primes:
        if number == prime:
            return True

        if number % prime == 0:
            return False

    # Представляем number - 1 в виде:
    # number - 1 = 2^s * d,
    # где d — нечётное число.
    d = number - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # Выполняем несколько раундов теста Миллера — Рабина.
    for _ in range(rounds):
        a = secrets.randbelow(number - 3) + 2

        x = pow(a, d, number)

        if x == 1 or x == number - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, number)

            if x == number - 1:
                break
        else:
            return False

    return True


def generate_q():
    """Генерирует простое число q требуемого размера."""

    while True:
        # Создаём случайное число длиной до 256 бит.
        q = secrets.randbits(256)

        # Гарантируем условие q > 2^254.
        q |= 1 << 254

        # Делаем q нечётным.
        q |= 1

        if is_prime(q):
            return q


def generate_p(q):
    """Генерирует простое p так, чтобы q было делителем p - 1."""

    p_min = 2 ** 509
    p_max = 2 ** 512

    # Так как p = multiplier * q + 1,
    # определяем допустимые границы multiplier.
    multiplier_min = (p_min // q) + 1
    multiplier_max = (p_max - 2) // q

    while True:
        multiplier = (
            secrets.randbelow(
                multiplier_max - multiplier_min + 1
            )
            + multiplier_min
        )

        # q нечётное. Чтобы p было нечётным,
        # multiplier должен быть чётным.
        if multiplier % 2 != 0:
            multiplier += 1

        if multiplier > multiplier_max:
            continue

        # Строим p так, чтобы q автоматически делило p - 1.
        p = multiplier * q + 1

        if is_prime(p):
            return p


def generate_a(p, q):
    """Генерирует параметр a, для которого a^q mod p = 1."""

    exponent = (p - 1) // q

    while True:
        base = secrets.randbelow(p - 3) + 2

        a = pow(base, exponent, p)

        if a > 1:
            return a


def generate_keys(p, q, a):
    """Генерирует секретный ключ x и открытый ключ y."""

    # Генерируем секретный ключ:
    # 1 < x < q.
    x = secrets.randbelow(q - 2) + 2

    # Вычисляем открытый ключ:
    # y = a^x mod p.
    y = pow(a, x, p)

    return x, y


def sign_message(message, p, q, a, x):
    """Формирует электронную подпись сообщения."""

    # Вычисляем контрольную сумму сообщения.
    h = hash_message(message)

    # Если h mod q = 0, принимаем h = 1.
    if h % q == 0:
        h = 1

    while True:
        # Генерируем случайный секретный сеансовый ключ:
        # 1 < k < q.
        k = secrets.randbelow(q - 2) + 2

        # Вычисляем r = a^k mod p.
        r = pow(a, k, p)

        # Вычисляем первую часть электронной подписи.
        r1 = r % q

        # При r1 = 0 выбираем новое значение k.
        if r1 == 0:
            continue

        # Вычисляем вторую часть электронной подписи.
        s = (x * r1 + k * h) % q

        # При s = 0 выбираем новое значение k.
        if s == 0:
            continue

        # Электронная подпись состоит из пары (r1, s).
        return r1, s


def verify_signature(message, signature, p, q, a, y):
    """Проверяет электронную подпись сообщения."""

    # Извлекаем две части электронной подписи.
    r1, s = signature

    # Проверяем допустимые значения подписи.
    if not (0 < r1 < q and 0 < s < q):
        return False

    # Повторно вычисляем контрольную сумму сообщения.
    h = hash_message(message)

    # Если h mod q = 0, принимаем h = 1.
    if h % q == 0:
        h = 1

    # Вычисляем обратное значение хэша по модулю q:
    # v = h^(q - 2) mod q.
    v = pow(h, q - 2, q)

    # Вычисляем промежуточные значения.
    z1 = (s * v) % q
    z2 = ((q - r1) * v) % q

    # Вычисляем проверочное значение:
    # u = (a^z1 * y^z2 mod p) mod q.
    u = (
        (
            pow(a, z1, p)
            * pow(y, z2, p)
        ) % p
    ) % q

    # Подпись действительна, если u совпадает с r1.
    return u == r1


def main():
    """Запускает программу."""

    # Генерируем параметры криптографической системы.
    q = generate_q()
    p = generate_p(q)
    a = generate_a(p, q)

    # Генерируем секретный и открытый ключи.
    x, y = generate_keys(p, q, a)

    # Получаем исходное сообщение от пользователя.
    message = input('Введите текст: ')

    # Вычисляем контрольную сумму исходного сообщения.
    hash_value = hash_message(message)

    # Формируем электронную подпись.
    signature = sign_message(
        message,
        p,
        q,
        a,
        x
    )

    print('\nИсходное сообщение:')
    print(message)
    print('Контрольная сумма:', hash_value)

    print('\nПараметры системы:')
    print('p =', p)
    print('q =', q)
    print('a =', a)

    print('\nКлючи:')
    print('Секретный ключ x =', x)
    print('Открытый ключ y =', y)

    print('\nЭлектронная подпись:')
    print('r1 =', signature[0])
    print('s =', signature[1])

    # Проверяем подпись исходного сообщения.
    is_valid = verify_signature(
        message,
        signature,
        p,
        q,
        a,
        y
    )

    print('\nПроверка исходного сообщения:')
    print('Контрольная сумма:', hash_value)
    print('Подпись действительна:', is_valid)

    # ---------------------------------------------------------
    # Проверка после изменения сообщения.
    # ---------------------------------------------------------

    # Добавляем один символ к исходному сообщению.
    modified_message = message + '!'

    # Вычисляем новую контрольную сумму.
    modified_hash_value = hash_message(modified_message)

    # Проверяем старую подпись для изменённого сообщения.
    modified_message_valid = verify_signature(
        modified_message,
        signature,
        p,
        q,
        a,
        y
    )

    print('\nПроверка изменённого сообщения:')
    print('Изменённый текст:', modified_message)
    print('Исходная контрольная сумма:', hash_value)
    print('Новая контрольная сумма:', modified_hash_value)
    print('Подпись действительна:', modified_message_valid)

    # ---------------------------------------------------------
    # Проверка после изменения электронной подписи.
    # ---------------------------------------------------------

    # Изменяем значение s, сохраняя его в допустимом диапазоне.
    modified_s = signature[1] + 1

    if modified_s >= q:
        modified_s = signature[1] - 1

    modified_signature = (
        signature[0],
        modified_s
    )

    # Проверяем изменённую подпись для исходного сообщения.
    modified_signature_valid = verify_signature(
        message,
        modified_signature,
        p,
        q,
        a,
        y
    )

    print('\nПроверка изменённой подписи:')
    print('Исходное s =', signature[1])
    print('Изменённое s =', modified_signature[1])
    print('Подпись действительна:', modified_signature_valid)

    # ---------------------------------------------------------
    # Дополнительная проверка параметров системы.
    # ---------------------------------------------------------

    print('\nПроверка параметров системы:')
    print('p простое:', is_prime(p))
    print('q простое:', is_prime(q))
    print('(p - 1) % q =', (p - 1) % q)
    print('a^q mod p =', pow(a, q, p))


if __name__ == '__main__':
    main()
