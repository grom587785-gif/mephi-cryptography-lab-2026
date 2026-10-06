import math


# Простые числа для варианта №10.
p = 233
q = 293

# Модуль RSA.
n = p * q

# Значение функции Эйлера.
phi_n = (p - 1) * (q - 1)

# Поиск минимального e, взаимно простого с phi_n.
for e in range(2, phi_n):
    if math.gcd(e, phi_n) == 1:
        break

# Вычисление закрытой части ключа.
d = pow(e, -1, phi_n)


def encrypt(message, e, n):
    """Шифрует число с помощью открытого ключа RSA."""
    encrypted = pow(message, e, n)
    return encrypted


def decrypt(encrypted_message, d, n):
    """Расшифровывает число с помощью закрытого ключа RSA."""
    decrypted = pow(encrypted_message, d, n)
    return decrypted


message = input('Введите сообщение: ')

# Преобразование символов сообщения в числовые коды.
message_numbers = []

for char in message:
    message_numbers.append(ord(char))

# Проверка условия RSA: каждый числовой блок должен быть меньше n.
for number in message_numbers:
    if number >= n:
        raise ValueError(
            f'Код символа {number} должен быть меньше n = {n}.'
        )

# Шифрование числовых кодов.
encrypted_numbers = []

for number in message_numbers:
    encrypted_numbers.append(encrypt(number, e, n))

# Расшифрование.
decrypted_numbers = []

for encrypted_number in encrypted_numbers:
    decrypted_numbers.append(
        decrypt(encrypted_number, d, n)
    )

# Преобразование чисел обратно в символы.
decrypted_chars = []

for number in decrypted_numbers:
    decrypted_chars.append(chr(number))

# Сборка расшифрованных символов в строку.
decrypted_message = ''.join(decrypted_chars)


print('\nПараметры RSA:')
print('p =', p)
print('q =', q)
print('n =', n)
print('phi(n) =', phi_n)
print('e =', e)
print('d =', d)

print('\nКлючи:')
print('Открытый ключ:', (e, n))
print('Закрытый ключ:', (d, n))

print('\nРезультаты:')
print('Исходное сообщение:', message)
print('Числовое представление:', message_numbers)
print('Зашифрованное сообщение:', encrypted_numbers)
print('Расшифрованное сообщение:', decrypted_message)
print('Проверка:', message == decrypted_message)
