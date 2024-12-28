import base64
import os
import random
import hashlib

def generate_key_and_iv():
    """Генерирует криптографически безопасный ключ и IV для AES-256 с помощью библиотеки cryptography."""
    key = os.urandom(32)  # 32 байта для AES-256
    iv = os.urandom(16)   # 16 байт для IV (AES использует 16-байтные IV)
    key_b64 = base64.b64encode(key).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    return [key_b64, iv_b64]

def generate_random_key(size: int) -> str:
    data = os.urandom(size)
    return base64.b64encode(data).decode('utf-8')  # Кодируем в base64 для удобства


def is_prime(n):
    """Проверка, является ли число простым."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_large_prime(min_value=100, max_value=1000):
    """Генерация большого простого числа в заданном диапазоне."""
    while True:
        candidate = random.randint(min_value, max_value)
        if is_prime(candidate):
            return candidate

def find_primitive_root(p):
    """Нахождение примитивного корня по модулю p."""
    for g in range(2, p):
        if all(power_mod(g, (p - 1) // factor, p) != 1 for factor in factorization(p - 1)):
            return g
    return None

def factorization(n):
    """Факторизация числа n на простые множители."""
    factors = []
    for i in range(2, int(n**0.5) + 1):
        while n % i == 0:
            factors.append(i)
            n //= i
    if n > 1:
        factors.append(n)
    return factors

def power_mod(base, exponent, mod):
    """Функция для вычисления (base^exponent) mod mod с использованием быстрого возведения в степень."""
    result = 1
    base = base % mod
    while exponent > 0:
        if (exponent % 2) == 1:  # Если exponent нечетный
            result = (result * base) % mod
        exponent = exponent >> 1  # Делим exponent на 2
        base = (base * base) % mod
    return result

def generate_private_key(p):
    """Генерируем случайный секретный ключ в диапазоне от 1 до p-1."""
    return random.randint(1, p - 1)


def hash_key(key):
    """Хешируем ключ с помощью SHA-256 и возвращаем первые 32 символа в шестнадцатичном формате."""
    hash_object = hashlib.sha256(key.to_bytes((key.bit_length() + 7) // 8, 'big'))
    return hash_object.hexdigest()[:32]

def generate_numbers():
    """Генерация чисел для передачи другому человеку (параметры p, g и секретные ключи a и b)."""
    p = generate_large_prime(100, 1000)  # Генерация простого числа
    g = find_primitive_root(p)  # Нахождение примитивного корня
    a = generate_private_key(p)  # Секретный ключ Алисы
    b = generate_private_key(p)  # Секретный ключ Боба

    # Возвращаем все необходимые значения в виде списка
    return [p, g, a, b]

def compute_shared_key(B, a, p):
    """Вычисление общего ключа на основе переданных значений B, a и p."""
    shared_key = power_mod(B, a, p)  # Общий ключ K = B^a mod p
    return hash_key(shared_key)  # Возвращаем хешированный ключ

# def main():
#     # Генерация чисел для передачи
#     numbers = generate_numbers()

#     # Извлечение p, g, a и b из списка
#     p, g, a, b = numbers

#     # Вычисление публичных значений A и B
#     A = power_mod(g, a, p)  # A = g^a mod p
#     B = power_mod(g, b, p)  # B = g^b mod p

#     # Вывод сгенерированных чисел
#     print(f"Сгенерированные числа (p, g, a, b): {numbers}")
#     print(f"Алиса отправляет A: {A}")
#     print(f"Боб отправляет B: {B}")

#     # Вычисление общего ключа
#     shared_key_Alice = compute_shared_key(B, a, p)
#     shared_key_Bob = compute_shared_key(A, b, p)

#     # Вывод общего ключа
#     print(f"Общий секретный ключ, вычисленный Алисой: {shared_key_Alice}")
#     print(f"Общий секретный ключ, вычисленный Бобом: {shared_key_Bob}")

# if __name__ == "__main__":
#     main()