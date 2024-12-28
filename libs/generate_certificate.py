import sys
sys.path.append(".")
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes  # Добавлено для использования SHA256
import datetime
import base64
import time
import json
from libs import generate_keys, crypter
import ipaddress


def create_self_signed_cert(cert_key_file: str, county_name: str, state_or_province: str, locality_name: str, organization_name: str, common_name: str, san_ip: str, time: int):
    # Генерация приватного ключа
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Создание самоподписанного сертификата
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, county_name),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])

    issuer = subject  # Для самоподписанного сертификата issuer и subject совпадают

    # Создание SAN для одного IP-адреса
    san_ip_address = x509.IPAddress(ipaddress.ip_address(san_ip))

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Сертификат будет действителен заданное количество дней
        datetime.datetime.utcnow() + datetime.timedelta(days=time)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([san_ip_address]), critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Сохранение сертификата и приватного ключа в один файл
    with open(cert_key_file, "wb") as cert_key_file_handle:
        cert_key_file_handle.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        cert_key_file_handle.write(b'\n')  # Добавляем новую строку для разделения
        cert_key_file_handle.write(cert.public_bytes(serialization.Encoding.PEM))



def pad_and_split(data):
    # Добавляем паддинг до кратности 64
    padding_length = (64 - len(data) % 64) % 64
    padded_data = data + '0' * padding_length

    # Разделяем на блоки по 64 символа
    blocks = [padded_data[i:i + 64] for i in range(0, len(padded_data), 64)]

    return blocks

def generate_SDTP_cer(path:str, name_user: str, city : str, country: str, time_validibale:int):
    header = "-----------------------------SDTP_CERTIFICATE_BEGIN-------------------------------------\n"
    footer = "------------------------------SDTP_CERTIFICATE_END--------------------------------------"
    data = {"Username" : "", "country" : "", "city" : ""}
    
    data["Username"] = name_user
    data["country"] = country
    data["city"] = city
    data["time_gen"] = str(time.time())
    data["time_valid"] = str(time.time() + time_validibale)
    data = str(data)
    
    print("DEBUG:", data)
    
    keys = generate_keys.generate_key_and_iv()
    print("DEBUG:", f"KEY: {keys[0]}, InitVector: {keys[1]}")
    key = keys[0]
    InitVector = keys[1]
    
    data = base64.b64encode(data.encode())
    data = data.decode()
    print("DEBUG:", f"Data b64: {data}")
    
    data = crypter.encode_my(key, InitVector, data)
    
    print("DEBUG:", f"Message: {data[0]}")
    print("DEBUG:", f"Message Hash: {data[1]}")
    napolnitel = generate_keys.generate_random_key(1024)
    print("DEBUG:", f"NAPOLNITEL: {napolnitel}")
    
    data = data[0] + "|" + key+ "|" + data[1] + "|" + napolnitel
    
    data = pad_and_split(data)
    
    result = []
    
    for block in data:
        block = base64.b64encode(block.encode())
        block = block.decode()
        block = block + "\n"
        result.append(block)
    
    with open(path, "wb") as file:
        file.write(header.encode())
        for block in result:
            file.write(block.encode())
        file.write(footer.encode())
    

def read_SDTP_cer(path:str):
    with open(path, "rb") as file:
        data = file.read()
    
    print("DEBUG:", f"CERTIFICATE DATA: {data.decode()}")
    data = data.decode()
    data = data.split("\n")
    
    del data[0]
    del data[-1]
        
    number = 0
    for i in data:
        number += 1
        print("DEBUG:", f"BLOCK NUMBER{number}, b64: {i}")
    
    new_data = []
    for block in data:
        block  = base64.b64decode(block.encode())
        block  = block.decode()
        new_data.append(block)
    
    number = 0
    for i in new_data:
        number += 1
        print("DEBUG:", f"BLOCK NUMBER {number}: {i}")
    block = new_data[-1]
    del new_data[-1]
    block = str(block).rstrip("0")
    new_data.append(block)   
    
    data = "".join(new_data)
    data = data.split("|")
    
    message = data[0]
    key = data[1]
    message_hash = data[2]
    napolnitel = data[-1]
    
    print("DEBUG:", f"MESSAGE: {message}")
    print("DEBUG:", f"KEY: {key}")
    print("DEBUG:", f"HASH: {message_hash}")
    print("DEBUG:", f"NAPOLNITEL: {napolnitel}")

    
    result_message = crypter.decode_my(key, message, message_hash)
    print("DEBUG:", f"MESSAGE: {result_message}")
    message = base64.b64decode(result_message.encode()).decode()
    print("DEBUG:", f"DECODED MESSAGE: {message}")
    message = message.replace("'", '"')
    message = json.loads(message)
    print("DEBUG:", f"MESSAGE DICT: {message}")
    
    time_valid = message["time_valid"]
    time_valid = float(time_valid)
    timestamp = time.time()
    
    if time_valid < timestamp:
        print("DEBUG:", f"CRITICAL CERTIFICATE ERROR: TIME_VALID EXPIRED: {timestamp - time_valid}")
    else:
        print("DEBUG:", f"CERTIFICATE CHECK OK, time valid ok certificate expired at {time_valid - timestamp}")
       