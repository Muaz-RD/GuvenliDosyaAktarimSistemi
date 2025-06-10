import socket
import math
import os
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from helpers import encrypt_data

PACKET_ID_KEY = 0x270F # Anahtar paketi ID'si
PACKET_ID_DATA = 0x2710 # Veri paketi ID'si

HEADER_FORMAT = "!HBI" # Başlık yapısı formatı
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # Başlık boyutu

MAX_UDP_PAYLOAD_SIZE = 1400 - HEADER_SIZE # UDP veri yükü için maksimum boyut

def send_file(file_path, dst_ip, udp_port, public_key_path, log_callback):
    """
    Dosyayı AES ile şifreler, AES anahtarını RSA ile şifreler
    ve standart soketler kullanarak parçalar halinde UDP üzerinden gönderir.
    """
    try:
        log_callback(f"[*] Alıcının genel anahtarı '{public_key_path}' yükleniyor...")
        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read()) # Alıcının açık anahtarını yükler
        rsa_cipher = PKCS1_OAEP.new(public_key) # RSA şifreleyici oluşturur
        log_callback("[✓] Genel anahtar başarıyla yüklendi.")

        aes_key = get_random_bytes(32) # Dosya şifrelemesi için rastgele AES anahtarı oluşturur
        log_callback(f"[*] AES anahtarı oluşturuldu: {aes_key.hex()}")

        encrypted_aes_key = rsa_cipher.encrypt(aes_key) # AES anahtarını RSA açık anahtarıyla şifreler
        log_callback(f"[*] AES anahtarı RSA ile şifrelendi. Boyut: {len(encrypted_aes_key)} bayt.")

        log_callback(f"[*] Dosya okunuyor: {file_path}")
        with open(file_path, "rb") as f:
            file_data = f.read() # Dosya içeriğini okur
        log_callback(f"[*] Dosya boyutu: {len(file_data)} bayt.")

        log_callback("[*] Dosya AES ile şifreleniyor...")
        encrypted_file_data = encrypt_data(file_data, aes_key) # Dosya verisini AES anahtarıyla şifreler
        log_callback(f"[✓] Dosya başarıyla şifrelendi. Şifreli boyut: {len(encrypted_file_data)} bayt.")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Standart UDP soketi kullanır

        log_callback(f"[*] Şifreli AES anahtarı gönderiliyor {dst_ip}:{udp_port}...")
        key_header = struct.pack(HEADER_FORMAT, PACKET_ID_KEY, 0, 0) # Anahtar paketi için başlık oluşturur
        sock.sendto(key_header + encrypted_aes_key, (dst_ip, udp_port)) # Şifreli AES anahtarını gönderir
        log_callback("[✓] Şifreli AES anahtarı gönderildi.")

        total_fragments = math.ceil(len(encrypted_file_data) / MAX_UDP_PAYLOAD_SIZE) # Toplam parça sayısını hesaplar
        log_callback(f"[*] {len(encrypted_file_data)} bayt veri {total_fragments} parçaya bölünüyor.")

        for i in range(total_fragments):
            start = i * MAX_UDP_PAYLOAD_SIZE
            end = start + MAX_UDP_PAYLOAD_SIZE
            fragment_data = encrypted_file_data[start:end] # Parça verisini alır

            byte_offset = start # Bu parçanın orijinal şifreli verideki bayt konumu
            
            fragment_flag = 1 if i == total_fragments - 1 else 0 # Son parça bayrağını ayarlar

            data_header = struct.pack(HEADER_FORMAT, PACKET_ID_DATA, fragment_flag, byte_offset) # Veri paketi için başlık oluşturur
            sock.sendto(data_header + fragment_data, (dst_ip, udp_port)) # Veri parçasını gönderir
            log_callback(f"[+] Parça {i+1}/{total_fragments} gönderildi (Offset: {byte_offset}, Boyut: {len(fragment_data)} bayt, Son Parça: {'Evet' if fragment_flag == 1 else 'Hayır'}).")

        sock.close() # Tüm veriler gönderildikten sonra soketi kapatır
        log_callback("[✓] Tüm dosya parçaları gönderildi.")

    except FileNotFoundError:
        log_callback(f"[!] Hata: Dosya bulunamadı: {file_path} veya {public_key_path}")
        raise # GUI hata mesajı için yeniden fırlatır
    except Exception as e:
        log_callback(f"[!] Hata oluştu: {e}")
        raise # GUI hata mesajı için yeniden fırlatır
