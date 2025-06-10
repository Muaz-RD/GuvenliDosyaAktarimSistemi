from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_data(data, key):
    """
    Veriyi AES'i CBC modunda rastgele oluşturulmuş bir IV ile şifreler.
    """
    iv = get_random_bytes(AES.block_size) # AES blok boyutu kadar rastgele IV oluşturur
    cipher = AES.new(key, AES.MODE_CBC, iv) # AES şifreleyici oluşturur
    padded_data = pad(data, AES.block_size) # Veriyi blok boyutunun katına göre doldurur
    ciphertext = cipher.encrypt(padded_data) # Doldurulmuş veriyi şifreler
    return iv + ciphertext # IV ve şifreli metni birleştirerek döndürür

def decrypt_data(encrypted_data, key):
    """
    AES şifreli veriyi (IV + şifreli metin) çözer.
    """
    iv = encrypted_data[:AES.block_size] # IV'yi başta ayıklar
    ciphertext = encrypted_data[AES.block_size:] # Geri kalan şifreli metindir
    cipher = AES.new(key, AES.MODE_CBC, iv) # AES şifreleyici oluşturur
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size) # Şifreli metni çözer ve doldurmayı kaldırır
    return plaintext # Çözülmüş düz metni döndürür
