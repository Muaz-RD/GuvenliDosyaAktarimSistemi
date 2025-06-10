import os
from Crypto.PublicKey import RSA

def generate_keys():
    """
    Yeni bir RSA açık ve özel anahtar çifti oluşturur ve bunları
    'public.pem' ve 'private.pem' dosyalarına kaydeder.
    """
    try:
        key = RSA.generate(2048) # 2048 bitlik bir RSA anahtar çifti oluşturur

        with open("private.pem", "wb") as f:
            f.write(key.export_key('PEM')) # Özel anahtarı PEM formatında kaydeder

        with open("public.pem", "wb") as f:
            f.write(key.publickey().export_key('PEM')) # Açık anahtarı PEM formatında kaydeder

        print("[rsa_keygen] RSA keys generated successfully: public.pem, private.pem")
    except Exception as e:
        print(f"[rsa_keygen] Error generating RSA keys: {e}")
        raise # GUI tarafından yakalanmak üzere istisnayı yeniden fırlatır

if __name__ == "__main__":
    print("Generating RSA keys...")
    generate_keys() # Anahtarları oluşturma fonksiyonunu çağırır
    print("Check public.pem and private.pem in the current directory.")
