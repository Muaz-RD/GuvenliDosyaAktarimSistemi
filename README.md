# 🔐 Gelişmiş Güvenli Dosya Aktarım Sistemi

Bu proje, bilgisayar ağları için geliştirilmiş, şifreleme ve paket yönetimi prensipleriyle güvenli dosya transferini sağlayan bir sistemdir.  
Amacı, modern şifreleme algoritmaları (**AES** ve **RSA**) kullanarak **veri gizliliği ve bütünlüğünü sağlarken**, ağ performansını analiz etmek ve **düşük seviyeli ağ protokollerine dair pratik deneyim** sunmaktır.  
Sistem, kullanımı kolay bir **Grafik Kullanıcı Arayüzü (GUI)** ile birlikte gelir.

---

## ✨ Temel Özellikler

- **Güvenli Dosya Aktarımı**: AES ve RSA şifrelemesi ile dosyaları güvenli bir şekilde gönderir ve alır.  
- **Paket Yönetimi**: Büyük dosyaları uygulama katmanında parçalara ayırır ve yeniden birleştirir.  
- **Ağ Performans Analizi**: `ping` (gecikme) ve `iPerf3` (bant genişliği) ile ağ performansını ölçer.  
- **Kullanıcı Arayüzü**: `Tkinter` ile geliştirilmiş kolay kullanımlı bir GUI sunar.  

---

## 🛠️ Çalışma Prensibi

Proje, **Python** ve **PyCryptodome** kütüphanesi kullanılarak geliştirilmiştir.

1. **Gönderici**:
   - Dosyayı AES ile şifreler.
   - AES anahtarını, alıcının RSA açık anahtarıyla şifreler.
   - Şifreli dosya ve anahtarı UDP üzerinden parçalara ayırarak gönderir.

2. **Alıcı**:
   - RSA özel anahtarıyla AES anahtarını çözer.
   - Gelen parçaları birleştirerek dosyayı deşifre eder.

---

## 💻 Kullanılan Teknolojiler

- Python 3.x  
- Tkinter (GUI için)  
- PyCryptodome (Kriptografi için)  
- `socket`, `struct`, `threading` (Ağ işlemleri için)  
- `ping`, `iPerf3`, `Wireshark` (Ağ analizi için)  

---

## 🚀 Kurulum ve Çalıştırma

```bash
# Projeyi GitHub'dan klonlayın

# Gerekli kütüphaneleri yükleyin
pip install pycryptodome

# Uygulamayı çalıştırın
python main_gui.py

YouTube Tanıtım Videosu: [YouTube Video Linkiniz Buraya Gelecek](https://www.youtube.com/watch?v=VIDEO_ID)
