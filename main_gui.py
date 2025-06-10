import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import font
import threading
import socket
import struct
import time


from rsa_keygen import generate_keys
from secure_sender_rsa import send_file as secure_send_file
from helpers import decrypt_data


class SecureFileTransferApp:
    def __init__(self, master):
        self.master = master
        master.title("Güvenli Dosya Aktarımı")
        master.geometry("950x800")
        master.resizable(True, True)
        master.configure(bg='#eceff1')

        self._receiver_stop_event = threading.Event() # Alıcı iş parçacığını durdurmak için olay
        self._receiver_thread = None # Alıcı iş parçacığı örneği

        self.setup_styles() # Uygulama stilini ayarlar
        self.create_widgets() # GUI bileşenlerini oluşturur

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing) # Pencere kapatma olayını yönetir

    def setup_styles(self):
        s = ttk.Style() # Stil nesnesi

        s.theme_use('clam') # 'clam' temasını kullanır

        base_font_family = "Segoe UI"
        try:
            tk.font.Font(family=base_font_family)
        except tk.TclError:
            base_font_family = "Helvetica" # Yedek font

        self.base_font = (base_font_family, 10) # Temel font
        self.bold_font = (base_font_family, 10, "bold") # Kalın font
        self.heading_font = (base_font_family, 14, "bold") # Başlık fontu
        self.log_font = ("Consolas", 9) # Log fontu (monospace)

        # Renk paleti tanımları
        primary_blue_gray = '#607D8B'
        light_blue_gray = '#B0BEC5'
        accent_green = '#8BC34A'
        dark_text = '#333333'
        light_text = '#FFFFFF'
        background_color = '#ECEFF1'
        entry_background = '#FFFFFF'
        notebook_bg = '#CFD8DC'
        log_background = '#fdfefe'
        log_foreground = '#424242'

        s.configure('.', font=self.base_font, background=background_color, foreground=dark_text) # Genel widget stili

        s.configure('TFrame', background=background_color, borderwidth=0, relief="flat") # Çerçeve stili

        s.configure('TLabel', background=background_color, foreground=dark_text, padding=(5, 5)) # Etiket stili
        s.configure('Heading.TLabel', font=self.heading_font, anchor="center") # Başlık etiketi stili

        s.configure('TButton',
                    font=self.bold_font,
                    background=primary_blue_gray,
                    foreground=light_text,
                    borderwidth=0,
                    focusthickness=3,
                    focuscolor=light_blue_gray,
                    padding=(10, 8),
                    relief='raised',
                    cursor="hand2"
                   ) # Buton stili
        s.map('TButton',
              background=[('active', light_blue_gray), ('pressed', primary_blue_gray), ('disabled', '#9E9E9E')],
              foreground=[('active', dark_text), ('pressed', light_text), ('disabled', '#BDBDBD')]
             ) # Buton durumuna göre renk değişimi

        s.configure('Accent.TButton', background=accent_green) # Vurgu butonu stili
        s.map('Accent.TButton',
              background=[('active', primary_blue_gray), ('pressed', accent_green), ('disabled', '#9E9E9E')],
              foreground=[('active', light_text), ('pressed', light_text), ('disabled', '#BDBDBD')]
             )

        s.configure('TEntry',
                    fieldbackground=entry_background,
                    foreground=dark_text,
                    borderwidth=1,
                    relief='flat',
                    padding=(5, 5)
                   ) # Giriş kutusu stili
        s.map('TEntry',
              fieldbackground=[('focus', '#E0F2F7')],
              bordercolor=[('focus', primary_blue_gray)]
             )

        s.configure('TScrolledtext.text',
                    background=log_background,
                    foreground=log_foreground,
                    relief='flat',
                    borderwidth=1,
                    font=self.log_font,
                    padding=(5, 5)
                   ) # Kaydırılabilir metin alanı stili

        s.configure('TNotebook',
                    background=notebook_bg,
                    borderwidth=0,
                    tabposition='nw'
                   ) # Sekme defteri stili
        s.configure('TNotebook.Tab',
                    background=background_color,
                    foreground=dark_text,
                    padding=[15, 8],
                    font=self.bold_font,
                    borderwidth=0,
                    relief='flat'
                   ) # Sekme stili
        s.map('TNotebook.Tab',
              background=[('selected', primary_blue_gray)],
              foreground=[('selected', light_text)],
              expand=[('selected', [0, 0, 0, 0])]
             )
        s.configure('TNotebook.Tab', focuscolor=notebook_bg)

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.master) # Sekme defteri oluşturur
        self.notebook.pack(expand=True, fill="both", padx=20, pady=20)

        self.key_frame = ttk.Frame(self.notebook, style='TFrame') # Anahtar oluşturma çerçevesi
        self.notebook.add(self.key_frame, text=" Anahtar Oluştur ")
        self.create_key_tab(self.key_frame)

        self.sender_frame = ttk.Frame(self.notebook, style='TFrame') # Gönderici çerçevesi
        self.notebook.add(self.sender_frame, text=" Dosya Gönder ")
        self.create_sender_tab(self.sender_frame)

        self.receiver_frame = ttk.Frame(self.notebook, style='TFrame') # Alıcı çerçevesi
        self.notebook.add(self.receiver_frame, text=" Dosya Al ")
        self.create_receiver_tab(self.receiver_frame)

    def create_key_tab(self, frame):
        frame.columnconfigure(0, weight=1) # Sütun ağırlığını ayarlar

        ttk.Label(frame, text="RSA Anahtar Çifti Oluştur", style='Heading.TLabel').grid(row=0, column=0, pady=20, padx=20, sticky="nsew")

        self.generate_key_button = ttk.Button(frame, text="Anahtarları Oluştur", command=self.run_generate_keys, style='Accent.TButton')
        self.generate_key_button.grid(row=1, column=0, pady=10, padx=20, sticky="ew")

        log_frame = ttk.Frame(frame, style='TFrame', relief='solid', borderwidth=1, padding=(5,5)) # Log çerçevesi
        log_frame.grid(row=2, column=0, pady=20, padx=20, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.key_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled',
                                                 font=self.log_font, bg='#fdfefe', fg='#424242', relief='flat', borderwidth=0) # Anahtar log alanı
        self.key_log.grid(row=0, column=0, sticky="nsew")


    def create_sender_tab(self, frame):
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Dosya Gönder", style='Heading.TLabel').grid(row=0, column=0, pady=20, padx=20, sticky="nsew")

        row_idx = 1
        ttk.Label(frame, text="Gönderilecek Dosya:", anchor="w").grid(row=row_idx, column=0, padx=20, pady=(10, 2), sticky="w")
        row_idx += 1
        file_frame = ttk.Frame(frame, style='TFrame')
        file_frame.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="ew")
        file_frame.columnconfigure(0, weight=1)
        self.file_path_entry = ttk.Entry(file_frame, width=50, style='TEntry') # Dosya yolu giriş alanı
        self.file_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        ttk.Button(file_frame, text="Dosya Seç", command=lambda: self.browse_file(self.file_path_entry)).grid(row=0, column=1, sticky="e") # Dosya seç butonu
        row_idx += 1

        ttk.Label(frame, text="Alıcının Genel Anahtarı (public.pem):", anchor="w").grid(row=row_idx, column=0, padx=20, pady=(10, 2), sticky="w")
        row_idx += 1
        key_frame = ttk.Frame(frame, style='TFrame')
        key_frame.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="ew")
        key_frame.columnconfigure(0, weight=1)
        self.public_key_path_entry = ttk.Entry(key_frame, width=50, style='TEntry') # Genel anahtar yolu giriş alanı
        self.public_key_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        ttk.Button(key_frame, text="Genel Anahtar Seç", command=lambda: self.browse_file(self.public_key_path_entry, is_pem=True)).grid(row=0, column=1, sticky="e") # Anahtar seç butonu
        row_idx += 1

        ttk.Label(frame, text="Hedef IP Adresi:", anchor="w").grid(row=row_idx, column=0, padx=20, pady=(10, 2), sticky="w")
        row_idx += 1
        self.ip_entry = ttk.Entry(frame, width=30, style='TEntry') # IP adresi giriş alanı
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="ew")
        row_idx += 1

        ttk.Label(frame, text="Hedef UDP Portu:", anchor="w").grid(row=row_idx, column=0, padx=20, pady=(10, 2), sticky="w")
        row_idx += 1
        self.port_entry = ttk.Entry(frame, width=30, style='TEntry') # UDP portu giriş alanı
        self.port_entry.insert(0, "5005")
        self.port_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 20), sticky="ew")
        row_idx += 1

        self.send_button = ttk.Button(frame, text="Dosyayı Gönder", command=self.run_send_file) # Gönder butonu
        self.send_button.grid(row=row_idx, column=0, pady=10, padx=20, sticky="ew")
        row_idx += 1

        log_frame = ttk.Frame(frame, style='TFrame', relief='solid', borderwidth=1, padding=(5,5))
        log_frame.grid(row=row_idx, column=0, pady=20, padx=20, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.sender_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled',
                                                    font=self.log_font, bg='#fdfefe', fg='#424242', relief='flat', borderwidth=0) # Gönderici log alanı
        self.sender_log.grid(row=0, column=0, sticky="nsew")

        frame.rowconfigure(row_idx, weight=1)


    def create_receiver_tab(self, frame):
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Dosya Al", style='Heading.TLabel').grid(row=0, column=0, pady=20, padx=20, sticky="nsew")

        row_idx = 1
        ttk.Label(frame, text="Özel Anahtarınız (private.pem):", anchor="w").grid(row=row_idx, column=0, padx=20, pady=(10, 2), sticky="w")
        row_idx += 1
        key_frame = ttk.Frame(frame, style='TFrame')
        key_frame.grid(row=row_idx, column=0, padx=20, pady=(0, 10), sticky="ew")
        key_frame.columnconfigure(0, weight=1)
        self.private_key_path_entry = ttk.Entry(key_frame, width=50, style='TEntry') # Özel anahtar yolu giriş alanı
        self.private_key_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        ttk.Button(key_frame, text="Özel Anahtar Seç", command=lambda: self.browse_file(self.private_key_path_entry, is_pem=True)).grid(row=0, column=1, sticky="e") # Anahtar seç butonu
        row_idx += 1
        
        ttk.Label(frame, text="Dinlenecek UDP Portu:", anchor="w").grid(row=row_idx, column=0, padx=20, pady=(10, 2), sticky="w")
        row_idx += 1
        self.listen_port_entry = ttk.Entry(frame, width=30, style='TEntry') # Dinleme portu giriş alanı
        self.listen_port_entry.insert(0, "5005")
        self.listen_port_entry.grid(row=row_idx, column=0, padx=20, pady=(0, 20), sticky="ew")
        row_idx += 1

        button_frame = ttk.Frame(frame, style='TFrame') # Butonlar için çerçeve
        button_frame.grid(row=row_idx, column=0, pady=10, padx=20, sticky="ew")
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        self.receive_button = ttk.Button(button_frame, text="Dinlemeyi Başlat", command=self.run_start_sniffing) # Dinlemeyi başlat butonu
        self.receive_button.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="ew")

        self.stop_receive_button = ttk.Button(button_frame, text="Dinlemeyi Durdur", command=self.stop_sniffing, state=tk.DISABLED) # Dinlemeyi durdur butonu
        self.stop_receive_button.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="ew")
        row_idx += 1

        log_frame = ttk.Frame(frame, style='TFrame', relief='solid', borderwidth=1, padding=(5,5))
        log_frame.grid(row=row_idx, column=0, pady=20, padx=20, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.receiver_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled',
                                                    font=self.log_font, bg='#fdfefe', fg='#424242', relief='flat', borderwidth=0) # Alıcı log alanı
        self.receiver_log.grid(row=0, column=0, sticky="nsew")

        frame.rowconfigure(row_idx, weight=1)

    def log_message(self, log_widget, message):
        log_widget.config(state='normal') # Log widget'ını düzenlenebilir yapar
        log_widget.insert(tk.END, message + "\n") # Mesajı ekler
        log_widget.see(tk.END) # En alta kaydırır
        log_widget.config(state='disabled') # Log widget'ını tekrar devre dışı bırakır

    def browse_file(self, entry_widget, is_pem=False):
        if is_pem:
            filename = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")]) # PEM dosyalarını filtreler
        else:
            filename = filedialog.askopenfilename() # Herhangi bir dosyayı açar
        
        if filename:
            entry_widget.delete(0, tk.END) # Mevcut metni siler
            entry_widget.insert(0, filename) # Seçilen dosya adını ekler

    def run_generate_keys(self):
        self.log_message(self.key_log, "[*] RSA anahtarları oluşturuluyor...")
        self.generate_key_button.config(state=tk.DISABLED) # Butonu devre dışı bırakır
        threading.Thread(target=self._generate_keys_thread, daemon=True).start() # Yeni bir iş parçacığında anahtar oluşturur

    def _generate_keys_thread(self):
        try:
            generate_keys() # Anahtarları oluşturur
            self.master.after(0, self.log_message, self.key_log, "[✓] RSA anahtarları başarıyla üretildi (public.pem, private.pem).")
        except Exception as e:
            self.master.after(0, self.log_message, self.key_log, f"[!] Anahtar oluşturma hatası: {e}")
            self.master.after(0, lambda: messagebox.showerror("Hata", f"Anahtar oluşturma hatası: {e}"))
        finally:
            self.master.after(0, lambda: self.generate_key_button.config(state=tk.NORMAL)) # Butonu tekrar etkinleştirir


    def run_send_file(self):
        file_path = self.file_path_entry.get() # Dosya yolunu alır
        public_key_path = self.public_key_path_entry.get() # Genel anahtar yolunu alır
        dst_ip = self.ip_entry.get() # Hedef IP'yi alır
        try:
            udp_port = int(self.port_entry.get()) # UDP portunu alır
        except ValueError:
            messagebox.showerror("Hata", "Geçersiz UDP portu. Lütfen bir sayı girin.")
            return

        if not file_path or not public_key_path:
            messagebox.showwarning("Uyarı", "Lütfen gönderilecek dosyayı ve alıcının genel anahtarını seçin.")
            return
        
        self.sender_log.config(state='normal') # Gönderici logunu temizler
        self.sender_log.delete('1.0', tk.END)
        self.sender_log.config(state='disabled')
        
        self.send_button.config(state=tk.DISABLED) # Butonu devre dışı bırakır
        thread = threading.Thread(target=self._send_file_thread, args=(file_path, dst_ip, udp_port, public_key_path), daemon=True) # Gönderim iş parçacığı
        thread.start()

    def _send_file_thread(self, file_path, dst_ip, udp_port, public_key_path):
        def log_callback(msg):
            self.master.after(0, self.log_message, self.sender_log, msg) # Log mesajı geri çağırma

        try:
            log_callback("[*] Dosya gönderme işlemi başlatılıyor...")
            secure_send_file(file_path, dst_ip, udp_port, public_key_path, log_callback) # Dosyayı güvenli bir şekilde gönderir
            log_callback("[✓] Dosya gönderme tamamlandı.")
        except Exception as e:
            log_callback(f"[!] Dosya gönderme hatası: {e}")
            self.master.after(0, lambda: messagebox.showerror("Hata", f"Dosya gönderme hatası: {e}"))
        finally:
            self.master.after(0, lambda: self.send_button.config(state=tk.NORMAL)) # Butonu tekrar etkinleştirir


    def run_start_sniffing(self):
        if self._receiver_thread and self._receiver_thread.is_alive():
            self.log_message(self.receiver_log, "[!] Dinleyici zaten çalışıyor.")
            return

        private_key_path = self.private_key_path_entry.get() # Özel anahtar yolunu alır
        try:
            listen_port = int(self.listen_port_entry.get()) # Dinleme portunu alır
        except ValueError:
            messagebox.showerror("Hata", "Geçersiz UDP portu. Lütfen bir sayı girin.")
            return
            
        if not private_key_path:
            messagebox.showwarning("Uyarı", "Lütfen dinleme için özel anahtarınızı seçin.")
            return

        self.receiver_log.config(state='normal') # Alıcı logunu temizler
        self.receiver_log.delete('1.0', tk.END)
        self.receiver_log.config(state='disabled')
        
        self._receiver_stop_event.clear() # Durdurma olayını temizler
        self.receive_button.config(state=tk.DISABLED) # Başlat butonunu devre dışı bırakır
        self.stop_receive_button.config(state=tk.NORMAL) # Durdur butonunu etkinleştirir

        self._receiver_thread = threading.Thread(target=self._start_sniffing_thread, args=(listen_port, private_key_path, self._receiver_stop_event), daemon=True) # Dinleme iş parçacığı
        self._receiver_thread.start()

    def stop_sniffing(self):
        self.log_message(self.receiver_log, "[*] Dinleme durduruluyor...")
        self._receiver_stop_event.set() # İş parçacığını durdurma sinyali verir


    def _start_sniffing_thread(self, udp_port, private_key_path, stop_event):
        import socket
        import struct
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA
        from helpers import decrypt_data

        PACKET_ID_KEY = 0x270F # Anahtar paketi ID'si
        PACKET_ID_DATA = 0x2710 # Veri paketi ID'si
        HEADER_FORMAT = "!HBI" # Başlık formatı
        HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # Başlık boyutu
        
        fragments = {} # Parçaları saklamak için sözlük
        aes_key = None # AES anahtarı
        file_transfer_complete = threading.Event() # Dosya transferi tamamlanma olayı

        def log_callback(msg):
            self.master.after(0, self.log_message, self.receiver_log, msg) # Log mesajı geri çağırma

        def load_private_key():
            try:
                with open(private_key_path, "rb") as f:
                    private_key = RSA.import_key(f.read()) # Özel anahtarı yükler
                log_callback(f"[*] RSA özel anahtarı '{private_key_path}' yükleniyor...")
                return PKCS1_OAEP.new(private_key) # RSA şifreleyici oluşturur
            except Exception as e:
                log_callback(f"[!] Özel anahtar yükleme hatası: {e}")
                return None

        rsa_cipher = load_private_key() # RSA şifreleyiciyi yükler
        if not rsa_cipher:
            log_callback("[!] Hata: RSA şifresi yüklenemedi. Dinleme başlatılamıyor.")
            self.master.after(0, lambda: self.receive_button.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.stop_receive_button.config(state=tk.DISABLED))
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP soketi oluşturur
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Portu yeniden kullanmaya izin verir
        
        try:
            sock.bind(("", udp_port)) # Portu bağlar
            log_callback(f"[*] UDP port {udp_port} dinleniyor... (Veri bekleniyor)")

            while not file_transfer_complete.is_set() and not stop_event.is_set():
                sock.settimeout(1.0) # Zaman aşımı ayarlar

                try:
                    data, addr = sock.recvfrom(65536) # Veri alır
                    log_callback(f"[*] Alınan veri (Toplam {len(data)} bayt) from {addr[0]}:{addr[1]}")

                except socket.timeout:
                    if file_transfer_complete.is_set() or stop_event.is_set():
                        break
                    continue

                if len(data) < HEADER_SIZE:
                    log_callback(f"[!] Alınan paket çok kısa ({len(data)} bayt < {HEADER_SIZE} beklenen header boyutu). Atlandı.")
                    continue

                header_bytes = data[:HEADER_SIZE] # Başlık baytları
                payload = data[HEADER_SIZE:] # Veri yükü

                try:
                    packet_type, fragment_flag, offset = struct.unpack(HEADER_FORMAT, header_bytes) # Başlığı açar
                    log_callback(f"  Unpacked Header: Type={hex(packet_type)}, Flag={fragment_flag}, Offset={offset}")
                except struct.error as se:
                    log_callback(f"[!] Paket başlığı çözme hatası: {se}. Header: {header_bytes.hex()}. Paket atlandı.")
                    continue

                if packet_type == PACKET_ID_KEY: # Anahtar paketi ise
                    if not aes_key:
                        log_callback(f"[*] AES anahtar paketi alındı from {addr[0]}:{addr[1]}.")
                        try:
                            aes_key = rsa_cipher.decrypt(payload) # AES anahtarını RSA ile çözer
                            log_callback("[✓] AES anahtarı başarıyla çözüldü.")
                        except Exception as e:
                            log_callback(f"[!] Anahtar çözme hatası: {e}")
                            aes_key = None
                    else:
                        log_callback("[*] Zaten AES anahtarı mevcut. Yeni anahtar paketi atlandı.")

                elif packet_type == PACKET_ID_DATA: # Veri paketi ise
                    if not aes_key:
                        log_callback("[!] Veri paketi alındı ancak AES anahtarı henüz yok. Paket atlandı.")
                        continue
                    
                    fragments[offset] = payload # Parçayı ofsete göre kaydeder
                    log_callback(f"[+] Parça alındı - Offset: {offset} - Boyut: {len(payload)}")

                    if fragment_flag == 1: # Son parça ise
                        log_callback("[*] Son parça alındı. Dosya transferi tamamlandı.")
                        file_transfer_complete.set() # Dosya tamamlanma olayını ayarlar

                else:
                    log_callback(f"[!] Bilinmeyen paket tipi: {hex(packet_type)}. Paket atlandı.")

            log_callback("\n[*] Dinleme döngüsü sona erdi.")

            if aes_key and fragments and file_transfer_complete.is_set(): # Tüm parçalar ve anahtar alındıysa
                log_callback("[*] AES anahtarı ve tüm dosya parçaları başarıyla alındı.")
                self.master.after(0, self._reassemble_and_save, aes_key, fragments) # Birleştir ve kaydet
            else:
                if stop_event.is_set():
                    log_callback("[!] Dinleme işlemi kullanıcı isteğiyle durduruldu.")
                else:
                    log_callback("[!] Dinleme tamamlandı ancak gerekli tüm paketler alınamadı veya dosya transferi eksik.")
                    if not aes_key: log_callback("[!] AES anahtarı alınamadı.")
                    if not fragments: log_callback("[!] Hiç veri parçası alınamadı.")
                    if not file_transfer_complete.is_set(): log_callback("[!] Son parça alınamadı.")

        except OSError as oe:
            log_callback(f"[!] Hata: Port {udp_port} kullanılıyor veya erişilemiyor: {oe}")
            self.master.after(0, lambda: messagebox.showerror("Hata", f"Port {udp_port} kullanılıyor veya erişilemiyor: {oe}"))
        except Exception as e:
            log_callback(f"[!] Dinleme başlatılırken veya çalışırken beklenmedik hata: {e}")
            self.master.after(0, lambda: messagebox.showerror("Hata", f"Dinleme başlatılırken veya çalışırken beklenmedik hata: {e}"))
        finally:
            if sock:
                sock.close() # Soketi kapatır
                log_callback("[*] Soket kapatıldı.")
            self.master.after(0, lambda: self.receive_button.config(state=tk.NORMAL)) # Butonları tekrar etkinleştirir
            self.master.after(0, lambda: self.stop_receive_button.config(state=tk.DISABLED))


    def _reassemble_and_save(self, aes_key, fragment_buffer):
        log_callback = lambda msg: self.master.after(0, self.log_message, self.receiver_log, msg)
        log_callback("[*] Parçalar birleştiriliyor...")
        try:
            sorted_fragments = sorted(fragment_buffer.items()) # Parçaları sıralar
            full_encrypted_data = b''.join(data for offset, data in sorted_fragments) # Tüm parçaları birleştirir
            log_callback(f"[*] Birleştirilmiş şifreli veri boyutu: {len(full_encrypted_data)} bayt.")

            decrypted_data = decrypt_data(full_encrypted_data, aes_key) # Verinin şifresini çözer
            log_callback("[✓] Verinin şifresi başarıyla çözüldü.")
            
            output_filename = filedialog.asksaveasfilename(
                title="Alınan dosyayı kaydet",
                defaultextension=".txt",
                filetypes=[("All Files", "*.*")]
            ) # Kaydetme iletişim kutusu açar
            if output_filename:
                with open(output_filename, "wb") as f:
                    f.write(decrypted_data) # Dosyayı yazar
                log_callback(f"[✓] Dosya başarıyla '{output_filename}' olarak kaydedildi.")
            else:
                log_callback("[!] Dosya kaydetme işlemi kullanıcı tarafından iptal edildi.")

        except Exception as e:
            log_callback(f"[!] Şifre çözme veya dosya kaydetme hatası: {e}")
            self.master.after(0, lambda: messagebox.showerror("Hata", f"Şifre çözme veya dosya kaydetme hatası: {e}"))

    def on_closing(self):
        if self._receiver_thread and self._receiver_thread.is_alive():
            self.log_message(self.receiver_log, "[*] Uygulama kapatılıyor. Dinleme durduruluyor...")
            self._receiver_stop_event.set() # Durdurma olayını ayarlar
            self._receiver_thread.join(timeout=1.0) # İş parçacığının bitmesini bekler
        self.master.destroy() # Ana pencereyi kapatır


if __name__ == "__main__":
    root = tk.Tk() # Tkinter ana penceresi oluşturur
    app = SecureFileTransferApp(root) # Uygulama örneği oluşturur
    root.mainloop() # Tkinter olay döngüsünü başlatır
