import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal
import hmac
import hashlib
import time
import requests
import urllib.parse  # URL encoding için gerekli


# İmza oluşturma fonksiyonu
def create_signature(api_secret, query_string):
    return hmac.new(
        bytes(api_secret, 'utf-8'),
        bytes(query_string, 'utf-8'),
        hashlib.sha256
    ).hexdigest()


# Çekim işlemi fonksiyonu
def withdraw_usdt_mexc(api_key, api_secret, coin, address, amount, network=None, memo=None):
    url = "https://api.mexc.com/api/v3/capital/withdraw/apply"

    # Sunucu zamanını al
    response = requests.get("https://api.mexc.com/api/v3/time")
    server_time = response.json().get("serverTime", 0)

    # Parametreleri hazırla
    params = {
        "address": address,
        "amount": str(amount),
        "coin": coin,
        "network": network,
        "timestamp": server_time,
    }

    if memo:
        params["memo"] = memo

    # Parametreleri alfabetik sıraya göre sırala ve query string oluştur
    sorted_params = sorted(params.items())
    query_string = "&".join([f"{key}={urllib.parse.quote(str(value))}" for key, value in sorted_params])

    # İmza oluştur ve ekle
    signature = create_signature(api_secret, query_string)
    query_string += f"&signature={signature}"

    # Header bilgileri
    headers = {
        "X-MEXC-APIKEY": api_key,
        "Content-Type": "application/json"
    }

    # Tam URL'yi oluştur ve POST isteğini gönder
    full_url = f"{url}?{query_string}"

    try:
        response = requests.post(full_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP Hatası: {response.status_code} - {response.reason}", "details": response.text}
    except Exception as e:
        return {"error": f"Hata: API'den yanıt alınamadı - {str(e)}"}


# PyQt5 uygulaması
class WithdrawApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("MEXC Withdraw")
        self.setGeometry(200, 200, 600, 600)

        layout = QVBoxLayout()

        # API Bilgileri
        self.api_key_input = QLineEdit()
        self.api_secret_input = QLineEdit()
        self.api_secret_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("API Key:"))
        layout.addWidget(self.api_key_input)
        layout.addWidget(QLabel("API Secret:"))
        layout.addWidget(self.api_secret_input)

        # Transfer Bilgileri
        self.coin_input = QLineEdit()
        self.coin_input.setPlaceholderText("Örneğin: USDT")
        self.address_input = QLineEdit()
        self.amount_input = QLineEdit()
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("Örneğin: Tron(TRC20)")
        self.memo_input = QLineEdit()
        self.memo_input.setPlaceholderText("Memo (Opsiyonel)")

        layout.addWidget(QLabel("Coin:"))
        layout.addWidget(self.coin_input)
        layout.addWidget(QLabel("Cüzdan Adresi:"))
        layout.addWidget(self.address_input)
        layout.addWidget(QLabel("Tutar:"))
        layout.addWidget(self.amount_input)
        layout.addWidget(QLabel("Ağ:"))
        layout.addWidget(self.network_input)
        layout.addWidget(QLabel("Memo (Opsiyonel):"))
        layout.addWidget(self.memo_input)

        # Konsol Çıktısı
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        layout.addWidget(QLabel("Sonuç:"))
        layout.addWidget(self.console_output)

        # Butonlar
        withdraw_button = QPushButton("Çekim Yap")
        withdraw_button.clicked.connect(self.execute_withdraw)
        layout.addWidget(withdraw_button)

        auto_withdraw_button = QPushButton("TXT'den Otomatik Çekim Yap")
        auto_withdraw_button.clicked.connect(self.execute_withdraw_from_file)
        layout.addWidget(auto_withdraw_button)

        self.setLayout(layout)

    def log_to_console(self, message):
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]", time.localtime())
        self.console_output.append(f"{timestamp} {message}")

    def execute_withdraw(self):
        api_key = self.api_key_input.text().strip()
        api_secret = self.api_secret_input.text().strip()
        coin = self.coin_input.text().strip()
        address = self.address_input.text().strip()
        amount = self.amount_input.text().strip()
        network = self.network_input.text().strip()
        memo = self.memo_input.text().strip()

        if not api_key or not api_secret or not coin or not address or not amount:
            self.log_to_console("Hata: Lütfen tüm alanları doldurun!")
            return

        try:
            amount = float(amount)
            if amount <= 0:
                self.log_to_console("Hata: Tutar sıfırdan büyük olmalıdır!")
                return

            self.log_to_console(f"Gönderilen Parametreler: coin={coin}, address={address}, amount={amount}, network={network}, memo={memo}")
            result = withdraw_usdt_mexc(api_key, api_secret, coin, address, amount, network, memo)
            if "error" in result:
                self.log_to_console(f"{result['error']} - Detay: {result.get('details', '')}")
            else:
                self.log_to_console(f"Başarılı! Çekim ID: {result.get('id', 'ID alınamadı')}")
        except ValueError:
            self.log_to_console("Hata: Tutar geçerli bir sayı olmalı!")
        except Exception as e:
            self.log_to_console(f"Hata: {str(e)}")

    def execute_withdraw_from_file(self):
        try:
            with open("withdraw_requests.txt", "r", encoding="utf-8") as file:
                lines = file.readlines()

            threads = []
            for line in lines:
                parts = line.strip().split(",")
                if len(parts) < 5:
                    self.log_to_console("Hata: Dosyada eksik bilgi var.")
                    continue

                api_key, api_secret, coin, amount, network, *rest = parts
                address = rest[0] if len(rest) > 0 else ""
                memo = rest[1] if len(rest) > 1 else None

                # Thread başlatma
                thread = WithdrawThread(self, api_key, api_secret, coin, address, amount, network, memo)
                thread.result_signal.connect(self.log_to_console)  # Sonuçları GUI'ye gönder
                thread.start()
                threads.append(thread)

            # Tüm thread'lerin bitmesini bekle
            for thread in threads:
                thread.wait()

        except FileNotFoundError:
            self.log_to_console("Hata: withdraw_requests.txt dosyası bulunamadı.")
        except Exception as e:
            self.log_to_console(f"Hata: {str(e)}")


# Thread sınıfı
class WithdrawThread(QThread):
    result_signal = pyqtSignal(str)  # GUI'ye sonuç gönderecek sinyal

    def __init__(self, parent, api_key, api_secret, coin, address, amount, network, memo):
        super().__init__(parent)
        self.api_key = api_key
        self.api_secret = api_secret
        self.coin = coin
        self.address = address
        self.amount = amount
        self.network = network
        self.memo = memo

    def run(self):
        try:
            result = withdraw_usdt_mexc(self.api_key, self.api_secret, self.coin, self.address, self.amount, self.network, self.memo)
            self.result_signal.emit(str(result))  # Sonuçları GUI'ye ilet
        except Exception as e:
            self.result_signal.emit(f"Hata: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WithdrawApp()
    window.show()
    sys.exit(app.exec_())
