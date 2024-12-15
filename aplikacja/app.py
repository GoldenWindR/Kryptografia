import os,math
import sys
import cv2
import numpy as np
import threading
import base64
import logging
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QFileDialog, QMessageBox, QSpinBox, QDialog, QDialogButtonBox,QScrollArea,  QGraphicsView, QGraphicsScene, 
    QGraphicsEllipseItem, QGraphicsTextItem, QGraphicsLineItem,QGraphicsTextItem, QGraphicsPolygonItem
)
from PySide6.QtGui import QImage, QPixmap,QFont, QFontMetrics, QColor, QPen,QBrush, QPolygonF
from PySide6.QtCore import QRectF, Qt , QPointF
from Crypto.Random import get_random_bytes
import skrypty.encryptor1 as caesar_cipher
import skrypty.encryptor2 as transposition_cipher
import skrypty.encryptor3 as cbc_cipher
import skrypty.encryptor4 as cfb_cipher
import skrypty.encryptor5 as rsa
import skrypty.encryptor6 as cer_uml
import skrypty.encryptor7 as pen
import skrypty.encryptor8 as hmac
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Szyfrowanie i Odszyfrowywanie")
        self.setMinimumSize(800, 600)  # Ustaw minimalny rozmiar na 800x600 pikseli
        self.resize(1024, 768)  # Ustaw początkowy rozmiar okna na 1024x768 pikseli


        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.add_encryptor_tab("Szyfrowanie Cezara", caesar_cipher, needs_key=False)
        self.add_encryptor_tab("Transpozycyjne", transposition_cipher, needs_key=False, supports_files=True)
        self.add_encryptor_tab("CBC", cbc_cipher, needs_key=True, supports_files=True)
        self.add_cfb_encryptor_tab("CFB", cfb_cipher)
        self.add_rsa_tab()
        self.add_certificate_uml_tab()
        self.add_digital_signature_tab()
        self.add_hmac_tab()


        self.running = False

    def add_encryptor_tab(self, name, skrypt, needs_key, supports_files=False):
        tab_widget = QTabWidget()

        szyfruj_tab = QWidget()
        szyfruj_layout = QVBoxLayout()
        szyfruj_input = QTextEdit()
        szyfruj_output = QTextEdit()
        szyfruj_button = QPushButton("Szyfruj")
        szyfruj_layout.addWidget(QLabel("Tekst do zaszyfrowania:"))
        szyfruj_layout.addWidget(szyfruj_input)

        if not needs_key:
            szyfruj_button.setEnabled(True)
        else:
            szyfruj_button.setEnabled(False)

        if needs_key:
            szyfruj_key = QLineEdit()
            szyfruj_layout.addWidget(QLabel("Klucz:"))
            szyfruj_layout.addWidget(szyfruj_key)
            szyfruj_key.textChanged.connect(lambda: szyfruj_button.setEnabled(bool(szyfruj_key.text().strip())))
        else:
            szyfruj_key = None

        szyfruj_layout.addWidget(QLabel("Zaszyfrowany tekst:"))
        szyfruj_layout.addWidget(szyfruj_output)
        szyfruj_button.clicked.connect(lambda: self.encrypt_text(szyfruj_input, szyfruj_output, skrypt, szyfruj_key))
        szyfruj_layout.addWidget(szyfruj_button)

        if supports_files:
            szyfruj_file_button = QPushButton("Szyfruj Plik")
            szyfruj_file_button.setEnabled(False)
            if szyfruj_key:
                szyfruj_key.textChanged.connect(lambda: szyfruj_file_button.setEnabled(bool(szyfruj_key.text().strip())))
            szyfruj_file_button.clicked.connect(lambda: self.encrypt_file(skrypt, szyfruj_key))
            szyfruj_layout.addWidget(szyfruj_file_button)

        szyfruj_tab.setLayout(szyfruj_layout)
        tab_widget.addTab(szyfruj_tab, "Szyfruj")

        odszyfruj_tab = QWidget()
        odszyfruj_layout = QVBoxLayout()
        odszyfruj_input = QTextEdit()
        odszyfruj_output = QTextEdit()
        odszyfruj_button = QPushButton("Odszyfruj")
        odszyfruj_layout.addWidget(QLabel("Tekst do odszyfrowania:"))
        odszyfruj_layout.addWidget(odszyfruj_input)

        if not needs_key:
            odszyfruj_button.setEnabled(True)
        else:
            odszyfruj_button.setEnabled(False)

        if needs_key:
            odszyfruj_key = QLineEdit()
            odszyfruj_layout.addWidget(QLabel("Klucz:"))
            odszyfruj_layout.addWidget(odszyfruj_key)
            odszyfruj_key.textChanged.connect(lambda: odszyfruj_button.setEnabled(bool(odszyfruj_key.text().strip())))
        else:
            odszyfruj_key = None

        odszyfruj_layout.addWidget(QLabel("Odszyfrowany tekst:"))
        odszyfruj_layout.addWidget(odszyfruj_output)
        odszyfruj_button.clicked.connect(lambda: self.decrypt_text(odszyfruj_input, odszyfruj_output, skrypt, odszyfruj_key))
        odszyfruj_layout.addWidget(odszyfruj_button)

        if supports_files:
            odszyfruj_file_button = QPushButton("Odszyfruj Plik")
            odszyfruj_file_button.setEnabled(False)
            if odszyfruj_key:
                odszyfruj_key.textChanged.connect(lambda: odszyfruj_file_button.setEnabled(bool(odszyfruj_key.text().strip())))
            odszyfruj_file_button.clicked.connect(lambda: self.decrypt_file(skrypt, odszyfruj_key))
            odszyfruj_layout.addWidget(odszyfruj_file_button)

        odszyfruj_tab.setLayout(odszyfruj_layout)
        tab_widget.addTab(odszyfruj_tab, "Odszyfruj")

        self.tabs.addTab(tab_widget, name)


    def encrypt_text(self, input_field, output_field, skrypt, key_field=None):
        try:
            message = input_field.toPlainText()
            if key_field:
                key = key_field.text().strip()
                if not key:
                    self.show_warning("Błąd", "Wprowadź klucz, aby zaszyfrować wiadomość.")
                    return
                encrypted_message = skrypt.encrypt(message, key)
            else:
                encrypted_message = skrypt.encrypt(message)
            output_field.setPlainText(encrypted_message)
        except Exception as e:
            self.show_warning("Błąd", f"Nie udało się zaszyfrować wiadomości: {e}")

    def decrypt_text(self, input_field, output_field, skrypt, key_field=None):
        try:
            encrypted_message = input_field.toPlainText()
            if key_field:
                key = key_field.text().strip()
                if not key:
                    self.show_warning("Błąd", "Wprowadź klucz, aby odszyfrować wiadomość.")
                    return
                decrypted_message = skrypt.decrypt(encrypted_message, key)
            else:
                decrypted_message = skrypt.decrypt(encrypted_message)
            output_field.setPlainText(decrypted_message)
        except Exception as e:
            self.show_warning("Błąd", f"Nie udało się odszyfrować wiadomości: {e}")

    def encrypt_file(self, skrypt, key_field):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik do zaszyfrowania")
            if not file_path:
                return
            key = key_field.text() if key_field else None
            output_dir = "Zaszyfrowane"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_path = os.path.join(output_dir, os.path.basename(file_path))
            skrypt.encrypt_file(file_path, output_path, key) if key else skrypt.encrypt_file(file_path, output_path)
            QMessageBox.information(self, "Sukces", f"Plik został zaszyfrowany i zapisany w {output_path}.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd szyfrowania pliku: {e}")

    def decrypt_file(self, skrypt, key_field):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik do odszyfrowania")
            if not file_path:
                return
            key = key_field.text() if key_field else None
            output_dir = "Odszyfrowane"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_path = os.path.join(output_dir, os.path.basename(file_path))
            skrypt.decrypt_file(file_path, output_path, key) if key else skrypt.decrypt_file(file_path, output_path)
            QMessageBox.information(self, "Sukces", f"Plik został odszyfrowany i zapisany w {output_path}.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd odszyfrowania pliku: {e}")


    def add_cfb_encryptor_tab(self, name, skrypt):
        tab_widget = QTabWidget()

        text_tab = QWidget()
        text_layout = QVBoxLayout()

        key_layout = QHBoxLayout()
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Wprowadź klucz (16, 24, lub 32 bajty)")
        key_layout.addWidget(self.key_input)

        generate_16_button = QPushButton("Generuj 16 bajtów")
        generate_16_button.clicked.connect(lambda: self.key_input.setText(get_random_bytes(16).hex()))
        key_layout.addWidget(generate_16_button)

        generate_24_button = QPushButton("Generuj 24 bajty")
        generate_24_button.clicked.connect(lambda: self.key_input.setText(get_random_bytes(24).hex()))
        key_layout.addWidget(generate_24_button)

        generate_32_button = QPushButton("Generuj 32 bajty")
        generate_32_button.clicked.connect(lambda: self.key_input.setText(get_random_bytes(32).hex()))
        key_layout.addWidget(generate_32_button)

        text_layout.addLayout(key_layout)

        input_text = QTextEdit()

        encrypted_text = QTextEdit()

        decrypted_text = QTextEdit()

        encrypted_text.setReadOnly(True)
        decrypted_text.setReadOnly(True)

        input_text.textChanged.connect(lambda: self.live_encrypt_decrypt(input_text, encrypted_text, decrypted_text, skrypt, self.key_input))

        text_layout.addWidget(QLabel("Tekst:"))
        text_layout.addWidget(input_text)
        text_layout.addWidget(QLabel("Zaszyfrowany tekst:"))
        text_layout.addWidget(encrypted_text)
        text_layout.addWidget(QLabel("Odszyfrowany tekst:"))
        text_layout.addWidget(decrypted_text)

        text_tab.setLayout(text_layout)
        tab_widget.addTab(text_tab, "Tekst")

        webcam_tab = QWidget()
        webcam_layout = QVBoxLayout()

        self.original_video_label = QLabel()
        self.decrypted_video_label = QLabel()

        webcam_layout.addWidget(QLabel("Oryginalny obraz z kamery:"))
        webcam_layout.addWidget(self.original_video_label)
        webcam_layout.addWidget(QLabel("Odszyfrowany obraz:"))
        webcam_layout.addWidget(self.decrypted_video_label)

        self.start_button = QPushButton("Uruchom kamerę")
        self.stop_button = QPushButton("Zatrzymaj kamerę")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_webcam)
        self.stop_button.clicked.connect(self.stop_webcam)
        
        webcam_layout.addWidget(self.start_button)
        webcam_layout.addWidget(self.stop_button)
        webcam_tab.setLayout(webcam_layout)

        tab_widget.addTab(webcam_tab, "Kamerka")

        self.tabs.addTab(tab_widget, name)

    def start_webcam(self):
        if not self.key_input.text().strip():
            self.show_warning("Brak klucza", "Wprowadź klucz, aby rozpocząć szyfrowanie wideo.")
            return

        self.running = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.thread = threading.Thread(target=self.capture_webcam)
        self.thread.start()

    def stop_webcam(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def capture_webcam(self):
        logging.debug("Rozpoczęcie przechwytywania obrazu z kamery.")
        try:
            cap = cv2.VideoCapture(0)
            app_width = self.size().width()
            app_height = self.size().height()
            scaled_width = int(app_width * 0.1)  
            scaled_height = int(app_height * 0.1) 
            
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, scaled_width)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, scaled_height)
            key = self.key_input.text().strip()
            if len(bytes.fromhex(key)) not in (16, 24, 32):
                self.show_warning("Invalid Key", "Key must be 16, 24, or 32 bytes long.")
                self.stop_webcam()
                return

            while self.running:
                ret, frame = cap.read()
                if not ret:
                    logging.error("Błąd podczas przechwytywania obrazu z kamery.")
                    break
                self.display_frame(self.original_video_label, frame)
                success, buffer = cv2.imencode('.jpg', frame)
                if not success:
                    logging.error("Błąd podczas kodowania obrazu.")
                    continue
                frame_bytes = buffer.tobytes()
                encrypted_base64 = cfb_cipher.encrypt(frame_bytes, bytes.fromhex(key))
                decrypted_bytes = cfb_cipher.decrypt(encrypted_base64, bytes.fromhex(key))
                print(encrypted_base64)
                decrypted_frame = cv2.imdecode(np.frombuffer(decrypted_bytes, np.uint8), cv2.IMREAD_COLOR)

                if decrypted_frame is not None:
                    self.display_frame(self.decrypted_video_label, decrypted_frame)
                else:
                    logging.warning("Nie udało się odszyfrować obrazu.")

        except Exception as e:
            logging.exception("Wystąpił nieoczekiwany błąd: %s", e)
        finally:
            cap.release()
            cv2.destroyAllWindows()
            logging.debug("Zakończenie przechwytywania obrazu z kamery.")


    def display_frame(self, label, frame):
        if frame is None or frame.size == 0:
            return  

        try:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        except cv2.error as e:
            print(f"Błąd konwersji obrazu: {e}")
            return  

        if len(frame.shape) < 3 or frame.shape[2] != 3:
            return  

        image = QImage(frame.data, frame.shape[1], frame.shape[0], QImage.Format_RGB888)
        pixmap = QPixmap.fromImage(image)
        label.setPixmap(pixmap)

    def live_encrypt_decrypt(self, input_field, encrypted_field, decrypted_field, skrypt, key_field):
        try:
            text = input_field.toPlainText()
            key = key_field.text().strip()
            if not key:
                encrypted_field.setPlainText("Wprowadź klucz, aby rozpocząć szyfrowanie.")
                decrypted_field.setPlainText("")
                return
            if len(bytes.fromhex(key)) not in (16, 24, 32):
                encrypted_field.setPlainText("Klucz musi mieć długość 16, 24 lub 32 bajtów.")
                decrypted_field.setPlainText("")
                return
            encrypted_text = skrypt.encrypt(text, bytes.fromhex(key))
            decrypted_text = skrypt.decrypt(encrypted_text, bytes.fromhex(key))
            encrypted_field.setPlainText(str(encrypted_text))
            decrypted_field.setPlainText(str(decrypted_text.decode('utf-8')))
        except Exception as e:
            encrypted_field.setPlainText(f"Błąd: {e}")
            decrypted_field.setPlainText("")

    def add_rsa_tab(self):
        self.public_key = None
        self.shared_key = None

        rsa_tab = QTabWidget()

        encrypt_tab = QWidget()
        encrypt_layout = QVBoxLayout()

        self.text_input_encrypt = QTextEdit()
        encrypt_layout.addWidget(QLabel("Tekst do zaszyfrowania:"))
        encrypt_layout.addWidget(self.text_input_encrypt)

        self.encrypt_button = QPushButton("Szyfruj tekst")
        self.encrypt_button.clicked.connect(self.encrypt_text_rsa)
        encrypt_layout.addWidget(self.encrypt_button)


        self.encrypt_file_button = QPushButton("Szyfruj Plik")
        self.encrypt_file_button.clicked.connect(self.encrypt_file_rsa)
        encrypt_layout.addWidget(self.encrypt_file_button)

        self.encrypted_text = QTextEdit()
        self.encrypted_text.setReadOnly(True)
        encrypt_layout.addWidget(QLabel("Zaszyfrowany tekst:"))
        encrypt_layout.addWidget(self.encrypted_text)

        encrypt_tab.setLayout(encrypt_layout)
        rsa_tab.addTab(encrypt_tab, "Szyfruj")

        decrypt_tab = QWidget()
        decrypt_layout = QVBoxLayout()

        self.text_input_decrypt = QTextEdit()
        decrypt_layout.addWidget(QLabel("Zaszyfrowany tekst (w formacie numerycznym):"))
        decrypt_layout.addWidget(self.text_input_decrypt)

        self.private_key_input = QLineEdit()
        decrypt_layout.addWidget(QLabel("Wpisz zaszyfrowany klucz prywatny RSA:"))
        decrypt_layout.addWidget(self.private_key_input)

        self.decrypt_button = QPushButton("Odszyfruj tekst")
        self.decrypt_button.clicked.connect(self.decrypt_text_rsa)
        decrypt_layout.addWidget(self.decrypt_button)


        self.decrypt_file_button = QPushButton("Odszyfruj Plik")
        self.decrypt_file_button.clicked.connect(self.decrypt_file_rsa)
        decrypt_layout.addWidget(self.decrypt_file_button)

        self.decrypted_text = QTextEdit()
        self.decrypted_text.setReadOnly(True)
        decrypt_layout.addWidget(QLabel("Odszyfrowany tekst:"))
        decrypt_layout.addWidget(self.decrypted_text)

        decrypt_tab.setLayout(decrypt_layout)
        rsa_tab.addTab(decrypt_tab, "Odszyfruj")

        key_tab = QWidget()
        key_layout = QVBoxLayout()

        
        self.p_input = QLineEdit()
        p_layout = QHBoxLayout()
        p_layout.addWidget(QLabel("Liczba pierwsza p:"))
        p_layout.addWidget(self.p_input)
        p_generate_button = QPushButton("Losuj")
        p_generate_button.clicked.connect(lambda: self.generate_prime_number(self.p_input))
        p_layout.addWidget(p_generate_button)
        key_layout.addLayout(p_layout)

        self.q_input = QLineEdit()
        q_layout = QHBoxLayout()
        q_layout.addWidget(QLabel("Liczba pierwsza q:"))
        q_layout.addWidget(self.q_input)
        q_generate_button = QPushButton("Losuj")
        q_generate_button.clicked.connect(lambda: self.generate_prime_number(self.q_input))
        q_layout.addWidget(q_generate_button)
        key_layout.addLayout(q_layout)

        generate_keys_button = QPushButton("Generuj klucze RSA")
        generate_keys_button.clicked.connect(self.generate_and_save_rsa_keys)
        key_layout.addWidget(generate_keys_button)

        key_tab.setLayout(key_layout)
        rsa_tab.addTab(key_tab, "Klucz RSA")
        dh_tab = QWidget()
        dh_layout = QVBoxLayout()

        self.p_dh_input = QLineEdit()
        p_dh_layout = QHBoxLayout()
        p_dh_layout.addWidget(QLabel("Liczba pierwsza p:"))
        p_dh_layout.addWidget(self.p_dh_input)
        p_dh_generate_button = QPushButton("Losuj")
        p_dh_generate_button.clicked.connect(lambda: self.generate_prime_number(self.p_dh_input))
        p_dh_layout.addWidget(p_dh_generate_button)
        dh_layout.addLayout(p_dh_layout)

        self.g_dh_input = QLineEdit()
        g_dh_layout = QHBoxLayout()
        g_dh_layout.addWidget(QLabel("Generator g:"))
        g_dh_layout.addWidget(self.g_dh_input)
        g_dh_generate_button = QPushButton("Losuj")
        g_dh_generate_button.clicked.connect(lambda: self.generate_prime_number(self.g_dh_input))
        g_dh_layout.addWidget(g_dh_generate_button)
        dh_layout.addLayout(g_dh_layout)

        compute_shared_key_button = QPushButton("Oblicz wspólny klucz DH")
        compute_shared_key_button.clicked.connect(self.compute_shared_key)
        dh_layout.addWidget(compute_shared_key_button)

        dh_tab.setLayout(dh_layout)

        rsa_tab.addTab(dh_tab, "Klucz DH")

        self.tabs.addTab(rsa_tab, "RSA")



    def encrypt_text_rsa(self):
        if not self.public_key:
            QMessageBox.warning(self, "Błąd", "Najpierw wygeneruj klucze RSA!")
            return
        plain_text = self.text_input_encrypt.toPlainText()
        encrypted_data = rsa.encrypt_rsa(plain_text, self.public_key)
        self.encrypted_text.setPlainText(' '.join(map(str, encrypted_data)))

    def decrypt_text_rsa(self):
        encrypted_key = self.private_key_input.text()
        if not self.shared_key:
            QMessageBox.warning(self, "Błąd", "Najpierw uzgodnij wspólny klucz DH!")
            return
        try:
            private_key = int(encrypted_key) ^ self.shared_key
            encrypted_data = list(map(int, self.text_input_decrypt.toPlainText().split()))
            n = self.public_key[1]
            decrypted_text = ''.join([chr(pow(char, private_key, n)) for char in encrypted_data])
            self.decrypted_text.setPlainText(decrypted_text)
        except OverflowError:
            QMessageBox.warning(self, "Błąd", "Liczba jest zbyt duża, aby mogła być obsłużona.")
        except Exception as e:
            QMessageBox.warning(self, "Błąd", f"Błąd odszyfrowywania: {str(e)}")



    def compute_shared_key(self):
        try:
            p = int(self.p_dh_input.text())
            g = int(self.g_dh_input.text())
            private_key, public_key = rsa.generate_dh_keys(p, g)
            self.shared_key = rsa.compute_shared_key(public_key, private_key, p)
            QMessageBox.information(self, "Wspólny klucz DH", f"Wspólny klucz: {self.shared_key}")
        except ValueError:
            QMessageBox.warning(self, "Błąd", "Wprowadź poprawne liczby pierwsze p i g.")

    def generate_prime_number(self, input_field):
        dialog = QDialog(self)
        dialog.setWindowTitle("Wybierz liczbę bitów")
        dialog_layout = QVBoxLayout()
        bits_input = QSpinBox()
        bits_input.setRange(2, 4096)
        bits_input.setValue(32)
        dialog_layout.addWidget(QLabel("Liczba bitów:"))
        dialog_layout.addWidget(bits_input)
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(lambda: self.on_prime_number_generated(bits_input.value(), input_field, dialog))
        button_box.rejected.connect(dialog.reject)
        dialog_layout.addWidget(button_box)
        dialog.setLayout(dialog_layout)
        dialog.exec()

    def on_prime_number_generated(self, bits, input_field, dialog):
        prime_number = rsa.generate_prime(bits)
        input_field.setText(str(prime_number))
        dialog.accept()

    def generate_and_save_rsa_keys(self):
        try:
            p = int(self.p_input.text())
            q = int(self.q_input.text())
            self.public_key, private_key = rsa.generate_rsa_keys(p, q)
            QMessageBox.information(self, "Klucz publiczny", f"Klucz publiczny: {self.public_key}")
            if not self.shared_key:
                QMessageBox.warning(self, "Błąd", "Najpierw uzgodnij wspólny klucz DH!")
                return
            encrypted_private_key = private_key[0] ^ self.shared_key  
            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getSaveFileName(self, "Zapisz klucz prywatny", "", "Pliki tekstowe (*.txt)", options=options)
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(str(encrypted_private_key))
                QMessageBox.information(self, "Sukces", "Klucz prywatny został zaszyfrowany i zapisany!")
        except Exception as e:
            QMessageBox.warning(self, "Błąd", f"Błąd generowania kluczy: {str(e)}")

    def encrypt_file_rsa(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik do zaszyfrowania")
            if not file_path:
                return
            key = self.public_key if self.public_key else None
            output_dir = "Zaszyfrowane"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_path = os.path.join(output_dir, os.path.basename(file_path))
            rsa.encrypt_file(file_path, output_path, key) if key else rsa.encrypt_file(file_path, output_path)
            QMessageBox.information(self, "Sukces", f"Plik został zaszyfrowany i zapisany w {output_path}.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd szyfrowania pliku: {e}")

    def decrypt_file_rsa(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik do odszyfrowania")
            if not file_path:
                return
            key = self.private_key_input.text() if self.private_key_input else None
            if not key:
                QMessageBox.warning(self, "Błąd", "Wprowadź klucz prywatny RSA.")
                return
            private_key = (int(key) ^ self.shared_key, self.public_key[1])
            output_dir = "Odszyfrowane"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_path = os.path.join(output_dir, os.path.basename(file_path))
            rsa.decrypt_file(file_path, output_path, private_key)
            QMessageBox.information(self, "Sukces", f"Plik został odszyfrowany i zapisany w {output_path}.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd odszyfrowania pliku: {e}")

    def add_certificate_uml_tab(self):
        certificate_uml_tab = QTabWidget()
        layout = QVBoxLayout()
        layout_help = QHBoxLayout()
        layout_help.setAlignment(Qt.AlignCenter)

        layout_help.addWidget(QLabel("Podaj adres UML strony"))
        self.text_input=QLineEdit()
        layout_help.addWidget(self.text_input)
        layout.addLayout(layout_help)

        self.button = QPushButton("Odczytaj")
        self.button.clicked.connect(self.Dialog_cert_show)
        layout.addWidget(self.button)
        

        certificate_uml_tab.setLayout(layout)
        self.tabs.addTab(certificate_uml_tab,"Certifikaty")



    def Dialog_cert_show(self):
        dialog = QDialog()
        dialog.setWindowTitle("Szczegóły certyfikatu")
        dialog.setMinimumSize(800, 600)
        input_text = self.text_input.text()
        try:
            certificate_details = cer_uml.get_ssl_certificate(input_text)
            cert_chain = cer_uml.get_certificate_chain(input_text)
        except Exception as e:
            certificate_details = f"Błąd pobierania certyfikatu: {e}"
            cert_chain = f"Błąd pobierania łańcucha certyfikatów: {e}"

        main_layout = QVBoxLayout()

        certificate_tab = QTabWidget()

        details_widget = QWidget()
        details_layout = QVBoxLayout()
        if isinstance(certificate_details, dict): 
            subject = ", ".join([entry[0][1] for entry in certificate_details.get('subject', [])])
            issuer = ", ".join([entry[0][1] for entry in certificate_details.get('issuer', [])])
            valid_from = certificate_details.get('notBefore', 'N/A')
            valid_to = certificate_details.get('notAfter', 'N/A')

            details_label = QLabel(
                f"<h3>Szczegóły certyfikatu</h3>"
                f"<p><b>Podmiot:</b> {subject}</p>"
                f"<p><b>Wystawca:</b> {issuer}</p>"
                f"<p><b>Ważny od:</b> {valid_from}</p>"
                f"<p><b>Ważny do:</b> {valid_to}</p>"
            )
        else:
            details_label = QLabel(f"Błąd: {certificate_details}")
        details_label.setWordWrap(True)
        details_layout.addWidget(details_label)
        details_widget.setLayout(details_layout)
        certificate_tab.addTab(details_widget, "Szczegóły")

        diagram_widget = QWidget()
        diagram_layout = QVBoxLayout()

        if isinstance(cert_chain, list): 
            graphics_view = QGraphicsView()
            scene = QGraphicsScene()

           
            spacing_y = 150 
            x, y = 0, 0 
            node_centers = [] 

            for idx, cert in enumerate(cert_chain):
                institution_name = cert['Subject (Nazwa instytucji)']

                font = QFont("Arial", 10)
                metrics = QFontMetrics(font)
                text_width = metrics.horizontalAdvance(institution_name) + 20
                text_height = metrics.height() + 20

                ellipse = QGraphicsEllipseItem(QRectF(x, y, text_width, text_height))
                ellipse.setBrush(QColor("lightblue"))
                ellipse.setPen(QPen(QColor("black"), 2))
                ellipse.setZValue(0)
                scene.addItem(ellipse)

                text_item = QGraphicsTextItem(institution_name)
                text_item.setFont(font)
                text_item.setPos(
                    x + text_width / 2 - metrics.horizontalAdvance(institution_name) / 2,
                    y + text_height / 2 - metrics.height() / 2
                )
                text_item.setZValue(1)
                scene.addItem(text_item)

                node_center = QPointF(x + text_width / 2, y + text_height / 2)
                node_centers.append(node_center)

                if idx > 0:
                    prev_center = node_centers[idx - 1]

                    line = QGraphicsLineItem(prev_center.x(), prev_center.y(), node_center.x(), node_center.y())
                    line.setPen(QPen(QColor("black"), 2))
                    line.setZValue(-1)
                    scene.addItem(line)

                    arrow_size = 10
                    dx = node_center.x() - prev_center.x()
                    dy = node_center.y() - prev_center.y()
                    angle = math.atan2(dy, dx)
                    arrow_tip = QPointF(
                        node_center.x() - arrow_size * math.cos(angle),
                        node_center.y() - arrow_size * math.sin(angle)
                    )
                    arrow_left = QPointF(
                        arrow_tip.x() + arrow_size * math.sin(angle + math.pi / 2),
                        arrow_tip.y() - arrow_size * math.cos(angle + math.pi / 2)
                    )
                    arrow_right = QPointF(
                        arrow_tip.x() + arrow_size * math.sin(angle - math.pi / 2),
                        arrow_tip.y() - arrow_size * math.cos(angle - math.pi / 2)
                    )
                    arrow_polygon = QPolygonF([node_center, arrow_left, arrow_right])
                    arrow_item = QGraphicsPolygonItem(arrow_polygon)
                    arrow_item.setBrush(QBrush(QColor("black")))
                    arrow_item.setZValue(-1)
                    scene.addItem(arrow_item)

                # Przesunięcie pozycji na osi Y dla kolejnego węzła
                y += spacing_y

            graphics_view.setScene(scene)
            diagram_layout.addWidget(graphics_view)
        else:
            diagram_layout.addWidget(QLabel(f"Błąd: {cert_chain}"))

        diagram_widget.setLayout(diagram_layout)
        certificate_tab.addTab(diagram_widget, "Diagram łańcucha")

        main_layout.addWidget(certificate_tab)

        # Przycisk zamknięcia
        close_button = QPushButton("Zamknij")
        close_button.clicked.connect(dialog.close)
        main_layout.addWidget(close_button, alignment=Qt.AlignCenter)

        dialog.setLayout(main_layout)
        dialog.exec()

    def add_digital_signature_tab(self):
        digital_signature_tab = QTabWidget()
        generate_tab = QWidget()
        generate_layout = QVBoxLayout()
        generate_help_layout = QHBoxLayout()
        generate_help_layout.setAlignment(Qt.AlignCenter)  
        generate_help_layout.addWidget(QLabel("Plik do podpisania:"))
        file_to_sign_input = QLineEdit()
        file_to_sign_input.setPlaceholderText("Ścieżka do pliku do podpisania")
        generate_help_layout.addWidget(file_to_sign_input)
        file_select_button = QPushButton("Wybierz plik")
        file_select_button.clicked.connect(
            lambda: file_to_sign_input.setText(QFileDialog.getOpenFileName(self, "Wybierz plik")[0])
        )
        generate_help_layout.addWidget(file_select_button)
        generate_layout.addLayout(generate_help_layout)

        generate_button = QPushButton("Generuj klucze i podpisz plik")
        generate_button.clicked.connect(
            lambda: self.generate_and_sign_file(file_to_sign_input.text())
        )
        generate_layout.addWidget(generate_button)

        generate_tab.setLayout(generate_layout)
        digital_signature_tab.addTab(generate_tab, "Generowanie podpisu")

        verify_tab = QWidget()
        verify_layout = QVBoxLayout()

        verify_help_layout = QHBoxLayout()
        verify_help_layout.setAlignment(Qt.AlignCenter)
        verify_help_layout.addWidget(QLabel("Plik do weryfikacji:"))
        file_to_verify_input = QLineEdit()
        file_to_verify_input.setPlaceholderText("Ścieżka do pliku do weryfikacji")
        verify_help_layout.addWidget(file_to_verify_input)
        verify_file_button = QPushButton("Wybierz plik")
        verify_file_button.clicked.connect(
            lambda: file_to_verify_input.setText(QFileDialog.getOpenFileName(self, "Wybierz plik")[0])
        )
        verify_help_layout.addWidget(verify_file_button)
        verify_layout.addLayout(verify_help_layout)

        signature_help_layout = QHBoxLayout()
        signature_help_layout.setAlignment(Qt.AlignCenter)
        signature_help_layout.addWidget(QLabel("Plik z podpisem:"))
        signature_file_input = QLineEdit()
        signature_file_input.setPlaceholderText("Ścieżka do pliku z podpisem")
        signature_help_layout.addWidget(signature_file_input)
        select_signature_button = QPushButton("Wybierz podpis")
        select_signature_button.clicked.connect(
            lambda: signature_file_input.setText(QFileDialog.getOpenFileName(self, "Wybierz plik z podpisem")[0])
        )
        signature_help_layout.addWidget(select_signature_button)
        verify_layout.addLayout(signature_help_layout)

        verify_button = QPushButton("Weryfikuj podpis")
        verify_button.clicked.connect(
            lambda: self.verify_file_signature(
                file_to_verify_input.text(), signature_file_input.text()
            )
        )
        verify_layout.addWidget(verify_button)

        verify_tab.setLayout(verify_layout)
        digital_signature_tab.addTab(verify_tab, "Weryfikacja podpisu")

        self.tabs.addTab(digital_signature_tab, "Cyfrowe podpisy")


    def generate_and_sign_file(self, file_path):
        if not file_path:
            QMessageBox.warning(self, "Błąd", "Wybierz plik do podpisania.")
            return

        keys_dir = "klucz"
        os.makedirs(keys_dir, exist_ok=True)
        private_key_file = os.path.join(keys_dir, "private_key.pem")
        public_key_file = os.path.join(keys_dir, "public_key.pem")

        try:
            pen.generate_keys(private_key_file, public_key_file)
            signature_file = pen.sign_file(file_path, private_key_file)

            QMessageBox.information(
                self,
                "Sukces",
                f"Klucze wygenerowane, podpis zapisany w '{signature_file}'.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd generowania podpisu: {e}")

    def verify_file_signature(self, file_path, signature_path):
        if not file_path or not signature_path:
            QMessageBox.warning(self, "Błąd", "Wybierz plik i podpis do weryfikacji.")
            return

        public_key_file = os.path.join("klucz", "public_key.pem")
        if not os.path.exists(public_key_file):
            QMessageBox.warning(self, "Błąd", "Brak pliku z kluczem publicznym.")
            return

        try:
            is_valid = pen.verify_signature(file_path, signature_path, public_key_file)

            if is_valid:
                QMessageBox.information(self, "Sukces", "Podpis jest prawidłowy.")
            else:
                QMessageBox.warning(self, "Błąd", "Podpis jest nieprawidłowy.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd weryfikacji podpisu: {e}")

    def add_hmac_tab(self):
        hmac_tab = QTabWidget()

        generate_tab = QWidget()
        generate_layout = QVBoxLayout()

        self.hmac_key_input = QLineEdit()
        self.hmac_key_input.setPlaceholderText("Podaj klucz...")
        generate_layout.addWidget(QLabel("Klucz:"))
        generate_layout.addWidget(self.hmac_key_input)

        self.hmac_message_input = QTextEdit()
        self.hmac_message_input.setPlaceholderText("Wprowadź wiadomość...")
        generate_layout.addWidget(QLabel("Wiadomość:"))
        generate_layout.addWidget(self.hmac_message_input)

        self.hmac_result_output = QTextEdit()
        self.hmac_result_output.setReadOnly(True)
        generate_layout.addWidget(QLabel("Wynik HMAC:"))
        generate_layout.addWidget(self.hmac_result_output)

        self.generate_hmac_button = QPushButton("Generuj HMAC")
        self.generate_hmac_button.clicked.connect(self.call_generate_hmac)
        generate_layout.addWidget(self.generate_hmac_button)

        generate_tab.setLayout(generate_layout)

        verify_tab = QWidget()
        verify_layout = QVBoxLayout()

        self.verify_hmac_key_input = QLineEdit()
        self.verify_hmac_key_input.setPlaceholderText("Podaj klucz...")
        verify_layout.addWidget(QLabel("Klucz:"))
        verify_layout.addWidget(self.verify_hmac_key_input)

        self.verify_hmac_message_input = QTextEdit()
        self.verify_hmac_message_input.setPlaceholderText("Wprowadź wiadomość...")
        verify_layout.addWidget(QLabel("Wiadomość:"))
        verify_layout.addWidget(self.verify_hmac_message_input)

        self.verify_hmac_input = QLineEdit()
        self.verify_hmac_input.setPlaceholderText("Podaj kod HMAC...")
        verify_layout.addWidget(QLabel("Kod HMAC:"))
        verify_layout.addWidget(self.verify_hmac_input)

        self.verify_hmac_output = QLabel("")
        verify_layout.addWidget(self.verify_hmac_output)

        self.verify_hmac_button = QPushButton("Weryfikuj HMAC")
        self.verify_hmac_button.clicked.connect(self.call_verify_hmac)
        verify_layout.addWidget(self.verify_hmac_button)

        verify_tab.setLayout(verify_layout)

        hmac_tab.addTab(generate_tab, "Generowanie HMAC")
        hmac_tab.addTab(verify_tab, "Weryfikacja HMAC")

        self.tabs.addTab(hmac_tab, "HMAC")

    def call_generate_hmac(self):
        key = self.hmac_key_input.text().strip()
        message = self.hmac_message_input.toPlainText().strip()

        if not key or not message:
            self.show_warning("Błąd", "Klucz i wiadomość nie mogą być puste.")
            return

        try:
            # Wywołanie funkcji z modułu encryptor8
            hmac_result = hmac.encrypt(message, key)
            self.hmac_result_output.setPlainText(hmac_result)
        except Exception as e:
            self.show_warning("Błąd", f"Nie udało się wygenerować HMAC: {e}")

    def call_verify_hmac(self):
        key = self.verify_hmac_key_input.text().strip()
        message = self.verify_hmac_message_input.toPlainText().strip()
        received_hmac = self.verify_hmac_input.text().strip()

        if not key or not message or not received_hmac:
            self.show_warning("Błąd", "Klucz, wiadomość i kod HMAC nie mogą być puste.")
            return

        try:
            calculated_hmac = hmac.verify(message, key,received_hmac)
            print(calculated_hmac)
            if calculated_hmac == True:
                QMessageBox.information(self,"Sukces","Wiadomość jest identyczna")
            else:
                QMessageBox.information(self,"Błąd","Wiadomość nie jest identyczna")

        except Exception as e:
            self.show_warning("Błąd", f"Nie udało się zweryfikować HMAC: {e}")


    def show_warning(self, title, message):
        QMessageBox.warning(self, title, message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
