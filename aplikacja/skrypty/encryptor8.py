import hmac
import hashlib

def encrypt(message, key):
        try:
            if not message:
                raise ValueError("Wiadomość nie może być pusta.")
            if not key:
                raise ValueError("Klucz nie może być pusty.")
            key_bytes = key.encode('utf-8')
            message_bytes = message.encode('utf-8')
            hmac_result = hmac.new(key_bytes, message_bytes, hashlib.sha256)
            return hmac_result.hexdigest()
        except Exception as e:
            raise Exception(f"Błąd podczas generowania HMAC: {e}")
   
def verify(message, key, received_hmac):
        key_bytes = key.encode('utf-8')
        message_bytes = message.encode('utf-8')
        generated_hmac = hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(generated_hmac, received_hmac)
