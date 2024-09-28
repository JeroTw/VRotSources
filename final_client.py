import socket
import importlib
import subprocess

"ЗДЕСЬ БЫЛ RELDICK ТРОЯНА НЕТ 100%"
"ПРОВЕРОЧКА НА ДОЛБАЕБА (А ТО ТАКИЕ БЫВАЮТ!)"

libraries = ["customtkinter", "cryptography", "requests"]

for library in libraries:
    try:
        importlib.import_module(library)
    except ImportError:
        print(f"Библиотека '{library}' не найдена. Установка...")
        try:
            subprocess.run(["pip", "install", library])
        except:
            pass
        try:
            subprocess.run(["py", "-m", "pip", "install", library])
        except:
            pass
        print(f"Библиотека '{library}' успешно установлена.")

# КОСТЫЛЬ ПОТОМУЧТО РАЗРАБ PYSOCKS - ПИДОР!
try:
    import socks
except ImportError:
    print("Библиотека 'socks' не найдена. Установка...")
    try:
        subprocess.run(["pip", "install", "pysocks"])  # Устанавливаем pysocks
    except:
        pass
    try:
        subprocess.run(["py", "-m", "pip", "install", "pysocks"])
    except:
        pass
    print("Библиотека 'socks' успешно установлена.")

# И ЕЩЕ ОДНА БИБЛИОТЕКА НА ИКОНКИ ДЛЯ ДОЛБАЕБОВ
try:
    from PIL import Image
except ImportError:
    print("Библиотека 'PIL' не найдена. Установка...")
    try:
        subprocess.run(["pip", "install", "pillow"])  # Устанавливаем pillow
    except:
        pass
    try:
        subprocess.run(["py", "-m", "pip", "install", "pillow"])
    except:
        pass
    print("Библиотека 'pillow' успешно установлена.")


"""НИЖЕ УЖЕ ИМПОРТЫ ВТОРОЙ РАЗ ЕПТА НА ВСЯКИЙ"""

import time
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import threading
import random
import requests
from PIL import Image
import select  # костыль
from customtkinter import *
import socks
from datetime import datetime, timezone
from io import BytesIO
from datetime import datetime, timezone


def get_if_debug():
    global debug
    try:
        open(".debug").read()
        debug = True
        if debug:
            print("[DEBUG] Debug is true so")
    except:
        debug = False


get_if_debug()


def get_salt():
    now = datetime.now(timezone.utc)
    salt = (
        base64.b64decode("aGFpcnlkdXJvdnNwdXNzeQ==").decode()
        + now.strftime("%d%m%Y")
        + base64.b64decode("aW5zaWRlcGFyaXM=").decode()
        + now.strftime("%A")
    )
    salt = salt.encode()
    if debug:
        print(f"[DEBUG] Got salt {salt}")
    return salt


salt = get_salt()


import time
import platform


def check_torrify():  # чекаем на тор!
    try:
        with socket.create_connection(("127.0.0.1", 9150), 0.5):
            return True
    except Exception:
        return False


def ping_latency(server_address):
    if check_torrify():
        return 0
    try:
        start_time = time.time()
        os_name = platform.system()
        if os_name == "Windows":
            subprocess.run(
                ["ping", "-n", "1", server_address], capture_output=True, timeout=2
            )
        else:
            subprocess.run(
                ["ping", "-c", "1", server_address], capture_output=True, timeout=2
            )
        end_time = time.time()
        return (end_time - start_time) * 1000
    except subprocess.TimeoutExpired:
        return -1
    except Exception:
        return -1


latency = ping_latency("server.vrot")

version_banner = "Beta 0.6 (file mechanic (еще нет), encryption enchant, small bugfixes)"  # пишем версию
banner = f"""                  _    __     _     
                 | |  / _|   | |    
 __   ___ __ ___ | |_| |_ ___| |__  
 \ \ / / '__/ _ \| __|  _/ __| '_ \ 
  \ V /| | | (_) | |_| | \__ \ |_) |
   \_/ |_|  \___/ \__|_| |___/_.__/ 
                                    
The best messanger ever.
Author channel: vrot
Version: {version_banner}

Connected to the server.
Ping: {latency:.0f} ms\n
"""
banner_tor = f"""
                 | |  / _|   | |    
 __   ___ __ ___ | |_| |_ ___| |__  
 \ \ / / '__/ _ \| __|  _/ __| '_ \ 
  \ V /| | | (_) | |_| | \__ \ |_) |
   \_/ |_|  \___/ \__|_| |___/_.__/ 
                                    
The best messanger ever.
Author channel: vrot
Version: {version_banner}

Connected to the server.
Ping: Tor\n
"""


stop_listen = False  # костыль чтобы закрывать ебанный поток


def get_encryption_key(key):
    if debug:
        print("[DEBUG] Generating encrypting keys from master")
    kdf = PBKDF2HMAC(
        algorithm=hashes.BLAKE2b(digest_size=64),
        length=32,
        salt=salt,
        iterations=1500000,
        backend=default_backend(),
    )
    lls = base64.urlsafe_b64encode(kdf.derive(str(key).encode()))
    if debug:
        print("[DEBUG] Keys generated")
        print(f"[DEBUG] Key lls is = {lls}")
    return lls


def encrypt(message, key):
    if debug:
        print("[DEBUG] Encrypting..")
    encrypted = f.encrypt(message.encode())
    if debug:
        print("[DEBUG] Encrypted.. go to sending")
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt(encrypted_message, key):
    if debug:
        print("[DEBUG] Decrypting")
    try:
        decrypted = f.decrypt(base64.urlsafe_b64decode(encrypted_message))
        return decrypted.decode()
    except:
        if debug:
            print("[DEBUG] Decrypt fail. Not for us")
        pass
    if debug:
        print("[DEBUG] Decrypt done")


def receive_messages(client_socket, chat_area):
    while True:
        timeout_seconds = 1
        ready_to_read, _, _ = select.select(
            [client_socket], [], [], timeout_seconds
        )  # костыль

        if client_socket in ready_to_read:
            data = client_socket.recv(16384).decode()
            if debug:
                print("[DEBUG] Data from main srv")
        else:
            if stop_listen:  # костыль
                if debug:
                    print("[DEBUG] Close receive..")
                break
            continue

        if data:
            decrypted_message = decrypt(data, key)
            if decrypted_message:
                chat_area.configure(state="normal")
                chat_area.insert(END, f"{decrypted_message}\n")
                chat_area.see(END)
                chat_area.configure(state="disabled")


def send_message(message_entry):
    if debug:
        print("[DEBUG] Sending message")
    global key
    message = message_entry.get()
    if message:
        if message == "/ping":
            if debug:
                print("[DEBUG] Is a command /ping")
            if check_torrify():
                chat_area.configure(state="normal")
                chat_area.insert(END, f"Пинг: 0 ms\n")
                chat_area.see(END)
                message_entry.delete(0, END)
            if not check_torrify():
                latency = ping_latency("server.vrot")
                message_entry.delete(0, END)
                chat_area.configure(state="normal")
                chat_area.insert(END, f"Пинг: {latency:.0f} ms\n")
                chat_area.see(END)
                chat_area.configure(state="disabled")
            return
        if message == "/help":
            if debug:
                print("[DEBUG] Is a command /help")
            message_entry.delete(0, END)
            chat_area.configure(state="normal")
            chat_area.insert(
                END,
                f"/help - Текущая команда\n/new - Генерирует рандомный ключ\n/key [символы] - Устанавливает ключ который вы задали\n/ping - Показывает ваш пинг\n",
            )
            chat_area.see(END)
            chat_area.configure(state="disabled")
            return
        if message == "/new":
            if debug:
                print("[DEBUG] Is a command /new")
            key = str(random.randint(10 ** (16 - 1), 10**16 - 1))
            update_key(key)
            message_entry.delete(0, END)
            chat_area.configure(state="normal")
            chat_area.insert(END, f"Чат ВРотФСБ: Установлен ключ {key}\n")
            chat_area.see(END)
            chat_area.configure(state="disabled")
            send_welcome_on_join(client_socket, nickname, key, encrypt)
            return
        if message.startswith("/clear"):
            chat_area.configure(state="normal")
            chat_area.delete(1.0, END)  # Удаляем всё содержимое чата
            chat_area.configure(state="disabled")
            message_entry.delete(0, END)
            if debug:
                print("[DEBUG] chat was cleared successfully")
            return
        if message.startswith("/key "):
            if debug:
                print("[DEBUG] Is a command /key")
            key = message[5:]
            message_entry.delete(0, END)
            update_key(key)
            chat_area.configure(state="normal")
            chat_area.insert(END, f"Чат ВРотФСБ: Установлен ключ {key}\n")
            chat_area.see(END)
            chat_area.configure(state="disabled")
            send_welcome_on_join(client_socket, nickname, key, encrypt)
            return
        encrypted_message = encrypt(f"{nickname}: {message}", key)
        client_socket.sendall(encrypted_message.encode())
        message_entry.delete(0, END)
        chat_area.configure(state="normal")
        chat_area.insert(END, f"{nickname}: {message}\n")
        chat_area.see(END)
        chat_area.configure(state="disabled")


def update_key(keyz):
    global f
    if debug:
        print("[DEBUG] Update key event")
    global key
    if len(keyz) > 40:
        chat_area.configure(state="normal")
        chat_area.insert(END, f"Куда тебе такое шифрование? Уменьшите размер ключа!\n")
        chat_area.see(END)
        chat_area.configure(state="disabled")
        raise ValueError("Куда тебе такое шифрование? Уменьшите размер ключа!")
    key = keyz
    with open(".anon", "w") as f:
        json.dump({"nickname": nickname, "key": key}, f)
    root.title(f"ВРотФСБ | User: {nickname} | Key: {key}")
    f = Fernet(get_encryption_key(key))
    if debug:
        print("[DEBUG] Update key done")


def send_welcome_on_join(client_socket, nickname, key, encrypt_function):
    if debug:
        print("[DEBUG] Welcome packet sending")
    welcome_message = f"Чат ВРотФСБ: Пользователь {nickname} зашел в чат!"
    encrypted_welcome_message = encrypt_function(welcome_message, key)
    client_socket.sendall(encrypted_welcome_message.encode())
    if debug:
        print("[DEBUG] Welcome packet sent")
    return welcome_message


def send_goodbye_on_close(client_socket, nickname, key, encrypt_function):
    if debug:
        print("[DEBUG] Goodbye packet sending")
    welcome_message = f"Чат ВРотФСБ: Пользователь {nickname} вышел из чата!"
    encrypted_welcome_message = encrypt_function(welcome_message, key)
    client_socket.sendall(encrypted_welcome_message.encode())
    if debug:
        print("[DEBUG] Goodbye packet sent")
    return welcome_message


def on_closing():
    global stop_listen  # костыль ее
    try:
        if debug:
            print("[DEBUG] Close event")
        send_goodbye_on_close(client_socket, nickname, key, encrypt)
        root.destroy()
        stop_listen = True
        raise SystemExit(1)
    except Exception:
        exit()


# Инициализация customTkinter
set_appearance_mode("Dark")  # Вы можете выбрать "System", "Dark", "Light"
set_default_color_theme("dark-blue")  # Вы можете выбрать "blue", "green", "dark-blue"

# Создание главного окна
if debug:
    print("[DEBUG] Tkinter init..")


# CTRL + C, CTRL + V потому что customtkinter не обрабатывает эти штуки лол так что вручную


# Загрузка ключа и ника из файла или запрос у пользователя
def get_key():
    global key
    global nickname
    if debug:
        print("[DEBUG] Getkey running")
    try:
        with open(".anon", "r") as f:
            data = json.load(f)
            nickname = data.get("nickname")
            key = data.get("key")

            # Проверка на наличие данных
            if not nickname or not key:
                raise ValueError("Некорректные данные в файле .anon")
            if len(nickname) > 24:
                raise ValueError("Ваш ник должен быть короче 25 симболов! (<25)")
            if len(key) > 40:
                raise ValueError("Куда тебе такое шифрование? Уменьшите размер ключа!")

    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        nickname = input("Введите ваш ник: ")
        if len(nickname) > 24:
            raise ValueError("Ваш ник должен быть короче 25 симболов! (<25)")
        key = input("Введите ваш ключ: ")
        if len(key) > 40:
            raise ValueError("Куда тебе такое шифрование? Уменьшите размер ключа!")
        with open(".anon", "w") as f:
            json.dump({"nickname": nickname, "key": key}, f)
    if debug:
        print(f"[DEBUG] Getkey finished. Key: {key} Nick: {nickname}")


get_key()
# Gui здесь начинается визуальные приколы

root = CTk()
root.geometry("800x600")
root.title("ВРотФСБ | Инициализация")
loading_label = CTkLabel(root, text="Загрузка", font=("Arial", 48))
loading_label.pack(pady=200)


# Запуск анимации в отдельном потоке
root.update()
root.protocol("WM_DELETE_WINDOW", on_closing)
if debug:
    print("[DEBUG] Tkinter inited.")
f = Fernet(get_encryption_key(key))
root.title(f"ВРотФСБ | User: {nickname} | Key: {key}")
if debug:
    print("[DEBUG] Title set")
loading_label.destroy()
# Создание области чата
chat_area = CTkTextbox(root, state="disabled", wrap="word")
chat_area.pack(expand=True, fill="both")

# Создание полосы прокрутки для области чата
scrollbar = CTkScrollbar(root, command=chat_area.yview)
scrollbar.pack(side="right", fill="y")

# Настройка области чата для использования полосы прокрутки
chat_area["yscrollcommand"] = scrollbar.set

# Создание поля ввода сообщения
message_entry = CTkEntry(root, width=50, placeholder_text="Введите сообщение")
message_entry.pack(side="bottom", fill="x")
message_entry.bind("<Return>", lambda event: send_message(message_entry))

input_frame = CTkFrame(root)
input_frame.pack(side="bottom", fill="x")

send_button = CTkButton(
    input_frame, text="Отправить", command=lambda: send_message(message_entry)
)

send_button.pack(side="right", padx=5)


def on_clip_icon_click(event):
    file_path = filedialog.askopenfilename()
    if file_path:
        print(f"Selected file: {file_path}")
        chat_area.configure(state="normal")
        chat_area.insert(END, f"Чат ВРотФСБ: Вложения еще не готовы!\n")
        chat_area.see(END)
        chat_area.configure(state="disabled")

        # send_message(file_path)


def download_image1(url):
    response = requests.get(url)
    return Image.open(BytesIO(response.content))


clip_icon_url = "http://server.vrot:9912/prish.png"  # устанавливаем
clip_icon = download_image1(clip_icon_url)  # загружаем
clip_icon = clip_icon.resize((20, 20))  # Размер иконки
clip_icon = CTkImage(light_image=clip_icon, dark_image=clip_icon, size=(20, 20))

# Создание лейбла с иконкой
clip_label = CTkLabel(
    input_frame, image=clip_icon, text=""
)  # Создание лейбла с иконкой
clip_label.pack(side="right", padx=5)

clip_label.bind("<Enter>", lambda event: clip_label.configure(cursor="hand2"))
clip_label.bind("<Leave>", lambda event: clip_label.configure(cursor=""))
# Привязка функции к событию клика на иконку
clip_label.bind("<Button-1>", on_clip_icon_click)


message_entry.bind("<Return>", lambda event: send_message(message_entry))

# Создание сокета и подключение к серверу
client_socket = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
if check_torrify():
    if debug:
        print(f"[DEBUG] Detected TOR Browser open. Using tor onion route.")
    client_socket.set_proxy(socks.SOCKS5, "127.0.0.1", 9150)


if debug:
    print("[DEBUG] Socket connecting")
client_socket.connect(("server.vrot", 1945))
if debug:
    print("[DEBUG] Socket connected")

# Отправка приветственного сообщения на сервер
send_welcome_on_join(client_socket, nickname, key, encrypt)
if debug:
    print("[DEBUG] Send welcome")


root.event_add("<<Paste>>", "<Control-igrave>")
root.event_add("<<Copy>>", "<Control-ntilde>")

# Запуск потока для приема сообщений
receive_thread = threading.Thread(
    target=receive_messages, args=(client_socket, chat_area)
)
receive_thread.start()
if debug:
    print("[DEBUG] Rcv thread started")


if not check_torrify():  # если тор не включен делаем
    for oop in banner.split("\n"):
        chat_area.configure(state="normal")
        chat_area.insert(END, f"{oop}\n")
        chat_area.see(END)
        chat_area.configure(state="disabled")
if check_torrify():  # если тор включен делаем и показываем баннер без пинга
    for oop in banner_tor.split("\n"):
        chat_area.configure(state="normal")
        chat_area.insert(END, f"{oop}\n")
        chat_area.see(END)
        chat_area.configure(state="disabled")
# Запуск цикла обработки событий
if debug:
    print("[DEBUG] Main loop lol")
root.mainloop()
