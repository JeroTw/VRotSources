import socket
import threading



def handle_client(client_socket, address):
    while True:
        try:
            data = client_socket.recv(16384).decode()
            print(data)
            if data and data.startswith("Z0FBQUFB"):
                print("msg detected. relaying")
                data = data.encode()
                for client in clients:
                    if client != client_socket:
                        try:
                            client.sendall(data)
                        except:
                            pass
            else:
                clients.remove(client_socket)
                client_socket.close()
                break
        except:
            clients.remove(client_socket)
            client_socket.close()
            break


clients = []

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("", 1945))  # Изменяем порт на 1945
server_socket.listen()

print("Сервер запущен на порту 1945")

while True:
    client_socket, address = server_socket.accept()
    print(f"Клиент подключился с адреса {address}")
    print(f"{clients}")
    clients.append(client_socket)

    # Запускаем новый поток для обработки клиента
    thread = threading.Thread(target=handle_client, args=(client_socket, address))
    thread.start()
