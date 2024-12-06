import socket
import json
import hashlib
import hmac
import logging
import time

# Configure logging
logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global data structure for client information
client_data = {}
MAX_DELAY = 3600
MAX_ID_LENGTH = 32
MAX_PASSWORD_LENGTH = 64
MAX_AMOUNT = 1_000_000
MAX_ACTIONS = 50


def generate_salt(user_id):
    user_id_hash = hashlib.sha256(user_id.encode()).hexdigest()
    return user_id_hash[:8]


def hash_password(password, salt):
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()


def handle_client(client_socket):
    try:
        # Receive client configuration
        config_data = client_socket.recv(1024).decode()
        client_info = json.loads(config_data)

        # Validate and truncate ID and password
        client_info["id"] = client_info["id"][:MAX_ID_LENGTH]
        client_info["password"] = client_info["password"][:MAX_PASSWORD_LENGTH]

        # Check for actions and handle client registration
        if "actions" in client_info:
            client_id = client_info["id"]
            password = client_info["password"]

            if register_client(client_socket, client_id, password):
                handle_actions(client_socket, client_id, client_info["actions"])
            else:
                client_socket.send(b"ERROR: Connection failed.")
        else:
            client_socket.send(b"ERROR: Missing actions.")
    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        client_socket.close()


def register_client(client_socket, client_id, password):
    salt = generate_salt(client_id)
    hashed_password = hash_password(password, salt)

    if client_id not in client_data:
        client_data[client_id] = {
            "password_hash": hashed_password,
            "counter": 0
        }
        client_socket.send(b"Connection successful for new client.")
        return True
    elif client_data[client_id]["password_hash"] == hashed_password:
        client_socket.send(b"Connection successful, welcome back.")
        return True
    else:
        client_socket.send(b"ERROR: Incorrect password.")
        return False


def handle_actions(client_socket, client_id, actions):
    delay = int(actions["delay"]) if actions["delay"].isdigit() and int(actions["delay"]) <= MAX_DELAY else None
    if delay is None:
        client_socket.send(b"ERROR: Invalid delay; skipping actions.")
        return

    for action in actions["steps"][:MAX_ACTIONS]:
        try:
            parts = action.split()
            if len(parts) != 2:
                raise ValueError("Invalid action format")

            command, amount = parts
            if command not in ["INCREASE", "DECREASE"]:
                raise ValueError("Invalid command")

            amount = int(amount)
            if abs(amount) > MAX_AMOUNT:
                client_socket.send(f"Action skipped: {action} (amount too large)".encode())
                continue

            if command == "INCREASE":
                client_data[client_id]["counter"] += amount
            elif command == "DECREASE":
                client_data[client_id]["counter"] -= amount

            response = f"Action {command} completed. Counter is now {client_data[client_id]['counter']}."
            client_socket.send(response.encode())
        except ValueError as e:
            client_socket.send(f"Invalid action skipped: {action} ({e})".encode())

        time.sleep(delay)


def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen()

    print("Server is running and listening...")
    while True:
        client_socket, address = server_socket.accept()
        print(f"Accepted connection from {address}")
        handle_client(client_socket)


if __name__ == "__main__":
    start_server("127.0.0.1", 65432)
