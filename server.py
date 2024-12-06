import socket
import ssl
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta
import bcrypt

# Configure logging
logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

client_data = {}
used_nonces = set()
connection_log = defaultdict(list)  # Tracks connection attempts by IP
MAX_DELAY = 3600
MAX_ID_LENGTH = 32
MAX_PASSWORD_LENGTH = 64
MIN_PASSWORD_LENGTH = 10
MAX_AMOUNT = 1_000_000
MAX_ACTIONS = 50
MAX_CONNECTIONS_PER_MINUTE = 10  # Maximum allowed connections per IP per minute
MAX_BACKLOG = 5  # Maximum queued connections in the socket

# Vulnerability weak password hashing 3:
# Implemented bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)


# Vulnerability multiple connections 4:
# Limited the number of connections
def rate_limit(ip):
    now = datetime.now()
    # Remove entries older than 1 minute
    connection_log[ip] = [timestamp for timestamp in connection_log[ip] if now - timestamp <= timedelta(minutes=1)]
    if len(connection_log[ip]) >= MAX_CONNECTIONS_PER_MINUTE:
        return False  # Too many connections in the last minute
    connection_log[ip].append(now)
    return True

# Vulnerability replay attack prevention 6:
# Validate nonce and timestamp
def validate_nonce_and_timestamp(client_nonce, client_timestamp):
    current_time = int(time.time())

    # Check if the nonce was already used
    if client_nonce in used_nonces:
        return False

    # Ensure the timestamp is within the allowed range
    if abs(current_time - client_timestamp) > MAX_DELAY:
        return False

    # Mark nonce as used
    used_nonces.add(client_nonce)
    return True

def handle_client(secure_socket, client_address):
    try:
        config_data = secure_socket.recv(1024).decode()
        client_info = json.loads(config_data)

        # Validate and process client info
        client_info["id"] = client_info["id"][:MAX_ID_LENGTH]
        client_info["password"] = client_info["password"][:MAX_PASSWORD_LENGTH]

        # Validate nonce and timestamp at the connection level
        client_nonce = client_info.get("nonce")
        client_timestamp = client_info.get("timestamp")
        if not validate_nonce_and_timestamp(client_nonce, client_timestamp):
            secure_socket.send(b"ERROR: Invalid or expired nonce/timestamp.")
            return

        if "actions" in client_info:
            client_id = client_info["id"]
            password = client_info["password"]

            # Vulnerability weak password policy 9:
            # Has to be between 10 and 64 characters
            if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
                secure_socket.send(
                    f"ERROR: Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters long.".encode()
                )
                return False

            if register_client(secure_socket, client_id, password):
                handle_actions(secure_socket, client_id, client_info["actions"])
            else:
                secure_socket.send(b"ERROR: Connection failed.")
        else:
            secure_socket.send(b"ERROR: Missing actions.")
    except Exception as e:
        logging.error(f"Error handling client from {client_address}: {e}")
    finally:
        secure_socket.close()


def register_client(secure_socket, client_id, password):
    if client_id not in client_data:
        hashed_password = hash_password(password)
        client_data[client_id] = {"password_hash": hashed_password, "counter": 0}
        secure_socket.send(b"Connection successful for new client.")
        return True
    else:
        stored_hash = client_data[client_id]["password_hash"]
        if verify_password(password, stored_hash):
            secure_socket.send(b"Connection successful, welcome back.")
            return True
        # Vulnerability error message 1:
        # Changed the print
        secure_socket.send(b"ERROR: Incorrect credentials.")
        return False


def handle_actions(secure_socket, client_id, actions):
    delay = int(actions["delay"]) if actions["delay"].isdigit() and int(actions["delay"]) <= MAX_DELAY else None
    if delay is None:
        secure_socket.send(b"ERROR: Invalid delay; skipping actions.")
        return

    for action in actions["steps"][:MAX_ACTIONS]:
        try:
            action_parts = action.split()
            if len(action_parts) != 2:
                raise ValueError("Invalid action format")

            command, amount = action_parts

            # Generate action-level nonce and timestamp
            action_nonce = f"{client_id}-action-{command}-{amount}"  # Unique per action
            action_timestamp = int(time.time())

            # Validate nonce and timestamp for the action
            if not validate_nonce_and_timestamp(action_nonce, action_timestamp):
                response = f"ERROR: Invalid or expired nonce/timestamp for action: {action}"
                secure_socket.send(response.encode())
                # Disconnect the client after the first invalid action
                return

            if command not in ["INCREASE", "DECREASE"]:
                raise ValueError("Invalid command")

            amount = int(amount)
            if abs(amount) > MAX_AMOUNT:
                secure_socket.send(f"Action skipped: {action} (amount too large)".encode())
                continue

            if command == "INCREASE":
                client_data[client_id]["counter"] += amount
            elif command == "DECREASE":
                client_data[client_id]["counter"] -= amount

            response = f"Action {command} completed. Counter is now {client_data[client_id]['counter']}."
            secure_socket.send(response.encode())
        except ValueError as e:
            secure_socket.send(f"Invalid action skipped: {action} ({e})".encode())

        time.sleep(delay)


# Vulnerability data transmission 2:
# Implemented SSL
def start_server(ip, port):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen(MAX_BACKLOG)  # Limit the number of queued connections

        print("Secure server is running and listening...")
        while True:
            client_socket, client_address = server_socket.accept()

            # Vulnerability rate limiting 4:
            # Implemented connection frequency tracking per IP
            if not rate_limit(client_address[0]):
                logging.warning(f"Rate limit exceeded for {client_address[0]}")
                client_socket.close()
                continue

            with context.wrap_socket(client_socket, server_side=True) as secure_socket:
                handle_client(secure_socket, client_address)


if __name__ == "__main__":
    start_server("localhost", 65432)