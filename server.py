import socket
import json
import time
import threading
import hashlib
import hmac
# Vulnerability Encrypted Logging 16:
# Used for the encrypted logging using the cryptography library
from cryptography.fernet import Fernet
import os

# Vulnerability Encrypted Logging 16:
# Generating a key or load from environment
if "LOG_ENCRYPTION_KEY" not in os.environ:
    os.environ["LOG_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

LOG_ENCRYPTION_KEY = os.environ["LOG_ENCRYPTION_KEY"].encode()
fernet = Fernet(LOG_ENCRYPTION_KEY)

# Vulnerability Encrypted Logging 16:
# Replacing plaintext logs with encrypted logs
def log_encrypted(message):
    encrypted_message = fernet.encrypt(message.encode()).decode()
    with open("server_logfile.log", "a") as log_file:
        log_file.write(encrypted_message + "\n")

# Vulnerability  rate limiting 17:
# Rate limiting parameters
RATE_LIMIT = 10  # Maximum number of requests per time window
TIME_WINDOW = 60  # Time window in seconds (e.g., 1 minute)
blacklist = set()  # Temporarily store blacklisted IPs
rate_limit_data = {}  # Track requests per client
rate_limit_lock = threading.Lock()  # Ensure thread-safe access to rate limit data

# Client data storage
client_data = {}
client_locks = threading.Lock()

# Function to generate a salt for password hashing
def generate_salt(user_id):
    user_id_hash = hashlib.sha256(user_id.encode()).hexdigest()
    return user_id_hash[:8]

# Function to hash passwords securely
def hash_password(password, salt):
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

# Vulnerability  rate limiting 17:
# Function to enforce rate limiting
def is_rate_limited(client_ip):
    current_time = time.time()

    # If the client is blacklisted, deny immediately
    if client_ip in blacklist:
        return True

    with rate_limit_lock:
        # Initialize data for new clients
        if client_ip not in rate_limit_data:
            rate_limit_data[client_ip] = []

        # Remove outdated requests outside the time window
        request_times = rate_limit_data[client_ip]
        rate_limit_data[client_ip] = [t for t in request_times if current_time - t < TIME_WINDOW]

        # Check if the client exceeds the rate limit
        if len(rate_limit_data[client_ip]) >= RATE_LIMIT:
            blacklist.add(client_ip)
            log_encrypted(f"Rate limit exceeded by {client_ip}. Added to blacklist.")
            return True

        # Log the current request and allow it
        rate_limit_data[client_ip].append(current_time)
        return False

# Vulnerability Encrypted Logging 16:
# Class to handle each client connection
class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address):
        super().__init__()
        self.client_socket = client_socket
        self.address = address
        self.id = None

    def run(self):
        client_ip = self.address[0]  # Get the client's IP address
        if is_rate_limited(client_ip):
            self.client_socket.send(b"ERROR: Too many requests. You are rate limited.")
            log_encrypted(f"Client {client_ip} denied due to rate limiting.")
            self.client_socket.close()
            return

        try:
            # Receive client configuration data
            config_data = self.client_socket.recv(1024).decode()
            client_info = json.loads(config_data)
            self.id = client_info["id"][:32]  # Max ID length
            client_info["password"] = client_info["password"][:64]  # Max password length

            if self.register_client(client_info):
                self.handle_actions(client_info["actions"])
            else:
                self.client_socket.send(b"ERROR: Registration failed.")
        finally:
            self.deregister_client()
            self.client_socket.close()

# Vulnerability Encrypted Logging 16:
# Vulnerability Vulnerable User Registration 14:
# Replaced plain text logging in with encrypted logging
    def register_client(self, client_info):
        incoming_id = client_info["id"]
        incoming_password = client_info["password"]

        # Validate user ID format
        if not incoming_id.strip() or not incoming_password.strip():
            self.client_socket.send(b"ERROR: Invalid ID or password.")
            return False

        # Generate salt and hash password
        salt = generate_salt(incoming_id)
        hashed_password = hash_password(incoming_password, salt)

        with client_locks:
            if incoming_id not in client_data:
                # Register new client
                client_data[incoming_id] = {
                    "password_hash": hashed_password,
                    "counter": 0,
                    "sessions": {self.address: True}
                }
                self.client_socket.send(b"Registration successful.")
                log_encrypted(f"User {incoming_id} registered successfully.")
                return True
            elif client_data[incoming_id]["password_hash"] == hashed_password:
                # Allow login if password matches
                client_data[incoming_id]["sessions"][self.address] = True
                self.client_socket.send(b"Login successful.")
                log_encrypted(f"User {incoming_id} logged in successfully.")
                return True
            else:
                self.client_socket.send(b"ERROR: Incorrect password.")
                log_encrypted(f"Failed login attempt for user {incoming_id}.")
                return False

    # Vulnerability Encrypted Logging 16:
    # Vulnerability Delay Implemented on Server-Side 15:
    # Replaced plain text logging in with encrypted logging
    def handle_actions(self, actions):
        actions = actions["steps"][:50]  # Limit to max 50 actions
        for action in actions:
            try:
                parts = action.split()
                if len(parts) != 2:
                    raise ValueError("Invalid action format")

                command, amount = parts
                if command not in ["INCREASE", "DECREASE"]:
                    raise ValueError("Invalid command")

                amount = int(amount)
                if abs(amount) > 1_000_000:  # Max amount limit
                    self.client_socket.send(f"Action skipped: {action} (amount too large)".encode())
                    log_encrypted(f"Action skipped for {self.id}: {action} (amount too large).")
                    continue

                with client_locks:
                    if command == "INCREASE":
                        client_data[self.id]["counter"] += amount
                    elif command == "DECREASE":
                        client_data[self.id]["counter"] -= amount

                    log_encrypted(f"User {self.id} performed action: {command} {amount}. Counter now: {client_data[self.id]['counter']}")
                    self.client_socket.send(f"Action {command} completed. Counter is now {client_data[self.id]['counter']}".encode())

            except ValueError as e:
                self.client_socket.send(f"Invalid action: {action} ({e})".encode())
                log_encrypted(f"Invalid action by {self.id}: {action} ({e}).")

    # Vulnerability Encrypted Logging 16:
    # Add encrypted logging to record user disconnections
    def deregister_client(self):
        if self.id and self.id in client_data:
            with client_locks:
                client_data[self.id]["sessions"].pop(self.address, None)
                if not client_data[self.id]["sessions"]:
                    del client_data[self.id]
        log_encrypted(f"User {self.id} disconnected.")

# Vulnerability  rate limiting 17:
# Function to clean the blacklist periodically
def clean_blacklist():
    while True:
        time.sleep(TIME_WINDOW)
        with rate_limit_lock:
            blacklist.clear()
            log_encrypted("Blacklist cleared.")

# Start server
def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, int(port)))
    server_socket.listen()
    print("Server is running & listening....")

    threading.Thread(target=clean_blacklist, daemon=True).start()  # Start blacklist cleaner
    while True:
        client_socket, address = server_socket.accept()
        handler = ClientHandler(client_socket, address)
        handler.start()

# Main entry point
if __name__ == "__main__":
    start_server("127.0.0.1", "65432")
