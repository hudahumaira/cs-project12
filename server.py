import hashlib
import hmac
import socket
import threading
import json
import logging
import time

# Configure logging to record server activity with timestamp and message format
logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global data structure to store client information with hashed passwords
client_data = {}
client_locks = threading.Lock()  # Lock to prevent concurrent access to client_data

# Define maximum limits for various inputs
MAX_DELAY = 3600          # Max delay in seconds for actions
MAX_ID_LENGTH = 32        # Max length for client ID
MAX_PASSWORD_LENGTH = 64  # Max length for client password
MAX_AMOUNT = 1_000_000    # Max amount for INCREASE or DECREASE actions
MAX_ACTIONS = 50          # Max number of actions allowed per client

# Function to generate a salt from a hash of the user ID
def generate_salt(user_id):
    user_id_hash = hashlib.sha256(user_id.encode()).hexdigest()
    return user_id_hash[:8]  # Use the first 8 characters of the hashed ID as salt

# Function to hash password with the derived salt
def hash_password(password, salt):
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

# Class to handle each client connection in a separate thread
class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address):
        super().__init__()
        self.client_socket = client_socket
        self.address = address
        self.id = None  # Initialize client ID

    # Main function to handle client connection and actions
    def run(self):
        try:
            # Receive client configuration data
            config_data = self.client_socket.recv(1024).decode()
            client_info = json.loads(config_data)

            # Limit client ID and password length to prevent overly large values
            client_info["id"] = client_info["id"][:MAX_ID_LENGTH]
            client_info["password"] = client_info["password"][:MAX_PASSWORD_LENGTH]

            # Register client and handle actions if registration is successful
            if "actions" in client_info:
                self.id = client_info["id"]
                self.password = client_info["password"]
                if self.register_client(client_info):
                    self.handle_actions(client_info["actions"])
                else:
                    self.client_socket.send(b'Error: Registration failed!')
            else:
                self.client_socket.send(b'Error: Missing actions.')
        finally:
            # Clean up client data and close connection on disconnect
            self.deregister_client()
            self.client_socket.close()

    # Register or re-login client with hashed password verification
    def register_client(self, client_info):
        incoming_id = client_info["id"]
        incoming_password = client_info["password"]

        # Check for empty ID or password
        if not incoming_id.strip() or not incoming_password.strip():
            self.client_socket.send(b"Error: Invalid ID or password.")
            return False

        # Generate salt and hash password for secure storage
        salt = generate_salt(incoming_id)
        hashed_password = hash_password(incoming_password, salt)

        # Lock access to client_data to avoid race conditions
        with client_locks:
            if incoming_id not in client_data:
                # Register new client
                client_data[incoming_id] = {
                    "password_hash": hashed_password,
                    "counter": 0,
                    "connections": 1
                }
                self.client_socket.send(b'Registration successful for new client!')
                return True
            elif client_data[incoming_id]["password_hash"] == hashed_password:
                # Allow re-login if password matches
                client_data[incoming_id]["connections"] += 1
                self.client_socket.send(b'Registration successful! Welcome back!')
                return True
            else:
                # Registration fails if password is incorrect
                return False

    # Handle actions sent by the client with validation and delay
    def handle_actions(self, actions):
        # Validate delay and cap it if it exceeds the max allowed value
        delay = int(actions["delay"]) if actions["delay"].isdigit() and int(actions["delay"]) <= MAX_DELAY else None
        if delay is None:
            self.client_socket.send(b"Error: Invalid delay; skipping actions.")
            return  # Exit if delay is invalid

        # Process each action up to MAX_ACTIONS
        actions = actions["steps"][:MAX_ACTIONS]
        for action in actions:
            try:
                parts = action.split()
                if len(parts) != 2:
                    raise ValueError("Invalid action format")

                # Parse command and amount, and validate each part
                command, amount = parts
                if command not in ["INCREASE", "DECREASE"]:
                    raise ValueError("Invalid command")

                amount = int(amount)
                if abs(amount) > MAX_AMOUNT:
                    # Skip action if amount exceeds the limit
                    logging.warning(f"Client {self.id} action skipped due to large amount: {action}")
                    self.client_socket.send(f"Action skipped: {action} (amount too large)".encode())
                    continue

                # Lock access to update client-specific data
                with client_locks:
                    # Update client counter based on command
                    if command == "INCREASE":
                        client_data[self.id]["counter"] += amount
                    elif command == "DECREASE":
                        client_data[self.id]["counter"] -= amount

                    # Log action and send response to client
                    logging.info(f"Client {self.id} {command.lower()}d by {amount}, new value: {client_data[self.id]['counter']}")
                    self.client_socket.send(f'Action {command} completed. Counter is now {client_data[self.id]["counter"]}'.encode())

            except ValueError as e:
                # Log and notify client of invalid action format
                logging.warning(f"Invalid action format from client {self.id}: {action} ({e})")
                self.client_socket.send(f"Invalid action skipped: {action} ({e})".encode())

            # Wait before processing the next action
            time.sleep(delay)

    # Deregister client by reducing connections or removing data if no active connections
    def deregister_client(self):
        if self.id and self.id in client_data:
            with client_locks:
                client_data[self.id]["connections"] -= 1
                if client_data[self.id]["connections"] == 0:
                    # Remove client data if no more active connections
                    del client_data[self.id]

# Start the server and listen for incoming connections
def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen()

    print("Server is running & listening...")
    while True:
        # Accept new client connection and create a handler for it
        client_socket, address = server_socket.accept()
        handler = ClientHandler(client_socket, address)
        handler.start()  # Start the thread to handle the client

# Run the server script
if __name__ == "__main__":
    start_server("127.0.0.1", 65432)
