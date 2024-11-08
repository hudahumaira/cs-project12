import hashlib
import hmac
import socket
import threading
import json
import logging
import time

# Configure logging to save logs in a file with timestamp and message format
logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionary that stores client data with hashed passwords
client_data = {}
# A lock to prevent access to client data from multiple threads
client_locks = threading.Lock()

# Function to generate a salt from a hash of the user ID
def generate_salt(user_id):
    user_id_hash = hashlib.sha256(user_id.encode()).hexdigest()
    return user_id_hash[:8]  # Use the first 8 characters of the hash as the salt

# Function to hash password with the derived salt
def hash_password(password, salt):
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

# Class that handles each client connection in a separate thread
class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address):
        super().__init__()
        # Store client socket and address for communication
        self.client_socket = client_socket
        self.address = address
        # Initialize client ID and password as None
        self.id = None
        self.password = None

    # This function is executed when the thread starts
    def run(self):
        try:
            # Receive initial configuration data from client
            config_data = self.client_socket.recv(1024).decode()
            # Parse the received data from JSON
            client_info = json.loads(config_data)

            # Register the client and handle actions if registration is successful
            if self.register_client(client_info):
                # Set ID and password only after successful registration
                self.id = client_info["id"]
                self.password = client_info["password"]
                self.handle_actions(client_info["actions"])
            else:
                # If registration is not successful, send an error message to the client
                self.client_socket.send(b'Error: Registration failed! ID already exists with a different password.')
        finally:
            # Remove the client reference on disconnect
            self.deregister_client()
            # Close the client socket connection
            self.client_socket.close()

    # Function for registering a client
    def register_client(self, client_info):
        incoming_id = client_info["id"]
        incoming_password = client_info["password"]
        # Generate a salt from the user ID
        salt = generate_salt(incoming_id)
        # Hash the incoming password with the derived salt
        hashed_password = hash_password(incoming_password, salt)

        # Get the lock before updating the client data
        with client_locks:
            # If the client ID is new, register it
            if incoming_id not in client_data:
                client_data[incoming_id] = {
                    "password_hash": hashed_password,
                    "counter": 0,
                    "connections": 1
                }
                self.client_socket.send(b'Registration successful for new client!')
                return True
            # If the client ID exists with the correct password hash, allow re-login and increase connections
            elif client_data[incoming_id]["password_hash"] == hashed_password:
                client_data[incoming_id]["connections"] += 1
                self.client_socket.send(b'Registration successful! Welcome back!')
                return True
            # If the client ID exists with a different password, make the registration unsuccessful
            else:
                return False

    # Function that handles client deregistration on disconnect
    def deregister_client(self):
        if self.id:
            with client_locks:
                if self.id in client_data:
                    # Decrease the connection count
                    client_data[self.id]["connections"] -= 1
                    # If no more active connections, remove client data to keep the server stateless
                    if client_data[self.id]["connections"] == 0:
                        del client_data[self.id]
                        print(f"Client {self.id} data removed from server.")

    # Function for handling actions received from the client
    def handle_actions(self, actions):
        delay = int(actions["delay"])
        for action in actions["steps"]:
            command, amount = action.split()
            amount = int(amount)

            # Get the lock before updating the client data
            with client_locks:
                # Update the counter based on the command
                if command == "INCREASE":
                    client_data[self.id]["counter"] += amount
                elif command == "DECREASE":
                    client_data[self.id]["counter"] -= amount

                # Log the action to the server log file and send response to client with updated counter value
                logging.info(f"Client {self.id} {command.lower()}d by {amount}, new value: {client_data[self.id]['counter']}")
                self.client_socket.send(f'Action {command} completed. Counter is now {client_data[self.id]["counter"]}'.encode())

            # Pause for the specified delay
            time.sleep(delay)

# Function to start the server and listen for incoming connections
def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen()

    print("Server is running & listening...")
    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection established with {address}")
        handler = ClientHandler(client_socket, address)
        handler.start()

# Run the server script
if __name__ == "__main__":
    start_server("127.0.0.1", 65432)
