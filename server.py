import socket
import json
import time
import threading
import hashlib
import hmac
import logging

#configure logging to record server activity with timestamp and message format
logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

#global data structure to store client information with hashed passwords and session tracking
client_data = {}
client_locks = threading.Lock()  # Lock to prevent concurrent access to client_data

#define max allowable values for various parameters

#max delay between actions in seconds (1hr)
MAX_DELAY = 3600 
#max length for client ID         
MAX_ID_LENGTH = 32   
#max length for client password    
MAX_PASSWORD_LENGTH = 64 
#max amount for INCREASE or DECREASE actions done by the client 
MAX_AMOUNT = 1_000_000    
#max number of actions allowed for each client
MAX_ACTIONS = 50          


#function to generate a salt from a hash of the user ID
def generate_salt(user_id):
    user_id_hash = hashlib.sha256(user_id.encode()).hexdigest()
    return user_id_hash[:8]  # Use the first 8 characters of the hashed ID as salt


#function to hash password with the derived salt
def hash_password(password, salt):
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()


#class to handle each client connection in a separate thread
class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address):
        super().__init__()
        self.client_socket = client_socket
        self.address = address
        self.id = None  
        self.session_id = None  

    def run(self):
        try:
            #receive client configuration data
            config_data = self.client_socket.recv(1024).decode()
            client_info = json.loads(config_data)

            #limit the length of the client ID and password to the max allowable length
            client_info["id"] = client_info["id"][:MAX_ID_LENGTH]
            client_info["password"] = client_info["password"][:MAX_PASSWORD_LENGTH]

            #register the client and handle actions if registration is successful
            if "actions" in client_info:
                self.id = client_info["id"]
                self.password = client_info["password"]
                self.session_id = f"{self.id}_{threading.get_ident()}" 

                if self.register_client(client_info):
                    self.handle_actions(client_info["actions"])
                else:
                    self.client_socket.send(b'ERROR: Connection failed :( ')
            else:
                self.client_socket.send(b'ERROR: Missing actions.')
        finally:
            #clean up client data and close connection on disconnect
            self.deregister_client()
            self.client_socket.close()

    #function to register the client and validate the password
    def register_client(self, client_info):
        incoming_id = client_info["id"]
        incoming_password = client_info["password"]

        #check for empty ID or password
        if not incoming_id.strip() or not incoming_password.strip():
            self.client_socket.send(b"ERROR: Invalid ID or password.")
            return False

        #generate salt and hash password for secure storage
        salt = generate_salt(incoming_id)
        hashed_password = hash_password(incoming_password, salt)

        #lock access to client_data to prevent race conditions
        with client_locks:
            if incoming_id not in client_data:
                #register new client
                client_data[incoming_id] = {
                    "password_hash": hashed_password,
                    "counter": 0,
                    "sessions": {self.session_id: True} 
                }
                self.client_socket.send(b'Connection successful for new client :D ')
                return True
            elif client_data[incoming_id]["password_hash"] == hashed_password:
                #allow another login if password matches, and update the session
                client_data[incoming_id]["sessions"][self.session_id] = True 
                self.client_socket.send(b'Connection successful, Welcome back :) ')
                return True
            else:
                #registration fails if password is incorrect
                self.client_socket.send(b'ERROR: Incorrect password. ')
                return False

    def handle_actions(self, actions):
        #validate delay and cap it if it exceeds the max allowed value
        delay = int(actions["delay"]) if actions["delay"].isdigit() and int(actions["delay"]) <= MAX_DELAY else None
        if delay is None:
            self.client_socket.send(b"ERROR: Invalid delay; skipping actions.")
            return

        #process each action up to max allowable value
        actions = actions["steps"][:MAX_ACTIONS]
        for action in actions:
            try:
                parts = action.split()
                if len(parts) != 2:
                    raise ValueError("Invalid action format")

                #parse command and amount, and validate each part
                command, amount = parts
                if command not in ["INCREASE", "DECREASE"]:
                    raise ValueError("Invalid command")

                amount = int(amount)
                if abs(amount) > MAX_AMOUNT:
                    #skip action if amount exceeds the limit and send an message
                    logging.warning(f"Client {self.id} action skipped due to large amount: {action}")
                    self.client_socket.send(f"Action skipped: {action} (amount too large)".encode())
                    continue

                #lock access to client_data to prevent concurrent updates
                with client_locks:
                    #update client counter based on command
                    if command == "INCREASE":
                        client_data[self.id]["counter"] += amount
                    elif command == "DECREASE":
                        client_data[self.id]["counter"] -= amount

                    #log action and send response to client
                    logging.info(f"Client {self.id} {command.lower()}d by {amount}, new value: {client_data[self.id]['counter']}")
                    self.client_socket.send(f'Action {command} completed. Counter is now {client_data[self.id]["counter"]}'.encode())

            except ValueError as e:
                #log and notify client of invalid action format
                logging.warning(f"Invalid action format from client {self.id}: {action} ({e})")
                self.client_socket.send(f"Invalid action skipped: {action} ({e})".encode())

            #wait before processing the next action, specified by the client
            time.sleep(delay)

    #function to remove the client from the client_data dictionary
    def deregister_client(self):
        if self.id and self.id in client_data:
            with client_locks:
                #remove the ID from the sessions dictionary
                client_data[self.id]["sessions"].pop(self.session_id, None)

                #fully deregister client only if no active sessions remain
                if not client_data[self.id]["sessions"]:
                    del client_data[self.id]


#function to start the server and listen for incoming connections
def start_server(ip, port):
    port = int(port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen()

    print("Server is running & listening....")
    while True:
        client_socket, address = server_socket.accept()
        handler = ClientHandler(client_socket, address)
        handler.start()


#run the server script
if __name__ == "__main__":
    start_server("127.0.0.1", "65432")
