# import socket
# import threading
# import json
# import logging
# import time

# #configuring logging to save logs in a file with timestamp and message format
# logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# #dictionary that stores the data of the clients that are connected to the server
# client_data = {}

# #class that handles each client connection in a separate thread
# class ClientHandler(threading.Thread):
#     def __init__(self, client_socket, address):
#         super().__init__()
#         #store client socket for communication
#         self.client_socket = client_socket
#         #store client address
#         self.address = address
#         #initialize client ID as None
#         self.id = None
#         #initialize client password as None
#         self.password = None

#     #this function executed when thread is started
#     def run(self):
#         try:
#             #receive initial configuration data from client
#             config_data = self.client_socket.recv(1024).decode()
#             #parse the received data from JSON
#             client_info = json.loads(config_data)

#             #get the client ID and password
#             self.id = client_info["id"]
#             self.password = client_info["password"]

#             #register the client and handle the actions if registration is successful
#             if self.register_client():
#                 self.handle_actions(client_info["actions"])
#             #if the registration is not successful, send an error message to the client
#             else:
#                 self.client_socket.send(b'Error: Registration failed! ID already exists with different password.')
#         finally:
#             #close the client socket connection
#             self.client_socket.close()
#             #remove the client data when disconnected if the client registered successfully
#             if self.id and self.id in client_data:
#                 del client_data[self.id]  
    
#     #function for registering a client if they are not already registered
#     def register_client(self, client_info):
#         # #check if the client is new or logging in again with the correct password
#         # if self.id not in client_data:
#         #     #register this client
#         #     client_data[self.id] = {"password": self.password, "counter": 0}
#         #     self.client_socket.send(b'Registration successful for new client! ')
#         #     return True
#         # elif client_data[self.id]["password"] == self.password:
#         #     #alow the client to relogin if the password is correct
#         #     self.client_socket.send(b'Registration successful! Welcome back!')
#         #     return True
#         # else:
#         #     #registration failed if password incorrect
#         #     self.client_socket.send(b'Error: Registration failed! ID already exists with a different password.')
#         #     return False
#                 # Temporarily store the incoming ID and password from the client info
#         incoming_id = client_info["id"]
#         incoming_password = client_info["password"]
        
#         # Check if the client is new
#         if incoming_id not in client_data:
#             # Register this new client
#             client_data[incoming_id] = {"password": incoming_password, "counter": 0}
#             self.client_socket.send(b'Registration successful for new client!')
#             return True
#         elif client_data[incoming_id]["password"] == incoming_password:
#             # Allow the client to re-login if the password matches
#             self.client_socket.send(b'Registration successful! Welcome back!')
#             return True
#         else:
#             # If the ID exists with a different password, prevent registration
#             self.client_socket.send(b'Error: Registration failed! ID already exists with a different password.')
#             return False

#     #function for handling the actions received from the client
#     def handle_actions(self, actions):
#         #delay between each action, specified by the client
#         delay = int(actions["delay"])
#         #loop through each action and perform the action
#         for action in actions["steps"]:
#             #split action into command and amount
#             command, amount = action.split()
#             amount = int(amount)

#             #update the counter based on the command
#             if command == "INCREASE":
#                 client_data[self.id]["counter"] += amount
#             elif command == "DECREASE":
#                 client_data[self.id]["counter"] -= amount

#             #log the action to the server log file and send response to client with updated counter value
#             logging.info(f"Client {self.id} {command.lower()}d by {amount}, new value: {client_data[self.id]['counter']}")
#             self.client_socket.send(f'Action {command} completed. Counter is now {client_data[self.id]["counter"]}'.encode())

#             #pause for the specified delay
#             time.sleep(delay)

# #function to start the server and listen for incoming connections
# def start_server(ip, port):
#     port = int(port)
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind((ip, port))
#     server_socket.listen()

#     print("Server is running & listening.....")
#     while True:
#         client_socket, address = server_socket.accept()
#         handler = ClientHandler(client_socket, address)
#         print(f"Connection established with {address}")
#         handler.start()

# if __name__ == "__main__":
#     start_server("127.0.0.1", "65432")

import socket
import threading
import json
import logging
import time

#configure logging to save logs in a file with timestamp and message format
logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

#dictionary that stores client data 
client_data = {}
#a lock to prevent access to client data from multiple threads
client_locks = threading.Lock()

#class that handles each client connection in a separate thread
class ClientHandler(threading.Thread):
    def __init__(self, client_socket, address):
        super().__init__()
        #store client socket and address for communication
        self.client_socket = client_socket
        self.address = address
        #initialize client ID and password as None
        self.id = None
        self.password = None

    #this function is executed when the thread starts
    def run(self):
        try:
            #receive initial configuration data from client
            config_data = self.client_socket.recv(1024).decode()
            #parse the received data from JSON
            client_info = json.loads(config_data)

            #register the client and handle actions if registration is successful
            if self.register_client(client_info):
                #set ID and password only after successful registration
                self.id = client_info["id"]
                self.password = client_info["password"]
                self.handle_actions(client_info["actions"])
            else:
                #if registration is not successful, send an error message to the client
                self.client_socket.send(b'Error: Registration failed! ID already exists with a different password.')
        finally:
            #remove the client reference on disconnect
            self.deregister_client()
            #close the client socket connection
            self.client_socket.close()
    
    #function for registering a client 
    def register_client(self, client_info):
        incoming_id = client_info["id"]
        incoming_password = client_info["password"]

        #get the lock before updating the client data
        with client_locks:
            #if the client ID is new, register it
            if incoming_id not in client_data:
                client_data[incoming_id] = {"password": incoming_password, "counter": 0, "connections": 1}
                self.client_socket.send(b'Registration successful for new client!')
                return True
            #if the client ID exists with the correct password, allow re-login and increase connections
            elif client_data[incoming_id]["password"] == incoming_password:
                client_data[incoming_id]["connections"] += 1
                self.client_socket.send(b'Registration successful! Welcome back!')
                return True
            #if the client ID exists with a different password, make the reigsration unsuccessful
            else:
                return False

    #function that handles client deregistration on disconnect
    def deregister_client(self):
        if self.id:
            with client_locks:
                if self.id in client_data:
                    #decrease the connection count
                    client_data[self.id]["connections"] -= 1
                    #if no more active connections, remove client data to keep the server stateless
                    if client_data[self.id]["connections"] == 0:
                        del client_data[self.id]
                        print(f"Client {self.id} data removed from server.")

    #function for handling actions received from the client
    def handle_actions(self, actions):
        delay = int(actions["delay"])
        for action in actions["steps"]:
            command, amount = action.split()
            amount = int(amount)

            #get the lock before updating the client data
            with client_locks:
                #update the counter based on the command
                if command == "INCREASE":
                    client_data[self.id]["counter"] += amount
                elif command == "DECREASE":
                    client_data[self.id]["counter"] -= amount

                #log the action to the server log file and send response to client with updated counter value
                logging.info(f"Client {self.id} {command.lower()}d by {amount}, new value: {client_data[self.id]['counter']}")
                self.client_socket.send(f'Action {command} completed. Counter is now {client_data[self.id]["counter"]}'.encode())

            #pause for the specified delay
            time.sleep(delay)

#function to start the server and listen for incoming connections
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

#run the server script
if __name__ == "__main__":
    start_server("127.0.0.1", 65432)
