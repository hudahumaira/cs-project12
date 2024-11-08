import socket
import json
import time
import threading

#function to start a single client and connect it to the server using the config
def start_single_client(config):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = config["server"]["ip"]
    server_port = config["server"]["port"]

    try:
        #connect to the server with specified IP and port
        client_socket.connect((server_ip, int(server_port)))
        #send entire configuration to the server as JSON
        client_socket.send(json.dumps(config).encode())

        #receive the response from the server
        response = client_socket.recv(1024).decode()
        print(f"{config['id']} - {response}")

        #perform actions if registration is successful
        if "successful" in response:
            #delay between each action, specified by the client
            delay = int(config["actions"]["delay"])
            #send each action to server and receive response
            for action in config["actions"]["steps"]:
                client_socket.send(action.encode())
                response = client_socket.recv(1024).decode()
                print(f"{config['id']} - {response}")
                #pause for the specified delay
                time.sleep(delay)
    finally:
        #close the client socket connection when actions are done
        client_socket.close()
        print(f"{config['id']} - Disconnected")

#function to start multiple clients at once using a config file
def start_clients(config_file):
    #load the client configurations from JSON file
    with open(config_file, 'r') as file:
        clients = json.load(file)

    #intialize a list of threads to run each client
    threads = []
    #in the for loop, start a thread for each client
    for config in clients:
        thread = threading.Thread(target=start_single_client, args=(config,))
        threads.append(thread)
        thread.start()

    #wait for all the threads to finish
    for thread in threads:
        thread.join()

#run the client script
if __name__ == "__main__":
    start_clients("client_config.json")
