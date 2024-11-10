import socket
import json
import time
import threading

#define max allowable values to prevent overflow or errors that could occur due to large inputs

#max delay betwwen actions in seconds (1hr)
MAX_DELAY = 3600
#max length for client ID
MAX_ID_LENGTH = 32
#max length for client password
MAX_PASSWORD_LENGTH = 64
#max amount for INCREASE or DECREASE actions done by the client
MAX_AMOUNT = 1_000_000
#max number of actions allowed for each client
MAX_ACTIONS = 50


#function to start a single client and connect it to the server using the config
def start_single_client(config):
    #create a new socket for client-server communication
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #get the server IP and port from the config
    server_ip = config["server"]["ip"]
    server_port = config["server"]["port"]

    try:
        #make sure that the client ID and password are within the max allowable length
        config["id"] = config["id"][:MAX_ID_LENGTH]
        config["password"] = config["password"][:MAX_PASSWORD_LENGTH]

        #validate the delay value in the config to ensure it is within the allowed limits
        delay_value = config["actions"]["delay"]
        if delay_value.isdigit() and int(delay_value) <= MAX_DELAY:
            #if it is valid, set the delay value as an integer 
            delay = int(delay_value) 
        else:
            #if it is not valid, print an error message and skip all the actions
            print(f"{config['id']}: Invalid delay value: {delay_value}. Skipping all actions.")
            return

        #create a list of valid actions 
        valid_actions = []
        #in the for loop, iterate through actions in config and validate them
        for action in config["actions"]["steps"][:MAX_ACTIONS]:
            parts = action.split()
            if len(parts) == 2:
                command, amount = parts
                #make sure that the action is only INCREASE or DECREASe and the amount is an integer
                if command in ["INCREASE", "DECREASE"] and amount.lstrip('-').isdigit():
                    amount = int(amount)
                    #make sure that the amount is within the max allowable limit
                    if abs(amount) <= MAX_AMOUNT:
                        #then add it to the list of valid actions
                        valid_actions.append(action)
                    else:
                        print(f"{config['id']}: Skipping action due to large amount: {action}")
                else:
                    print(f"{config['id']}: Skipping invalid action format or command: {action}")
            else:
                print(f"{config['id']}: Skipping action with invalid format: {action}")

        #if there are no valid actions, print a message and return
        if not valid_actions:
            print(f"{config['id']}: No valid actions to process.")
            return

        #update the list of valid actions in the config
        config["actions"]["steps"] = valid_actions

        #connect the client socket to the server and send the config as JSON
        client_socket.connect((server_ip, int(server_port)))
        client_socket.send(json.dumps(config).encode())

        #receive and print the server's response to connection
        response = client_socket.recv(1024).decode()
        print(f"{config['id']}: {response}")

        #if connection was successful, start processing each valid action
        if "successful" in response:
            for action in valid_actions:
                #send each action to the server and receive the response
                client_socket.send(action.encode())
                response = client_socket.recv(1024).decode()
                print(f"{config['id']}: {response}")

                #delay between actions as specified by the client config
                time.sleep(delay)
    finally:
        #close the client socket connection upon completion
        client_socket.close()
        print(f"{config['id']}: Disconnected")


#function to start multiple clients at once using a JSON configuration file
def start_clients(config_file):
    #load client configurations from the JSON file
    with open(config_file, 'r') as file:
        clients = json.load(file)

    #create a list of threads to run each client configuration
    threads = []
    for config in clients:
        #create a thread for each client configuration
        thread = threading.Thread(target=start_single_client, args=(config,))
        threads.append(thread)
        #start the thread
        thread.start()

    #wait for all threads to finish
    for thread in threads:
        thread.join()


#run the start_clients function if this script is executed directly
if __name__ == "__main__":
    start_clients("client_config.json")
