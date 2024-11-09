import socket
import json
import time
import threading

# Define maximum allowable values to prevent overflow or errors due to large inputs
MAX_DELAY = 3600  # Maximum delay in seconds (1 hour)
MAX_ID_LENGTH = 32  # Maximum length for client ID
MAX_PASSWORD_LENGTH = 64  # Maximum length for client password
MAX_AMOUNT = 1_000_000  # Maximum amount for INCREASE or DECREASE commands
MAX_ACTIONS = 50  # Maximum number of actions allowed per client


# Function to start a single client and connect it to the server using the config
def start_single_client(config):
    # Create a new socket for client-server communication
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = config["server"]["ip"]
    server_port = config["server"]["port"]

    try:
        # Limit ID and password length to prevent overly large values from being sent
        config["id"] = config["id"][:MAX_ID_LENGTH]
        config["password"] = config["password"][:MAX_PASSWORD_LENGTH]

        # Validate the delay value in the config
        delay_value = config["actions"]["delay"]
        if delay_value.isdigit() and int(delay_value) <= MAX_DELAY:
            delay = int(delay_value)  # Set the delay if it's within the allowed limit
        else:
            print(f"{config['id']} - Invalid delay value: {delay_value}. Skipping all actions.")
            return  # Skip all actions if delay is invalid

        # Validate and filter actions based on amount limit and correct format
        valid_actions = []
        for action in config["actions"]["steps"][:MAX_ACTIONS]:  # Limit the number of actions
            parts = action.split()
            if len(parts) == 2:
                command, amount = parts
                # Ensure the command is either INCREASE or DECREASE and amount is a valid integer
                if command in ["INCREASE", "DECREASE"] and amount.lstrip('-').isdigit():
                    amount = int(amount)
                    # Only add actions with an amount within the allowed range
                    if abs(amount) <= MAX_AMOUNT:
                        valid_actions.append(action)  # Add valid action to the list
                    else:
                        print(f"{config['id']} - Skipping action due to large amount: {action}")
                else:
                    print(f"{config['id']} - Skipping invalid action format or command: {action}")
            else:
                print(f"{config['id']} - Skipping action with invalid format: {action}")

        # Continue only if there are valid actions to process
        if not valid_actions:
            print(f"{config['id']} - No valid actions to process.")
            return

        # Update the config with the validated actions list
        config["actions"]["steps"] = valid_actions

        # Connect to the server and send the configuration data
        client_socket.connect((server_ip, int(server_port)))
        client_socket.send(json.dumps(config).encode())

        # Receive and print the server's response to registration or login
        response = client_socket.recv(1024).decode()
        print(f"{config['id']} - {response}")

        # If registration/login was successful, start processing each valid action
        if "successful" in response:
            for action in valid_actions:
                # Send each action to the server and receive the response
                client_socket.send(action.encode())
                response = client_socket.recv(1024).decode()
                print(f"{config['id']} - {response}")

                # Delay between actions as specified by the client config
                time.sleep(delay)
    finally:
        # Close the client socket connection upon completion
        client_socket.close()
        print(f"{config['id']} - Disconnected")


# Function to start multiple clients at once using configurations from a file
def start_clients(config_file):
    # Load client configurations from the JSON file
    with open(config_file, 'r') as file:
        clients = json.load(file)

    threads = []  # List to keep track of client threads
    for config in clients:
        # Create a thread for each client configuration
        thread = threading.Thread(target=start_single_client, args=(config,))
        threads.append(thread)
        thread.start()  # Start the client thread

    # Wait for all threads to finish
    for thread in threads:
        thread.join()


# Main entry point to run the client script
if __name__ == "__main__":
    start_clients("client_config.json")
