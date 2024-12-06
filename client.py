import socket
import json
import time

MAX_DELAY = 3600
MAX_ID_LENGTH = 32
MAX_PASSWORD_LENGTH = 64
MAX_AMOUNT = 1_000_000
MAX_ACTIONS = 50


def start_client(config):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = config["server"]["ip"]
    server_port = int(config["server"]["port"])

    try:
        # Validate and truncate ID and password
        config["id"] = config["id"][:MAX_ID_LENGTH]
        config["password"] = config["password"][:MAX_PASSWORD_LENGTH]

        # Validate delay
        delay_value = config["actions"]["delay"]
        if delay_value.isdigit() and int(delay_value) <= MAX_DELAY:
            delay = int(delay_value)
        else:
            print(f"{config['id']}: Invalid delay value. Skipping actions.")
            return

        # Validate actions
        valid_actions = []
        for action in config["actions"]["steps"][:MAX_ACTIONS]:
            parts = action.split()
            if len(parts) == 2 and parts[0] in ["INCREASE", "DECREASE"] and parts[1].lstrip('-').isdigit():
                amount = int(parts[1])
                if abs(amount) <= MAX_AMOUNT:
                    valid_actions.append(action)
                else:
                    print(f"{config['id']}: Skipping action due to large amount: {action}")
            else:
                print(f"{config['id']}: Skipping invalid action: {action}")

        if not valid_actions:
            print(f"{config['id']}: No valid actions to process.")
            return

        config["actions"]["steps"] = valid_actions

        # Connect to the server
        client_socket.connect((server_ip, server_port))
        client_socket.send(json.dumps(config).encode())

        # Receive server response
        response = client_socket.recv(1024).decode()
        print(f"{config['id']}: {response}")

        # Process actions
        if "successful" in response:
            for action in valid_actions:
                client_socket.send(action.encode())
                response = client_socket.recv(1024).decode()
                print(f"{config['id']}: {response}")
                time.sleep(delay)
    finally:
        client_socket.close()
        print(f"{config['id']}: Disconnected")


if __name__ == "__main__":
    with open("client_config.json", "r") as file:
        clients = json.load(file)
        for config in clients:
            start_client(config)
