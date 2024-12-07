## please have a look at the README.md file for the list of vulnerabilities
## and their respective fixes

import socket
import json
import time
import ssl
import uuid

# Constants for limits
MAX_DELAY = 60
MAX_ID_LENGTH = 32
MAX_PASSWORD_LENGTH = 64
MAX_AMOUNT = 1_000_000
MAX_ACTIONS = 50

# Start client with secure connection
def start_client(config):
    context = ssl.create_default_context()
    context.load_verify_locations("server_cert.pem")
    server_ip = config["server"]["ip"]
    server_port = int(config["server"]["port"])

    try:
        with socket.create_connection((server_ip, server_port)) as sock:
            with context.wrap_socket(sock, server_hostname=server_ip) as client_socket:

                # Validate delay
                delay_value = config["actions"]["delay"]
                delay = int(delay_value) if delay_value.isdigit() and int(delay_value) <= MAX_DELAY else None
                if delay is None:
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

                if not valid_actions:
                    print(f"{config['id']}: No valid actions to process.")
                    return

                # Add nonce and timestamp to configuration
                config["nonce"] = str(uuid.uuid4())
                config["timestamp"] = int(time.time())
                config["actions"]["steps"] = valid_actions

                try:
                    client_socket.send(json.dumps(config).encode())
                except Exception:
                    print(f"{config['id']}: Error sending configuration.")
                    return


               
                # Process actions
                # print(valid_actions)
                response = client_socket.recv(1024).decode()
                print(f"{config['id']}: {response}")
                time.sleep(delay)
                for action in valid_actions:
                    response = client_socket.recv(1024).decode()
                    print(f"{config['id']}: {response}")
                    time.sleep(delay)
    except Exception as e:
        print(f"{config['id']}: Unexpected error: {e}")


if __name__ == "__main__":
    with open("client_config.json", "r") as file:
        clients = json.load(file)
        for config in clients:
            start_client(config)
