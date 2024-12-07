import socket
import json
import time
import ssl
import uuid

#constants for limits
#Vulnerability 05: Too Much Delay Allowed 
#changed the delay from 1 hour to 1 minute
MAX_DELAY = 60 
MAX_ID_LENGTH = 32
MAX_PASSWORD_LENGTH = 64
MAX_AMOUNT = 1_000_000
MAX_ACTIONS = 50

#Fix of Vulnerability 02: Insecure Data Transmission
#added SSL/TLS to secure the connection
def start_client(config):
    #create SSL context
    context = ssl.create_default_context()
    context.load_verify_locations("server_cert.pem")
    server_ip = config["server"]["ip"]
    server_port = int(config["server"]["port"])

    try:
        #secure connection
        with socket.create_connection((server_ip, server_port)) as sock:
            with context.wrap_socket(sock, server_hostname=server_ip) as client_socket:
                #validate ID and password
                config["id"] = config["id"]
                config["password"] = config["password"]

                #validate delay
                delay_value = config["actions"]["delay"]
                if delay_value.isdigit() and int(delay_value) <= MAX_DELAY:
                    delay = int(delay_value)
                else:
                    print(f"{config['id']}: Invalid delay value. Skipping actions.")
                    return

                #validate actions
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

                #add nonce and timestamp to the configuration
                #generate a unique nonce
                config["nonce"] = str(uuid.uuid4()) 
                #add the current timestamp
                config["timestamp"] = int(time.time())  
                config["actions"]["steps"] = valid_actions

                #send configuration to server
                client_socket.send(json.dumps(config).encode())

                #receive server response
                response = client_socket.recv(1024).decode()
                print(f"{config['id']}: {response}")

                #process actions
                if "successful" in response:
                    for action in valid_actions:
                        client_socket.send(action.encode())
                        response = client_socket.recv(1024).decode()
                        print(f"{config['id']}: {response}")
                        time.sleep(delay)
    except BrokenPipeError:
        print("No further actions can be taken for the client")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    with open("client_config.json", "r") as file:
        clients = json.load(file)
        for config in clients:
            start_client(config)
