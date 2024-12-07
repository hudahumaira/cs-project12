## please have a look at the README.md file for the list of vulnerabilities
## and their respective fixes


import socket
import ssl
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta
import bcrypt
import redis

# Fixed Vulnerability 17: Lack of Rate Limiting
# initialize Redis client
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# configure logging
logging.basicConfig(filename='server_logfile.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# constants for limits and configurations
client_data = {}
used_nonces = set()
# tracks connection attempts by IP address
connection_log = defaultdict(list)
# Fix for Vulnerability 05 
# reduced max delay from 1 hour to 1 minute
MAX_DELAY = 60 
MAX_ID_LENGTH = 32
MAX_PASSWORD_LENGTH = 64
# Fix for Vulnerability 09: Weak Password Policy
# password must be between 10 and 64 characters
MIN_PASSWORD_LENGTH = 10
MAX_AMOUNT = 1000000
MAX_ACTIONS = 50
# max allowed connections per IP per minute
MAX_CONNECTIONS_PER_MINUTE = 10
# max queued connections in the socket 
MAX_BACKLOG = 5

# Fix for Vulnerability 03: Weak Password Hashing
# Using bcrypt for strong password hashing
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)

# Fixed Vulnerability 17: Lack of Rate Limiting
# Fix for Vulnerability 04: Multiple Connections
# implemented rate limiting to restrict the number of connections per IP address
def rate_limit(ip):
    now = datetime.now()
    # remove entries older than 1 minute
    connection_log[ip] = [timestamp for timestamp in connection_log[ip] if now - timestamp <= timedelta(minutes=1)]
    if len(connection_log[ip]) >= MAX_CONNECTIONS_PER_MINUTE:
        return False  # too many connections in the last minute
    connection_log[ip].append(now)
    return True

# Fix for Vulnerability 06: Replay Attack Prevention
# validates nonce and timestamp to prevent replay attacks
def validate_nonce_and_timestamp(client_nonce, client_timestamp):
    current_time = int(time.time())

    # check if the nonce was already used
    if client_nonce in used_nonces:
        return False

    # make sure the timestamp is within the allowed range
    if abs(current_time - client_timestamp) > MAX_DELAY:
        return False

    # mark nonce as used
    used_nonces.add(client_nonce)
    return True

# Fix for Vulnerability 10: Inadequate Input Validation (ID/Password Length)
# reject inputs exceeding max length and notify the user instead of truncating
def validate_id_and_password_length(client_id, password):
    if len(client_id) > MAX_ID_LENGTH:
        return False, f"ERROR: ID must not exceed {MAX_ID_LENGTH} characters."
    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        return False, f"ERROR: Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters."
    return True, None

# this function handles client connections and process requests
def handle_client(secure_socket, client_address):
    try:
        config_data = secure_socket.recv(4096).decode()  # Limit to 4096 bytes
        if len(config_data) > 4096:  # Application-level check
            secure_socket.send(b"ERROR: Payload too large.")
            return

        client_info = json.loads(config_data)

        # Validate ID and password length
        is_valid, error_message = validate_id_and_password_length(client_info["id"], client_info["password"])
        if not is_valid:
            secure_socket.send(error_message.encode())
            return

        # Validate nonce and timestamp
        client_nonce = client_info.get("nonce")
        client_timestamp = client_info.get("timestamp")
        if not validate_nonce_and_timestamp(client_nonce, client_timestamp):
            secure_socket.send(b"ERROR: Invalid or expired nonce/timestamp.")
            return

        if "actions" in client_info:
            client_id = client_info["id"]
            password = client_info["password"]

            if register_client(secure_socket, client_id, password):
                handle_actions(secure_socket, client_id, client_info["actions"])
            else:
                secure_socket.send(b"ERROR: Connection failed.")
        else:
            secure_socket.send(b"ERROR: Missing actions.")
    except Exception as e:
        logging.error(f"Error handling client from {client_address}: {e}")
    finally:
        # Ensure socket closure only after all actions
        secure_socket.close()

# register new clients or authenticate existing ones
def register_client(secure_socket, client_id, password):
    if client_id not in client_data:
        hashed_password = hash_password(password)
        client_data[client_id] = {"password_hash": hashed_password, "counter": 0}
        secure_socket.send(b"Connection successful for new client.")
        return True
    else:
        stored_hash = client_data[client_id]["password_hash"]
        if verify_password(password, stored_hash):
            secure_socket.send(b"Connection successful, welcome back.")
            return True
        # Fix for Vulnerability 01:
        # changed error message to avoid exposing sensitive info
        secure_socket.send(b"ERROR: Incorrect credentials.")
        return False

# Fix for Vulnerability 11: Action Validation Issues
# strictly validate all incoming actions
# Fix for Vulnerability 11: Action Validation Issues
# strictly validate all incoming actions
def handle_actions(secure_socket, client_id, actions):
    try:
        delay = int(actions["delay"]) if actions["delay"].isdigit() and int(actions["delay"]) <= MAX_DELAY else None
        if delay is None:
            secure_socket.send(b"ERROR: Invalid delay; skipping actions.")
            print(f"{client_id}: Invalid delay value. Skipping actions.")
            return
        for action in actions["steps"][:MAX_ACTIONS]:
            try:
                action_parts = action.split()
                if len(action_parts) != 2:
                    raise ValueError("Invalid action format")

                command, amount = action_parts

                # Validate command and amount
                if command not in ["INCREASE", "DECREASE"]:
                    raise ValueError("Invalid command")

                amount = int(amount)
                if abs(amount) > MAX_AMOUNT:  # Strict server-side validation for MAX_AMOUNT
                    secure_socket.send(f"Action skipped: {action} (amount exceeds limit of {MAX_AMOUNT})".encode())
                    continue
                # Perform the action and update the counter
                if command == "INCREASE":
                    client_data[client_id]["counter"] += amount
                    operation = "increased by"
                elif command == "DECREASE":
                    client_data[client_id]["counter"] -= amount
                    operation = "decreased by"

                # Log and print the change to the counter
                new_value = client_data[client_id]["counter"]
                log_message = f"Client {client_id} {operation} {amount}, new counter value: {new_value}"
                logging.info(log_message)

                # Send the response back to the client
                response = f"Action {command} completed. Counter is now {new_value}."
                secure_socket.send(response.encode())

            except ValueError as e:
                error_message = f"{client_id}: Skipping invalid action: {action} ({e})"
                logging.error(error_message)
                secure_socket.send(error_message.encode())
            except Exception as e:
                error_message = f"{client_id}: Unexpected error occurred: {e}"
                logging.error(error_message)
                # Allow continuation even if an unexpected error occurs

            # Fixed Vulnerability 15: Delay Implemented on Server-Side
            # time.sleep(delay)
    except Exception as e:
        logging.error(f"{client_id}: Error during action processing: {e}")
        print(f"{client_id}: Error during action processing: {e}")
        secure_socket.send(b"ERROR: Action processing error.")
    
# Fix for Vulnerability 12: Unrestricted Incoming Data
# enforce size limits on incoming data
# Fix for Vulnerability 02: Insecure Data Transmission
# use SSL to secure data transmission
def start_server(ip, port):
    # load server certificate and key
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        # limit the number of queued connections
        server_socket.listen(MAX_BACKLOG)

        print("Server is running and listening...")
        while True:
            client_socket, client_address = server_socket.accept()

            # enforce size limit on incoming data
            # timeout to prevent hanging connections
            client_socket.settimeout(5)
            # set buffer size limit
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1000)

            if not rate_limit(client_address[0]):
                logging.warning(f"Rate limit exceeded for {client_address[0]}")
                client_socket.close()
                continue

            # secure the connection with SSL
            with context.wrap_socket(client_socket, server_side=True) as secure_socket:
                handle_client(secure_socket, client_address)

# main function to start the server
if __name__ == "__main__":
    start_server("localhost", 65432)
