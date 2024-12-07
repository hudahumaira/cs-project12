# Computer Security Project - Group 12

## Group Members:
- **Huda Humaira Ahmed**
- **Mateuez Zientała**
- **Hai Nguyen**
- **Sokratis Hadjichristodoulou**

## Overview
This project involves the implementation of a secure client-server system for our Computer Security course. In this system, each client can perform actions to increase or decrease amounts, with the server enforcing limits, authentication, and logging for security. 

## Instructions to Run the Project:
### Server
1. Start the server in the Terminal:
```bash
   python server.py
```
A message will be printed which indicates that the server is running smoothly and listening.

### Clients
1. Set up the `client_config.json` with client details (ID, password and actions). Currently, this file already contains some data.
2. Start client in another Terminal:
```bash
   python client.py
```

### Features:
- Passwords are **hashed with salt**, allowing only valid logins.
- Clients are limited to a maximum number of actions, delay time, ID and password length.
- Handles multiple sessions per client.
- Logs all actions in `server_logfile.log` with date and timestamp.

## Output
1. Server: Logs registration and actions in `server_logfile.log`
2. Client: Displays logins, action results, error messages, and logouts.

### Example of the current client output (not complete - for complete overview run the project):
```plaintext
Tom: Connection successful for new client :D 
Sarah: Skipping action due to large amount: INCREASE 1000001
Tom: Action INCREASE completed. Counter is now 10
Tom: ERROR: Incorrect password. 
Tom: Connection successful, Welcome back :) 
Tom: Disconnected
Tom: Action INCREASE completed. Counter is now 1510
Jerry: Connection successful for new client :D
....
```

## Fixing Vulnerabilities
1. Explicit Error Messages
   - Detailed errors reveal if a username or password is incorrect
   - Fix: Used generic messages like "Invalid credentials"

2. Insecure Data Transmission
   - Data is sent in plaintext
   - Fix: Used SSL/TLS to encrypt to all data

3. Weak Password Hashing
   - Deterministic salt makes password hashes predictable
   - Fix: Used random salt and secure algorithm called bcrypt
     
4. Resource Exhaustion via Multiple Connections
   - Unlimited connections can overwhelm server
   - Fix: Limit the concurrent connections & add rate limiting
     
5. Denial of Service via Large Delays
   - Long delays block server threads
   - Fix: Move delays to the client-side & limit the max delay

6. Replay Attack
   - No nonce or timestamp validation allows replays
   - Fix: Used unique nonces & timestamps; invalid after use

7. Plaintext Logging
   - Logs store sensitive data in plaintext
   - Reason for not fixing: Encryption adds debugging complexitites; not mentioned as part of project
   
8. Hardcoded Sensitive Information
   - Sensitive data is stored in plaintext
   - Reason for not fixing: The format of json file was provided in the project description hence we followed this implementation
   
9. Weak Password Policy
   - Weak passwords are allowed
   - Reason for not fixing: Stricter policies may not effectively prevent breaches. (although, max and min characters for password is implemented)
   
10. Inadequate Input Validation
   - Execessivel long inputs are truncated, causing collisions
   - Fix: Reject long inputs with proper error messages to inform clients

11. Action Validation Issues
   - Malformed or invalid actions can crash the server
   - Fix: Strictly validate incoming actions

12.  Unrestricted Incoming Data
     - No size limits allow attackers to send huge payloads
     - Fix: Enforce strict data size limits at server and network levels
      
13. Log Injection
   - Unsanitized inputs in logs can inject malicious content
   - Reason for not fixing: Logs are assumed to not execute malicious payload; increases debugging complexities

14. Vulnerable User Registration
   - Arbitrary registrations can overload the system
   - Reason for not fixing: Not implemented to avoid blocking legitimate users with shared IPs

15. Server-Side Delays
    - Server-side delays block threads
    - Fix: Moved delays to client-side

16. Unencrypted Log Files
   - Logs are stored in plaintext, exposing data
   - Reason for not fixing: Plaintext logs simplify debugging and no sensitive data is logged
     
17. Lack of Rate Limiting
   - Unlimited requests overwhelm the server
   - Implement IP-based or token-based rate limiting
