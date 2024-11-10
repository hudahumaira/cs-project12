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
