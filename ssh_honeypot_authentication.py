import paramiko
import socket
import threading
import logging

# Configure logging
logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s - %(message)s')


# Custom SSH server class inheriting from paramiko.ServerInterface
class SSHServer(paramiko.ServerInterface):
    # Dictionary to store failed login attempts
    failed_login_attempts = {}

    # Method to check authentication using password
    def check_auth_password(self, username: str, password: str) -> int:
        # Log username and password for each authentication attempt
        logging.info(f"Authentication attempt: {username}:{password}")

        # Implement basic brute-force protection
        if username in self.failed_login_attempts:
            # If username is found in failed_login_attempts dictionary
            if self.failed_login_attempts[username] >= 3:
                # If the number of failed attempts exceeds threshold (e.g., 3), reject authentication
                logging.warning(f"Brute-force attempt blocked for user: {username}")
                return paramiko.AUTH_FAILED
            else:
                # Increment failed login attempts count
                self.failed_login_attempts[username] += 1
        else:
            # If username is not found in dictionary, initialize failed login attempts count
            self.failed_login_attempts[username] = 1

        # Perform actual authentication (for demonstration, always return AUTH_FAILED)
        return paramiko.AUTH_FAILED


# Function to handle incoming connections
def handle_connections(client_sock, ssh):
    # Create a new transport instance for the client socket
    transport = paramiko.Transport(client_sock)

    # Load server's RSA private key (replace 'key' with the actual path to your private key file)
    server_key = paramiko.RSAKey.from_private_key_file('key')

    # Add server's RSA key to the transport
    transport.add_server_key(server_key)

    # Initialize SSHServer instance for handling SSH protocol negotiation
    ssh = SSHServer()

    # Start the SSH server on the transport
    transport.start_server(server=ssh)


# Main function to set up the server
def main():
    # Create a TCP socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow reusing the address
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the address and port
    server_sock.bind(('', 2222))

    # Start listening for incoming connections with a backlog of 223
    server_sock.listen(223)

    # Main server loop
    while True:
        # Accept incoming connection
        client_sock, client_addr = server_sock.accept()

        # Log connection information
        logging.info(f"Connection from {client_addr[0]}:{client_addr[1]}")

        # Spawn a new thread to handle the connection
        t = threading.Thread(target=handle_connections, args=(client_sock,))
        t.start()


# Entry point of the script
if __name__ == "__main__":
    main()
