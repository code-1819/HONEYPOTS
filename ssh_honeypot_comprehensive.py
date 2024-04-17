import paramiko
import socket
import threading
import logging
import geoip2.database

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
                # If the number of failed attempts exceeds threshold (e.g., 3), trigger alert
                trigger_alert(f"Suspicious activity: Brute-force attempt detected for user {username}")
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

    # Method to handle SSH command execution
    def check_channel_exec_request(self, channel, command):
        # Log the executed command
        logging.info(f"Command executed: {command}")

        # For demonstration, respond with a predetermined output based on the command
        if command.startswith("ls"):
            response = "file1.txt file2.txt file3.txt"
        elif command.startswith("cat"):
            response = "Content of file1.txt"
        else:
            response = "Command not recognized"

        # Send the response back to the client
        channel.send(response)

        # Indicate that the command was successfully handled
        return True


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

    # Gather geolocation information
    geo_info = get_geolocation(client_sock.getpeername()[0])
    logging.info(f"Geolocation information: {geo_info}")


# Function to trigger alerts
def trigger_alert(message):
    # Log the alert message
    logging.warning(message)
    # You can implement additional actions here such as sending emails or notifications


# Function to get geolocation information
def get_geolocation(ip_address):
    # Path to the GeoLite2 database file
    geoip_database_path = 'GeoLite2-City.mmdb'

    # Initialize GeoIP2 database reader
    with geoip2.database.Reader(geoip_database_path) as reader:
        try:
            # Retrieve geolocation information based on the IP address
            response = reader.city(ip_address)
            geo_info = {
                'city': response.city.name,
                'country': response.country.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
            return geo_info
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"


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
