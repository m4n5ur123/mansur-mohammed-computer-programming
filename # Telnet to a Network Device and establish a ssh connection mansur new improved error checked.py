# Telnet to a network device
# Establish an SSH connection
import pexpect  # Import pexpect module for managing child applications

# Prompt the user to enter Telnet credentials
def get_telnet_credentials():
    ip_address = input('Enter IP address: ')
    username = input('Enter username: ')
    password = input('Enter password: ')
    return ip_address, username, password

# Prompt the user to enter SSH credentials
def gather_ssh_info():
    ip_address = input('Enter IP address: ')
    password = input('Enter password: ')
    enable_password = input('Enter enable password: ')
    return ip_address, username, password, enable_password

# Create a Telnet session
def create_telnet_session(ip_address, username, password):
    try:
        # Start Telnet session
        session = pexpect.spawn(f'telnet {ip_address}', encoding='utf-8', timeout=20)
        result = session.expect(['Username:', pexpect.TIMEOUT])

        # Check if the session is created properly
        if result != 0:
            print(f'--- Error: Unable to connect to {ip_address} via Telnet.')
            return None

        # Enter username
        session.sendline(username)
        result = session.expect(['Password:', pexpect.TIMEOUT])
        if result != 0:
            print(f'--- Error: Incorrect username for {ip_address}.')
            return None

        # Enter password
        session.sendline(password)
        result = session.expect(['#', pexpect.TIMEOUT])
        if result != 0:
            print(f'--- Error: Incorrect password for {ip_address}.')
            return None

        # Display success message
        print(f'--- Telnet connection established to {ip_address}')
        return session
    except Exception as e:
        print(f'--- Telnet session creation failed: {str(e)}')
        return None

# Create an SSH session
def create_ssh_session(ip_address, username, password, enable_password):
    try:
        # Start SSH session
        session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
        result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

        # Check if the session is created properly
        if result != 0:
            print(f'--- Error: Unable to connect to {ip_address} via SSH.')
            return None

        # Enter password
        session.sendline(password)
        result = session.expect(['>', '#', pexpect.TIMEOUT, pexpect.EOF])
        if result not in [0, 1]:
            print(f'--- Error: Incorrect SSH password for {ip_address}.')
            return None

        # Enter enable mode
        session.sendline('enable')
        result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('--- Error: Failed to enter enable mode.')
            return None

        # Enter enable password
        session.sendline(enable_password)
        result = session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('--- Error: Incorrect enable password.')
            return None

        # Display success message
        print(f'--- SSH connection established to {ip_address}')
        return session
    except Exception as e:
        print(f'--- SSH session creation failed: {str(e)}')
        return None

# Main function to handle user input and establish either Telnet or SSH connection
def main():
    # Prompt the user to choose either Telnet or SSH
    choice = input("Enter 'Telnet' to use Telnet or 'SSH' to use SSH: ").strip().lower()

    if choice == 'telnet':
        # Get Telnet credentials
        ip_address, username, password = get_telnet_credentials()
        # Create Telnet session
        session = create_telnet_session(ip_address, username, password)

        if session:
            # Example command execution after Telnet session is established
            session.sendline('show ip interface brief')
            session.expect('#')
            print(session.before)  # Print the output of the command
            session.sendline('exit')  # Exit the Telnet session
            session.close()  # Close the session
    elif choice == 'ssh':
        # Get SSH credentials
        ip_address, username, password, enable_password = gather_ssh_info()
        # Create SSH session
        session = create_ssh_session(ip_address, username, password, enable_password)

        if session:
            # Example command execution after SSH session is established
            session.sendline('show ip interface brief')
            session.expect('#')
            print(session.before)  # Print the output of the command
            session.sendline('exit')  # Exit the SSH session
            session.close()  # Close the session
    else:
        # Handle invalid choice
        print("Invalid choice. Please enter 'Telnet' or 'SSH'.")

# Entry point for the script
if __name__ == "__main__":
    main()