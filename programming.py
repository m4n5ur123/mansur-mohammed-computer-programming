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





from netmiko import ConnectHandler # type: ignore
import difflib
import os

# Define device SSH connection details
device = {
    'device_type': 'cisco_ios',
    'host': '192.168.56.101',  # Device IP address
    'username': 'cisco',
    'password': 'cisco123!',
}

def compare_configs(config1, config2, label1="Running Config", label2="Startup Config"):
    """Compare two configurations and return the differences."""
    diff = difflib.unified_diff(
        config1.splitlines(),
        config2.splitlines(),
        fromfile=label1,
        tofile=label2,
        lineterm=""
    )
    return '\n'.join(diff)

def retrieve_configs(device):
    """Retrieve running and startup configurations from the device."""
    with ConnectHandler(**device) as connection:
        running_config = connection.send_command("show running-config")
        startup_config = connection.send_command("show startup-config")
    return running_config, startup_config

def load_local_config(file_path):
    """Load an offline config file from the local system."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    with open(file_path, 'r') as file:
        return file.read()

def main(compare_to_local=False, local_file_path=None):
    # Establish SSH connection and modify hostname
    connection = ConnectHandler(**device)
    connection.send_config_set(['hostname SSHRouter'])
    connection.disconnect()

    # Retrieve running and startup configs from the device
    running_config, startup_config = retrieve_configs(device)
    
    # Compare running config with startup config
    print("Comparing Running Config with Startup Config:")
    diff_output = compare_configs(running_config, startup_config)
    print(diff_output if diff_output else "No differences found.")

    # Compare with a local config file if specified
    if compare_to_local and local_file_path:
        local_config = load_local_config(local_file_path)
        print("\nComparing Running Config with Local Config:")
        diff_output_local = compare_configs(running_config, local_config, label1="Running Config", label2="Local Config")
        print(diff_output_local if diff_output_local else "No differences found.")

# Example Usage
if __name__ == "__main__":
    # To compare with startup config only
    main()

    # To compare with a local config file
    #
    import socket
import subprocess
import platform

def get_ip_range():
    """
    Get the local IP address and generate a range for scanning.
    """
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Your local IP address is: {local_ip}")
    
    # Assuming a standard subnet of /24
    ip_parts = local_ip.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    return ip_range

def ping_sweep(ip_range):
    """
    Perform a ping sweep on the local network to find active hosts.
    """
    print(f"Scanning the network range: {ip_range}")
    active_hosts = []
    for i in range(1, 255):
        ip = f"{ip_range[:-3]}{i}"
        response = subprocess.call(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response == 0:
            print(f"Host {ip} is active.")
            active_hosts.append(ip)
        else:
            print(f"Host {ip} is inactive.")
    return active_hosts

def check_vulnerabilities(active_hosts):
    """
    Check for common vulnerabilities on active hosts.
    """
    print("\nChecking for common vulnerabilities...")
    for host in active_hosts:
        print(f"Scanning {host} for vulnerabilities...")
        # Placeholder for vulnerability checks
        # In a real-world scenario, you would integrate with a vulnerability scanning tool here
        print(f"Host {host} has no known vulnerabilities (simulated check).")

def main():
    print("Welcome to the Cybersecurity Pathway: Basic Network Scanner")
    print("This tool will help you identify active hosts on your local network and check for basic vulnerabilities.")
    
    ip_range = get_ip_range()
    active_hosts = ping_sweep(ip_range)
    
    if active_hosts:
        check_vulnerabilities(active_hosts)
    else:
        print("No active hosts found in the network range.")

if __name__ == "__main__":
    main()
    from netmiko import ConnectHandler

# Device details for SSH connection
device = {
    'device_type': 'cisco_ios',
    'host': '192.168.56.101',  # Router's IP address
    'username': 'cisco',
    'password': 'cisco123!',
}

def configure_loopback_and_interface():
    """
    Configures a loopback interface and another interface on the router.
    """
    config_commands = [
        'interface loopback0',
        'ip address 10.1.1.1 255.255.255.0',
        'no shutdown',
        'interface gigabitEthernet0/0',
        'ip address 192.168.1.1 255.255.255.0',
        'no shutdown'
    ]

    with ConnectHandler(**device) as connection:
        print("--- Configuring Loopback and GigabitEthernet Interfaces ---")
        output = connection.send_config_set(config_commands)
        print(output)


def configure_ospf():
    """
    Configures OSPF on the router and advertises networks.
    """
    ospf_commands = [
        'router ospf 1',
        'network 10.1.1.0 0.0.0.255 area 0',
        'network 192.168.1.0 0.0.0.255 area 0'
    ]

    with ConnectHandler(**device) as connection:
        print("--- Configuring OSPF Routing Protocol ---")
        output = connection.send_config_set(ospf_commands)
        print(output)


def main():
    print("Welcome to Delivery Milestone 3 Script")
    
    # Configuring interfaces
    configure_loopback_and_interface()
    
    # Configuring OSPF
    configure_ospf()

if __name__ == "__main__":
    main()