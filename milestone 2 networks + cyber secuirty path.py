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
    