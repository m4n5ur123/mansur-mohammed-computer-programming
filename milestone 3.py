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
    