import sys
import json

def ipv4_to_value(ipv4_addr):
    """
    Convert a dots-and-numbers IP address to a single numeric value.

    Example:

    There is only one return value, but it is shown here in 3 bases.

    ipv4_addr: "255.255.0.0"
    return:    0xffff0000 0b11111111111111110000000000000000 4294901760

    ipv4_addr: "1.2.3.4"
    return:    0x01020304 0b00000001000000100000001100000100 16909060
    """
    addr = '0b'
    ip_numbers = ipv4_addr.split(".")

    for ip in ip_numbers:
        addr += str(f"{int(ip):08b}") # Converts to binary with leading zeroes then a string to concat together
    return addr

def value_to_ipv4(addr):
    """
    Convert a single 32-bit numeric value to a dots-and-numbers IP
    address.

    Example:

    There is only one input value, but it is shown here in 3 bases.

    addr:   0xffff0000 0b11111111111111110000000000000000 4294901760
    return: "255.255.0.0"

    addr:   0x01020304 0b00000001000000100000001100000100 16909060
    return: "1.2.3.4"
    """
    addr = addr[2:] # Removes '0b' binary header
    binary_numbers = [addr[i:i + 8] for i in range(0, len(addr), 8)] # Splits every 8th number
    ipv4_addr = ''
    for num in binary_numbers:
        ip_numbers = int(num, 2) # Converts from binary to integer
        ipv4_addr = ipv4_addr + str(ip_numbers) + '.'
    ipv4_addr = ipv4_addr.rstrip(ipv4_addr[-1]) # Strips last period from address
    return ipv4_addr

def get_subnet_mask_value(slash):
    """
    Given a subnet mask in slash notation, return the value of the mask
    as a single number. The input can contain an IP address optionally,
    but that part should be discarded.

    Example:

    There is only one return value, but it is shown here in 3 bases.

    slash:  "/16"
    return: 0xffff0000 0b11111111111111110000000000000000 4294901760

    slash:  "10.20.30.40/23"
    return: 0xfffffe00 0b11111111111111111111111000000000 4294966784
    """

    index = slash.find('/')
    value = int(slash[index + 1:]) # Takes number after slash 
    if value == 0:
        return ipv4_to_value('0.0.0.0')
    else:
        ip_part = 0
        ipv4_addr = []
        addr_space = 256

        for i in range(value):
            ip_part = ip_part + (addr_space / 2) # Adds half of the previous value each digit of the ip address
            addr_space = addr_space / 2
            if ip_part == 255: # Appends to ipv4_addr list if digit equals 255, resets the digit and addr_space
                ipv4_addr.append(int(ip_part))
                ip_part = 0
                addr_space = 256

        if (ip_part != 255 and len(ipv4_addr) < 4): # Makes sure to add any hanging addresses less than 255
            ipv4_addr.append(int(ip_part)) 

        while len(ipv4_addr) != 4: # Appends zeroes to address if length does not fill four digits
            ipv4_addr.append(0)

        ipv4_addr = ('.'.join(str(x) for x in ipv4_addr)) # Concats address into string
        return ipv4_to_value(ipv4_addr)


def ips_same_subnet(ip1, ip2, slash):
    """
    Given two dots-and-numbers IP addresses and a subnet mask in slash
    notataion, return true if the two IP addresses are on the same
    subnet.

    FOR FULL CREDIT: this must use your get_subnet_mask_value() and
    ipv4_to_value() functions. Don't do it with pure string
    manipulation.

    This needs to work with any subnet from /1 to /31

    Example:

    ip1:    "10.23.121.17"
    ip2:    "10.23.121.225"
    slash:  "/23"
    return: True
    
    ip1:    "10.23.230.22"
    ip2:    "10.24.121.225"
    slash:  "/16"
    return: False
    """
    # Gets addresses from ipv4 and subnet of ipv4
    ip1_addr = (ipv4_to_value(ip1))
    ip2_addr = (ipv4_to_value(ip2))
    ip1_subnet = get_subnet_mask_value(ip1 + slash)
    ip2_subnet = get_subnet_mask_value(ip2 + slash)
    
    # Converts to int that way bitwise AND operator can be used
    ip1_network_number = int(ip1_addr, 2) & int(ip1_subnet, 2)
    ip2_network_number = int(ip2_addr, 2) & int(ip2_subnet, 2)

    if ip1_network_number == ip2_network_number:
        return True
    else:
        return False

def get_network(ip_value, netmask):
    """
    Return the network portion of an address value.

    Example:

    ip_value: 0x01020304
    netmask:  0xffffff00
    return:   0x01020300
    """

    network_addr = int(ip_value, 2) & int(netmask, 2)
    network_addr = bin(network_addr)
    while len(network_addr) != 34: # Adds leading zeroes to make 32 binary bytes, accounting for 0b on binary string
        network_addr = network_addr[:2] + '0' + network_addr[2:]
    return network_addr

def find_router_for_ip(routers, ip):
    """
    Search a dictionary of routers (keyed by router IP) to find which
    router belongs to the same subnet as the given IP.

    Return None if no routers is on the same subnet as the given IP.

    FOR FULL CREDIT: you must do this by calling your ips_same_subnet()
    function.

    Example:

    [Note there will be more data in the routers dictionary than is
    shown here--it can be ignored for this function.]

    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.3.5"
    return: "1.2.3.1"


    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.5.6"
    return: None
    """
    for key in routers.keys():
        routers_ip = key # Gets router ip address
        ip_data_pair = (routers[key])
        for key in ip_data_pair:
            netmask_number = str((ip_data_pair["netmask"])) # Gets netmask number from data pair
            if ips_same_subnet(ip, routers_ip, netmask_number) == True: # Checks if user ip and routers ip is on same subnet 
                return routers_ip
    return None

# Uncomment this code to have it run instead of the real main.
# Be sure to comment it back out before you submit!
"""
def my_tests():
    print("-------------------------------------")
    print("This is the result of my custom tests")
    print("-------------------------------------")

    print(x)

    # Add custom test code here
"""

## -------------------------------------------
## Do not modify below this line
##
## But do read it so you know what it's doing!
## -------------------------------------------

def usage():
    print("usage: netfuncs.py infile.json", file=sys.stderr)

def read_routers(file_name):
    with open(file_name) as fp:
        json_data = fp.read()
        
    return json.loads(json_data)

def print_routers(routers):
    print("Routers:")

    routers_list = sorted(routers.keys())

    for router_ip in routers_list:

        # Get the netmask
        slash_mask = routers[router_ip]["netmask"]
        netmask_value = get_subnet_mask_value(slash_mask)
        netmask = value_to_ipv4(netmask_value)

        # Get the network number
        router_ip_value = ipv4_to_value(router_ip)
        network_value = get_network(router_ip_value, netmask_value)
        network_ip = value_to_ipv4(network_value)

        print(f" {router_ip:>15s}: netmask {netmask}: " \
            f"network {network_ip}")

def print_same_subnets(src_dest_pairs):
    print("IP Pairs:")

    src_dest_pairs_list = sorted(src_dest_pairs)

    for src_ip, dest_ip in src_dest_pairs_list:
        print(f" {src_ip:>15s} {dest_ip:>15s}: ", end="")

        if ips_same_subnet(src_ip, dest_ip, "/24"):
            print("same subnet")
        else:
            print("different subnets")

def print_ip_routers(routers, src_dest_pairs):
    print("Routers and corresponding IPs:")

    all_ips = sorted(set([i for pair in src_dest_pairs for i in pair]))

    router_host_map = {}

    for ip in all_ips:
        router = find_router_for_ip(routers, ip)
        
        if router not in router_host_map:
            router_host_map[router] = []

        router_host_map[router].append(ip)

    for router_ip in sorted(router_host_map.keys()):
        print(f" {router_ip:>15s}: {router_host_map[router_ip]}")

def main(argv):
    if "my_tests" in globals() and callable(my_tests):
        my_tests()
        return 0

    try:
        router_file_name = argv[1]
    except:
        usage()
        return 1

    json_data = read_routers(router_file_name)

    routers = json_data["routers"]
    src_dest_pairs = json_data["src-dest"]

    print_routers(routers)
    print()
    print_same_subnets(src_dest_pairs)
    print()
    print_ip_routers(routers, src_dest_pairs)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
    