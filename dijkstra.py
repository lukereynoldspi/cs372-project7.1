import sys
import json
import math  # If you want to use math.inf for infinity
import netfuncs
SLASH = "/24" # Subnet mask number
    
def dijkstras_shortest_path(routers, src_ip, dest_ip):
    """
    This function takes a dictionary representing the network, a source
    IP, and a destination IP, and returns a list with all the routers
    along the shortest path.

    The source and destination IPs are **not** included in this path.

    Note that the source IP and destination IP will probably not be
    routers! They will be on the same subnet as the router. You'll have
    to search the routers to find the one on the same subnet as the
    source IP. Same for the destination IP. [Hint: make use of your
    find_router_for_ip() function from the last project!]

    The dictionary keys are router IPs, and the values are dictionaries
    with a bunch of information, including the routers that are directly
    connected to the key.

    This partial example shows that router `10.31.98.1` is connected to
    three other routers: `10.34.166.1`, `10.34.194.1`, and `10.34.46.1`:

    {
        "10.34.98.1": {
            "connections": {
                "10.34.166.1": {
                    "netmask": "/24",
                    "interface": "en0",
                    "ad": 70
                },
                "10.34.194.1": {
                    "netmask": "/24",
                    "interface": "en1",
                    "ad": 93
                },
                "10.34.46.1": {
                    "netmask": "/24",
                    "interface": "en2",
                    "ad": 64
                }
            },
            "netmask": "/24",
            "if_count": 3,
            "if_prefix": "en"
        },
        ...

    The "ad" (Administrative Distance) field is the edge weight for that
    connection.

    **Strong recommendation**: make functions to do subtasks within this
    function. Having it all built as a single wall of code is a recipe
    for madness.
    """
    # Uses code from Project 6 to compare subnets
    src_router = netfuncs.find_router_for_ip(routers, src_ip)
    dest_router = netfuncs.find_router_for_ip(routers, dest_ip)
    if netfuncs.ips_same_subnet(src_router, dest_router, SLASH) == True:
        return [] # Returns an empty array if on same subnet, /24 used for testing
    
    # Dijkstra set and dictionaries
    to_visit = set()
    distance = {}
    parent = {}

    # Initializes variables
    for router in routers:
        parent[router] = None
        distance[router] = math.inf
        to_visit.add(router)
    distance[src_router] = 0

    while len(to_visit) != 0:
        # Removes node with smallest distance
        current_node = next(iter(to_visit))
        for node in to_visit:
            if distance[node] < distance[current_node]:
                current_node = node
        to_visit.remove(current_node)

        # Gets the shortest distance from neighboring nodes
        for neighbor in routers[current_node]["connections"]:
            if neighbor in to_visit:
                node_distance = distance[current_node] + routers[current_node]["connections"][neighbor]["ad"] # Adds distance of current node with edge weight
                if node_distance < distance[neighbor]:
                    distance[neighbor] = node_distance
                    parent[neighbor] = current_node
    
    current_node = dest_router
    path = get_path(src_router, current_node, parent)

    return path

def get_path(src_router, current_node, parent):
    path = []
    while current_node != src_router:
        path.append(current_node)
        current_node = parent[current_node]
    path.append(src_router)
    path.reverse() # Reverses path 
    return path

#------------------------------
# DO NOT MODIFY BELOW THIS LINE
#------------------------------
def read_routers(file_name):
    with open(file_name) as fp:
        data = fp.read()

    return json.loads(data)

def find_routes(routers, src_dest_pairs):
    for src_ip, dest_ip in src_dest_pairs:
        path = dijkstras_shortest_path(routers, src_ip, dest_ip)
        print(f"{src_ip:>15s} -> {dest_ip:<15s}  {repr(path)}")

def usage():
    print("usage: dijkstra.py infile.json", file=sys.stderr)

def main(argv):
    try:
        router_file_name = argv[1]
    except:
        usage()
        return 1

    json_data = read_routers(router_file_name)

    routers = json_data["routers"]
    routes = json_data["src-dest"]

    find_routes(routers, routes)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
    
