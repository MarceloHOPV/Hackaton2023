from scapy.all import *
import psutil
from collections import defaultdict
import os
from threading import Thread
import pandas as pd
import socket

# Endereço da máquina local
HOST = '127.0.0.1'  

# Portas efêmeras utilizadas para comunicação por socket
PORT_NETWORK_TRAFFIC = 50000  
PORT_PROTOCOL_TRAFFIC = 50001
PORT_HOSTNAME_TRAFFIC = 50002
# TODO: Create function to fetch traffic per hostname

# Intervalo de esgotação (em segundos) para todos os sockets
SOCKET_TIMEOUT = 5

# Atraso padrão (em segundos) para envio de informação 
# Esse atraso é compartilhado entre todas as funções que enviam informações via comunicação por socket
# Ele NÃO afeta a taxa de captura de pacotes do Scapy 
INFO_DELAY = 1

# Variável que armazena todas as interfaces de rede disponíveis
all_macs = set()

for iface in psutil.net_if_addrs():
    try:
        mac = psutil.net_if_addrs()[iface][0].address.lower()
        if(os.name == "nt"):
            mac = mac.replace("-", ":")
    except:
        mac = psutil.net_if_addrs()[iface][0].address
    finally:
        all_macs.add(mac)

# Dicionário que mapeia cada conexão com o seu respection ID de processo (PID)
connection2pid = {}

# Dicionário que mapeia cada PID a um total de tráfego de Upload (0) e Download(1)
pid2traffic = defaultdict(lambda: [0, 0])

# Dicionário que mapeia cada protocolo a um total de tráfego(0), Upload(1) e Download(2)
protocol2traffic = defaultdict(lambda: [0, 0, 0])

# Dicionário que mapeia cada host a um total de tráfego(0), Upload(1) e Download(2)
host2traffic = defaultdict(lambda: [0, 0, 0])

# The global Pandas DataFrame that's used to track previous traffic stats
global_df = None
process_traffic_df = None
protocol_traffic_df = None
host_traffic_df = None

# Global boolean for status of the program
is_program_running = True

def get_size(bytes):
    """
    Returns the formatted size of bytes, up to Petabytes
    """

    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024


def get_traffic_by_protocol(packet):
    """
    Translates the port and protocol numbers to protocol name and stores the protocol along with upload/download statistics into the `protocol2traffic` dict
    """

    global protocol2traffic
    port = 0
    is_source = False

    if(packet.haslayer(IP)):
        try:
            packet_ports = (packet.sport, packet.dport)
        except AttributeError:
            # If the IP Layer does not contain source/destination ports, the packet is ignored
            pass
        else:
            # Check whether the protocol is being stored on the source or destionation port
            if(packet.src not in all_macs):
                port = packet_ports[0]
                is_source = True
            else:
                port = packet_ports[1]

            protocol = IP().get_field("proto").i2s[packet[IP].proto]

            try:
                service_name = socket.getservbyport(port, protocol)
            except OSError:
                # "socket.getservbyport" has a limited amount of port-protocol combinations. If none match, we simply label the service as "others"
                service_name = "others"
            

            protocol2traffic[service_name][0] += len(packet)
            if(is_source):
                protocol2traffic[service_name][1] += len(packet)
            else:
                protocol2traffic[service_name][2] += len(packet)

def get_traffic_by_process(packet):
    """
    Maps each connection to a process ID and store this information along with download/upload statics into the `pid2traffic` dict
    """
    global pid2traffic
    try:
        # Get the packet source & destination IP addresses and ports
        packet_connection = (packet.sport, packet.dport)
    except (AttributeError, IndexError):
        # Sometimes the packet does not have TCP/UDP layers, we just ignore these packets
        pass
    else:
        # Get the PID responsible for this connection from our `connection2pid` global dictionary
        packet_pid = connection2pid.get(packet_connection)
        if packet_pid:
            if packet.src in all_macs:
                # The source MAC address of the packet is our MAC address
                # So it's an outgoing packet, meaning it's upload
                pid2traffic[packet_pid][0] += len(packet)
            else:
                # Incoming packet, download
                pid2traffic[packet_pid][1] += len(packet)

def get_traffic_by_host(packet):
    global host2traffic
    is_source = False
    ip = ""
        
    if(packet.haslayer(IP)):
        if(packet.src not in all_macs):
            ip = packet[IP].src
            is_source = True
        else:
            ip = packet[IP].dst

        host2traffic[ip][0] += len(packet)
        if(is_source):
            host2traffic[ip][1] += len(packet)
        else:
            host2traffic[ip][2] += len(packet)

def process_packet(packet):
    """
    A function that process the packets into information used by the traffic analyzer.
    It is used as a callback for Scapy's sniff() function.
    All relevant data are stored into dictionaries.
    """

    get_traffic_by_process(packet)
    get_traffic_by_protocol(packet)
    get_traffic_by_host(packet)
    

def get_connections():
    """A function that keeps listening for connections on this machine 
    and adds them to `connection2pid` dict"""

    global connection2pid
    # While is_program_running:
        # Using psutil, we can grab each connection's source and destination ports
        # And their process ID
    for c in psutil.net_connections():
        if c.laddr and c.raddr and c.pid:
            # If local address, remote address and PID are in the connection
            # Add them to our global dictionary
            connection2pid[(c.laddr.port, c.raddr.port)] = c.pid
            connection2pid[(c.raddr.port, c.laddr.port)] = c.pid

def encode_traffic_by_process():
    """
    Function that encodes the traffic by process dictionary into a dataframe and a JSON.
    The dataframe is printed into the console, while the JSON is output by socket communication.
    """

    global global_df, process_traffic_df
    # Initialize the list of processes
    processes = []
    for pid, traffic in pid2traffic.items():
        # `pid` is an integer that represents the process ID
        # `traffic` is a list of two values: total Upload and Download size in bytes
        try:
            # Get the process object from psutil
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            # If process is not found, simply continue to the next PID for now
            continue
        # Get the name of the process, such as chrome.exe, etc.
        name = p.name()
        # Get the time the process was spawned
        try:
            create_time = datetime.fromtimestamp(p.create_time())
        except OSError:
            # System processes, using boot time instead
            create_time = datetime.fromtimestamp(psutil.boot_time())
        # Construct our dictionary that stores process info
        process = {
            "pid": pid, "name": name, "create_Time": create_time.strftime("%d/%m/%Y, %H:%M:%S"), "last_time_updated": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            "upload": traffic[0], "download": traffic[1],
        }
        try:
            # Calculate the upload and download speeds by simply subtracting the old stats from the new stats
            process["upload_speed"] = traffic[0] - global_df.at[pid, "upload"]
            process["download_speed"] = traffic[1] - global_df.at[pid, "download"]
        except (KeyError, AttributeError):
            # If it's the first time running this function, then the speed is the current traffic
            # You can think of it as if old traffic is 0
            process["upload_speed"] = traffic[0]
            process["download_speed"] = traffic[1]
        # Append the process to our processes list
        processes.append(process)
    # Construct our Pandas DataFrame

    df = pd.DataFrame(processes)

    try:
        # Set the PID as the index of the dataframe
        df = df.set_index("pid")
        # Sort by column, feel free to edit this column
        df.sort_values("download", inplace=True, ascending=False)
    except KeyError:
        # When dataframe is empty
        pass

    # Make another copy of the dataframe just for fancy printing
    printing_df = df.copy()

    try:
        # Apply the function get_size to scale the stats like '532.6KB/s', etc.
        printing_df["download"] = printing_df["download"].apply(get_size)
        printing_df["upload"] = printing_df["upload"].apply(get_size)
        printing_df["download_speed"] = printing_df["download_speed"].apply(get_size).apply(lambda s: f"{s}/s")
        printing_df["upload_speed"] = printing_df["upload_speed"].apply(get_size).apply(lambda s: f"{s}/s")
    except KeyError:
        # When dataframe is empty again
        pass

    df_json = printing_df.to_json(orient='index').encode()

    # Update the global and process_traffic dataframes to our dataframe
    global_df = df
    process_traffic_df = printing_df

    return df_json

def encode_traffic_by_protocol():
    """
    Function that encodes the traffic by protocol dictionary into a dataframe and a JSON.
    The dataframe is printed into the console, while the JSON is output by socket communication.
    """

    global protocol_traffic_df
    protocols = []

    for proto_name, traffic in protocol2traffic.items():
        try:
            protocol = {"protocol" : proto_name, "total": traffic[0], "download": traffic[1], "upload": traffic[2]}
            protocols.append(protocol)
        except KeyError:
            pass
 
    df = pd.DataFrame(protocols)

    try:
        df = df.set_index("protocol")
    except KeyError:
        # when dataframe is empty
        pass

    printing_df = df.copy()

    try:
        printing_df["total"] = printing_df["total"].apply(get_size)
        printing_df["download"] = printing_df["download"].apply(get_size)
        printing_df["upload"] = printing_df["upload"].apply(get_size)
    except KeyError:
        # when dataframe is empty again
        pass

    # Converts dataframe to JSON and sends it to clients connected to the PORT_PROTOCOL_USAGE
    df_json = printing_df.to_json(orient='index').encode()

    protocol_traffic_df = printing_df

    return df_json

def encode_traffic_by_host():
    global host_traffic_df
    hosts = []

    for host_name, traffic in host2traffic.items():
        try:
            host = {"host" : host_name,  "total": traffic[0], "download": traffic[1], "upload": traffic[2]}
            hosts.append(host)
        except KeyError:
            pass

    df = pd.DataFrame(hosts)

    try:
        df = df.set_index("hosts")
    except KeyError:
        # when dataframe is empty
        pass

    printing_df = df.copy()

    try:
        printing_df["total"] = printing_df["total"].apply(get_size)
        printing_df["download"] = printing_df["download"].apply(get_size)
        printing_df["upload"] = printing_df["upload"].apply(get_size)
    except KeyError:
        # when dataframe is empty again
        pass

    df_json = printing_df.to_json(orient='index').encode()

    host_traffic_df = printing_df

    return df_json


def send_traffic_by_protocol():
    """
    Sends all protocol/network statistics by socket communication.
    This function runs in its Thread to optimize performance and allow parallel socket connections.
    """

    protocol_socket = socket.socket()

    try:
        protocol_socket.bind((HOST, PORT_PROTOCOL_TRAFFIC))
    except OSError:
        print("Port",PORT_PROTOCOL_TRAFFIC,"already in use, unable to bind port to socket.")
    else:
        protocol_socket.listen(1)
        print("Waiting for client connection on port", PORT_PROTOCOL_TRAFFIC, "for streaming network usage per protocol.")
    
        client_socket, client_address = protocol_socket.accept()
        print("Client connected on", client_address, ". Now streaming network usage per protocol.")

        protocol_socket.settimeout(SOCKET_TIMEOUT)

        while is_program_running:
            time.sleep(INFO_DELAY)
            json = encode_traffic_by_protocol()

            response = (
                'HTTP/1.1 200 OK\r\n'
                'Content-Type: application/json\r\n'
                'Access-Control-Allow-Origin: *\r\n'
                'Access-Control-Allow-Headers: Content-Type\r\n'
                'Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n'
                f'Content-Length: {len(json)}\r\n'
                '\r\n'
                f'{json}\r\n'
            )

            try:
                client_socket.sendall(response.encode())
            except (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError, BrokenPipeError):
                print(f"Connection problem on port {PORT_PROTOCOL_TRAFFIC}")
                client_socket, client_address = attempt_socket_reconnection(protocol_socket, PORT_PROTOCOL_TRAFFIC, 5)
                if(client_socket == False):
                    print("Connection aborted by client, closing thread.")
                    break
                else:
                    print("Connection reestablished.")
                    continue

def send_traffic_by_process():
    """
    Sends all process/network statistics by socket communication.
    This function runs in its Thread to optimize performance and allow parallel socket connections.
    """

    process_socket = socket.socket()

    try:
        process_socket.bind((HOST, PORT_NETWORK_TRAFFIC))
    except OSError:
        print("Port",PORT_NETWORK_TRAFFIC,"already in use, unable to bind port to socket.")
    else:
        process_socket.listen(1)
        print("Waiting for client connection on port", PORT_NETWORK_TRAFFIC, "for streaming network usage per application.")

        client_socket, client_address = process_socket.accept()
        print("Client connected on", client_address, ". Now streaming network usage per application.")

        process_socket.settimeout(SOCKET_TIMEOUT)

        while is_program_running:
            time.sleep(INFO_DELAY)
            get_connections()
            json = encode_traffic_by_process()

            response = (
                'HTTP/1.1 200 OK\r\n'
                'Content-Type: application/json\r\n'
                'Access-Control-Allow-Origin: *\r\n'
                'Access-Control-Allow-Headers: Content-Type\r\n'
                'Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n'
                f'Content-Length: {len(json)}\r\n'
                '\r\n'
                f'{json}\r\n'
            )

            try:
                client_socket.sendall(response.encode())
            except (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError, BrokenPipeError):
                print(f"Connection problem on port {PORT_NETWORK_TRAFFIC}")
                client_socket, client_address = attempt_socket_reconnection(process_socket, PORT_NETWORK_TRAFFIC, 5)
                if(client_socket == False):
                    print("Connection aborted by client, closing thread.")
                    break
                else:
                    print("Connection reestablished.")
                    continue

def send_traffic_by_host():
    """
    Sends all host/network statistics by socket communication.
    This function runs in its Thread to optimize performance and allow parallel socket connections.
    """

    process_socket = socket.socket()

    try:
        process_socket.bind((HOST, PORT_HOSTNAME_TRAFFIC))
    except OSError:
        print("Port",PORT_HOSTNAME_TRAFFIC,"already in use, unable to bind port to socket.")
    else:
        process_socket.listen(1)
        print("Waiting for client connection on port", PORT_HOSTNAME_TRAFFIC, "for streaming network usage per host.")

        client_socket, client_address = process_socket.accept()
        print("Client connected on", client_address, ". Now streaming network usage per host.")

        process_socket.settimeout(SOCKET_TIMEOUT)

        while is_program_running:
            time.sleep(INFO_DELAY)
            json = encode_traffic_by_host()
            
            response = (
                'HTTP/1.1 200 OK\r\n'
                'Content-Type: application/json\r\n'
                'Access-Control-Allow-Origin: *\r\n'
                'Access-Control-Allow-Headers: Content-Type\r\n'
                'Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n'
                f'Content-Length: {len(json)}\r\n'
                '\r\n'
                f'{json}\r\n'
            )

            try:
                client_socket.sendall(response.encode())
            except (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError, BrokenPipeError):
                print(f"Connection problem on port {PORT_HOSTNAME_TRAFFIC}")
                client_socket, client_address = attempt_socket_reconnection(process_socket, PORT_HOSTNAME_TRAFFIC, 5)
                if(client_socket == False):
                    print("Connection aborted by client, closing thread.")
                    break
                else:
                    print("Connection reestablished.")
                    continue

def attempt_socket_reconnection(task_socket: socket, port: int, attempts: int):
    """
    Attempts to reconnect to a given socket and port by a non-negative number of attempts.
    """
    current_attempt = 1

    if attempts < 0:
        attempts = 5

    while(current_attempt <= attempts):
        print("Attempting to reconnect to port %d (%d/%d)" %(port, current_attempt, attempts))
        try:
            client_socket, client_address = task_socket.accept()
            return client_socket, client_address
        except socket.timeout:
            current_attempt += 1
            continue
    
    return False, False


def print_traffic_by_process():
    """
    Prints all processes exchanging network data in the console
    """

    while is_program_running:
        time.sleep(INFO_DELAY)
        get_connections()
        encode_traffic_by_process()

def print_traffic_by_protocol():
    """
    Prints all protocols exchanging network data in the console
    """

    while is_program_running:
        time.sleep(INFO_DELAY)
        encode_traffic_by_protocol()

def print_all_traffic():
    """
    Prints all processes, protocols and TODO:hosts exchanging network data in the console
    """

    global global_df
    global protocol_traffic_df
    while is_program_running:
        time.sleep(INFO_DELAY)
        os.system("cls") if "nt" in os.name else os.system("clear")
        
        print(process_traffic_df.to_string())
        print(protocol_traffic_df.to_string())


if __name__ == "__main__":

    traffic_by_process_thread = Thread(target=send_traffic_by_process)
    traffic_by_process_thread.start()

    traffic_by_protocol_thread = Thread(target=send_traffic_by_protocol)
    traffic_by_protocol_thread.start()

    traffic_by_host_thread = Thread(target=send_traffic_by_host)
    traffic_by_host_thread.start()

     # Starts network sniffing
    print("Network sniffer initialized.")
    sniff(prn=process_packet, store=False)
    
    # Setting the global variable to False to exit the program
    is_program_running = False   
