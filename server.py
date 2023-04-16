import socket
import struct
import sys
import threading
import os
import random
import signal
import time
from datetime import datetime
from datetime import timedelta


J=2
S=3
W=3
R=2

lock_printing = threading.Lock()
lock_clients_data = threading.Lock()
valid_clients_data = []
sockets = None
debug_mode = False
server_data = None

class Client:
    def __init__(self):
        self.state = "DISCONNECTED" 
        self.id = None
        self.mac_address = None
        self.num_ale = random.randint(0, 999999)
        self.udp_port = None
        self.ip_address = None
        self.consecutives_none_received_alives = 0
        self.is_alive_received = False
        self.is_data_received = False
        self.is_end_data_received = False
        self.data_received_timeout_exceeded = False
        self.conf_tcp_socket = None
        
       
class Server:
    def __init__(self):
        self.id = None
        self.mac_address = None
        

class Sockets:
    def __init__(self):
        self.udp_socket = None
        self.udp_port = None

        self.tcp_socket = None
        self.tcp_port = None 
        
        


def commands():
    # create thread (daemon) to handle stdin
        thread_for_stdin = threading.Thread(target=command_line_input)
        thread_for_stdin.daemon = True
        thread_for_stdin.start()
        
def command_line_input():
    try:
        while True:
            command = read_from_console()
            if command == "list":
                show_accepted_clients()
            elif command == "quit":
                os.kill(os.getpid(), signal.SIGINT)
            else:
                print_message("ERROR -> " + command + " is not an accepted command")
                show_accepted_commands()
    except (KeyboardInterrupt, SystemExit):
        return
    
    
def show_accepted_clients():
    if valid_clients_data:
        lock_printing.acquire()
        lock_clients_data.acquire()
        print("  ID   |      IP      |      MAC      | RAND NUM |     STATE     ")
        print("-------|--------------|---------------|----------|---------------")
        for client in valid_clients_data:
            print(" " + client.id + " | " + str(13 * " " if client.ip_address is None else
                  client.ip_address + " " * (13 - len(client.ip_address))) + "| " +
                  client.mac_address + "  | " + str(format(client.num_ale, "06")) + "   | " +
                  client.state + "")

        print  # simply prints new line
        sys.stdout.flush()
        lock_printing.release()
        lock_clients_data.release()
        


    

def read_from_console():
    line = sys.stdin.readline()
    return line.split("\n")[0]


def show_accepted_commands():
    print_message("INFO  -> Accepted commands are:\n" +
                  "\t\t    quit -> finishes server\n" +
                  "\t\t    list -> lists allowed clients")


def read_and_save_argv(argv):
    software_config_file = None
    allowed_clients_file = None
    
    for i, arg in enumerate(argv):
        if arg == "-d":
            global debug_mode
            debug_mode = True
            print_message("INFO  -> debug mode activated (-d)")
        elif arg == "-c" and len(argv) > i + 1:
            try:
                software_config_file = open(argv[i + 1], 'r')
            except IOError:
                print_message(f"ERROR -> Can't open file named: {argv[i + 1]}. Will open server.cfg (default config. file)")
        elif arg == "-u" and len(argv) > i + 1:
            try:
                allowed_clients_file = open(argv[i + 1], 'r')
            except IOError:
                print_message(f"ERROR -> Can't open file named: {argv[i + 1]}. Will open equips.dat (default allowed clients file)")

    if debug_mode:
        print_message("DEBUG -> Read command line input")

    if software_config_file is None:
        try:
            software_config_file = open("server.cfg", 'r')
        except IOError:
            print_message("ERROR -> Can't open default file ./client.cfg")
            exit(1)

    if allowed_clients_file is None:
        try:
            allowed_clients_file = open("equips.dat", 'r')
        except IOError:
            print_message("ERROR -> Can't open default file ./equips.dat")
            exit(1)
    
    with software_config_file, allowed_clients_file:
        save_software_config_file_data(software_config_file)
        save_allowed_clients_file_data(allowed_clients_file)

    if debug_mode:
        print_message("DEBUG -> Read data from configuration files")

def save_software_config_file_data(software_config_file):
    global server_data
    global sockets
    server_data = Server()
    sockets = Sockets()

    for line in software_config_file:
        if line.strip():
            attribute, value = line.strip().split(" ")
            if attribute == "Id":
                server_data.id = value
            elif attribute == "MAC":
                server_data.mac_address = value
            elif attribute == "UDP-port":
                sockets.udp_port = int(value)
            elif attribute == "TCP-port":
                sockets.tcp_port = int(value)

def save_allowed_clients_file_data(allowed_clients_file):
    global valid_clients_data
    num_clients = 0
    for line in allowed_clients_file:
        if line.strip():
            client = Client()
            client_id, client_mac = line.strip().split(" ")
            client.id = client_id
            client.mac_address = client_mac
            valid_clients_data.append(client)
            num_clients += 1

    if debug_mode:
        print_message("DEBUG -> Read " + str(num_clients) + " allowed clients' data")

def print_message(to_print):
    with lock_printing:
        current_time = time.strftime("%H:%M:%S", time.localtime(time.time()))
        print(f"{current_time} - {to_print}")
        sys.stdout.flush()


def setup_sockets():
    global sockets
    
    """setup the udp socket"""
    sockets.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockets.udp_socket.bind(("", sockets.udp_port))
    
    """setup the tcp socket"""
    sockets.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockets.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sockets.tcp_socket.bind(("", sockets.tcp_port))
    sockets.tcp_socket.listen(5)
    

def udp_function():
    
    """open a udp chanel and wait for connection"""
    if debug_mode:
        print_message("UDP chanel opened")
    
    while True: 
        received_package_unpacked, client_ip_address, client_udp_port = \
            receive_package_via_udp_from_client(78)

        thread_to_serve_udp_connection = threading.Thread(target=serve_udp_connection,
                                                          args=(received_package_unpacked,
                                                                client_ip_address,
                                                                client_udp_port))
        thread_to_serve_udp_connection.daemon = True
        thread_to_serve_udp_connection.start()
        
        
def receive_package_via_udp_from_client(number_of_bytes):
    received_package_packed, (client_ip_address, client_udp_port) = sockets.udp_socket.\
                                                                    recvfrom(number_of_bytes)
    received_package_unpacked = struct.unpack('B7s13s7s50s', received_package_packed)
    package_type = received_package_unpacked[0]
    client_id = received_package_unpacked[1].decode().split("\x00")[0]
    client_mac_address = received_package_unpacked[2].decode().split("\x00")[0]
    num_ale= received_package_unpacked[3].decode().split("\x00")[0]
    data = received_package_unpacked[4].decode('utf-8', 'ignore').split("\x00")[0]

    
    if debug_mode:
        print_message("DEBUG -> \t\t Received " + get_packet_string(package_type) +
                      "; \n" + "\t\t\t\t\t  Bytes: " + str(number_of_bytes) + ", \n" +
                      "\t\t\t\t\t  ,id: " + client_id + ", \n" +
                      "\t\t\t\t\t  ,mac: " + client_mac_address + ", \n" +
                      "\t\t\t\t\t  ,numero aleatorio: " + num_ale+ ", \n" +
                      "\t\t\t\t\t  ,data: " + data + "\n")
    return received_package_unpacked, client_ip_address, client_udp_port

def tcp_function():
    if debug_mode:
        print_message("DEBUG -> TCP socket enabled")

    while True:
        new_socket, (ip_address, port) = sockets.tcp_socket.accept()
        received_package_unpacked = receive_package_via_tcp_from_client(new_socket, 178)
        # create thread to serve tcp connection
        thread_to_serve_tcp_connection = threading.Thread(target=serve_tcp_connection,
                                                          args=(received_package_unpacked,
                                                                new_socket, ip_address))
        thread_to_serve_tcp_connection.daemon = True
        thread_to_serve_tcp_connection.start()
        
def serve_udp_connection(received_package_unpacked, client_ip_address, client_udp_port):
    package_type = received_package_unpacked[0]

    if package_type == get_packet_type_from_string("REGISTER_REQ"):
        register_req(received_package_unpacked, client_ip_address, client_udp_port)
    elif package_type == get_packet_type_from_string("ALIVE_INF"):
        alive_inf(received_package_unpacked, client_ip_address, client_udp_port)
        
    
def serve_tcp_connection(received_package_unpacked, socket, client_ip_address):
    package_type = received_package_unpacked[0]

    if package_type == get_packet_type_from_string("SEND_FILE"):
        send_file(received_package_unpacked, client_ip_address, socket)
    elif package_type == get_packet_type_from_string("GET_FILE"):
        get_file(received_package_unpacked, client_ip_address, socket)

def receive_package_via_tcp_from_client(new_socket, num_of_bytes):
    received_package_packed = new_socket.recv(num_of_bytes)
    received_package_unpacked = struct.unpack('B7s13s7s150s', received_package_packed)
    package_type = received_package_unpacked[0]
    client_id = received_package_unpacked[1].decode().split("\x00")[0]
    client_mac_address = received_package_unpacked[2].decode().split("\x00")[0]
    random_num = received_package_unpacked[3].decode().split("\x00")[0]
    data = received_package_unpacked[4].decode('utf-8', 'ignore').split("\x00")[0]

    if debug_mode:
        print_message("DEBUG -> \t\t Received " + get_packet_string(package_type) +
                      "; \n" + "\t\t\t\t\t  Bytes: " + str(num_of_bytes) + ", \n" +
                      "\t\t\t\t\t  id: " + client_id + ", \n" +
                      "\t\t\t\t\t  mac: " + client_mac_address + ", \n" +
                      "\t\t\t\t\t  rand num: " + random_num + ", \n" +
                      "\t\t\t\t\t  data: " + data + "\n")
    return received_package_unpacked



        
def register_req(received_package_unpacked, client_ip_address, client_udp_port):
    """When an ALIVE_INF pdu is received, this function 
    is triggered to handle its contents. If the client 
    is in a DISCONNECTED state and the received ALIVE_INF 
    pdu is valid, then the keep_in_touch function is executed.
    The function takes in the unpacked received_package and
    information about the client's IP address and UDP port.
    """
    try:
        client_id, client_mac_address, random_num = map(lambda x: x.decode().split("\x00")[0], received_package_unpacked[1:4])
        
        if not are_id_and_mac_valid(client_id, client_mac_address):
            if debug_mode:
                print_message(f"DEBUG -> Declined REG_REQUEST. Client: {client_id}, ip: {client_ip_address}, mac: {client_mac_address} (not allowed)")
            register_rej = construct_register_rej_package("Client not allowed in system")
            send_package_via_udp(register_rej, client_udp_port, client_ip_address)
            return
        
        client = get_client_from_id(client_id)
        if client.state == "DISCONNECTED":
            if random_num != "000000":
                if debug_mode:
                    print_message("DEBUG -> Declined REG_REQUEST. REGISTER_REQ's rand is not 000000")
                register_nack = construct_register_nack_package("wrong data received")
                send_package_via_udp(register_nack, client_udp_port, client_ip_address)
                return
            
            lock_clients_data.acquire()
            client.ip_address = client_ip_address
            client.udp_port = client_udp_port
            change_client_state(client_id, "REGISTERED")
            lock_clients_data.release()

            alive_inf_timeout = datetime.now() + timedelta(seconds=(J * R))
            register_ack = construct_register_ack_package(get_client_num_ale(client_id))
            send_package_via_udp(register_ack, client_udp_port, client_ip_address)

            keep_in_touch_with_client(client, alive_inf_timeout)

        elif client.state in ["REGISTERED", "ALIVE"]:
            if not are_random_num_and_ip_address_valid(client_id, random_num, client_ip_address):
                if debug_mode:
                    print_message(f"DEBUG -> Error in received REGISTER_REQ. Client: {client_id}, ip: {client_ip_address}, mac: {client_mac_address}, rand_num: {random_num} (Registered as: {client.id}, ip: {client.ip_address}, mac: {client.mac_address}, rand_num: {client.num_ale})")
                register_nack = construct_register_nack_package("wrong data received")
                send_package_via_udp(register_nack, client_udp_port, client_ip_address)
                return
            
            lock_clients_data.acquire()
            change_client_state(client_id, "REGISTERED")
            lock_clients_data.release()
            register_ack = construct_register_ack_package(get_client_num_ale(client_id))
            send_package_via_udp(register_ack, client_udp_port, client_ip_address)
            
    except AttributeError:
        return

def alive_inf(received_package_unpacked, client_ip_address, client_udp_port):
    """
    Processes an ALIVE_INF pdu and notifies the keep_in_touch_with_client function that
    an ALIVE_INF for a specific client has been received.
    :param received_package_unpacked: ALIVE_INF pdu to be processed
    :param client_ip_address: IP address of the client that sent the pdu
    :param client_udp_port: UDP port where the pdu was received
    """
    client_id = received_package_unpacked[1].decode().split("\x00")[0]
    client_mac_address = received_package_unpacked[2].decode().split("\x00")[0]
    random_num = int(received_package_unpacked[3].decode().split("\x00")[0])

    # Get the client from its id
    client = get_client_from_id(client_id)

    # Check if the client matches the IP and UDP port from the received package
    client_from_udp_and_ip = get_client_from_udp_port_and_ip(client_udp_port, client_ip_address)
    if client_from_udp_and_ip is not None:
        client_from_udp_and_ip.is_alive_received = True

    lock_clients_data.acquire()

    # Check if the id and MAC address are valid and the client is registered or alive
    if not are_id_and_mac_valid(client_id, client_mac_address) or \
            client.state not in ["REGISTERED", "ALIVE"]:
        if debug_mode:
            print_message("DEBUG -> Declined ALIVE_INF. Client:" + client_id + ", ip:" +
                          client_ip_address + ", mac:" + client_mac_address +
                          str(" (not allowed)" if not are_id_and_mac_valid(client_id,
                              client_mac_address) else " (not registered)"))

        alive_rej = construct_alive_rej_package(str("not allowed" if not
                                                    are_id_and_mac_valid(client_id,
                                                                            client_mac_address)
                                                    else "not registered"))
        lock_clients_data.release()
        send_package_via_udp(alive_rej, client_udp_port, client_ip_address)
        return

    # Check if the random number and IP address are valid
    elif not are_random_num_and_ip_address_valid(client_id, random_num, client_ip_address):
        if debug_mode:
            print_message("DEBUG -> Error in received ALIVE_INF. Client:" + client_id + " ip:" +
                          client_ip_address + ", mac:" + client_mac_address + ", rand_num:" +
                          str(random_num) + " (Registered as: " + client.id + ", ip:" +
                          client.ip_address + ", mac:" + client.mac_address + ", rand_num:" +
                          str(client.num_ale) + ")")

        lock_clients_data.release()
        alive_nack = construct_alive_nack_package("wrong data received")
        send_package_via_udp(alive_nack, client_udp_port, client_ip_address)
        return
    else:  # everything is correct
        change_client_state(client.id, "ALIVE")
        lock_clients_data.release()
        alive_ack = construct_alive_ack_package(client.num_ale)
        send_package_via_udp(alive_ack, client_udp_port, client_ip_address)
        


def send_file(received_package_unpacked, client_ip_address, socket):
    try:
        client_id = received_package_unpacked[1].decode().split("\x00")[0]
        client_mac_address = received_package_unpacked[2].decode().split("\x00")[0]
        client_random_num = int(received_package_unpacked[3].decode().split("\x00")[0])
        client = get_client_from_id(client_id)

        lock_clients_data.acquire()
        if not are_id_and_mac_valid(client_id, client_mac_address) \
                or client.state == "DISCONNECTED":
            reason = "not allowed" if not are_id_and_mac_valid(client_id, client_mac_address) \
                     else "not registered"
            if debug_mode:
                print_message(f"DEBUG -> Declined SEND_FILE request. Client: {client_id}, ip: "
                              f"{client_ip_address}, mac: {client_mac_address} ({reason})")
            send_rej = construct_send_rej_package(reason)
            lock_clients_data.release()
            send_package_via_tcp(send_rej, socket)
            socket.close()
            return

        if not are_random_num_and_ip_address_valid(client_id, client_random_num,
                                                    client_ip_address) \
                or client.conf_tcp_socket is not None:
            if debug_mode and client.conf_tcp_socket is None:
                print_message(f"DEBUG -> Error in received SEND_FILE. Client: {client_id}, "
                              f"ip: {client_ip_address}, mac: {client_mac_address}, rand_num: "
                              f"{client_random_num} (Registered as: {client.id}, ip: {client.ip_address}, "
                              f"mac: {client.mac_address}, rand_num: {str(client.num_ale)})")

            if client.conf_tcp_socket is not None:
                print_message(f"INFO -> There already is an operation on configuration file going on. "
                              f"Client: {client_id}, ip: {client_ip_address}, mac: {client_mac_address}, "
                              f"rand_num: {str(client_random_num)} (Registered as: {client.id}, ip: "
                              f"{client.ip_address}, mac: {client.mac_address}, rand_num: {str(client.num_ale)})")
                lock_clients_data.release()
                send_nack = construct_send_nack_package("existant operation already going on")
            else:
                lock_clients_data.release()
                send_nack = construct_send_nack_package("wrong data received")

            send_package_via_tcp(send_nack, socket)
            socket.close()
            return

        # everything correct
        client.conf_tcp_socket = socket
        lock_clients_data.release()
        print_message(f"INFO  -> Accepted configuration file sending request. Client: {client_id}, "
                      f"ip: {client_ip_address}, mac: {client_mac_address}, random num: {str(client_random_num)}")
        send_ack = construct_send_ack_package(client.id, client.num_ale)
        send_package_via_tcp(send_ack, socket)
        to_write = open(f"{client.id}.cfg", "w+")  # creates file
        # thread to keep track of received send_data packages timeout
        thread_for_send_data = threading.Thread(target=keep_in_touch_send_data,
                                                args=(client, datetime.now() + timedelta(seconds=W)))
        thread_for_send_data.daemon = True
        thread_for_send_data.start()
        save_send_data_packages(socket, to_write, client)
        socket.close()
        to_write.close()
        lock_clients_data.acquire()
        client.conf_tcp_socket = None
        lock_clients_data.release()

    except AttributeError:
        # datetime.now() is None
         return



def get_file(received_package_unpacked, client_ip_address, socket):
    """
    This method is executed when receiving a GET_FILE package on tcp socket.
    It processes the received GET_FILE package contents and if everything
    goes as planned calls the send_get_data_and_get_end_packages function.
    :param received_package_unpacked: received get_file pdu
    :param client_ip_address: ip address of client that sent received_package_unpacked
    :param socket: socket where received_package_unpacked was received and which will
    be used for further communication with client
    """
    client_id = received_package_unpacked[1].decode().split("\x00")[0]
    client_mac_address = received_package_unpacked[2].decode().split("\x00")[0]
    client_random_num = int(received_package_unpacked[3].decode().split("\x00")[0])
    client = get_client_from_id(client_id)

    try:
        with open(client_id + ".cfg", 'r') as client_conf_file:
            pass
    except IOError:
        if debug_mode:
            error_message = "DEBUG -> Declined GET_FILE request. File " + client_id + ".cfg cannot be accessed or does not exist. Client: {}, ip: {}, mac: {}".format(client_id, client_ip_address, client_mac_address)
            print_message(error_message)

        get_rej = construct_get_rej_package("file " + client_id + ".cfg cannot be accessed. ")
        send_package_via_tcp(get_rej, socket)
        socket.close()
        return

    with lock_clients_data:
        if not are_id_and_mac_valid(client_id, client_mac_address) or client.state == "DISCONNECTED":
            error_reason = "not allowed" if not are_id_and_mac_valid(client_id, client_mac_address) else "not registered"
            if debug_mode:
                error_message = "DEBUG -> Declined GET_FILE request. Client: {}, ip: {}, mac: {} ({})".format(client_id, client_ip_address, client_mac_address, error_reason)
                print_message(error_message)

            get_rej = construct_get_rej_package(error_reason)
            send_package_via_tcp(get_rej, socket)
            socket.close()
            return

        elif not are_random_num_and_ip_address_valid(client_id, client_random_num, client_ip_address) or client.conf_tcp_socket is not None:
            if client.conf_tcp_socket is not None:
                error_message = "INFO -> There already is an operation on configuration file going on. Client: {}, ip: {}, mac: {}, rand_num: {} (Registered as: {}, ip: {}, mac: {}, rand_num: {})".format(client_id, client_ip_address, client_mac_address, client_random_num, client.id, client.ip_address, client.mac_address, client.num_ale)
                print_message(error_message)
                get_nack = construct_get_nack_package("existant operation already going on")
            else:
                error_message = "INFO -> Declined GET_FILE request. Client: {}, ip: {}, mac: {}, rand_num: {}".format(client_id, client_ip_address, client_mac_address, client_random_num)
                print_message(error_message)
                get_nack = construct_get_nack_package("wrong data received")

            send_package_via_tcp(get_nack, socket)
            socket.close()
            return

        else:
            client.conf_tcp_socket = socket
            print_message("INFO -> Accepted configuration file obtaining request. Client: {}, ip: {}, mac: {}, random num: {}".format(client_id, client_ip_address, client_mac_address, client_random_num))
            get_ack = construct_get_ack_package(client_id, client_random_num)
            send_package_via_tcp(get_ack, socket)
            send_get_data_and_get_end_packages(socket, client_conf_file, client_random_num)
            socket.close()
            client.conf_tcp_socket = None




def are_id_and_mac_valid(client_id, client_mac_address):
    return any(valid_client.id == client_id and valid_client.mac_address == client_mac_address for valid_client in valid_clients_data)

def are_random_num_and_ip_address_valid(client_id, to_check_random_num, to_check_ip_address):
    for valid_client in valid_clients_data:
        if valid_client.id == client_id:
            return valid_client.ip_address == to_check_ip_address and \
                   valid_client.num_ale == to_check_random_num
    return False


def get_client_from_id(client_id):
    return next((client for client in valid_clients_data if client.id == client_id), None)

def get_client_num_ale(client_id):
    for valid_client in valid_clients_data:
        if valid_client.id == client_id:
            return valid_client.num_ale
    return None


def get_client_from_udp_port_and_ip(udp_port, ip_address):
    for valid_client in valid_clients_data:
        if udp_port == valid_client.udp_port and ip_address == valid_client.ip_address:
            return valid_client
    return None



def construct_register_rej_package(reason):
    register_rej = struct.pack('B7s13s7s50s', get_packet_type_from_string("REGISTER_REJ"), "".encode(),
                               "000000000000".encode(), "000000".encode(), reason.encode())
    return register_rej

def construct_register_nack_package(reason):
    register_nack = struct.pack('B7s13s7s50s', get_packet_type_from_string("REGISTER_NACK"), "".encode(),
                                "000000000000".encode() , "000000".encode(), reason.encode())
    return register_nack

def construct_register_ack_package(client_random_num):
    register_ack = struct.pack('B7s13s7s50s', get_packet_type_from_string("REGISTER_ACK"),
                               str(server_data.id).encode(),str(server_data.mac_address).encode(), str(client_random_num).encode(),
                               str(sockets.tcp_port).encode())
    return register_ack

def construct_alive_rej_package(reason):
    alive_rej = struct.pack('B7s13s7s50s', get_packet_type_from_string("ALIVE_REJ"), "".encode(),
                                "000000000000".encode() , "000000".encode(), reason.encode())
    return alive_rej

def construct_alive_ack_package(client_random_num):
    alive_ack = struct.pack('B7s13s7s50s', get_packet_type_from_string("ALIVE_ACK"),
                            str(server_data.id).encode(), str(server_data.mac_address).encode(), str(client_random_num).encode(), "".encode())
    return alive_ack

def construct_alive_nack_package(reason):
    alive_nack = struct.pack('B7s13s7s50s', get_packet_type_from_string("ALIVE_NACK"), "".encode(),
                                "000000000000".encode() , "000000".encode(), reason.encode())
    return alive_nack

def construct_send_rej_package(reason):
    send_rej = struct.pack('B7s13s7s150s', get_packet_type_from_string("SEND_REJ"), "".encode(),
                                "000000000000".encode() , "000000".encode(), reason.encode())
    return send_rej

def construct_send_nack_package(reason):
    send_nack = struct.pack('B7s13s7s150s', get_packet_type_from_string("SEND_NACK"), "".encode(),
                                "000000000000".encode() , "000000".encode(), reason.encode())
    return send_nack

def construct_send_ack_package(client_id, client_random_num):
    send_ack = struct.pack('B7s13s7s150s', get_packet_type_from_string("SEND_ACK"),
                           str(server_data.id).encode(), str(server_data.mac_address).encode(), str(client_random_num).encode(),
                           (client_id + ".cfg").encode())
    return send_ack

def construct_get_rej_package(reason):
    get_rej = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_REJ"), "".encode(),
                            "000000000000".encode() , "000000".encode(), reason.encode())
    return get_rej


def construct_get_nack_package(reason):
    get_nack = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_NACK"), "".encode(),
                            "000000000000".encode() , "000000".encode(), reason.encode())
    return get_nack

def construct_get_ack_package(client_id, client_random_num):
    get_ack = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_ACK"),
                          str(server_data.id).encode(), str(server_data.mac_address).encode(), str(client_random_num).encode(),
                          (client_id.encode() + ".cfg").encode())
    return get_ack

def construct_get_data(data_to_fill, client_random_num):
    get_data = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_DATA"),
                           str(server_data.id).encode(), str(server_data.mac_address).encode(), str(client_random_num).encode(),
                           data_to_fill.encode())
    return get_data


def construct_get_end(client_random_num):
    get_end = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_END"),
                          str(server_data.id).encode(), str(server_data.mac_address).encode(), str(client_random_num).encode(),
                          "".encode())
    return get_end

           
def send_package_via_udp(package_to_send, to_udp_port, to_ip_address):
    """
    This function sends a package to a client via UDP socket and prints debug information if debug_mode is enabled.
    :param package_to_send: package to be sent
    :param to_udp_port: udp port to send the package to
    :param to_ip_address: ip address of the client to send the package to
    """
    sockets.udp_socket.sendto(package_to_send, (to_ip_address, to_udp_port))
    package_to_send_unpacked = struct.unpack('B7s13s7s50s', package_to_send)
    if debug_mode:
        packet_type = get_packet_string(package_to_send_unpacked[0])
        packet_bytes = struct.calcsize('B7s13s7s50s')
        packet_id = package_to_send_unpacked[1].split(b"\x00")[0]
        packet_mac = package_to_send_unpacked[2].split(b"\x00")[0]
        packet_rand_num = package_to_send_unpacked[3].split(b"\x00")[0]
        packet_data = package_to_send_unpacked[4].split(b"\x00")[0]
        print_message(f"DEBUG -> Sent {packet_type}:\n"
              f"\t\t\t Bytes: {packet_bytes},\n"
              f"\t\t\t Id: {packet_id},\n"
              f"\t\t\t mac: {packet_mac},\n"
              f"\t\t\t rand num: {packet_rand_num},\n"
              f"\t\t\t data: {packet_data}\n")


def send_package_via_tcp(package_to_send, socket):
    socket.sendall(package_to_send)
    package_to_send_unpacked = struct.unpack('B7s13s7s150s', package_to_send)
    if debug_mode:
        packet_type = get_packet_string(package_to_send_unpacked[0])
        packet_size = struct.calcsize('B7s13s7s50s')
        client_id = package_to_send_unpacked[1].split("\x00")[0]
        client_mac = package_to_send_unpacked[2].split("\x00")[0]
        client_rand_num = package_to_send_unpacked[3].split("\x00")[0]
        packet_data = package_to_send_unpacked[4].split("\x00")[0]
        
        print_message(f"DEBUG -> Sent {packet_type};"
                f"\n\t\t\t Bytes: {packet_size},"
                f"\n\t\t\t id: {client_id},"
                f"\n\t\t\t mac: {client_mac},"
                f"\n\t\t\t rand num: {client_rand_num},"
                f"\n\t\t\t data: {packet_data}\n")

def send_get_data_and_get_end_packages(socket, client_conf_file, client_random_num):
    for line in client_conf_file:
        get_data = construct_get_data(line, client_random_num)
        send_package_via_tcp(get_data, socket)
    get_end = construct_get_end(client_random_num)
    send_package_via_tcp(get_end, socket)

def change_client_state(client_id, new_state):
    client = next((c for c in valid_clients_data if c.id == client_id), None)
    if client:
        if client.state != new_state:
            client.state = new_state
            if new_state == "REGISTERED" and debug_mode:
                print_message(f"INFO  -> Client {client_id} successfully signed up on server; " +
                              f"ip: {client.ip_address} mac: {client.mac_address} rand_num: {client.num_ale}")
            print_message(f"INFO  -> Client {client_id} changed its state to: {new_state}")
        else:
            if new_state == "REGISTERED" and debug_mode:
                print_message("DEBUG -> Client 'changed' its state to REGISTERED (Duplicated signup)")
    else:
        print_message(f"ERROR -> Client {client_id} not found")

def keep_in_touch_with_client(client, first_alive_inf_timeout):
    """
    Makes sure client stays in touch with server using udp socket by checking whether
    client.is_alive_received is True before a countdown.
    client.is_alive_received is changed to True on serve_alive_inf function when
    receiving an ALIVE_INF pdu and then changed to False inside this function.
    :param client: client that must keep in touch
    :param first_alive_inf_timeout: maximum datetime to receive first alive_inf
    """

    while True:
        try:
            if client.state == "REGISTERED":
                is_first_alive_received = False
                while datetime.now() < first_alive_inf_timeout:
                    if client.is_alive_received:
                        is_first_alive_received = True
                        lock_clients_data.acquire()
                        client.is_alive_received = False
                        lock_clients_data.release()
                    time.sleep(0.01)
                    if datetime.now() >= first_alive_inf_timeout:
                        break
                if not is_first_alive_received:
                    print_message("INFO  -> Have not received first ALIVE_INF in "
                                  + str(J * R) + " seconds")
                    lock_clients_data.acquire()
                    change_client_state(client.id, "DISCONNECTED")
                    lock_clients_data.release()
                    return

            elif client.state == "ALIVE":
                alive_inf_timeout = datetime.now() + timedelta(seconds=R)
                is_alive_received = False
                while datetime.now() < alive_inf_timeout:
                    if client.is_alive_received:
                        lock_clients_data.acquire()
                        client.consecutive_non_received_alives = 0
                        client.is_alive_received = False
                        lock_clients_data.release()
                    time.sleep(0.01)
                    if datetime.now() >= alive_inf_timeout:
                        break
                if not is_alive_received:
                    lock_clients_data.acquire()
                    client.consecutive_non_received_alives += 1
                    if client.consecutive_non_received_alives == S:
                        print_message("INFO  -> Have not received " + str(S) +
                                      " consecutive ALIVES")
                        change_client_state(client.id, "DISCONNECTED")
                        client.consecutive_non_received_alives = 0
                        lock_clients_data.release()
                        return
                    lock_clients_data.release()
        # datetime.now() is None when main thread exits, so could throw AttributeError
        except AttributeError:
            return


def keep_in_touch_send_data(client, send_data_max_timeout):
    """
    Makes sure client stays in touch with server on tcp socket
    by checking whether client.is_data_received is True before a countdown.
    :param client: client that must keep in touch
    :param send_data_max_timeout: datetime object that represents the receiving limit time
    """
    try:
        # Loop until the maximum time to receive data is reached
        while datetime.now() < send_data_max_timeout:
            # If data has been received, update the maximum time and set the data received flag to false
            if client.is_data_received:
                send_data_max_timeout = datetime.now() + timedelta(seconds=W)
                client.is_data_received = False
            # If all data has been received, exit the function
            if client.is_end_data_received:
                return
        # If all data has not been received before the maximum time, set a timeout flag and print an error message
        if not client.is_end_data_received:
            print_message("INFO  -> Not received information on TCP socket during " + str(W) +
                          " seconds")
            client.data_received_timeout_exceeded = True
            return
    # Handle an AttributeError in case the main thread has exited
    except AttributeError:
        return


def save_send_data_packages(socket, file_to_fill, client):
    """
    This function is executed when receiving a correct SEND_FILE
    package from a client. The goal is to save in a file all the
    future SEND_DATA packages received.
    :param socket: socket where SEND_DATA packages will be received.
    :param file_to_fill: file to fill up with the payload in SEND_DATA pdu
    :param client: client to send the packages
    """
    while not client.data_received_timeout_exceeded:
        received_package_packed = socket.recv(178)
        received_package_unpacked = struct.unpack('B7s13s7s150s', received_package_packed)
        package_type, client_id, client_mac_address, random_num, data = received_package_unpacked[:5]
        client_id = client_id.split(b"\x00")[0].decode()
        client_mac_address = client_mac_address.split(b"\x00")[0].decode()
        random_num = random_num.split(b"\x00")[0].decode()
        data = data.split(b"\x00")[0]

        if client.data_received_timeout_exceeded:
            break

        if debug_mode:
            print(f"DEBUG -> \t\t Received {get_packet_string(package_type)}; \n"
                  f"\t\t\t\t\t  Bytes: 178, \n"
                  f"\t\t\t\t\t  id: {client_id}, \n"
                  f"\t\t\t\t\t  mac: {client_mac_address}, \n"
                  f"\t\t\t\t\t  rand num: {random_num}, \n"
                  f"\t\t\t\t\t  data: {data}\n")

        if package_type != get_packet_type_from_string("SEND_END"):
            file_to_fill.write(data)

        else:
            print(f"INFO  -> Client succesfully ended sending of configuration file. "
                  f"Client: {client.id}, ip: {client.ip_address}, mac: {client.mac_address}, "
                  f"random num: {client.num_ale}")
            return



def get_packet_string(integer):
    # signup packet types
    if integer == 0x00:
        return "REGISTER_REQ"
    elif integer == 0x02:
        return "REGISTER_ACK"
    elif integer == 0x04:
        return "REGISTER_NACK"
    elif integer == 0x06:
        return "REGISTER_REJ"
    # keep in touch packet types
    elif integer == 0x10:
        return "ALIVE_INF"
    elif integer == 0x12:
        return "ALIVE_ACK"
    elif integer == 0x14:
        return "ALIVE_NACK"
    elif integer == 0x16:
        return "ALIVE_REJ"
    # send configuration packet types
    elif integer == 0x20:
        return "SEND_FILE"
    elif integer == 0x22:
        return "SEND_DATA"
    elif integer == 0x24:
        return "SEND_ACK"
    elif integer == 0x26:
        return "SEND_NACK"
    elif integer == 0x28:
        return "SEND_REJ"
    elif integer == 0x2A:
        return "SEND_END"
    # get configuration packet types
    elif integer == 0x30:
        return "GET_FILE"
    elif integer == 0x32:
        return "GET_DATA"
    elif integer == 0x34:
        return "GET_ACK"
    elif integer == 0x36:
        return "GET_NACK"
    elif integer == 0x38:
        return "GET_REJ"
    elif integer == 0x3A:
        return "GET_END"
    # error
    else:
        return "ERROR"
    

def get_packet_type_from_string(string):
    # signup packet types
    if string == "REGISTER_REQ":
        return 0x00
    elif string == "REGISTER_ACK":
        return 0x02
    elif string == "REGISTER_NACK":
        return 0x04
    elif string == "REGISTER_REJ":
        return 0x06
    # keep in touch packet types
    elif string == "ALIVE_INF":
        return 0x10
    elif string == "ALIVE_ACK":
        return 0x12
    elif string == "ALIVE_NACK":
        return 0x14
    elif string == "ALIVE_REJ":
        return 0x16
    # send configuration packet types
    elif string == "SEND_FILE":
        return 0x20
    elif string == "SEND_DATA":
        return 0x22
    elif string == "SEND_ACK":
        return 0x24
    elif string == "SEND_NACK":
        return 0x26
    elif string == "SEND_REJ":
        return 0x28
    elif string == "SEND_END":
        return 0x2A
    # get configuration packet types
    elif string == "GET_FILE":
        return 0x30
    elif string == "GET_DATA":
        return 0x32
    elif string == "GET_ACK":
        return 0x34
    elif string == "GET_NACK":
        return 0x36
    elif string == "GET_REJ":
        return 0x38
    elif string == "GET_END":
        return 0x3A
    # error
    else:
        return 0x0F
    



if __name__ == '__main__':
    try:
        
        read_and_save_argv(sys.argv)
        setup_sockets()
        
        thread_for_tcp = threading.Thread(target=tcp_function)
        thread_for_tcp.daemon = True
        thread_for_tcp.start()
        udp_function()
        
        
        
    except(KeyboardInterrupt, SystemExit):
        # close client conf sockets (if any in use)
        commands()
        lock_clients_data.acquire()
        for client in valid_clients_data:
            if client.conf_tcp_socket is not None:
                client.conf_tcp_socket.close()
        lock_clients_data.release()
        print  # simply prints new line
        print_message("Exiting server...")
        sockets.udp_socket.close()
        sockets.tcp_socket.close()
        exit(1)  # does exit all daemon threads as well
        







