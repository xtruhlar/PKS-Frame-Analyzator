from binascii import hexlify
from os.path import exists
import ruamel.yaml
from scapy.compat import raw
from scapy.utils import rdpcap

# Ruamel for Literalscalarstring in YAML
yaml = ruamel.yaml.YAML()


# Class for TCP
class TCP_commun:
    def __init__(self, src_port, dst_port, src_ip, dst_ip):
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.order = []
        self.packets = []
        self.established = False
        self.complete = False


# Class for TFTP
class UDP_comm:
    def __init__(self, src_port, dst_port, src_ip, dst_ip):
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.packets = []
        self.order = []
        self.complete = False


# Class for ARP
class ARP_comm:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.packets = []
        self.order = []
        self.complete = False


# Class for ICMP
class ICMP_comm:
    def __init__(self, src_ip, dst_ip, id_n, seq):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.id = id_n
        self.seq = seq
        self.order = []
        self.packets = []
        self.complete = False


# This function is used to load protocols from external files 'LLC.txt' and 'ETHER.txt'
def load_protocols_from_file(frame_type):
    protocols = {}
    if frame_type < 512:
        with open('Protocols/LLC.txt', 'r') as file:
            for line in file:
                line = line.strip()
                parts = line.split(":")
                if len(parts) == 2:
                    key = int(parts[0])
                    value = parts[1]
                    protocols[key] = value
    else:
        with open('Protocols/ETHER.txt', 'r') as file:
            for line in file:
                line = line.strip()
                parts = line.split(":")
                if len(parts) == 2:
                    key = int(parts[0])
                    value = parts[1]
                    protocols[key] = value
    return protocols


# This function is used to load protocols from external file 'IP.txt'
def load_protocols_for_ip():
    protocols = {}
    with open('Protocols/IP.txt', 'r') as file:
        for line in file:
            line = line.strip()
            parts = line.split(":")
            if len(parts) == 2:
                key = int(parts[0])
                value = parts[1]
                protocols[key] = value
    return protocols


# This function is used to load ports from external file 'L4.txt'
def load_ports():
    ports_in_l4 = {}
    with open('Protocols/L4.txt', 'r') as file:
        for line in file:
            line = line.strip()
            parts = line.split(":")
            if len(parts) == 2:
                key = int(parts[0])
                value = parts[1]
                ports_in_l4[key] = value
    return ports_in_l4


# This function is used to load ICMP codes from external file 'ICMP.txt'
def load_icmp():
    icmp = {}
    with open('Protocols/ICMP.txt', 'r') as file:
        for line in file:
            line = line.strip()
            parts = line.split(":")
            if len(parts) == 2:
                key = int(parts[0])
                value = parts[1]
                icmp[key] = value
    return icmp


# This function is used to return src and dst port from packet
def get_ports(packet):
    src_port = int(str(hexlify(packet[34:36]))[2:-1], 16)
    dst_port = int(str(hexlify(packet[36:38]))[2:-1], 16)
    return src_port, dst_port


# This function is used to return src and dst MAC addresses from packet
def get_mac_addresses(packet):
    src_MAC = ''
    dst_MAC = ''
    for i in range(6):
        src_MAC += str(hexlify(packet[i:i + 1]))[2:-1] + ':'
    for i in range(6, 12):
        dst_MAC += str(hexlify(packet[i:i + 1]))[2:4] + ':'
    # This 2 lines remove last ':' from MAC addresses
    src_MAC = src_MAC[:-1]
    dst_MAC = dst_MAC[:-1]
    return src_MAC.upper(), dst_MAC.upper()


# This function is used to return src and dst IP addresses from packet
def get_ip_addresses(packet):
    # IPv4 is default
    src_ip = ''
    dst_ip = ''
    for i in range(26, 30):
        src_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
    for i in range(30, 34):
        dst_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
    # This 2 lines remove last '.' from IP addresses
    src_ip = src_ip[:-1]
    dst_ip = dst_ip[:-1]

    # ARP - same logic as IPv4 but different offset
    ether_type = int(str(hexlify(packet[12:14]))[2:-1], 16)
    if ether_type == 2054:
        src_ip = ''
        dst_ip = ''
        for i in range(28, 32):
            src_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
        for i in range(38, 42):
            dst_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
        src_ip = src_ip[:-1]
        dst_ip = dst_ip[:-1]

    return src_ip, dst_ip


# This function is used to return src IP address from packet, when TTL is exceeded
def get_time_to_live_exceeded_address(packet):
    src_ip = ''
    for i in range(26, 30):
        src_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
    src_ip = src_ip[:-1]
    return src_ip


# This function is used to return the right format of hexdump, which is required in output
def format_hexadump(packet):
    the_right_format = ''
    for i in range(len(packet)):
        the_right_format += str(hexlify(packet[i:i + 1]))[2:-1] + ' '
        # 16 bytes per line
        if (i + 1) % 16 == 0:
            the_right_format = the_right_format[:-1]
            the_right_format += '\n'
    # This 3 lines remove last ' ', add '\n' and change to upper case
    the_right_format = the_right_format[:-1]
    the_right_format += '\n'
    the_right_format = the_right_format.upper()
    # Literalscalarstring
    '''
    Information about scalarstring.LiteralScalarString was obtained from:
    https://docs.rundeck.com/docs/manual/document-format-reference/job-yaml-v12.html#job-map-contents
    '''
    # This deletes '-' from the beginning of the string
    the_right_format = ruamel.yaml.scalarstring.LiteralScalarString(the_right_format)

    return the_right_format


# This function is used to return frame type and protocol name
def get_protocol_info(packet):
    frame_type = int(str(hexlify(packet[12:14]))[2:-1], 16)
    protocol_name = ''
    # First 2 bytes of frame type are used to determine frame type
    if frame_type >= 1500 or frame_type == 512 or frame_type == 513:
        frame_type = "ETHERNET II"
        protocol = int(str(hexlify(packet[12:14]))[2:-1], 16)
        if protocol in protocols_ether:
            protocol_name = protocols_ether.get(protocol)
        elif protocol in protocols_llc:
            protocol_name = protocols_llc.get(protocol)
    else:
        if str(hexlify(packet[14:16]))[2:-1] == "aaaa":
            frame_type = "IEEE 802.3 LLC & SNAP"
            protocol = int(str(hexlify(packet[20:22]))[2:-1], 16)
            if protocol in protocols_ether:
                protocol_name = protocols_ether.get(protocol)
                if protocol_name == "CDP":
                    array_of_comms.append(packet)
        elif str(hexlify(packet[14:16]))[2:-1] == "ffff":
            frame_type = "IEEE 802.3 RAW"
        else:
            frame_type = "IEEE 802.3 LLC"
            # SAP is defined in 15th byte
            sap = int(str(hexlify(packet[14:15]))[2:-1], 16)
            if sap == 170:
                # PID is defined in 48th byte
                pid = int(str(hexlify(packet[47:48]))[2:-1], 16)
                if pid in protocols_llc:
                    protocol_name = protocols_llc[pid]
                elif pid in protocols_ether:
                    protocol_name = protocols_ether[pid]
            elif sap in protocols_llc:
                protocol_name = protocols_llc[sap]
    return frame_type, protocol_name


# This function is used to output the right format of YAML part1
def format_output_1(packet, task_number):
    info = {}
    # Obtain all information about packet
    len_frame_pcap = len(packet)
    if len_frame_pcap < 64:
        len_frame_medium = 64
    else:
        len_frame_medium = len_frame_pcap + 4
    frame_type, pid_sap = get_protocol_info(packet)
    src_mac, dst_mac = get_mac_addresses(packet)
    src_ip, dst_ip = get_ip_addresses(packet)
    # If task 3 is selected, then IP statistics are counted
    if task_number == "3":
        if src_ip not in hash_table_IP:
            hash_table_IP[src_ip] = 1
        else:
            hash_table_IP[src_ip] += 1
    src_port, dst_port = get_ports(packet)
    if src_port in ports:
        app_protocol = ports[src_port]
    elif dst_port in ports:
        app_protocol = ports[dst_port]
    else:
        app_protocol = ''

    # Format output
    info["len_frame_pcap"] = len_frame_pcap
    info["len_frame_medium"] = len_frame_medium
    info["frame_type"] = frame_type
    info["src_mac"] = src_mac
    info["dst_mac"] = dst_mac

    if frame_type == "IEEE 802.3 LLC & SNAP":
        info["pid"] = pid_sap
    elif frame_type == "IEEE 802.3 LLC":
        info["sap"] = pid_sap

    if frame_type == "ETHERNET II":
        ether_type = int(str(hexlify(packet[12:14]))[2:-1], 16)
        if ether_type in protocols_ether:
            info["ether_type"] = protocols_ether[ether_type]
            if protocols_ether[ether_type] == 'ARP':
                arp_operation = int(str(hexlify(packet[20:22]))[2:-1], 16)
                if arp_operation == 1:
                    info["arp_opcode"] = "REQUEST"
                elif arp_operation == 2:
                    info["arp_opcode"] = "REPLY"

            if protocols_ether[ether_type] == 'IPv4':
                info["src_ip"] = src_ip
                info["dst_ip"] = dst_ip
                protocol_l4 = int(str(hexlify(packet[23:24]))[2:-1], 16)
                if protocol_l4 in protocols_ip:
                    info["protocol"] = protocols_ip[protocol_l4]
                    if protocols_ip[protocol_l4] == 'TCP' or protocols_ip[protocol_l4] == 'UDP':
                        info["src_port"] = src_port
                        info["dst_port"] = dst_port
                        if app_protocol != '':
                            info["app_protocol"] = app_protocol
                    elif protocols_ip[protocol_l4] == 'ICMP':
                        icmp_type = int(str(hexlify(packet[34:35]))[2:-1], 16)
                        if icmp_type in icmp_codes:
                            info["icmp_type"] = icmp_codes[icmp_type]

    return info


# This function is used to output the right format of YAML part2
def format_output_2(packet):
    hexdump = format_hexadump(packet)
    info = {"hexa_frame": hexdump}

    return info


# This function is used to print the right format of YAML and save it to file
def print_it(menu, task):
    output_filename = 'output-{}.yaml'.format(task)

    with open(output_filename, 'w') as file:
        yaml.dump(menu, file)

    # Inform user about successful output
    print("  ✅Výstup bol uložený do 🧾{}🎉".format(output_filename))
    return


# This is function for task 1, task 2 and task 3
def tasks_1_2_3(pcap_subor, task_number):
    output = []
    # Check if file exists and load it to packets
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]

    # If file doesn't exist, print error message
    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    else:
        frame_num = 1
        # Iterate through all packets and save them to output
        for packet in packets:
            packet = raw(packet)
            packet_info = {"frame_number": frame_num}

            packet_info.update(format_output_1(packet, task_number))
            packet_info.update(format_output_2(packet))

            frame_num += 1
            output.append(packet_info)

        # Format menu for YAML
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "packets": output,
        }

        # Task 3 - IP statistics
        if task_number == "3":
            # Sort hash table by values
            sorted_hash = dict(sorted(hash_table_IP.items(), key=lambda item: item[1]))

            # Add IP statistics to menu
            menu["ipv4_senders"] = []
            for key, value in sorted_hash.items():
                menu["ipv4_senders"].append({'node': key, 'number_of_sent_packets': value})
            menu["max_send_packets_by"] = []
            max_ip = max(sorted_hash.values())
            for key, value in sorted_hash.items():
                if value == max_ip:
                    menu["max_send_packets_by"].append(key)

        print_it(menu, "all")
    return


# This is function for task 4 - UDP [TFTP filter]
def task4_udp(pcap_subor):
    counter = 0
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]
    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    # First I find all UDP - TFTP communications
    for packet in packets:
        counter += 1
        packet = raw(packet)
        if int(str(hexlify(packet[23:24]))[2:-1], 16) == 17:
            # a ak je to tftp
            port = int(str(hexlify(packet[36:38]))[2:-1], 16)
            if port != 137:
                order_and_packet[counter] = packet

    # If there are no UDP - TFTP communications, print error message
    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne TFTP pakety")
        return

    # Then I sort them into individual communications
    for packet_num, raw_packet in order_and_packet.items():
        IHL = int(str(hexlify(raw_packet[14:15]))[3: -1], 16) * 4 + 14
        src_port = int(str(hexlify(raw_packet[IHL:IHL + 2]))[2:-1], 16)
        dst_port = int(str(hexlify(raw_packet[IHL + 2:IHL + 4]))[2:-1], 16)
        src_ip, dst_ip = get_ip_addresses(raw_packet)
        op_code = int(str(hexlify(raw_packet[IHL + 8:IHL + 10]))[2:-1], 16)
        # 1 Read Request (RRQ)     2 Write Request (WRQ)   3 Data (DATA)     4 Acknowledgment (ACK)     5 Error (ERROR)

        # If it is a new communication, I create it
        if dst_port == 69 and op_code in [1, 2]:
            communication = UDP_comm(src_port, dst_port, src_ip, dst_ip)
            communication.order.append(packet_num)
            communication.packets.append(raw_packet)
            array_of_comms.append(communication)

        # If it is not a new communication, I add it to the existing one
        elif len(array_of_comms) != 0:
            for comm in array_of_comms:
                # If it is not complete, I add it to the existing one
                if comm.complete is False:
                    if (
                            src_ip == comm.dst_ip and dst_ip == comm.src_ip or src_ip == comm.src_ip and dst_ip == comm.dst_ip and dst_port == 69) \
                            or (
                            src_port == comm.dst_port and dst_port == comm.src_port or src_port == comm.src_port and dst_port == comm.dst_port):
                        # If there is port 69 in the packet, I change the port
                        if comm.dst_port == 69:
                            comm.dst_port = src_port
                        if (
                                comm.src_port == src_port and comm.dst_port == dst_port or comm.src_port == dst_port and comm.dst_port == src_port):
                            comm.order.append(packet_num)
                            comm.packets.append(raw_packet)
                        # If the communication is complete, I change the flag
                        if op_code == 4 and len(comm.packets[-2]) <= len(comm.packets[1]):
                            comm.complete = True
                        # If the op_code is 5 or 4 and the packet is longer than the second one, I leave the flag on False
                        if op_code == 5 or (op_code == 4 and len(comm.packets[-2]) > len(comm.packets[1])):
                            comm.complete = False

                # If it is complete, I create a new one
                else:
                    if dst_port == 69 and op_code in [1, 2]:
                        communication = UDP_comm(src_port, dst_port, src_ip, dst_ip)
                        communication.order.append(packet_num)
                        communication.packets.append(raw_packet)
                        array_of_comms.append(communication)

    # Sort communications into complete and partial
    complete_c = []
    partial_c = []
    for comm in array_of_comms:
        if comm.complete is True:
            complete_c.append(comm)
        else:
            partial_c.append(comm)

    # Format menu for YAML
    if len(complete_c) != 0 and len(partial_c) != 0:
        menu = {"name": str('PKS2023/24'), "pcap_name": str(pcap_subor), "filter_name": 'tftp'.upper(),
                "complete_comms": [], "partial_comms": []}

    elif len(complete_c) != 0 and len(partial_c) == 0:
        menu = {"name": str('PKS2023/24'), "pcap_name": str(pcap_subor), "filter_name": 'tftp'.upper(),
                "complete_comms": []}

    elif len(complete_c) == 0 and len(partial_c) != 0:
        menu = {"name": str('PKS2023/24'), "pcap_name": str(pcap_subor), "filter_name": 'tftp'.upper(),
                "partial_comms": []}

    compl_num = 0
    partial_num = 0
    processed_communications = set()

    for comm in array_of_comms:
        if comm in processed_communications:
            # Skip already processed communications
            continue
        processed_communications.add(comm)

        # Menu may differ based on complete and partial communications
        if comm.complete:
            compl_num += 1
            commun_info = {
                "number_comm": compl_num,
                "packets": []
            }
            menu["complete_comms"].append(commun_info)
        else:
            partial_num += 1
            commun_info = {
                "number_comm": partial_num,
                "packets": []
            }
            menu["partial_comms"].append(commun_info)

        # Format output for YAML
        for packet in comm.packets:
            packet = raw(packet)
            packet_info = {}
            frame_number = comm.order[comm.packets.index(packet)]
            packet_info["frame_number"] = frame_number
            packet_info.update(format_output_1(packet, "tftp"))
            packet_info.update(format_output_2(packet))
            commun_info["packets"].append(packet_info)

    print_it(menu, "tftp")
    return


# This is function for task 4 - ARP filter
def task4_arp(pcap_subor):
    counter = 0
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]
    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    # Firstly I find all ARP packets
    for packet in packets:
        counter += 1
        packet = raw(packet)
        if int(str(hexlify(packet[12:14]))[2:-1], 16) == 2054:
            order_and_packet[counter] = packet

    # If there are no ARP packets, print error message
    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne ARP pakety")
        return

    complete_c = []
    partial_requests = []
    bad_array = []

    # Then I sort them into individual communications
    for packet_num, raw_packet in order_and_packet.items():
        # IHL je dlzka hlavicky v bajtoch použita ako offset
        IHL = int(str(hexlify(raw_packet[14:15]))[3: -1], 16) * 4 + 14
        src_ip, dst_ip = get_ip_addresses(raw_packet)
        op_code = int(str(hexlify(raw_packet[IHL + 6:IHL + 8]))[2:-1], 16)

        # If it is a new communication, I create it op_code == 1 is request
        if op_code == 1:
            communication = ARP_comm(src_ip, dst_ip)
            communication.order.append(packet_num)
            communication.packets.append(raw_packet)
            array_of_comms.append(communication)

        # If it is not a new communication, I add it to the existing one
        elif len(array_of_comms) != 0:
            for comm in array_of_comms:
                # If it is not complete, I add it to the existing one
                if comm.complete is False:
                    # If it is a reply, I add it to the existing one
                    if src_ip == comm.dst_ip and dst_ip == comm.src_ip:
                        if op_code == 2:
                            comm.order.append(packet_num)
                            comm.packets.append(raw_packet)
                            comm.complete = True
                            break
                # If it is complete, I create a new one
                else:
                    if op_code == 1:
                        communication = ARP_comm(src_ip, dst_ip)
                        communication.order.append(packet_num)
                        communication.packets.append(raw_packet)
                        array_of_comms.append(communication)

        # If it is reply, but there is no request, I add it to bad_array
        elif op_code == 2 and len(array_of_comms) == 0:
            bad = ARP_comm(src_ip, dst_ip)
            bad.order.append(packet_num)
            bad.packets.append(raw_packet)
            bad_array.append(bad)

    # Sort communications into complete and partial
    for comm in array_of_comms:
        if comm.complete is True:
            complete_c.append(comm)
        else:
            # If it is request, I add it to partial_requests
            if comm.packets[0][20:22] == b'\x00\x01':
                partial_requests.append(comm)

    # partial_replies are bad_array
    partial_replies = bad_array

    # Format menu for YAML
    if len(complete_c) != 0 and (len(partial_requests) != 0 or len(partial_replies) != 0):
        menu = {"name": str('PKS2023/24'), "pcap_name": str(pcap_subor), "filter_name": 'arp'.upper(),
                "complete_comms": [], "partial_comms": []}
        complete_coms = {
            "number_comm": 1,
            "packets": []
        }
        menu["complete_comms"].append(complete_coms)
        if len(partial_requests) != 0:
            partial_coms = {
                "number_comm": 1,
                "packets": []
            }
            menu["partial_comms"].append(partial_coms)
        if len(partial_replies) != 0:
            partial_coms = {
                "number_comm": 2,
                "packets": []
            }
            menu["partial_comms"].append(partial_coms)

    elif len(complete_c) != 0 and (len(partial_requests) == 0 and len(partial_replies) == 0):
        menu = {"name": str('PKS2023/24'), "pcap_name": str(pcap_subor), "filter_name": 'arp'.upper(),
                "complete_comms": []}
        complete_coms = {
            "number_comm": 1,
            "packets": []
        }
        menu["complete_comms"].append(complete_coms)

    elif len(complete_c) == 0 and (len(partial_requests) != 0 or len(partial_replies) != 0):
        menu = {"name": str('PKS2023/24'), "pcap_name": str(pcap_subor), "filter_name": 'arp'.upper(),
                "partial_comms": []}

        if len(partial_requests) != 0:
            partial_coms = {
                "number_comm": 1,
                "packets": []
            }
            menu["partial_comms"].append(partial_coms)
        if len(partial_replies) != 0:
            partial_coms = {
                "number_comm": 2,
                "packets": []
            }
            menu["partial_comms"].append(partial_coms)

    # This loop saves same lines of code
    def forcycle(packet_to_cycle):
        packet_to_cycle = raw(packet_to_cycle)
        frame_number = comm.order[comm.packets.index(packet_to_cycle)]

        packet_information = {"frame_number": frame_number}
        packet_information.update(format_output_1(packet_to_cycle, "arp"))
        packet_information.update(format_output_2(packet_to_cycle))
        return packet_information

    # Format output for YAML
    for comm in complete_c:
        for packet in comm.packets:
            packet_info = forcycle(packet)
            complete_coms["packets"].append(packet_info)

    for comm in partial_requests:
        for packet in comm.packets:
            packet_info = forcycle(packet)
            partial_coms["packets"].append(packet_info)

    for comm in bad_array:
        for packet in comm.packets:
            packet_info = forcycle(packet)
            partial_coms["packets"].append(packet_info)

    print_it(menu, "arp")
    return


# This is function for task 4 - ICMP filter
def task4_icmp(pcap_subor):
    counter = 0
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]

    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    complete_c = []
    partial_c = []

    enu = 0
    # This dictionary is used to communications
    enumerated_comunication = {}

    # Fistly I find all ICMP packets
    for packet in packets:
        counter += 1
        packet = raw(packet)
        ether_type = int(str(hexlify(packet[12:14]))[2:-1], 16)
        if ether_type == 2048:
            protocol_ip = int(str(hexlify(packet[23:24]))[2:-1], 16)
            if protocol_ip in protocols_ip:
                if protocols_ip[protocol_ip] == 'ICMP':
                    order_and_packet[counter] = packet

    # If there are no ICMP packets, print error message
    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne ICMP pakety")
        return

    # Then I sort them into individual communications
    for packet_num, raw_packet in order_and_packet.items():
        ip_source, ip_destination = get_ip_addresses(raw_packet)
        icmp_type = int(str(hexlify(raw_packet[34:35]))[2:-1], 16)

        id_number = int(str(hexlify(raw_packet[38:40]))[2:-1], 16)
        seq_number = int(str(hexlify(raw_packet[40:42]))[2:-1], 16)

        # If icmp_type == 11, then I need to get the IP address
        if icmp_type == 11:
            addr = get_time_to_live_exceeded_address(packet)

        # If the communication is new, I create it, icmp_type == 8 is request
        if icmp_type == 8:
            communication = ICMP_comm(ip_source, ip_destination, id_number, seq_number)
            communication.order.append(packet_num)
            communication.packets.append(raw_packet)
            array_of_comms.append(communication)

        # If the communication is not new, I add it to the existing one
        elif len(array_of_comms) != 0:
            for comm in array_of_comms:
                # If the communication is not complete, I add it to the existing one
                if comm.complete is False:
                    # This is for ICMP type 11
                    if icmp_type == 11 and addr == comm.dst_ip and ip_destination == comm.src_ip:
                        comm.order.append(packet_num)
                        comm.packets.append(raw_packet)
                        comm.complete = True
                        break
                    # This is for ICMP type 0
                    elif ip_source == comm.dst_ip and ip_destination == comm.src_ip:
                        if icmp_type == 0 and id_number == comm.id:
                            comm.order.append(packet_num)
                            comm.packets.append(raw_packet)
                            comm.complete = True
                            break

                # If the communication is complete, I create a new one
                else:
                    if icmp_type == 8:
                        communication = ICMP_comm(ip_source, ip_destination, id_number, seq_number)
                        communication.order.append(packet_num)
                        communication.packets.append(raw_packet)
                        array_of_comms.append(communication)

        # If the icmp_type is 3, 4 or 5, I add it to partial_c
        if icmp_type in [3, 4, 5]:
            bad = ICMP_comm(ip_source, ip_destination, id_number, seq_number)
            bad.order.append(packet_num)
            bad.packets.append(raw_packet)
            partial_c.append(bad)

    # Sort communications into complete and partial
    for comm in array_of_comms:
        if comm.complete:
            complete_c.append(comm)
        else:
            partial_c.append(comm)

    # Sort communications into pairs based on id and ip
    for pair in complete_c:
        found = False
        # Check if there is already a communication with the same id and ip
        for key, existing_comm in enumerated_comunication.items():
            # If there is, I add it to the existing one
            if ((existing_comm.src_ip == pair.src_ip and existing_comm.dst_ip == pair.dst_ip) or (
                    existing_comm.src_ip == pair.dst_ip and existing_comm.dst_ip == pair.src_ip)) and existing_comm.id == pair.id:
                existing_comm.order.append(pair.order[0])
                existing_comm.order.append(pair.order[1])
                existing_comm.packets.extend(pair.packets)
                existing_comm.complete = True
                # I set found to True, so I know that I found the right communication
                found = True
                break
        # If there is not, I create a new one
        if not found:
            enumerated_comunication[enu] = pair
            enu += 1

    # Format menu for YAML
    if len(enumerated_comunication) != 0 and len(partial_c) != 0:
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "filter_name": 'icmp'.upper(),
            "complete_comms": [],
            "partial_comms": []
        }
    elif len(enumerated_comunication) != 0 and len(partial_c) == 0:
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "filter_name": 'icmp'.upper(),
            "complete_comms": [],
        }

    elif len(enumerated_comunication) == 0 and len(partial_c) != 0:
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "filter_name": 'icmp'.upper(),
            "partial_comms": []
        }

    order_number = 0
    # Format output for YAML
    for comm in enumerated_comunication.values():
        order_number += 1
        complete_coms = {
            "number_comm": order_number,
            "src_comm": comm.src_ip,
            "dst_comm": comm.dst_ip,
            "packets": []
        }
        for packet in comm.packets:
            packet = raw(packet)
            frame_number = comm.order[comm.packets.index(packet)]
            icmp_id = int(str(hexlify(packet[38:40]))[2:-1], 16)
            icmp_seq = int(str(hexlify(packet[40:42]))[2:-1], 16)
            packet_info = {"frame_number": frame_number}
            packet_info.update(format_output_1(packet, "icmp"))
            packet_info["icmp_id"] = icmp_id
            packet_info["icmp_seq"] = icmp_seq
            packet_info.update(format_output_2(packet))

            complete_coms["packets"].append(packet_info)
        menu["complete_comms"].append(complete_coms)

    number = 0
    for comm in partial_c:
        number += 1
        partial_coms = {
            "number_comm": number,
            "packets": []
        }
        for packet in comm.packets:
            packet = raw(packet)
            frame_number = comm.order[comm.packets.index(packet)]
            packet_info = {"frame_number": frame_number}
            packet_info.update(format_output_1(packet, "icmp"))
            packet_info.update(format_output_2(packet))
            partial_coms["packets"].append(packet_info)
        menu["partial_comms"].append(partial_coms)

    print_it(menu, "icmp")

    return


# This is function for task 4 - TCP filters, task_code is used to determine which filter to use
def task4_tcp(pcap_subor, task_code):
    counter = 0
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]

    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    # Firstly I find all TCP packets, based on task_code I find the right ports
    for packet in packets:
        counter += 1
        packet = raw(packet)
        ether_type = int(str(hexlify(packet[12:14]))[2:-1], 16)
        if ether_type == 2048:
            protocol_ip = int(str(hexlify(packet[23:24]))[2:-1], 16)
            if protocol_ip in protocols_ip:
                if protocols_ip[protocol_ip] == 'TCP':
                    src_port, dst_port = get_ports(packet)
                    if src_port in ports or dst_port in ports:
                        if src_port in ports:
                            port = ports[src_port]
                        else:
                            port = ports[dst_port]
                        if port == task_code:
                            order_and_packet[counter] = packet

    # If there are no TCP packets, print error message
    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne TCP pakety")
        return

    # Then I sort them into individual communications usig dictionary
    # key = (src_ip, src_port, dst_ip, dst_port), value = [packet_num, raw_packet]
    server_and_client_ip_port = {}
    for packet_num, raw_packet in order_and_packet.items():
        src_ip, dst_ip = get_ip_addresses(raw_packet)
        src_porty, dst_porty = get_ports(raw_packet)

        # If src_porty and dst_porty are not None, I create a unique key for this communication
        if src_porty is not None and dst_porty is not None:
            # Create keys for both directions
            key1 = (src_ip, src_porty, dst_ip, dst_porty)
            key2 = (dst_ip, dst_porty, src_ip, src_porty)

            # Check if this communication already exists
            # If yes, add this packet to existing communication with this key
            if key1 in server_and_client_ip_port:
                server_and_client_ip_port[key1].append([packet_num, raw_packet])
            elif key2 in server_and_client_ip_port:
                server_and_client_ip_port[key2].append([packet_num, raw_packet])
            else:
                # If not, create new communication
                server_and_client_ip_port[key1] = [[packet_num, raw_packet]]

    # Flags for checking if the communication is established
    flag_there_was_syn = False
    flag_there_was_syn_ack = False
    flag_there_was_ack = False

    # Flags for checking if the communication is complete
    flag_there_was_fin_ack_one = False
    flag_there_was_ack_one = False
    flag_there_was_fin_ack_two = False

    # For each key, value in dictionary I create a new communication
    for ip_port, tuple_pair in server_and_client_ip_port.items():
        # For each packet in communication I check if it is SYN, SYN ACK, ACK
        for packet_num, raw_packet in tuple_pair:
            src_ip, dst_ip = get_ip_addresses(raw_packet)
            src_port, dst_port = get_ports(raw_packet)
            # Binary representation of flags
            flags = bin(int(str(hexlify(raw_packet[47:48]))[2:-1], 16))
            flags = flags[2:]  # remove 0b
            flags = flags.zfill(8)  # fill with zeros to length 8
            # Flags are set
            SYN = int(flags[-2])
            ACK = int(flags[-5])
            FIN = int(flags[-1])
            RST = int(flags[-3])

            # If there is no communication, I create it
            if len(array_of_comms) == 0:
                communication = TCP_commun(src_port, dst_port, src_ip, dst_ip)
                communication.order.append(packet_num)
                communication.packets.append(raw_packet)
                array_of_comms.append(communication)
                # If the first packet has SYN, I set the flag
                if SYN == 1 and ACK == 0 and FIN == 0 and RST == 0:
                    flag_there_was_syn = True

            # If there is a communication, I add it to the existing one
            elif len(array_of_comms) != 0 and (src_ip == communication.src_ip or dst_ip == communication.src_ip) and (
                    dst_ip == communication.dst_ip or dst_ip == communication.src_ip) and (
                    src_port == communication.dst_port or src_port == communication.src_port) and (
                    dst_port == communication.src_port or dst_port == communication.dst_port):
                # Searching for established communication
                if flag_there_was_syn is False and (SYN == 1 and ACK == 0 and FIN == 0 and RST == 0):
                    flag_there_was_syn = True
                    communication = TCP_commun(src_port, dst_port, src_ip, dst_ip)
                    communication.order.append(packet_num)
                    communication.packets.append(raw_packet)
                    array_of_comms.append(communication)
                elif flag_there_was_syn is True and flag_there_was_syn_ack is False and (
                        SYN == 1 and ACK == 1 and FIN == 0 and RST == 0):
                    flag_there_was_syn_ack = True
                    communication.order.append(packet_num)
                    communication.packets.append(raw_packet)
                elif flag_there_was_syn is True and flag_there_was_syn_ack is True and flag_there_was_ack is False and (
                        SYN == 0 and ACK == 1 and FIN == 0 and RST == 0):
                    flag_there_was_ack = True
                    communication.order.append(packet_num)
                    communication.packets.append(raw_packet)
                    communication.established = True

                # If connection is established
                elif flag_there_was_syn is True and flag_there_was_syn_ack is True and flag_there_was_ack is True:
                    # The same communication has to use same ip addresses and ports
                    if (src_ip == communication.src_ip or src_ip == communication.dst_ip) and (
                            dst_ip == communication.dst_ip or dst_ip == communication.src_ip) and (
                            src_port == communication.src_port or src_port == communication.dst_port) and (
                            dst_port == communication.dst_port or dst_port == communication.src_port):
                        # If the communication is established, I am looking for the end of the communication
                        if communication.established is True:
                            # There are 4 way of ending connection
                            # If last packet has RST
                            if RST == 1:
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                                communication.complete = True
                                flag_there_was_syn = False
                                flag_there_was_syn_ack = False
                                flag_there_was_ack = False
                            # If last packet has RST and ACK
                            elif RST == 1 and ACK == 1:
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                                communication.complete = True
                                flag_there_was_syn = False
                                flag_there_was_syn_ack = False
                                flag_there_was_ack = False
                            # If communication[-3] has FIN and ACK, communication[-2] has FIN and ACK and communication[-1] has ACK
                            elif flag_there_was_fin_ack_one is False and FIN == 1 and ACK == 1:
                                flag_there_was_fin_ack_one = True
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                            elif flag_there_was_fin_ack_one is True and flag_there_was_fin_ack_two is False and FIN == 1 and ACK == 1:
                                flag_there_was_fin_ack_two = True
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                            elif flag_there_was_fin_ack_one is True and flag_there_was_fin_ack_two is True and FIN == 0 and ACK == 1:
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                                communication.complete = True
                                flag_there_was_syn = False
                                flag_there_was_syn_ack = False
                                flag_there_was_ack = False
                                flag_there_was_fin_ack_one = False
                                flag_there_was_fin_ack_two = False
                            # If communication[-4] has FIN and ACK, communication[-3] has ACK, communication[-2] has FIN and ACK and communication[-1] has ACK
                            elif flag_there_was_fin_ack_one is False and FIN == 1 and ACK == 1:
                                flag_there_was_fin_ack_one = True
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                            elif flag_there_was_fin_ack_one is True and flag_there_was_fin_ack_two is False and FIN == 0 and ACK == 1:
                                flag_there_was_ack_one = True
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                            elif flag_there_was_fin_ack_one is True and flag_there_was_ack_one is True and flag_there_was_fin_ack_two is False and FIN == 1 and ACK == 1:
                                flag_there_was_fin_ack_two = True
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                            elif flag_there_was_fin_ack_one is True and flag_there_was_ack_one is True and flag_there_was_fin_ack_two is True and FIN == 0 and ACK == 1:
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                                communication.complete = True
                                flag_there_was_syn = False
                                flag_there_was_syn_ack = False
                                flag_there_was_ack = False
                                flag_there_was_fin_ack_one = False
                                flag_there_was_fin_ack_two = False
                                flag_there_was_ack_one = False
                            # Else the packet is DATA and I add it to the existing communication
                            else:
                                communication.order.append(packet_num)
                                communication.packets.append(raw_packet)
                # If the communication is not established, I add it to the existing one
                else:
                    communication.order.append(packet_num)
                    communication.packets.append(raw_packet)
            # If there is no communication, I create it
            else:
                communication = TCP_commun(src_port, dst_port, src_ip, dst_ip)
                communication.order.append(packet_num)
                communication.packets.append(raw_packet)
                array_of_comms.append(communication)
                # If the first packet has SYN, I set the flag
                if SYN == 1 and ACK == 0 and FIN == 0 and RST == 0:
                    flag_there_was_syn = True
                else:
                    flag_there_was_syn = False
                # All other flags are set to False
                flag_there_was_syn_ack = False
                flag_there_was_ack = False
                flag_there_was_fin_ack_one = False
                flag_there_was_ack_one = False
                flag_there_was_fin_ack_two = False

        # Sort communications into complete and partial
        complete_c = []
        partial_c = []
        for comm in array_of_comms:
            if comm.complete:
                complete_c.append(comm)
            elif comm.complete is False:
                partial_c.append(comm)

    # Format menu for YAML
    if len(complete_c) != 0 and len(partial_c) != 0:
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "filter_name": task_code.upper(),
            "complete_comms": [],
            "partial_comms": []
        }

    elif len(complete_c) != 0 and len(partial_c) == 0:
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "filter_name": task_code.upper(),
            "complete_comms": [],
        }

    elif len(complete_c) == 0 and len(partial_c) != 0:
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "filter_name": task_code.upper(),
            "partial_comms": []
        }

    order_number = 0
    if len(complete_c) != 0:
        for comm in complete_c:
            order_number += 1
            complete_coms = {
                "number_comm": order_number,
                "src_comm": comm.src_ip,
                "dst_comm": comm.dst_ip,
                "packets": []
            }
            for packet in comm.packets:
                packet = raw(packet)
                frame_number = comm.order[comm.packets.index(packet)]
                packet_info = {"frame_number": frame_number}
                packet_info.update(format_output_1(packet, "tcp"))
                packet_info.update(format_output_2(packet))
                complete_coms["packets"].append(packet_info)
            menu["complete_comms"].append(complete_coms)

    if len(partial_c) != 0:
        comm = partial_c[0]
        partial_coms = {
            "number_comm": 1,
            "packets": []
        }
        for packet in comm.packets:
            packet = raw(packet)
            frame_number = comm.order[comm.packets.index(packet)]
            packet_info = {"frame_number": frame_number}
            packet_info.update(format_output_1(packet, "tcp"))
            packet_info.update(format_output_2(packet))
            partial_coms["packets"].append(packet_info)
        menu["partial_comms"].append(partial_coms)

    print_it(menu, task_code.lower())

    return


# Doimplementovat CDP ako filter pre 802.3 LLC + SNAP
def task_CDP(pcap_subor):
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]
    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    counter = 0
    # This is the dictionary for CDP packets
    for packet in packets:
        counter += 1
        packet = raw(packet)
        AAAA = str(hexlify(packet[14:15]))[2:-1]
        if AAAA == "aa":
            protocol_c = int(str(hexlify(packet[20:22]))[2:-1], 16)
            if protocol_c == 8192:
                order_and_packet[counter] = packet

    # If there are no CDP packets, print error message
    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne CDP pakety")
        return

    # for each packet I find the right information
    for packet_num, raw_packet in order_and_packet.items():
        protocol_c = int(str(hexlify(raw_packet[20:22]))[2:-1], 16)
        if protocol_c == 8192:
            order_and_packet[packet_num] = raw_packet

    # Format menu for YAML
    menu = {
        "name": str('PKS2023/24'),
        "pcap_name": str(pcap_subor),
        "packets": []
    }

    # Format output for YAML
    for packet_num, raw_packet in order_and_packet.items():
        packet = raw_packet
        frame_number = packet_num
        packet_info = {"frame_number": frame_number}
        packet_info.update(format_output_1(packet, "cdp"))
        packet_info.update(format_output_2(packet))
        menu["packets"].append(packet_info)

    number_of_packets = len(menu["packets"])
    menu["number_frames"] = number_of_packets
    print_it(menu, "all")
    return


# Those are functions for loading infromation from external files
protocols_llc = load_protocols_from_file(100)
protocols_ether = load_protocols_from_file(513)
protocols_ip = load_protocols_for_ip()
ports = load_ports()
icmp_codes = load_icmp()
array_of_comms = []
order_and_packet = {}
hash_table_IP = {}


# MAIN
def main():
    # Program header
    print("\n\t\tDávid Truhlář - 120897 - PKS Zadanie číslo 1\n\t\t   🌐🔍Analyzátor sieťovej komunikácie🔍🌐")
    print("-------------------------------------------------------------")
    # Loop for User Interface
    file_loaded = False
    check2 = 0
    check_complete = -1
    while True:
        if file_loaded is False:
            # File selection
            input_user = input("  ✍️ Zadaj názov súboru: ")
            if input_user == "exit":
                print("  🙋‍♂️")
                return 0
            pcap_subor = "test_pcap_files/"
            pcap_subor += input_user
            # Check if file exists
            if not exists(pcap_subor):
                print("  ⛔ 📄{} neexistuje\n  ✍️ Skús znova alebo zadaj 🚪 exit\n".format(pcap_subor))
                continue
            else:
                file_loaded = True
                print("  📄{} 👌".format(pcap_subor))
        if check2 != 1:
            # Task selection
            print()
            print("  📋1 a 2 Výpis informácií o pakete")
            print("  📊3 Zobrazenie štatistiky - IP")
            print("  🌪️4 Zadaj názov filtra:")
            print("  \t\tHTTP | HTTPS | TELNET | SSH \n  \tFTPcontrol | FTPdata | TFTP | ARP | ICMP | CDP")

            print("  🚪exit")
        check = 1
        if check_complete != 0:
            task = input("\n\t👉Vyber úlohu:")
        else:
            q = input("  Quit? (y/n)")
            if q == "y":
                print("  🙋‍♂️")
                return 0
            else:
                print("  🙋‍♂️ Aj tak hotovo 👍🎉")
                return 0

        if task == "1" or task == "2" or task == "3":
            tasks_1_2_3(pcap_subor, task)
            check = 0
            check2 = 1
            check_complete = 0
        if task == "tftp" or task == "TFTP" or task == "udp" or task == "UDP":
            task4_udp(pcap_subor)
            check = 0
            check2 = 1
            check_complete = 0
        if task == "arp" or task == "ARP":
            task4_arp(pcap_subor)
            check = 0
            check2 = 1
            check_complete = 0
        if task == "icmp" or task == "ICMP":
            task4_icmp(pcap_subor)
            check = 0
            check2 = 1
            check_complete = 0
        if task == "4":
            check = 0
            print()
            print(
                "  Uloha 4 - Zadaj meno filtra:\n  HTTP | HTTPS | TELNET\n  SSH | FTPcontrol | FTPdata\n  TFTP | ARP | ICMP | CDP")
            check2 = 1
        if task == "CDP":
            task_CDP(pcap_subor)
            check = 0
            check2 = 1
        if task == "http" or task == "HTTP" or task == "https" or task == "HTTPS" or task == "telnet" or task == "TELNET" or task == "ssh" or task == "SSH" or task == "ftpcontrol" or task == "FTPcontrol" or task == "FTPc" or task == "ftpdata" or task == "FTPdata" or task == "FTPd" or task == "ftpd" or task == "ftpc":
            check = 0
            check2 = 1
            if task == "http":
                task = "HTTP"
            if task == "https":
                task = "HTTPS"
            if task == "telnet":
                task = "TELNET"
            if task == "ssh":
                task = "SSH"
            if task == "ftpcontrol" or task == "FTPcontrol" or task == "FTPc" or task == "ftpc":
                task = "FTP-CONTROL"
            if task == "ftpdata" or task == "FTPdata" or task == "FTPd" or task == "ftpd":
                task = "FTP-DATA"
            task4_tcp(pcap_subor, task)
            check_complete = 0
        if task == "exit":
            print("  🙋‍♂️")
            return 0
        else:
            if check == 1:
                print("  ⛔ Zadal si nesprávny vstup, skús znova / exit")
                check2 = 1


if __name__ == '__main__':
    main()
