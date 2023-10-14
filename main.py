from binascii import hexlify
from os.path import exists
import ruamel.yaml
from scapy.compat import raw
from scapy.utils import rdpcap

yaml = ruamel.yaml.YAML()
hash_table_IP = {}


# Class pre TCP
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


# Class pre TFTP filter
class UDP_comm:
    def __init__(self, src_port, dst_port, src_ip, dst_ip):
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.packets = []
        self.order = []
        self.complete = False


# Class pre ARP filter
class ARP_comm:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.packets = []
        self.order = []
        self.complete = False


# Class pre ICMP filter
class ICMP_comm:
    def __init__(self, src_ip, dst_ip, id_n, seq):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.id = id_n
        self.seq = seq
        self.order = []
        self.packets = []
        self.complete = False


# Funkcia na načítanie protokolov LLC a ETHER z textového súboru
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


# Funkcia na načítanie protokolov IP z textového súboru
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


# Funkcia na načítanie portov z textového súboru
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


# Funkcia na načítanie ICMP kódov z textového súboru
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


# Funkcia na získanie zdrojového a cieľového portu
def get_ports(packet):
    src_port = str(hexlify(packet[34:36]))[2:-1]
    src_port = int(src_port, 16)
    dst_port = str(hexlify(packet[36:38]))[2:-1]
    dst_port = int(dst_port, 16)
    return src_port, dst_port


# Funkcia na získanie zdrojovej a cieľovej MAC adresy
def get_mac_addresses(packet):
    zdroj_mac = ''
    ciel_mac = ''
    # Získanie zdrojovej a cieľovej MAC adresy
    for i in range(6):
        zdroj_mac += str(hexlify(packet[i:i + 1]))[2:-1] + ':'
    for i in range(6, 12):
        ciel_mac += str(hexlify(packet[i:i + 1]))[2:4] + ':'
    # Upravenie MAC adries do požadovaného formátu
    zdroj_mac = zdroj_mac[:-1]
    ciel_mac = ciel_mac[:-1]
    return zdroj_mac.upper(), ciel_mac.upper()


# Funkcia na získanie zdrojovej a cieľovej IP adresy
def get_ip_addresses(packet):
    zdroj_ip = ''
    ciel_ip = ''
    # Získanie zdrojovej a cieľovej MAC adresy
    for i in range(26, 30):
        zdroj_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
    for i in range(30, 34):
        ciel_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
    # Upravenie MAC adries do požadovaného formátu
    zdroj_ip = zdroj_ip[:-1]
    ciel_ip = ciel_ip[:-1]
    # if ip is not in zoznam_ip then add it

    ether_type = str(hexlify(packet[12:14]))[2:-1]
    ether_type = int(ether_type, 16)
    if ether_type == 2054:
        zdroj_ip = ''
        ciel_ip = ''
        for i in range(28, 32):
            zdroj_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
        for i in range(38, 42):
            ciel_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
        zdroj_ip = zdroj_ip[:-1]
        ciel_ip = ciel_ip[:-1]

    return zdroj_ip, ciel_ip


# Funkcia na získanie adresy pre ICMP packet s TTL exceeded
def get_time_to_live_exceeded_address(packet):
    src_ip = ''
    for i in range(26, 30):
        src_ip += str(int(str(hexlify(packet[i:i + 1]))[2:-1], 16)) + '.'
    src_ip = src_ip[:-1]
    return src_ip


# Funkcia na upravenie hexdumpu do požadovaného formátu
def format_hexadump(packet):
    # Upravenie hexdumpu do požadovaného formátu
    formatted_packet = ''
    for i in range(len(packet)):
        formatted_packet += str(hexlify(packet[i:i + 1]))[2:-1] + ' '
        if (i + 1) % 16 == 0:
            formatted_packet = formatted_packet[:-1]
            formatted_packet += '\n'
    formatted_packet = formatted_packet[:-1]
    formatted_packet += '\n'
    formatted_packet = formatted_packet.upper()
    # Literalscalarstring pre zachovanie formátovania
    '''
    Information about scalarstring.LiteralScalarString was obtained from:
    https://docs.rundeck.com/docs/manual/document-format-reference/job-yaml-v12.html#job-map-contents
    '''
    formatted_packet = ruamel.yaml.scalarstring.LiteralScalarString(formatted_packet)

    return formatted_packet


# Funkcia na získanie informácií o EtherType
def get_protocol_info(packet):
    frame_type = str(hexlify(packet[12:14]))[2:-1]
    frame_type = int(frame_type, 16)
    protocol_name = ''
    # Získanie informácií o EtherType
    if frame_type >= 1500 or frame_type == 512 or frame_type == 513:
        frame_type = "ETHERNET II"
        protocol_bytes = str(hexlify(packet[12:14]))[2:-1]
        protocol = int(protocol_bytes, 16)
        if protocol in protocols_ether:
            protocol_name = protocols_ether.get(protocol)
        elif protocol in protocols_llc:
            protocol_name = protocols_llc.get(protocol)
    else:
        if str(hexlify(packet[14:16]))[2:-1] == "aaaa":
            frame_type = "IEEE 802.3 LLC & SNAP"
            protocol_bytes = str(hexlify(packet[20:22]))[2:-1]
            protocol = int(protocol_bytes, 16)
            if protocol in protocols_ether:
                protocol_name = protocols_ether.get(protocol)
        elif str(hexlify(packet[14:16]))[2:-1] == "ffff":
            frame_type = "IEEE 802.3 RAW"
        else:
            frame_type = "IEEE 802.3 LLC"
            sap_byte = str(hexlify(packet[14:15]))[2:-1]
            sap = int(sap_byte, 16)
            if sap == 170:
                pid_bytes = str(hexlify(packet[47:48]))[2:-1]
                pid = int(pid_bytes, 16)
                if pid in protocols_llc:
                    protocol_name = protocols_llc[pid]
                elif pid in protocols_ether:
                    protocol_name = protocols_ether[pid]
            elif sap in protocols_llc:
                protocol_name = protocols_llc[sap]
    return frame_type, protocol_name


# Funckia na format outputu Zaciatok
def format_output_1(packet, task_number):
    info = {}

    len_frame_pcap = len(packet)
    if len_frame_pcap < 64:
        len_frame_medium = 64
    else:
        len_frame_medium = len_frame_pcap + 4
    frame_type, pid_sap = get_protocol_info(packet)
    src_mac, dst_mac = get_mac_addresses(packet)
    src_ip, dst_ip = get_ip_addresses(packet)
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

    # Formát menu pre YAML
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


# Funkcia na format outputu Pokracovanie
def format_output_2(packet):
    cely_packet = format_hexadump(packet)
    info = {"hexa_frame": cely_packet}

    return info


# Funkcia na format outputu Koniec
def print_it(menu, task):
    output_filename = 'output-{}.yaml'.format(task)

    with open(output_filename, 'w') as file:
        yaml.dump(menu, file)

    # Výpis úspešného ukončenia programu
    print("  ✅Výstup bol uložený do 🧾{}🎉".format(output_filename))
    return


# Funkcia task1 spája úlohy 1, 2 a 3
def task1(pcap_subor, task_number):
    vystup = []
    # Spracovanie pcap súboru
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]

    # Chybové hlásenie
    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    else:
        poradie = 1
        for packet in packets:
            packet = raw(packet)
            packet_info = {"frame_number": poradie}

            packet_info.update(format_output_1(packet, task_number))
            packet_info.update(format_output_2(packet))

            poradie += 1
            vystup.append(packet_info)

        # Uloženie výstupu do súboru
        menu = {
            "name": str('PKS2023/24'),
            "pcap_name": str(pcap_subor),
            "packets": vystup,
        }

        # Task 3 - IP statistika
        if task_number == "3":
            # sort hash_table by the max send packets
            sorted_hash = dict(sorted(hash_table_IP.items(), key=lambda item: item[1]))

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


# Filter TFTP
def task4_udp(pcap_subor):
    counter = 0
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]
    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    # Najskor najdem vsetky TFTP komunikacie
    for packet in packets:
        counter += 1
        packet = raw(packet)
        if int(str(hexlify(packet[23:24]))[2:-1], 16) == 17:
            order_and_packet[counter] = packet

    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne TFTP pakety")
        return

    # Potom ich roztriedim do jednotlivych komunikacii
    for packet_num, raw_packet in order_and_packet.items():
        IHL = int(str(hexlify(raw_packet[14:15]))[3: -1], 16) * 4 + 14
        src_port = int(str(hexlify(raw_packet[IHL:IHL + 2]))[2:-1], 16)
        dst_port = int(str(hexlify(raw_packet[IHL + 2:IHL + 4]))[2:-1], 16)
        src_ip, dst_ip = get_ip_addresses(raw_packet)
        op_code = int(str(hexlify(raw_packet[IHL + 8:IHL + 10]))[2:-1],
                      16)  # 1 Read Request (RRQ)     #2 Write Request (WRQ)   #3 Data (DATA)     #4 Acknowledgment (ACK)     #5 Error (ERROR)

        # Ak je to nová komunikácia, tak ju vytvorím
        if dst_port == 69 and op_code in [1, 2]:
            communication = UDP_comm(src_port, dst_port, src_ip, dst_ip)
            communication.order.append(packet_num)
            communication.packets.append(raw_packet)
            array_of_comms.append(communication)

        # Ak nie je nová komunikácia, tak ju pridám do existujúcej
        elif len(array_of_comms) != 0:
            for comm in array_of_comms:
                if comm.complete is False:
                    if (
                            src_ip == comm.dst_ip and dst_ip == comm.src_ip or src_ip == comm.src_ip and dst_ip == comm.dst_ip and dst_port == 69) \
                            or (
                            src_port == comm.dst_port and dst_port == comm.src_port or src_port == comm.src_port and dst_port == comm.dst_port):
                        # Ak je port 69, tak ho zmením na port, ktorý je v komunikácii
                        if comm.dst_port == 69:
                            comm.dst_port = src_port
                        if (
                                comm.src_port == src_port and comm.dst_port == dst_port or comm.src_port == dst_port and comm.dst_port == src_port):
                            comm.order.append(packet_num)
                            comm.packets.append(raw_packet)
                        # Ak je to ACK, tak je komunikácia ukončená a velkost paketu je menšia ako velkost paketu, ktorý bol poslaný ako druhy
                        if op_code == 4 and len(comm.packets[-2]) < len(comm.packets[1]):
                            comm.complete = True
                            break
                        # Ak je to Error alebo dohodnutá velkost paketu nie je ako bola dohodnuta
                        if op_code == 5 or (op_code == 4 and len(comm.packets[-2]) >= len(comm.packets[1])):
                            comm.complete = False

                # Ak je komunikácia ukončená, tak vytvorím novú
                else:
                    if dst_port == 69 and op_code in [1, 2]:
                        communication = UDP_comm(src_port, dst_port, src_ip, dst_ip)
                        communication.order.append(packet_num)
                        communication.packets.append(raw_packet)
                        array_of_comms.append(communication)

    # Formát menu pre YAML
    menu = {"name": str('PKS2023/24'), "pcap_name": str(pcap_subor), "filter_name": 'tftp'.upper(),
            "complete_comms": [], "partial_comms": []}

    compl_num = 0
    partial_num = 0
    processed_communications = set()

    for comm in array_of_comms:
        if comm in processed_communications:
            continue  # Skip already processed communications
        processed_communications.add(comm)

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


# Filter ARP
def task4_arp(pcap_subor):
    counter = 0
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]
    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    # Najskor najdem vsetky ARP komunikacie
    for packet in packets:
        counter += 1
        packet = raw(packet)
        if int(str(hexlify(packet[12:14]))[2:-1], 16) == 2054:
            order_and_packet[counter] = packet

    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne ARP pakety")
        return

    complete_c = []
    partial_requests = []
    bad_array = []

    # Potom ich roztriedim do jednotlivych komunikacii
    for packet_num, raw_packet in order_and_packet.items():
        # IHL je dlzka hlavicky v bajtoch použita ako offset
        IHL = int(str(hexlify(raw_packet[14:15]))[3: -1], 16) * 4 + 14
        src_ip, dst_ip = get_ip_addresses(raw_packet)
        op_code = int(str(hexlify(raw_packet[IHL + 6:IHL + 8]))[2:-1], 16)

        # Ak je to nová komunikácia, tak ju vytvorím
        if op_code == 1:
            communication = ARP_comm(src_ip, dst_ip)
            communication.order.append(packet_num)
            communication.packets.append(raw_packet)
            array_of_comms.append(communication)

        # Ak nie je nová komunikácia, tak ju pridám do existujúcej
        elif len(array_of_comms) != 0:
            for comm in array_of_comms:
                if comm.complete is False:
                    # Ak je to ARP reply, tak je komunikácia ukončená
                    if src_ip == comm.dst_ip and dst_ip == comm.src_ip:
                        if op_code == 2:
                            comm.order.append(packet_num)
                            comm.packets.append(raw_packet)
                            comm.complete = True
                            break
                # Ak je komunikácia ukončená, tak vytvorím novú
                else:
                    if op_code == 1:
                        communication = ARP_comm(src_ip, dst_ip)
                        communication.order.append(packet_num)
                        communication.packets.append(raw_packet)
                        array_of_comms.append(communication)

        # Ak je to ARP reply a neexistuje žiadna komunikácia, tak vytvorím novú a pridám ju do zoznamu bad_array
        elif op_code == 2 and len(array_of_comms) == 0:
            bad = ARP_comm(src_ip, dst_ip)
            bad.order.append(packet_num)
            bad.packets.append(raw_packet)
            bad_array.append(bad)

    # Roztriedenie komunikácií do complete a partial
    for comm in array_of_comms:
        if comm.complete is True:
            complete_c.append(comm)
        else:
            if comm.packets[0][20:22] == b'\x00\x01':
                partial_requests.append(comm)

    partial_replies = bad_array

    # Formát menu pre YAML
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

    def forcycle(packet_to_cycle):
        packet_to_cycle = raw(packet_to_cycle)
        frame_number = comm.order[comm.packets.index(packet_to_cycle)]

        packet_information = {"frame_number": frame_number}
        packet_information.update(format_output_1(packet_to_cycle, "arp"))
        packet_information.update(format_output_2(packet_to_cycle))
        return packet_information

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


# Filter ICMP
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
    enumerated_comunication = {}

    # Najskor najdem vsetky ICMP komunikacie
    for packet in packets:
        counter += 1
        packet = raw(packet)
        ether_type = int(str(hexlify(packet[12:14]))[2:-1], 16)
        if ether_type == 2048:
            protocol_ip = int(str(hexlify(packet[23:24]))[2:-1], 16)
            if protocol_ip in protocols_ip:
                if protocols_ip[protocol_ip] == 'ICMP':
                    order_and_packet[counter] = packet

    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne ICMP pakety")
        return

    # Potom ich roztriedim do jednotlivych komunikacii
    for packet_num, raw_packet in order_and_packet.items():
        ip_source, ip_destination = get_ip_addresses(raw_packet)
        icmp_type = int(str(hexlify(raw_packet[34:35]))[2:-1], 16)

        id_number = int(str(hexlify(raw_packet[38:40]))[2:-1], 16)
        seq_number = int(str(hexlify(raw_packet[40:42]))[2:-1], 16)

        # Ak je icmp_type 11, tak zistím adresu, ktorá je v pakete
        if icmp_type == 11:
            addr = get_time_to_live_exceeded_address(packet)

        # Ak je to nová komunikácia, tak ju vytvorím
        if icmp_type == 8:
            communication = ICMP_comm(ip_source, ip_destination, id_number, seq_number)
            communication.order.append(packet_num)
            communication.packets.append(raw_packet)
            array_of_comms.append(communication)

        # Ak nie je nová komunikácia, tak ju pridám do existujúcej
        elif len(array_of_comms) != 0:
            for comm in array_of_comms:
                if comm.complete is False:
                    # Ošetrenie pre ICMP type 11
                    if icmp_type == 11 and addr == comm.dst_ip and ip_destination == comm.src_ip:
                        comm.order.append(packet_num)
                        comm.packets.append(raw_packet)
                        comm.complete = True
                        break
                    # Ošetrenie pre ICMP type 0
                    elif ip_source == comm.dst_ip and ip_destination == comm.src_ip:
                        if icmp_type == 0 and id_number == comm.id:
                            comm.order.append(packet_num)
                            comm.packets.append(raw_packet)
                            comm.complete = True
                            break

                # Ak je komunikácia ukončená, tak vytvorím novú
                else:
                    if icmp_type == 8:
                        communication = ICMP_comm(ip_source, ip_destination, id_number, seq_number)
                        communication.order.append(packet_num)
                        communication.packets.append(raw_packet)
                        array_of_comms.append(communication)

        # Ak je icmp_type 3, 4 alebo 5, tak vytvorím novú komunikáciu a pridám ju do zoznamu partial_c
        if icmp_type in [3, 4, 5]:
            bad = ICMP_comm(ip_source, ip_destination, id_number, seq_number)
            bad.order.append(packet_num)
            bad.packets.append(raw_packet)
            partial_c.append(bad)

    # Roztriedenie komunikácií do complete a partial
    for comm in array_of_comms:
        if comm.complete:
            complete_c.append(comm)
        else:
            partial_c.append(comm)

    # Rozdelenie jednotlivých párov do jednotlivých komunikácií podľa IP a id
    for pair in complete_c:
        found = False
        # Kontrola, či už existuje komunikácia s daným id a ip
        for key, existing_comm in enumerated_comunication.items():
            # Ak áno, tak pridám par do existujúcej komunikácie
            if ((existing_comm.src_ip == pair.src_ip and existing_comm.dst_ip == pair.dst_ip) or (
                    existing_comm.src_ip == pair.dst_ip and existing_comm.dst_ip == pair.src_ip)) and existing_comm.id == pair.id:
                existing_comm.order.append(pair.order[0])
                existing_comm.order.append(pair.order[1])
                existing_comm.packets.extend(pair.packets)
                existing_comm.complete = True
                found = True
                break

        # Ak neexistuje komunikácia s daným id a ip, tak vytvorím novú
        if not found:
            enumerated_comunication[enu] = pair
            enu += 1

    # Formát menu pre YAML
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


def task4_tcp(pcap_subor, task_code):
    counter = 0
    try:
        packets = rdpcap(pcap_subor)
        pcap_subor = pcap_subor.split('/')[-1]

    except Exception as e:
        print(f"Chyba pri čítaní pcap súboru: {e}")

    # Najskor najdem vsetky TCP komunikacie
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

    if len(order_and_packet) == 0:
        print("  🚫 V súbore sa nenachádzajú žiadne TCP pakety")
        return

    server_and_client_ip_port = {}
    for packet_num, raw_packet in order_and_packet.items():
        src_ip, dst_ip = get_ip_addresses(raw_packet)
        src_porty, dst_porty = get_ports(raw_packet)

        # Skontrolujte, či máte dostupné IP adresy a porty
        if src_porty is not None and dst_porty is not None:
            # Vytvorte unikátny kľúč pre túto komunikáciu
            key1 = (src_ip, src_porty, dst_ip, dst_porty)
            key2 = (dst_ip, dst_porty, src_ip, src_porty)

            # Skontrolujte, či už máte takýto kľúč v slovníku
            if key1 in server_and_client_ip_port:
                # Ak áno, pridajte tento paket do existujúcej komunikácie
                server_and_client_ip_port[key1].append([packet_num, raw_packet])
            elif key2 in server_and_client_ip_port:
                # Ak nie, pridajte tento paket do existujúcej komunikácie s iným kľúčom
                server_and_client_ip_port[key2].append([packet_num, raw_packet])
            else:
                # Ak neexistuje ani jeden z týchto kľúčov, vytvorte nový zoznam pre túto komunikáciu
                server_and_client_ip_port[key1] = [[packet_num, raw_packet]]

    flag_there_was_syn = False
    flag_there_was_syn_ack = False
    flag_there_was_ack = False

    flag_there_was_fin_ack_one = False
    flag_there_was_ack_one = False
    flag_there_was_fin_ack_two = False

    # Pre kazdu server a client komunikaciu kontrolujem nadviazanie spojenia a ukoncenie
    for ip_port, tuple_pair in server_and_client_ip_port.items():
        for packet_num, raw_packet in tuple_pair:
            src_ip, dst_ip = get_ip_addresses(raw_packet)
            src_port, dst_port = get_ports(raw_packet)
            flags = bin(int(str(hexlify(raw_packet[47:48]))[2:-1], 16))
            flags = flags[2:]
            flags = flags.zfill(8)
            SYN = int(flags[-2])
            ACK = int(flags[-5])
            FIN = int(flags[-1])
            RST = int(flags[-3])

            # Nadviazanie spojenia
            if flag_there_was_syn is False:
                if SYN == 1 and ACK == 0 and FIN == 0 and RST == 0:
                    flag_there_was_syn = True
                    communication = TCP_commun(src_port, dst_port, src_ip, dst_ip)
                    communication.order.append(packet_num)
                    communication.packets.append(raw_packet)
                    array_of_comms.append(communication)
            elif flag_there_was_syn is True and flag_there_was_syn_ack is False:
                if SYN == 1 and ACK == 1 and FIN == 0 and RST == 0:
                    flag_there_was_syn_ack = True
                    communication.order.append(packet_num)
                    communication.packets.append(raw_packet)
            elif flag_there_was_syn is True and flag_there_was_syn_ack is True and flag_there_was_ack is False:
                if SYN == 0 and ACK == 1 and FIN == 0 and RST == 0:
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
                        else:
                            communication.order.append(packet_num)
                            communication.packets.append(raw_packet)
        else:
            flag_there_was_syn = False
            flag_there_was_syn_ack = False
            flag_there_was_ack = False
            flag_there_was_fin_ack_one = False
            flag_there_was_ack_one = False
            flag_there_was_fin_ack_two = False

    # Roztriedenie komunikácií do complete a partial
    complete_c = []
    partial_c = []
    for comm in array_of_comms:
        if comm.complete:
            complete_c.append(comm)
        else:
            partial_c.append(comm)

    # todo eth-1 otvorenie komunikacii
    # Formát menu pre YAML
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


protocols_llc = load_protocols_from_file(100)
protocols_ether = load_protocols_from_file(513)
protocols_ip = load_protocols_for_ip()
ports = load_ports()
icmp_codes = load_icmp()
array_of_comms = []
order_and_packet = {}


def main():
    print("\n\t\tDávid Truhlář - 120897 - PKS Zadanie číslo 1\n\t\t   🌐🔍Analyzátor sieťovej komunikácie🔍🌐")
    print("-------------------------------------------------------------")
    # Uživatelske rozhranie loop
    file_loaded = False
    check2 = 0
    while True:
        if file_loaded is False:
            # Načítanie a otvorenie pcap súboru
            input_user = input("✍️ Zadaj názov súboru: ")
            if input_user == "exit":
                print("🙋‍♂️")
                return 0
            pcap_subor = "test_pcap_files/"
            pcap_subor += input_user
            if not exists(pcap_subor):
                print("⛔ 📄{} neexistuje\n✍️ Skús znova alebo zadaj 🚪 exit\n".format(pcap_subor))
                continue
            else:
                file_loaded = True
                print("📄{} 👌".format(pcap_subor))
        if check2 != 1:
            # Výber úlohy
            print("\n\t👉Vyber úlohu:")
            print("  📋1 a 2 Výpis informácií o pakete")
            print("  📊3 Zobrazenie štatistiky - IP")
            print("  🌪️4 Zadaj názov filtra:")
            print("  HTTP | HTTPS | TELNET | SSH \n  FTPcontrol | FTPdata | TFTP | ARP | ICMP")
            print("  🔙 back | 🚪exit")
        check = 1
        task = input("\n  ✍️ Zadaj číslo úlohy: ")
        if task == "1" or task == "2" or task == "3":
            task1(pcap_subor, task)
            check = 0
        if task == "tftp" or task == "TFTP" or task == "udp" or task == "UDP":
            task4_udp(pcap_subor)
            check = 0
        if task == "arp" or task == "ARP":
            task4_arp(pcap_subor)
            check = 0
        if task == "icmp" or task == "ICMP":
            task4_icmp(pcap_subor)
            check = 0
        if task == "http" or task == "HTTP" or task == "https" or task == "HTTPS" or task == "telnet" or task == "TELNET" or task == "ssh" or task == "SSH" or task == "ftpcontrol" or task == "FTPcontrol" or task == "FTPc" or task == "ftpdata" or task == "FTPdata" or task == "FTPd" or task == "ftpd" or task == "ftpc":
            check = 0
            if task == "http":
                task = "HTTP"  # trace-10.pcap
            if task == "https":
                task = "HTTPS"  # trace-10.pcap
            if task == "telnet":
                task = "TELNET"  # trace-9.pcap
            if task == "ssh":
                task = "SSH"  # eth-5.pcap
            if task == "ftpcontrol" or task == "FTPcontrol" or task == "FTPc" or task == "ftpc":
                task = "FTP-CONTROL"  # trace-14.pcap
            if task == "ftpdata" or task == "FTPdata" or task == "FTPd" or task == "ftpd":
                task = "FTP-DATA"  # trace-14.pcap
            task4_tcp(pcap_subor, task)
        if task == "back":
            file_loaded = False
            print()
            continue
        if task == "exit":
            print("🙋‍♂️")
            return 0
        else:
            if check == 1:
                print("  ⛔ Zadal si nesprávny vstup, skús znova / exit")
                check2 = 1


if __name__ == '__main__':
    main()
