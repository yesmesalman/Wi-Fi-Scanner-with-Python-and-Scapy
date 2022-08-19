from scapy.all import *
import sys
import signal
import os


def signal_handler(signal, frame):
    print("\n ============================")
    print("execution aborted by user")
    print("\n ============================")
    os.system("kill -9 " + str(os.getpid()))
    sys.exit(1)

def usage():
    if len(sys.argv) < 3:
        print("\n usage: ")
        print("\t wifi-scanner.py -i <interface> \n ")
        sys.exit(1)

def check_root():
    if not os.geteuid() == 0:
        print("you must run this script with root privileges.")
        sys.exit(1)


def setup_monitor(iface):
    print("Setting up sniffing options ...")
    os.system('ifconfig '+ iface + ' down')

    try:
        os.system('iwconfig '+ iface +' mode monitor')
    except:
        print("Failed to setup your interface in monitor mode")
        sys.exit(1)

    os.system('ifconfig ' + iface + ' up')
    return iface

def init_process():
    global ssid_list
    ssid_list = {}
    global s
    s = conf.L2socket(iface=newiface)


def sniffpackets(packet):
    try:
        SRMAC = packet[0].addr2
        DSTMAC = packet[0].addr1
        BSSID = packet[0].addr3
    except:
        print("Cannot read MAC Address")
        print(str(packet))

    try:
        SSIDSize = packet[0][Dot11Elt].len
        SSID = packet[0][Dot11Elt].info
    except:
        SSID = ""
        SSIDSize = 0


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    usage()
    check_root()
    parameters = {sys.argv[1]: sys.argv[2]}

    if "mon" not in str(parameters["-i"]):
        newiface = setup_monitor(parameters["-i"])
    else:
        newiface = str(parameters["-i"])

    init_process()
    print("Starting Wi-Fi Sniffer \n")
    print("Sniffing on interface "+ str(newiface) +"... \n")
    sniff(iface=newiface, prn=sniffpackets, store=0)
