from discombobulator import *

if __name__ == "__main__":
    tprint("          ARP_H4X0R")
    tprint("                            1337")
    print("Type \"arp\" for arp mode, or \"dns\" for dns mode.")

    selected=False
    while not selected:
        cmd=raw_input()
        if cmd=="arp":
            main_arp()
            selected=True
        elif cmd=="dns":
            main_dns()
            selected=True
        else:
            print("Invalid command.")