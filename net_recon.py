# Start of the Program

my_name = "Rahul Ramesh R00207989"
bold_my_name = "\033[1m" + my_name + "\033[0"
print(bold_my_name)

# Importing the necessary modules
import datetime
import sys


# We will try importing the Scapy library, else it will throw an error
try:
    from scapy.all import *

except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()

# The help command that will help the user understand the basic functionality of the script
def helpcommand():
    print("  This is a tool for active and passive recon")
    print("net_recon 1.0, is a network scanner and ARP packet sniffer")
    print(" ")
    print("Usage: net_recon.py [MODE]... [OPTION]... [INTERFACE NAME] ")
    print(" ")
    print("MODE:")
    print("-a or -- active              For Active Recon")
    print("-p or -- active              For Passive Recon")
    print(" ")
    print("OPTION")
    print("-i or --iface                Switch for mentioning interface")
    print(" ")
    print("INTERFACE NAME")
    print("<name of the interface>          Enter the network interface name")

    print("use '-a' for active scanning")
    print("use '-p' for passive scanning/ARP Sniffer")
    print("Disclaimer: I am not liable to any misuse of this tool.")
    print(" ")
    print('\033[1m' + 'Usage Example: net_recon.py -a -i eth0' + '\033[0m')
    print('\033[1m' + 'A Tool made by Rahul Ramesh' + '\033[0m')
    
var = ['-h','--help']

# Checking if the 1st CLI argument is the name of the file and is the only argument.
if (sys.argv[0]) == 'net_recon.py' and len(sys.argv) == 1:
    helpcommand()
    exit()

# Checking if the 1st CLI argument is the name of the file and is the only argument.
if ((sys.argv[1]) == var[1]) or ((sys.argv[1]) == var[0]):
    helpcommand()
    exit()

# Displaying the user to make him run as a user
print("\n!Make sure to run this program as ROOT !\n")


class Passive:  # A Class to wrap the function
    def __call__(self): # Passive method to call in future


        # Setting network interface in promiscuous mode
     
    # Promiscuous mode is normally used for packet sniffing that takes place on a router or on a computer connected to a hub.
   
    # Error handling in the Command line Arguments, if the 4th or 3rd argument is the interface, we set the interface etho promiscuous mode, else it will print the error accordingly

        if conf.iface == sys.argv[3] or conf.iface == sys.argv[2]:
            subprocess.call(["ifconfig", sys.argv[3], "promisc"], stdout=None, stderr=None, shell=False)
            print("\nInterface %s was set to PROMISCUOUS mode.\n" % conf.iface)
        else:
            print("\nFailed to configure interface as promiscuous.\n")
            print('\033[1m' + "\nCheck the name of the interface.\n" + '\033[0m')
            exit()




        # Setting 0 as infinite so that our program could capture packets forever
        pkt_count = 0
        pkt_to_sniff = pkt_count

        if int(pkt_to_sniff) == 0:
            print("\nThe program will capture packets until the timeout expires.\n")

        # Setting the time to 0 for infinity
        time_to_sniff = 0
        if int(time_to_sniff) != 0:
            print("\nThe program will capture ARP packets forever.\n")

        # This program will capture only the ARP packets.

        proto_sniff = "arp"

        # Considering the case when the sniffing protocol is ARP.

        if (proto_sniff == "arp"):
            print("\nThe program will capture only ARP packets.\n")

        # The function will extract parameters from the packet and then log each packet
        def packet_log(packet):
            # Getting the current timestamp
            now = datetime.now()
            
            # Multiple ARP requests won't be stored
            if (packet[0].src in packet[0]):
               print("The duplicate MAC won't be stored!")
               exit()

        # Writing the packet information to the log file
            elif (proto_sniff == "arp"):
            # Writing the data to the log file
               print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + "\t" + " Src IP " + packet[0].psrc + "\t" + " Dest IP " + packet[0].pdst + "\t" + " Source MAC: " + packet[0].src + "\t" + " Dest MAC: " + packet[0].dst)

        # Printing an informational message to the screen
        print("\n* Starting the capture...")

        # Running the sniffing process (with or without a filter)

        if proto_sniff == "arp":
            sniff(iface=conf.iface, filter=proto_sniff, count=int(pkt_to_sniff), prn=packet_log)

        else:
            print("\nCould not identify the protocol.\n")
            sys.exit()


ip_addr = get_if_addr(conf.iface)
ip_cidr = ip_addr + "/24"


class Active: # A class to wrap the function
    def __call__(self): # A self-calling function when the class is invoked.
    
        # The scan function
        def scan(ip_cidr):
        
       
            arp_request = ARP(pdst=ip_cidr) # Sending ARP request in the network
            
            # The MAC address used for brdcast (Broadcast MAC address) is ff:ff:ff:ff:ff:ff. Broadcast MAC address is a MAC address consisting of all binary 1s
            brdcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            
                # ARP sends a request packet to all the machines on the LAN and inquires whether any of them are            utilizing that specific IP address. 
            arp_request_brdcast = brdcast / arp_request 
            
            # Layer 2 packets are sent and received.
            answered_list = srp(arp_request_brdcast, timeout=1, verbose=False)[0]

        # Storing the list of clients in client_list after looping through the answered list
            client_list = []
            for element in answered_list:
                client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                client_list.append(client_dictionary)
            return client_list
        
        # Printing the clients who responded to our machine
        def print_result(results_list):
            print("IP\t\t\tMAC Address\n-------------------------------------")
            for client in results_list:
                print(client["ip"] + "\t\t" + client["mac"])

        # Feeding the IP address in the scan by pass by reference method and printing the scan result
        scan_result = scan(ip_cidr)
        print_result(scan_result)


passive = Passive() #Created an object to call the class.
active = Active() #Created an object to call the class
    
        
        # Error handling validation for passive, active, -i, --iface, <interface>


string = ['-i','--iface','-a','--active','-p','--passive',conf.iface]


if (((sys.argv[1]) == string[4]) or ((sys.argv[1]) == string[5])) and (((sys.argv[2]) == string[0]) or ((sys.argv[2]) == string[1])) and ((sys.argv[3]) == conf.iface):

    passive()
    
elif ((sys.argv[3]) == string[4] or (sys.argv[3]) == string[5]) and ((sys.argv[1]) == string[0] or (sys.argv[1]) == string[1]) and (sys.argv[2] == conf.iface):

    passive()
    
    exit()

elif ((sys.argv[1]) == string[2] or (sys.argv[1]) == string[3]) and ((sys.argv[2]) == string[0] or (sys.argv[2]) == string[1]) and (sys.argv[3] == conf.iface):

    active()

elif ((sys.argv[3]) == string[2] or (sys.argv[3]) == string[3]) and ((sys.argv[1]) == string[0] or (sys.argv[1]) == string[1]) and (sys.argv[2] == conf.iface):
    
    active()
    
    exit()

elif ((sys.argv[1]) == string[4]) or ((sys.argv[1]) == string[5]):

	print('\033[1m' + "Passive Scanning failed. Interface Name does not exist! Check the interface name or switch and try again, or hit 'net_recon.py --help'" + '\033[0m')

elif ((sys.argv[1]) == string[2]) or ((sys.argv[1]) == string[3]):
	
	print('\033[1m' + "Active Scanning failed. Interface Name does not exist! Check the interface name or switch and try again, or hit 'net_recon.py --help'" + '\033[0m')
	exit()

# End of the program
