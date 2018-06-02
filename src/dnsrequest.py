################################################################################
# COMS3200 Assignment 2
# Python 3 DNS Requester
# DNS Request Class
# - Asks question to a specified DNS server about a specified host.
################################################################################

# Add to PYTHONPATH, since PyCharm did this automatically...
import sys
import os
PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.realpath(os.path.dirname(__file__))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))
# Add to PYTHONPATH, since PyCharm did this automatically...

from src.sharedconsts import *
from src.dnsquery import *
import socket


class DNSRequest:
    """
    DNS Request client that queries a specified DNS server and
    stores responses to query.
    """
    def __init__(self, dns, port):
        # Server
        self.dns_server = dns
        self.port = port

        # Connectivity
        self.socket = None

        # Question
        self.host = ""
        self.flag_reverse = False
        # Query for IP4
        self.qIP4 = None
        # Query for IP6
        self.qIP6 = None
        # Query for Mail Server, retrieves mail server host names.
        self.qMX = None
        # Query for IP's hostname
        self.qReverse = None

        # Answers
        self.ansIP4 = None
        self.ansIP6 = None
        self.ansMailHosts = None
        self.ansMailIPs = list()
        self.ansReverse = None

    def create_sock(self):
        """
        Create a socket for UDP datagram query.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print('Failed to create socket')
            sys.exit()

    def input_dns(self):
        """
        Temporary, sets the DNS server target.
        """
        dns = input("Enter DNS server, e.g., 8.8.8.8. Blank for default: ").strip()

        if dns:
            self.set_dns(dns)

    def set_dns(self, dns):
        """
        Sets DNS Server address.
        Args:
            dns (str): DNS server IP address.
        """
        self.dns_server = dns

    def request_host(self):
        """
        Temporary, request host by console for DNS query, input from client.
        """
        host = input("Enter host to query, e.g., google.com OR 130.102.79.33: ").strip().lower()

        if not host:
            print("Please enter a host to query!")

        self.set_host(host)

    def set_host(self, host):
        self.host = host
        if is_ip(self.host):
            self.flag_reverse = True
            self.qReverse = DNSQuery()
            # Reverse host for lookup
            reversed_host = ".".join(
                reversed(self.host.split('.'))) + '.in-addr.arpa'
            self.qReverse.set_question(reversed_host, 3)
        else:
            self.qIP4 = DNSQuery()
            self.qIP4.set_question(self.host, 0)
            self.qIP6 = DNSQuery()
            self.qIP6.set_question(self.host, 1)
            self.qMX = DNSQuery()
            self.qMX.set_question(self.host, 2)

    def connect_socket(self):
        """
        Establishes socket connection.
        """
        try:
            self.socket.connect((self.dns_server, self.port))
        except socket.timeout:
            print("Socket connection timed out. Exiting.")
            sys.exit()
        except socket.error:
            print("Failed to connect to host: {}. Exiting.".format(self.host))
            sys.exit()

    def send_query(self):
        """
        Sends the DNS Query.
        """
        if self.flag_reverse:
            self.send_reverse_lookup()
        else:
            self.send_standard_request()

    def send_standard_request(self):
        """
        Sends DNS Query to server to get IP4, IP6 and MX answers.

        Results stored as DNSRecord object in query class.
        """
        self.create_sock()
        self.connect_socket()
        # IPv4
        try:
            self.socket.sendall(bytes(self.qIP4.get_request().pack()))
        except socket.error:
            print("Request failed, at IPv4")
            sys.exit()

        data = self.socket.recv(4096)
        self.qIP4.set_response(data)
        self.socket.close()

        self.create_sock()
        self.connect_socket()
        # IPv6
        try:
            self.socket.sendall(bytes(self.qIP6.get_request().pack()))
        except socket.error:
            print("Request failed, at IPv6")
            sys.exit()

        data = self.socket.recv(4096)
        self.qIP6.set_response(data)
        self.socket.close()

        self.create_sock()
        self.connect_socket()
        # MailServ
        try:
            self.socket.sendall(bytes(self.qMX.get_request().pack()))
        except socket.error:
            print("Request failed, at MX")
            sys.exit()

        data = self.socket.recv(4096)
        self.qMX.set_response(data)
        self.socket.close()
        self.parse_answers()

    def send_reverse_lookup(self):
        """
        Sends DNS Query to server to reverse PTR request of an IP.

        Results stored as DNSRecord object in query class.
        """
        self.create_sock()
        self.connect_socket()

        try:
            self.socket.sendall(bytes(self.qReverse.get_request().pack()))
        except socket.error:
            print("Request failed, at IPv4")
            sys.exit()

        data = self.socket.recv(4096)
        self.qReverse.set_response(data)

        self.socket.close()
        self.parse_answers()

    def parse_answers(self):
        """
        Parse retrieved answers into list format for processing.
        """
        if not self.flag_reverse:
            self.ansIP4 = self.qIP4.answers()
            self.ansIP6 = self.qIP6.answers()
            self.ansMailHosts = self.qMX.answers()

            check = str(self.ansMailHosts[0]).split()
            if len(check) > 1:
                self.query_mail_servers()
        else:
            self.ansReverse = self.qReverse.answers()

    def query_mail_servers(self):
        """
        Queries for mail server IPs. Appends to this query's answers.
        """
        if self.ansMailHosts:
            for mail_host in self.ansMailHosts:
                name = str(mail_host).split()
                mail_query = DNSRequest(self.dns_server, self.port)
                mail_query.set_host(name[1][:-1])

                # Retrieve IPv4 for mail server.
                mail_query.create_sock()
                mail_query.connect_socket()
                # IPv4
                try:
                    mail_query.socket.sendall(bytes(mail_query.qIP4.get_request().pack()))
                except socket.error:
                    print("Request failed, at IPv4")
                    sys.exit()

                data = mail_query.socket.recv(4096)
                mail_query.qIP4.set_response(data)
                mail_query.socket.close()

                # Parse IP address
                mail_query.ansIP4 = mail_query.qIP4.answers()
                self.ansMailIPs.append(mail_query.ansIP4[0])

    def print_answers(self):
        """
        Temporary answers sans GUI.
        """
        print("Host Input: {}\n".format(self.host))
        if self.flag_reverse:
            self.print_reverse_ans()
        else:
            # IP Addresses
            self.print_IPs()
            # Mail Servers
            check = str(self.ansMailHosts[0]).split()
            if len(check) > 1:
                self.print_mailserv()

    def print_reverse_ans(self):
        """
        Retrieves names from reverse lookup response and prints.
        """
        print("Name:")
        for name in self.ansReverse:
            print(str(name)[:-1])

    def print_IPs(self):
        """
        Retrieves CNames, IPv4, and IPv6 from response and prints.
        """
        names = list()
        addresses = list()

        for record in self.ansIP4:
            if not is_ip(str(record)):
                names.append(record)
            else:
                addresses.append(record)

        # Print
        print("Canonical Name(s):")
        if not names:
            print("No CNAME records.\n")
        else:
            for name in names:
                print(str(name)[:-1])
            print()
        print("Addresses:")
        for addr in addresses:
            print(str(addr))
        print()

    def print_mailserv(self):
        """
        Retrieves mail server names and IP addresses.
        """
        names = list()
        addresses = list()

        for record in self.ansMailHosts:
            names.append(str(record).split()[1][:-1])

        for address in self.ansMailIPs:
            addresses.append(str(address))

        # Print
        print("Mail Servers:")
        for i in range(len(names)):
            print("{}, {}".format(names[i], addresses[i]))
        print()


if __name__ == "__main__":
    # # DNS
    # test_request = DNSRequest(DNS_DEF, PORT)
    # test_request.input_dns()
    #
    # # Set Request
    # test_request.request_host()
    #
    # # Parse Request
    # test_request.send_query()
    # test_request.parse_answers()
    # test_request.print_answers()
