################################################################################
# COMS3200 Assignment 2
# Python 3 DNS Requester
# DNS Query Application
# - GUI implementation for user to input host, dns server, and get results for:
# - IPv4, IPv6, CNAMEs, and MailServers.
################################################################################


# Add to PYTHONPATH, since PyCharm did this automatically...
import sys
import os
PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.realpath(os.path.dirname(__file__))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))
# Add to PYTHONPATH, since PyCharm did this automatically...

import src.dnsrequest as dnsrequest
from src.sharedconsts import *
from PyQt5.QtWidgets import QApplication, QWidget, QGridLayout, QLabel, \
    QLineEdit, QTextEdit, QPushButton
from PyQt5.QtCore import pyqtSlot


class DNSApp(QWidget):

    def __init__(self):
        super().__init__()
        self._title = "DNS Query Application - COMS3200"
        self._wsize = {'left': 100, 'top': 100, 'width': 480, 'height': 320}
        self.grid = QGridLayout()

        # Labels for input
        self.host_name = QLabel('Host:')
        self.dns_server = QLabel('DNS Server:')
        self.result = QLabel('Results: ')

        # Text boxes
        self.host_input = QLineEdit()
        self.dns_input = QLineEdit(DNS_DEF)
        self.result_box = QTextEdit()

        self.start_btn = QPushButton("Send Request")
        self.start_btn.clicked.connect(self.on_send_request)

        # DNS Requester
        self.DNSSearch = dnsrequest.DNSRequest(DNS_DEF, PORT)

        self.initGUI()

    def initGUI(self):
        """
        Initialise GUI elements and alignment on grid.
        """
        self.setWindowTitle(self._title)
        self.setGeometry(self._wsize['left'], self._wsize['top'],
                         self._wsize['width'], self._wsize['height'])

        # Set scroll bar to top if needed.
        self.result_box.verticalScrollBar().setValue(0)

        # Query Button
        self.start_btn.setMaximumWidth(100)

        # Result Box
        self.result_box.setReadOnly(1)

        # Layout in Grid
        self.grid.setSpacing(10)
        self.grid.addWidget(self.host_name, 0, 0)
        self.grid.addWidget(self.host_input, 0, 1)

        self.grid.addWidget(self.dns_server, 1, 0)
        self.grid.addWidget(self.dns_input, 1, 1)

        self.grid.addWidget(self.start_btn, 2, 1)

        self.grid.addWidget(self.result, 3, 0)
        self.grid.addWidget(self.result_box, 3, 1, 5, 1)

        self.setLayout(self.grid)

        self.show()

    @pyqtSlot()
    def on_send_request(self):
        """
        Handler for button press. Instructs app to send a query to a
        specified DNS server.

        Handles exception from dnsrequest.py should an erroneous hostname
        or dns server be input.
        """
        host = self.host_input.text()
        dns = self.dns_input.text()
        if not host or not dns:
            self.result_box.append("All fields need to be filled!\n")
        else:
            self.result_box.clear()
            try:
                self.run_query(host, dns)
            except:
                self.result_box.append("Error, check host and/or DNS.")
            # Reset for next query.
            self.DNSSearch = dnsrequest.DNSRequest(DNS_DEF, PORT)

    def run_query(self, host, dns):
        """
        Runs a DNS Query for specified host to a specified dns server.

        Finally, prints results in GUI.
        Args:
            host (str): the host name or IP address to query.
            dns (str): the dns IP address to send request to.
        """
        self.DNSSearch.set_host(host)
        self.DNSSearch.set_dns(dns)

        # Initial Input Confirmation
        self.result_box.append("Host Queried: {}".format(host))
        self.result_box.append("DNS: {}".format(dns))
        self.result_box.append(" ")

        # Do query
        self.DNSSearch.send_query()

        # Print Query
        self.print_results()

    def print_results(self):
        """
        Prints results, dependent on reverse or standard query.
        """
        if self.DNSSearch.flag_reverse:
            self.reverse_results()
        else:
            self.standard_results()

    def reverse_results(self):
        """
        Prints resultant host name for a reverse IP query.
        """
        self.result_box.append("Name(s):")
        for name in self.DNSSearch.ansReverse:
            self.result_box.append(str(name)[:-1])

    def standard_results(self):
        """
        Prints standard results in order of:
        - Canonical Name
        - IPv4 Addresses
        - IPv6 Addresses
        - Mail Servers

        If no record are found, will indicate as such.
        """
        # Print any CNames
        self.name_results()
        self.ip4_results()
        self.ip6_results()
        self.mail_results()

    def name_results(self):
        """
        Retrieve any CNAME records, if applicable and prints results.
        """
        names = list()

        for record in self.DNSSearch.ansIP4:
            if not is_ip(str(record)):
                names.append(str(record))

        self.result_box.append("Canonical Name:")

        if not names:
            self.result_box.append("No CNAME record.")
        else:
            for name in names:
                self.result_box.append(name)

        self.result_box.append(" ")

    def ip4_results(self):
        """
        Retrieves IPv4 results if applicable, and prints results.
        """
        addresses = list()

        for record in self.DNSSearch.ansIP4:
            if is_ip(str(record)):
                addresses.append(str(record))

        self.result_box.append("IPv4 Addresses:")

        for addr in addresses:
            self.result_box.append(addr)

        self.result_box.append(" ")

    def ip6_results(self):
        """
        Retrieves IPv6 results if applicable, and prints results.
        """
        addresses = list()

        for record in self.DNSSearch.ansIP6:
            if is_ip(str(record)):
                addresses.append(str(record))

        self.result_box.append("IPv6 Addresses:")

        if not addresses:
            self.result_box.append("No IPv6 Records.")
        else:
            for addr in addresses:
                self.result_box.append(addr)

        self.result_box.append(" ")

    def mail_results(self):
        """
        Retrieves mail server name and ip addresses, if applicable.
        Prints results as needed.
        """
        self.result_box.append("Mail Servers:")

        check = str(self.DNSSearch.ansMailHosts[0]).split()
        if len(check) > 1:
            names = list()
            addresses = list()

            # Retrieve mail servers and IP addresses in order
            for record in self.DNSSearch.ansMailHosts:
                names.append(str(record).split()[1][:-1])

            for address in self.DNSSearch.ansMailIPs:
                addresses.append(str(address))

            # Print Mail servers and IP addresses in order
            for i in range(len(names)):
                self.result_box.append("{}, {}".format(names[i], addresses[i]))
        else:
            self.result_box.append("No mail server records.")

        self.result_box.append(" ")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = DNSApp()
    sys.exit(app.exec_())
