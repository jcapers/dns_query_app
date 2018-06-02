################################################################################
# COMS3200 Assignment 2
# Python 3 DNS Requester
# DNS Query Class
# - creates and processes DNS question and response packets. Using dnslib.
################################################################################

# Add to PYTHONPATH, since PyCharm did this automatically...
import sys
import os
PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.realpath(os.path.dirname(__file__))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))
# Add to PYTHONPATH, since PyCharm did this automatically...

from dnslib import *
from src.sharedconsts import *


class DNSQuery:
    """
    DNSQuery object which stores questions, and answers. It also parses
    in order to assist query construction and interpretation.
    """
    def __init__(self):
        # DNS Request for this Query
        self._dns_request = None
        # Response from DNS server to this Query
        self._dns_response = None
        # Answers from dns response
        self._dns_answers = list()

    def set_question(self, host, qtype):
        """
        Setup DNS Question and headers.
        Args:
            host (str): address to query. E.g., "google.com"
            qtype (int): integer code to represent question type.
                        0 = IPv4, 1 = IPv6, 2 = Mail Server, 3 = Reverse

        """
        try:
            self._dns_request = DNSRecord.question(host, QUERY_TYPES[qtype])
        except dns.DNSError:
            print("Unrecognised query type.")

    def set_response(self, packet):
        """
        Stores response returned by DNS server.
        Args:
            packet (bytes): Byte array of a dns response packet.

        """
        try:
            self._dns_response = DNSRecord.parse(packet)
        except Exception as e:
            print("Unable to parse packet. Error: {}".format(str(e)))

    def get_request(self):
        """
        Get DNS query.
        Returns:
            DNSRecord: DNSRecord object from dnslib. Not parsed to bytes.

        """
        return self._dns_request

    def get_response(self):
        """
        Gets the response from DNS server.
        Returns:
            DNSRecord: DNSRecord object from dnslib, not human readable.

        """
        return self._dns_response

    def answers(self):
        """
        Parses DNS Response for answers to query.
        Returns:
            list: A list of all answers returned by DNS server.

        """
        if self._dns_response is None:
            print("No answers available.")
        else:
            self._dns_answers = [record.rdata for record in self._dns_response.rr]
        return self._dns_answers

#
# print("*Rough Test of Answers*")
# packet = binascii.unhexlify(b'd5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93')
# test_query = DNSQuery()
# test_query.set_response(packet)
# print("Printing Response Packet")
# print(test_query.get_response())
# test_answers = test_query.answers()
# print("\nPrinting Answers")
# print(test_answers)
#
# print("*Rough Test of Questions*")
# test_q2 = DNSQuery()
# test_q2.set_question("www.google.com", 3)
# print("Printing Query")
# print(test_q2.get_request())
#
# print(is_ip(test_answers[0]))
# print(is_ip("2404:6800:4006:809::200e"))
# print("End!")
