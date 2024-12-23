''' Module containing logic for conversion to byte message to
and from the dns server.

HEADER
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

'''
import random
import struct
import socket
import re
import copy


NAMESERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30"
]


class MessageGenerator:
    ''' Creates the message in the required byte format.
    '''

    def __init__(self):
        self.header_id = random.randint(0, 65535)

    def create_header(self):
        ''' Creates the header for message'''
        # Saving in self for later match with response
        flags = 0x0000
        questions = 1

        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        return struct.pack(
            "!HHHHHH", # ! for endian
            self.header_id,
            flags,
            questions,
            answer_rrs,
            authority_rrs,
            additional_rrs
        )

    def generate_question(self, domain_name, qtype, qclass):
        parts = domain_name.split(".")
        encoded_name = b"".join(
            [bytes([len(part)]) + part.encode() for part in parts]
        ) + b"\x00"

        return encoded_name + struct.pack("!HH", qtype, qclass)
    
    def create_message(self, domain_name, qtype=1, qclass=1):
        return self.create_header() + self.generate_question(
            domain_name, qtype, qclass
        )


class NameServerClient:
    ''' Communicates with the servername and receives and
    process the ip address associated with domain name.
    We are using google dns server to resolve the names.'''

    UDP_PORT = 53

    @classmethod
    def request_dns_server(self, message, udp_ip):
        
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        ## Make requests to recieve data.
        sock.sendto(message, (udp_ip, self.UDP_PORT))

        response, addr = sock.recvfrom(512)
        return response


class ResponseParser:
    ''' The domain name system utilizes a compression algorithm.
    This class helps decompress the message and create a suitable
    datastructure holding different part of response'''

    def parse(self, response, transaction_id):
        ''' Divides the response into different parts
        and decode each part into an organized data structure.'''
        current_offset = 0
        header, current_offset = self.get_header(response, current_offset)
        self.validate_QR(header[1])

        if transaction_id != header[0]:
            raise Exception("Invalid response!")
        domain_name, current_offset = self.decode_domain(response, current_offset)
        answers, current_offset = self.decode(response, current_offset, header[3])
        authorities, current_offset = self.decode(response, current_offset, header[4])
        additional_sections, current_offset = self.decode(response, current_offset, header[5])

        return header, domain_name, answers, authorities, additional_sections
    
    def validate_QR(self, flag):
        ''' Validates that the recieved QR is 1.'''
        if not (flag >> 15 & 1):
            # bring the QR value to least signiicant bit.
            raise Exception("Invalid QR!")

    def decode(self, response, offset, n):
        ''' Decodes the portion from the response and moves the offset
        as required.
        ANSWERS, ADDITIONAL_SECTION, AUTHORITIES
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                      NAME                     /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     CLASS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TTL                      |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   RDLENGTH                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        /                     RDATA                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        '''
        results = []

        for _ in range(n):
            name = response[offset: offset+2]
            # if first two bits are set, then decompression is required.
            if name[0] & 0xC0 == 0xC0:
                pointer = (name[0] & 0x3F) << 8 | name[1]
                name, _ = self.decode_domain(response, pointer)
                offset += 2 # Skip the pointer as we dont need domain names
            else:
                while response[offset] != 0x00:
                    offset += 1
                offset += 1

            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", response[offset: offset+10])
            offset += 10

            rdata = response[offset: offset+rdlength]

            if rtype == 1:
                rdata = "".join(map(str, socket.inet_ntoa(rdata)))
            elif rtype in (5, 6, 2):
                rdata = self.decode_domain(response, offset)[0]

            offset += rdlength

            results.append({
                "name": name,
                "rtype": rtype,
                "rclass": rclass,
                "ttl": ttl,
                "rdlength": rdlength,
                "rdata": rdata
            })

        return results, offset

    def decode_domain(self, response, offset):
        domain = []
        while True:
            length = response[offset]
            if length == 0x00: # 0 length represents the end of the domain name
                offset += 1
                break
            elif length & 0xC0 == 0xC0:
                pointer = ((length & 0x3F) << 8) | response[offset + 1]
                offset += 2
                domain.append(self.decode_domain(response, pointer)[0])
                break
            else:
                offset += 1 # Skip the length offset and move to next first character
                # Read till length and decode it
                domain.append(response[offset:offset + length].decode("utf-8"))
                offset += length

        # Adding 4 to offset to skip QTYPE and QCLASS associated with domain.
        return ".".join(domain), offset + 4

    def get_header(self, response, offset):
        ''' Reads and parse the header.'''
        return struct.unpack(
            "!HHHHHH",
            response[offset: offset + 12] # First 12 bytes represent the header.
        ), offset + 12


def valid_domain(domain_name):
    pattern = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$')
    return bool(pattern.match(domain_name))


if __name__ == "__main__":
    domain_name = input("Enter the name of domain:- ")
    while not valid_domain(domain_name):
        domain_name = input("Please enter a valid domain name:- ")

    # using stack to keep track of all the server used
    nameserver_stack = copy.deepcopy(NAMESERVERS)

    name_server_client = NameServerClient()
    message_generator = MessageGenerator()
    response_parser = ResponseParser()

    while True:
        if not nameserver_stack: raise Exception("Name servers not available!")

        nameserver = nameserver_stack.pop()
        print(f"Querying {nameserver} for {domain_name}")

        message = message_generator.create_message(
            domain_name=domain_name
        )

        response = name_server_client.request_dns_server(message, nameserver)

        # Parse the response to check if the domain is available
        response = response_parser.parse(
            response, message_generator.header_id)
        
        rcode = response[0][1] & 0x0F # Get the last four bits of the header.
        if rcode == 3: # Domain does not exist
            raise Exception(
                "Non existent domain. No IP address is connected to this domain.")

        resolved_addresses = response[2]
        if resolved_addresses != []:
            address = resolved_addresses[0]
            if address['rtype'] == 1: break
            else:
                domain_name = address['rdata']
                nameserver_stack = copy.deepcopy(NAMESERVERS)
        else:
            for address in response[3]:
                nameserver_stack.append(address['rdata'])

    # Print the address
    for answer in resolved_addresses:
        print(answer['rdata'])
