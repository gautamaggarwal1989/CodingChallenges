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


class MessageGenerator:
    ''' Creates the message in the required byte format.
    '''

    def create_header(self):
        ''' Creates the header for message'''
        # Saving in self for later match with response
        self.header_id = random.randint(0, 65535)
        flags = 0x0100
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

    UDP_IP = "8.8.8.8"
    UDP_PORT = 53

    def request_dns_server(self, message):
        
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        ## Make requests to recieve data.
        sock.sendto(message, (self.UDP_IP, self.UDP_PORT))

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
        self.header, current_offset = self.get_header(response, current_offset)
        self.validate_QR()

        if transaction_id != self.header[0]:
            raise Exception("Invalid response!")
        domain_name, current_offset = self.decode_domain(response, current_offset)
        answers, current_offset = self.decode_answer(response, current_offset)
        # authorities, current_offset = self.decode_authorities(response, current_offset)
        # additional_sections = self.decode_additional_sections(response, current_offset)

        return self.header, domain_name, answers
    
    def validate_QR(self):
        ''' Validates that the recieved QR is 1.'''
        flag = self.header[1]
        if not (flag >> 15 & 1):
            # bring the QR value to least signiicant bit.
            raise Exception("Invalid QR!")
    
    def decode_answer(self, response, offset):
        ''' Decodes the answer from the response and moves the offset
        as required.
        ANSWER
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
        n_answers = self.header[3]
        answers = []

        for _ in range(n_answers):
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
            elif rtype == 5:
                rdata = self.decode_domain(response, offset)[0]

            offset += rdlength

            answers.append({
                "name": name,
                "rtype": rtype,
                "rclass": rclass,
                "ttl": ttl,
                "rdlength": rdlength,
                "rdata": rdata
            })

        return answers, offset

    def decode_authorities(self, response, offset):
        ''' Decodes the authorities from the response and moves the offset
        as required.'''
        n_authorities = self.header[4]

    def decode_additional_sections(self, response, offset):
        ''' Decodes the additional section from response and moves the offset
        as required.'''
        n_sections = self.header[5]


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

if __name__ == "__main__":
    message_generator = MessageGenerator()
    message = message_generator.create_message(
        domain_name='dns.google.com'
    )

    name_server_client = NameServerClient()
    response = name_server_client.request_dns_server(message)

    response_parser = ResponseParser()
    data = response_parser.parse(
        response, message_generator.header_id)

    print(data)

