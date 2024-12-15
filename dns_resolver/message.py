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


class MessageGenerator:
    ''' Creates the message in the required byte format.
    '''

    def create_header(self):
        ''' Creates the header for message'''
        header_id = random.randint(0, 65535)
        flags = 0x0100
        questions = 1

        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        return struct.pack(
            "!HHHHHH",
            header_id,
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


if __name__ == '__main__':
    message = MessageGenerator()

    print(message.create_message("dns.google.com"))
