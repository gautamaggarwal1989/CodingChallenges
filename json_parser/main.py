'''Coding challenge 
https://codingchallenges.fyi/challenges/challenge-json-parser

We will be using recursive descent parsing to parse the json string.
'''
import string


class InvalidJson(Exception):
    '''Invalid Json!'''

ESCAPE_CHARACTER = '\"'

CHARACTERS = set(string.ascii_lowercase + string.ascii_uppercase)
 

class Lexer:
    ''' Creates a token on the basis of json grammar.
    Uses recursive descent parsing to go through the tokens.
    '''
    def __init__(self, string, position):
        self.string = string
        self.position = 0
        self.tokens = []
        self.len = len(string)

    def parse_json(self):
        if self.string[self.position] == '[':
            self.parse_array()
        elif self.string[self.position] == '{':
            self.parse_object()
        else:
            raise InvalidJson()

    def parse_array(self):
        if self.string[self.position] == "[":
            self.tokens.append(
                ("LBRACKET", "[")
            )
            self.position += 1
        
        while self.position < self.len and self.string[self.position] !=  "]":
            if self.string[self.position] == '"':
                self.parse_string()
            elif self.string[self.position] == '{':
                self.parse_object()
            elif self.string[self.position].isnumeric():
                self.parse_numeric()
            elif self.string[self.position] == '[':
                self.parse_array()

        if self.string[self.position] !=  "]":
            raise InvalidJson()
        else:
            self.tokens.append(("RBRACKET", ']'))
            self.position += 1

    def parse_object(self):
        if self.string[self.position] == "{":
            self.tokens.append(
                ("LBRACE", "{")
            )
            self.position += 1

        while self.position < self.len and self.string[self.position] != "}":
            self.parse_values()

        if self.string[self.position] != "}":
            raise InvalidJson()
        else:
            self.tokens.append(('RBRACE', '}'))

    def parse_string(self):
        if self.string[self.position] == '"':
            self.position += 1
            word = ''
            while self.position < self.len and self.string[self.position] != '"':
                word += self.string[self.position]
                self.position += 1

            self.tokens.append(
                ("STRING", word)
            )
        if self.string[self.position] != '"':
            raise InvalidJson()

    def parse_numeric(self):
        num = ''
        if self.string[self.position].isnumeric():
            num += self.string[self.position]
            self.position += 1

