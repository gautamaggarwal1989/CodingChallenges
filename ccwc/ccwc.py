''' Python copy of wc command in unix.
https://codingchallenges.fyi/challenges/challenge-wc
'''

import os
import argparse
import sys
from contextlib import contextmanager

from pathlib import Path

SEPERATOR = "  " # Using double space as seperator for output
# Commands ENUM
LINE_COUNT, BYTE_COUNT, WORDS_COUNT, CHAR_COUNT = (
    0, 1, 2, 3
)

# Get the command line arguments.
parser = argparse.ArgumentParser(
    prog="ccwc",
    description="counts the number of lines, words and bytes of a file or a file stream"
)
parser.add_argument("-c", "--count", action="store_true",  help="Get the byte count for the file.")
parser.add_argument("-w", "--words", action="store_true", help="Get the words count for the file.")
parser.add_argument("-m", "--chars", action="store_true", help="Get the words count for the file.")
parser.add_argument("-l", "--lines", action="store_true", help="Get the words count for the file.")
parser.add_argument("filepath",nargs="?", help="Name of the file to be processed.")
args = parser.parse_args()


@contextmanager
def get_input_stream(filepath=None):
    if not sys.stdin.isatty():
        yield sys.stdin.buffer
    elif filepath:
        filepath = Path(args.filepath).resolve()
        if not filepath.is_file():
            raise FileNotFoundError(f"{filepath.name}: open: No such file or directory")

        with open(filepath, 'rb') as file:
            yield file
    else:
        raise Exception('open: No input stream provided')

def process_commands(input_stream, commands=None, no_option_selected=False):
    ''' This function processes the commands and expects
    input type as a list of commands.'''
    if not isinstance(commands, list):
        raise Exception("Invalid argument!")
    
    result = [0] * 4
    for line in input_stream: # Lazy loading.
        if commands[LINE_COUNT] or no_option_selected:
            result[LINE_COUNT] += 1
        if commands[WORDS_COUNT] or no_option_selected:
            result[WORDS_COUNT] += len(line.split())

        if commands[CHAR_COUNT]:
            result[CHAR_COUNT] += len(line.decode())

        if commands[BYTE_COUNT] or no_option_selected:
            result[BYTE_COUNT] += len(line)

    return result

if __name__ == "__main__":
    try:
        commands = [None] * 4
        commands[LINE_COUNT] = args.lines
        commands[CHAR_COUNT] = args.chars
        commands[WORDS_COUNT] = args.words
        commands[BYTE_COUNT] = args.count

        # Handles the situation where no flag is selected
        no_option_selected = not any(commands)

        with get_input_stream(args.filepath) as input_stream:
            result = process_commands(
                input_stream,
                commands,
                no_option_selected
            )

        output = SEPERATOR
        
        if args.lines or no_option_selected:
            output += SEPERATOR + str(result[LINE_COUNT])

        if args.words or no_option_selected:
            output += SEPERATOR + str(result[WORDS_COUNT])

        if args.chars:
            output += SEPERATOR + str(result[CHAR_COUNT])

        if args.count or no_option_selected:
            output += SEPERATOR + str(result[BYTE_COUNT])
        
        # Add the filename at the end
        filename = ''
        if args.filepath:
            filename = args.filepath.split('/')[-1]

        output +=  SEPERATOR + filename

        print(output)
    except Exception as e:
        print(f"ccwc: {str(e)}")
