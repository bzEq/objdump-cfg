#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import subprocess
import argparse
import shutil
import bisect
import logging
import io

# FIXME: Currently fallthrough is not considered as another basic block.
FUNCTION_BEGIN_LINE = re.compile(r'^(\d+)\s+<(.+)>:$')
INSTRUCTION_LINE = re.compile(r'^\s*(\d+):\s*(.*(<(.+)>)?)$')


class Function(object):
    def __init__(self, name):
        self.name = name
        self.address = 0
        self.instructions = []

    def GetOrCreateBB(self, address):
        pass

    def OutputDot(self, out_stream):
        pass

    def Append(self, address, instruction):
        self.instructions.append((address, instruction))


class BranchAnalyzer(object):
    def __init__(self, function):
        self.function = function

    def Analyze(self):
        pass


class ParseContext(object):
    def __init__(self, in_stream):
        self.current_function = ''
        self.functions = {}
        self.in_stream = in_stream

    def Parse(self):
        for l in self.in_stream:
            self.parseLine(l)

    def parseLine(self, l):
        if not self.current_function:
            m = FUNCTION_BEGIN_LINE.match(l)
            if m:
                logging.info('Found: {}'.format(m.group(2)))
                self.current_function = Function(m.group(2))
                self.current_function.address = int(m.group(1), 16)
                self.functions[
                    self.current_function.name] = self.current_function
        else:
            m = INSTRUCTION_LINE.match(l)
            if not m:
                # Current function ends.
                self.current_function = None
            else:
                address = int(m.group(1), 16)
                instruction = m.group(2)
                self.current_function.Append(address, instruction)


def main():
    parser = argparse.ArgumentParser(
        description='Output CFG dot file via objdump.')
    parser.add_argument('--objdump', default=shutil.which('objdump'))
    parser.add_argument('--verbose', default=False, action='store_true')
    parser.add_argument('obj', nargs=1)
    config = parser.parse_args()
    if config.verbose:
        logging.basicConfig(level=logging.INFO)
    cmd = [
        config.objdump,
        '-d',
        '--no-show-raw-insn',
        config.obj[0],
    ]
    cp = subprocess.run(cmd, capture_output=True)
    if cp.returncode != 0:
        logging.error('Failed to run {}'.format(cmd))
        return cp.returncode
    context = ParseContext(io.StringIO(cp.stdout.decode('utf-8')))
    context.Parse()


if __name__ == '__main__':
    sys.exit(main())
