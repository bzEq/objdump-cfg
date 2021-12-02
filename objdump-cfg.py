#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# FIXME: A more reliable way to get this task done should be implementing the dumper in llvm-objdump.
import os
import sys
import re
import subprocess
import argparse
import shutil
import bisect
import logging
import io

FUNCTION_BEGIN_LINE = re.compile(r'^([0-9a-f]+)\s+<(.+)>:$')
INSTRUCTION_LINE = re.compile(r'^\s*([0-9a-f]+):\s*(.*)$')
INSTRUCTION = re.compile(r'([^<#]+)(<([^\+]+)(\+([0-9a-fx]+))?>)?')

UNCONDITIONAL_BRANCHES = [re.compile(x) for x in [r'\bb\b', r'\bjmp\b']]
LONG_BRANCHES = [re.compile(x) for x in [r'\bblr\b', '\bretq\b']]


class Function(object):
    def __init__(self, name):
        self.name = name
        self.address = -1
        self.instructions = []

    def Append(self, address, instruction):
        self.instructions.append((address, instruction))

    def IsEmpty(self):
        return len(self.instructions) == 0


class CFGPainter(object):
    def __init__(self, function, branch_analyzer):
        self.F = function
        self.BA = branch_analyzer
        self.BBs = []  # List of (i, len).
        self.branch_targets = set()

    def Plan(self):
        logging.debug('Planning painting for {}'.format(self.F.name))
        if self.F.IsEmpty():
            return
        self.branch_targets.add(0)
        for branch in self.BA.branches:
            self.branch_targets.update(set(self.BA.branches[branch]))
        i = -1
        j = 0
        while j < len(self.F.instructions):
            if j in self.branch_targets:
                if i != -1:
                    self.BBs.append((i, j - i + 1))
                i = j
            if j in self.BA.branches:
                assert (i != -1)
                self.BBs.append((i, j - i + 1))
                i = -1
            j += 1
        if i != -1:
            self.BBs.append((i, j - i + 1))

    def Dot(self, out_stream):
        pass


def IsUncondBr(s):
    for r in UNCONDITIONAL_BRANCHES:
        if r.search(s):
            return True
    return False


def IsLongBranch(s):
    for r in LONG_BRANCHES:
        if r.search(s):
            return True
    return False


def LowerBound(a, x, lo=0, hi=None, key=lambda x: x):
    l = lo
    r = hi if hi else len(a)
    mid = l + (r - l) // 2
    while l < r:
        if key(a[mid]) >= x:
            r = mid
        else:
            l = mid + 1
        mid = l + (r - l) // 2
    return r


def UpperBound(a, x, lo=0, hi=None, key=lambda x: x):
    l = lo
    r = hi if hi else len(a)
    mid = l + (r - l) // 2
    while l < r:
        if key(a[mid]) > x:
            r = mid
        else:
            l = mid + 1
        mid = l + (r - l) // 2
    return r


class BranchAnalyzer(object):
    def __init__(self, context, function):
        self.context = context
        self.function = function
        self.branches = {}

    def Analyze(self):
        logging.debug('Analyzing {}'.format(self.function.name))
        for i in range(len(self.function.instructions)):
            t = self.function.instructions[i]
            inst = t[1]
            m = INSTRUCTION.match(inst)
            assert (m)
            mg = m.groups()
            assert (len(mg) >= 1)
            inst_main = mg[0]
            if IsLongBranch(inst_main):
                self.branches[i] = []
            elif len(mg) >= 5 and mg[4]:
                label = mg[2]
                # We have encountered a branch.
                offset = int(mg[4], 16)
                label_address = self.context.FindAddress(label)
                if label_address < 0:
                    continue
                targets = []
                index_of_address = self.findIndexOfAddress(label_address +
                                                           offset)
                if index_of_address >= 0:
                    targets.append(index_of_address)
                if not IsUncondBr(inst_main) and (i + 1) < len(
                        self.function.instructions):
                    targets.append(i + 1)
                if not targets:
                    logging.debug(
                        '{} is branching to external function'.format(inst))
                self.branches[i] = targets

    def findIndexOfAddress(self, address):
        i = LowerBound(self.function.instructions, address, key=lambda t: t[0])
        if i == len(self.function.instructions
                    ) or self.function.instructions[i][0] != address:
            return -1
        return i


class ParseContext(object):
    def __init__(self, in_stream):
        self.current_function = ''
        self.functions = {}
        self.in_stream = in_stream

    def FindAddress(self, label):
        if label in self.functions:
            return self.functions[label].address
        return -1

    def Parse(self):
        for l in self.in_stream:
            self.parseLine(l)

    def parseLine(self, l):
        if not self.current_function:
            m = FUNCTION_BEGIN_LINE.match(l)
            if m:
                logging.debug('Found: {}'.format(m.group(2)))
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
    parser.add_argument('--debug', default=False, action='store_true')
    parser.add_argument('--func', default='')
    parser.add_argument('obj', nargs=1)
    config = parser.parse_args()
    if config.debug:
        logging.basicConfig(level=logging.DEBUG)
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
    func = set(config.func.split(','))
    for label in context.functions:
        if func and label not in func:
            continue
        function = context.functions[label]
        BA = BranchAnalyzer(context, function)
        BA.Analyze()
        logging.debug("{}'s branches: {}".format(function.name, BA.branches))
        P = CFGPainter(function, BA)
        P.Plan()
        logging.debug("{}'s basic block layout: {}".format(
            function.name, P.BBs))


if __name__ == '__main__':
    sys.exit(main())
