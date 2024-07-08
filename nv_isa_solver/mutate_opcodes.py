"""
Simple utility to mutate known opcodes with known rest of instructions.
"""

from .disasm_utils import Disassembler

import argparse
from argparse import ArgumentParser


def main():
    arg_parser = ArgumentParser()
    arg_parser.add_argument("--arch", default="SM90a")
    arg_parser.add_argument("--cache_file", default="disasm_cache.txt")
    arg_parser.add_argument("--nvdisasm", default="nvdisasm")
    arg_parser.add_argument("file", type=argparse.FileType("r"))

    arguments = arg_parser.parse_args()

    disassembler = Disassembler(arguments.arch, nvdisasm=arguments.nvdisasm)
    disassembler.load_cache(arguments.cache_file)

    known_opcodes = set()
    known_instruction_seeds = set()

    instructions = disassembler.find_uniques_from_cache()
    for key, inst in instructions.items():
        inst = disassembler.distill_instruction(inst)

        opcode = inst[:2]  # opcode + pred
        seed = inst[2:]
        known_opcodes.add(opcode)
        known_instruction_seeds.add(seed)

    print("Found", len(known_opcodes), "opcodes")
    print("Found", len(known_instruction_seeds), "seeds")

    insts = []
    for opcode in known_opcodes:
        for seed in known_instruction_seeds:
            insts.append(opcode + seed)
    disassembler.disassemble_parallel(insts)
    disassembler.dump_cache(arguments.cache_file)


if __name__ == "__main__":
    main()
