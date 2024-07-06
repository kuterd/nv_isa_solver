from argparse import ArgumentParser

from disasm_utils import Disassembler, set_bit_range

parser = ArgumentParser()
parser.add_argument("--arch", default="SM90a")
parser.add_argument("--cache_file", default="disasm_cache.txt")
parser.add_argument("--nvdisasm", default="nvdisasm")
arguments = parser.parse_args()

disassembler = Disassembler(arguments.arch, nvdisasm=arguments.nvdisasm)


def flip_bit(array, i):
    bit_offset = i % 8
    array[i // 8] ^= 1 << bit_offset


inst = []
for i in range(pow(2, 12)):
    # Read write barriers!
    array = bytearray(bytes.fromhex("00000000000000000000000000e00f00"))
    set_bit_range(array, 0, 12, i)
    inst.append(array)
    for j in range(13, 8 * 13):
        array_ = bytearray(array)
        flip_bit(array_, j)
        inst.append(array_)

disassembler.disassemble_parallel(inst, arguments.arch)
disassembler.dump_cache(arguments.cache_file)
