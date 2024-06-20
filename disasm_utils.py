import subprocess
import tempfile
import tqdm
from enum import Enum
from typing import Union
import time
import parser


# DISASM = "/usr/local/cuda-12.5/bin/nvdisasm"
DISASM = "/opt/cuda/bin/nvdisasm"
BATCH_SIZE = 32


def _process_dump(dump):
    lines = dump.split("\n")[1:]
    result = []
    for line in lines:
        result.append(line[line.find("*/") + 2 :].strip())
    return "\n".join(result).strip()


def disassemble(dump: bytes, arch: str):
    with tempfile.NamedTemporaryFile(delete_on_close=False) as tmp:
        tmp.write(dump)
        tmp.close()
        result = subprocess.run(
            [DISASM, tmp.name, "--binary", arch], capture_output=True
        )
    return _process_dump(result.stdout.decode("ascii"))


def set_bit_range(byte_array, start_bit, end_bit, value):
    length = end_bit - start_bit - 1
    for i in range(start_bit, end_bit):
        mask = 1 << (7 - (i % 8))
        if value & (1 << (length - i + start_bit)):
            byte_array[i // 8] |= mask
        else:
            byte_array[i // 8] &= ~mask


def set_bit_range2(byte_array, start_bit, end_bit, value):
    length = end_bit - start_bit - 1
    for i in range(start_bit, end_bit):
        # mask = 1 << (7 - i % 8)
        mask = 1 << (i % 8)
        if value & (1 << (i - start_bit)):
            byte_array[i // 8] |= mask
        else:
            byte_array[i // 8] &= ~mask


def disasm_parallel(array, arch):
    if len(array) > BATCH_SIZE:
        result = []
        for i in tqdm.tqdm(range(0, len(array), BATCH_SIZE)):
            result += disasm_parallel(array[i : i + BATCH_SIZE], arch)
        assert len(result) == len(array)
        return result

    processes = []
    tmp_files = []
    for i, inst in enumerate(array):
        tmp = tempfile.NamedTemporaryFile(delete_on_close=False)
        tmp.__enter__()
        tmp_files.append(tmp)
        tmp.write(inst)
        name = tmp.name
        tmp.close()

        process = subprocess.Popen(
            [DISASM, name, "--binary", arch],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        processes.append(process)

    results = []
    for process in processes:
        results.append(_process_dump(process.stdout.read().decode("ascii")))

    for tmp in tmp_files:
        tmp.__exit__(None, None, None)
    return results


def mutate_inst(inst, arch, start=0, end=16 * 8):
    """
    Mutate the instruction by fliping a bit.
    """
    processes = []
    tmp_files = []
    for i in range(start, end):
        inst_ = bytearray(bytes(inst))
        inst_[i // 8] = inst_[i // 8] ^ (1 << (7 - i % 8))
        tmp = tempfile.NamedTemporaryFile(delete_on_close=False)
        tmp.__enter__()
        tmp_files.append(tmp)
        tmp.write(inst_)
        name = tmp.name
        tmp.close()

        process = subprocess.Popen(
            [DISASM, name, "--binary", arch],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        processes.append((i, inst_, process))

    results = []
    for i, inst_, process in processes:
        results.append((i, inst_, _process_dump(process.stdout.read().decode("ascii"))))

    for tmp in tmp_files:
        tmp.__exit__(None, None, None)

    return results


def inst_disasm_range(base, bit_start, bit_end, arch):
    """
    Brute force a bit range.
    """
    instructions = []
    for i in range(pow(2, bit_end - bit_start + 1)):
        inst_bytes = bytearray(bytes(base))
        set_bit_range2(inst_bytes, bit_start, bit_end, i)
        instructions.append(inst_bytes)
    return zip(instructions, disasm_parallel(instructions, arch))


"""
def dump_bitrange(inst):
    for i in range(8*16):
        bit_index = 7 - i % 8
        byte_index = i // 8
        print((inst[byte_index] & (1 << (bit_index))) >> bit_index, end="")
        if i == 64 - 1:
            print("")
    print("\n")
"""


def dump_bitrange(inst):
    for i in range(8 * 8):
        if i % 8 == 0:
            print(" ", end="")
        print(7 - i % 8, end="")
    print("")
    for i in range(8 * 16):
        if i % 8 == 0:
            print("", end=" ")
        bit_index = 7 - i % 8
        byte_index = i // 8
        print((inst[byte_index] >> bit_index) & 1, end="")
        if i == 64 - 1:
            print("")
    print("\n")


def dump_bits(inst):
    for i in range(8 * 16):
        bit_index = 7 - i % 8
        byte_index = i // 8
        print((inst[byte_index] & (1 << (bit_index))) >> bit_index, end="")
        if i == 64 - 1:
            print("")
    print("\n")


def read_corpus(filename):
    file = open(filename, "r")
    entries = []
    for line in file:
        entries.append(bytes.fromhex(line.split("---")[1].strip()))
    file.close()
    return entries
