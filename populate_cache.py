from disasm_utils import Disassembler, set_bit_range2

disassembler = Disassembler("SM90a")


def flip_bit(array, i):
    bit_offset = i % 8
    array[i // 8] |= 1 << bit_offset


inst = []
for i in range(pow(2, 12)):
    # Read write barriers!
    array = bytearray(bytes.fromhex("20090000000000000000800300c00f00"))
    set_bit_range2(array, 0, 12, i)
    inst.append(array)
    for j in range(13, 8 * 13):
        array_ = bytearray(array)
        flip_bit(array_, j)
        inst.append(array)

disassembler.disassemble_parallel(inst, "SM90a")
disassembler.dump_cache("sm90a_cache.txt")
