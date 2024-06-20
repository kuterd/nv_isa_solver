import disasm_utils


def flip_bit(array, i):
    bit_offset = i % 8
    array[i // 8] |= 1 << bit_offset


inst = []
for i in range(pow(2, 12)):
    array = bytearray(b"\0" * 16)
    disasm_utils.set_bit_range2(array, 0, 12, i)
    inst.append(array)
    for j in range(13, 8 * 13):
        array_ = bytearray(array)
        flip_bit(array_, j)
        inst.append(array)

result = disasm_utils.disasm_parallel(inst, "SM90a")

file = open("disasm_cache.txt", "w")
for inst, disasm in zip(inst, result):
    file.write(disasm + " --- " + inst.hex() + "\n")
file.close()
