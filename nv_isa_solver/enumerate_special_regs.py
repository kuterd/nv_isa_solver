from instruction_solver import ISASpec
from disasm_utils import Disassembler

isa = ISASpec.from_file("isa.json")
inst = isa.find_instruction("S2R_R_SR")

for i in range(255):
    encoded = inst.encode([0, i])
    disassembler = Disassembler("SM90a")
    result = disassembler.disassemble(encoded)
    print(result)
