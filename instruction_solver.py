import re
import json
import subprocess
import tempfile
import tqdm
from enum import Enum
from typing import List

from disasm_utils import disassemble, _process_dump, inst_disasm_range, disasm_parallel
import table_utils
import parser
from parser import InstructionParser

DISASM = "/opt/cuda/bin/nvdisasm"


def mutate_inst(inst, arch, start=0, end=16 * 8):
    """
    Mutate the instruction by fliping a bit.
    """
    processes = []
    tmp_files = []
    for i in range(start, end):
        inst_ = bytearray(bytes(inst))
        inst_[i // 8] = inst_[i // 8] ^ (1 << (i % 8))
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


operand_colors = [
    "#FE8386",
    "#F5B7DC",
    "#BF91F3",
    "#C9F3FF",
    "#FBDA73",
    "#72fc44",
    "#888efc",
]


class EncodingRangeType(str, Enum):
    CONSTANT = "constant"

    OPERAND = "operand"
    OPERAND_FLAG = "operand_flag"
    OPERAND_MODIFIER = "operand_modifier"

    FLAG = "flag"
    MODIFIER = "modifier"

    # Just the predicate.
    PREDICATE = "predicate"

    # Control code stuff.
    STALL_CYCLES = "stall"
    YIELD_FLAG = "yield_flag"
    READ_BARRIER = "read_barrier"
    WRITE_BARRIER = "write_barrier"
    BARRIER_MASK = "barrier_mask"
    REUSE_MASK = "reuse_mask"


class EncodingRange:
    def __init__(
        self, _type, start, length, operand_index=None, name=None, constant=None
    ):
        self.type = _type
        self.start = start
        self.length = length
        self.operand_index = operand_index
        self.name = name
        self.constant = constant

    def to_json(self):
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_str):
        json_dict = json.loads(json_str)
        return cls(**json_dict)

    def __repr__(self):
        return self.to_json()


def generate_encoding_table(ranges: List[EncodingRange]):
    builder = table_utils.TableBuilder()
    builder.tbody_start()

    def seperator():
        builder.tr_start("smoll")
        for i in range(64):
            builder.push(str(i % 8), 1)
        builder.tr_end()

    seperator()
    current_length = 0
    builder.tr_start()
    for erange in ranges:
        if current_length == 8 * 8:
            print("Inserting seperator")
            builder.tr_end()
            seperator()
            builder.tr_start()

        bg_color = None
        if erange.operand_index is not None:
            bg_color = operand_colors[erange.operand_index]
        text = erange.name

        if not text:
            text = erange.type
            if erange.type == "operand_modifier":
                text = "modi"

        vertical = (
            erange.type == EncodingRangeType.FLAG
            or erange.type == EncodingRangeType.OPERAND_FLAG
        )

        if erange.type == EncodingRangeType.CONSTANT:
            text = bin(erange.constant)[2:].zfill(erange.length)[::-1]
            for c in text:
                builder.push(c, 1, bg=bg_color, vertical=vertical)
            current_length += erange.length
            continue
        elif erange.type == EncodingRangeType.OPERAND:
            text += f" {erange.operand_index}"

        length = erange.length
        # Current range is split across two rows.
        if current_length < 8 * 8 and current_length + length > 8 * 8:
            diff = 8 * 8 - current_length
            builder.push(text, diff, bg=bg_color, vertical=vertical)

            # insert the row seperator.
            builder.tr_end()
            seperator()
            builder.tr_start()
            length -= diff
        # Push the remainder range.
        builder.push(text, length, bg=bg_color, vertical=vertical)
        current_length += erange.length
    builder.tr_end()
    builder.tbody_end()
    builder.end()
    return builder.result


class InstructionMutationSet:
    def __init__(self, inst, disasm, mutations):
        self.inst = inst
        self.disasm = disasm
        self.mutations = mutations

        # TODO: Maybe combine this into one map.
        self.operand_type_bits = set()
        self.opcode_bits = set()
        self.operand_value_bits = set()
        self.operand_modifier_bits = set()
        self.operand_modifier_bit_flag = {}
        self.modifier_bits = set()
        self.instruction_modifier_bit_flag = {}

        self.bit_to_operand = {}
        self.predicate_bits = set()
        self._analyze()

    def _analyze(self):
        parsed = InstructionParser.parseInstruction(self.disasm)
        parsed_operands = parsed.get_flat_operands()

        for i_bit, inst, asm in self.mutations:
            # The disassembler refused to decode this instruction.
            asm = asm.strip()
            if len(asm) == 0:
                self.opcode_bits.add(i_bit)
                continue

            try:
                mutated_parsed = InstructionParser.parseInstruction(asm)
            except Exception as e:
                print(e)
                continue
            # print(mutated_parsed.get_key())
            if parsed.get_key() != mutated_parsed.get_key():
                # NOTE: Should we only say this is a opcode bit if the base instruction is different.
                self.opcode_bits.add(i_bit)
                continue
            mutated_operands = mutated_parsed.get_flat_operands()

            if parsed.predicate != mutated_parsed.predicate:
                self.predicate_bits.add(i_bit)
            for i, (a, b) in enumerate(zip(mutated_operands, parsed_operands)):
                # What about top level modifiers?
                a_modifiers = set(a.modifiers)
                b_modifiers = set(b.modifiers)
                missing_operands = b_modifiers.difference(a_modifiers)
                new_operands = a_modifiers.difference(b_modifiers)

                change_sum = len(missing_operands) + len(new_operands)
                # For a flag field change number should add up to one.
                if not a.compare(b):
                    self.operand_value_bits.add(i_bit)
                    self.bit_to_operand[i_bit] = i
                elif change_sum > 0:
                    print("Missing", missing_operands, "new operands", new_operands)
                    self.bit_to_operand[i_bit] = i
                    self.operand_modifier_bits.add(i_bit)

                    if change_sum == 1:
                        flag_set = set()
                        flag_set.update(missing_operands)
                        flag_set.update(new_operands)
                        flag_name = next(iter(flag_set))
                        self.operand_modifier_bit_flag[i_bit] = flag_name

    # NOTE: This is currently broken.
    def analyze_second_stage(self):
        def flip_bit(array, i):
            bit_offset = i % 8
            array[i // 8] |= 1 << bit_offset

        modifier_mutations = []

        for bit in self.instruction_modifier_bit_flag:
            inst_ = bytearray(self.inst)
            flip_bit(inst_, bit)
            flip_bit(inst_, bit + 1)
            modifier_mutations.append((inst_, bit, bit + 1))

            if bit - 1 not in self.instruction_modifier_bit_flag:
                inst_ = bytearray(self.inst)
                flip_bit(inst_, bit)
                flip_bit(inst_, bit - 1)
                modifier_mutations.append((inst_, bit, bit - 1))
        if len(modifier_mutations) == 0:
            return
        instructions, offsets, adj_offsets = zip(*modifier_mutations)

        disassembled = disasm_parallel(instructions, "SM90")
        for disasm, bit, adj in zip(disassembled, offsets, adj_offsets):
            if bit not in self.instruction_modifier_bit_flag:
                continue  # Already eleminated.
            flag_name = self.instruction_modifier_bit_flag[bit]
            # If the flag name is not in the disassembled instruction, this is not really a flag.
            if not disasm:
                continue
            try:
                parsed = InstructionParser.parseInstruction(disasm)
            except Exception:
                pass
            if not parsed:
                continue
            if flag_name not in parsed["InstructionTokens"]:
                print(disasm)
                print("Eleminated flag", flag_name)
                del self.instruction_modifier_bit_flag[bit]
                if adj in self.instruction_modifier_bit_flag:
                    del self.instruction_modifier_bit_flag[adj]

    def dump_encoding_ranges(self):
        result = []
        current_range = None

        def _push():
            nonlocal current_range
            if current_range:
                result.append(current_range)
            current_range = None

        for i in range(0, 8 * 16):
            new_range = None
            if i in self.modifier_bits:
                if i in self.instruction_modifier_bit_flag:
                    _push()
                    current_range = EncodingRange(
                        EncodingRangeType.FLAG,
                        i,
                        1,
                        name=self.instruction_modifier_bit_flag[i],
                    )
                    _push()
                    continue
                else:
                    new_range = EncodingRange(EncodingRangeType.MODIFIER, i, 1)
            elif i in self.predicate_bits:
                new_range = EncodingRange(EncodingRangeType.PREDICATE, i, 1)
            elif i in self.operand_value_bits:
                new_range = EncodingRange(
                    EncodingRangeType.OPERAND,
                    i,
                    1,
                    operand_index=self.bit_to_operand[i],
                )
            elif i in self.operand_modifier_bits:
                operand_index = self.bit_to_operand[i]
                new_type = EncodingRangeType.OPERAND_MODIFIER
                # is this a flag
                if i in self.operand_modifier_bit_flag:
                    # Flush the current cell no matter what.
                    _push()
                    current_range = EncodingRange(
                        EncodingRangeType.OPERAND_FLAG,
                        i,
                        1,
                        operand_index=operand_index,
                        name=self.operand_modifier_bit_flag[i],
                    )
                    _push()
                    continue
                else:
                    new_range = EncodingRange(
                        EncodingRangeType.OPERAND_MODIFIER,
                        i,
                        1,
                        operand_index=operand_index,
                    )

            # Handle constant
            if new_range is None:
                new_range = EncodingRange(EncodingRangeType.CONSTANT, i, 1, constant=0)

            # Decide if we should extend the current range or not.
            if (
                current_range
                and new_range.type == current_range.type
                and new_range.operand_index == current_range.operand_index
                and (new_range.type != EncodingRangeType.CONSTANT or i != 8 * 8)
            ):
                current_range.length += 1
            else:
                # Push current range
                _push()
                current_range = new_range

            if current_range.type == EncodingRangeType.CONSTANT:
                current_range.constant |= ((self.inst[i // 8] >> (i % 8)) & 1) << (
                    current_range.length - 1
                )

        _push()

        return result


class InstructionDescGenerator:
    def generate(self, instruction):
        self.result = '<div class="instruction-desc">'
        self.result += f'<span class="base-name">{instruction.base_name}</span>'

        # Assign numbers to sub operands.
        flat_op_i = 0
        for op in instruction.operands:
            for sop in op.flatten():
                sop.flat_operand_index = flat_op_i
                flat_op_i += 1

        self.result += '<span class="operands"> &nbsp; '
        for i, op in enumerate(instruction.operands):
            if i != 0:
                self.result += ","
            self.result += " "
            self.visit(op)
        self.result += "</span>"

        self.result += "</div>"
        return self.result

    def visit(self, op):
        if isinstance(op, parser.DescOperand):
            self.visitDescOperand(op)
        elif isinstance(op, parser.ConstantMemOperand):
            self.visitConstantMemOperand(op)
        elif isinstance(op, parser.IntIMMOperand):
            self.visitIntIMMOperand(op)
        elif isinstance(op, parser.FloatIMMOperand):
            self.visitFloatIMMOperand(op)
        elif isinstance(op, parser.AddressOperand):
            self.visitAddressOperand(op)
        elif isinstance(op, parser.RegOperand):
            self.visitRegOperand(op)

    def begin_section(self, op):
        self.result += f"<span class='flat-operand-section' style='background-color:{operand_colors[op.flat_operand_index]}'>"

    def end_section(self):
        self.result += "</span>"

    def visitDescOperand(self, op):
        self.result += "desc["
        self.visit(op.sub_operands[0])
        self.result += "]"
        self.visit(op.sub_operands[1])

    def visitConstantMemOperand(self, op):
        self.result += "cx" if op.cx else "c"
        self.result += "["
        self.visit(op.sub_operands[0])
        self.result += "]"
        self.visit(op.sub_operands[1])

    def visitIntIMMOperand(self, op):
        self.begin_section(op)
        self.result += "INT_IMM"
        self.end_section()

    def visitFloatIMMOperand(self, op):
        self.begin_section(op)
        self.result += "FIMM"
        self.end_section()

    def visitAddressOperand(self, op):
        self.result += "["
        for i, sop in enumerate(op.sub_operands):
            if i != 0:
                self.result += "+"
            self.visit(sop)
        self.result += "]"

    def visitRegOperand(self, op):
        self.begin_section(op)
        self.result += op.get_operand_key()
        self.end_section()


class ISADecoder:
    def __init__(self, corpus, arch, parserArch):
        self.corpus = {}
        self.newly_discovered = set()
        self.base_instructions = set()
        self.base_map = {}
        self.arch = arch

        disasm = disasm_parallel(corpus, arch)

        for inst, asm in zip(corpus, disasm):
            self._insert_inst(inst, asm)

        self.invalid_instr = set()

    def _insert_inst(self, inst, disasm=None):
        if disasm is None:
            # We loose way too much here during initilization.
            disasm = disassemble(inst, self.arch)

        disasm = re.sub("\\?PM[0-9]*", "", disasm)
        try:
            parsed_instruction = InstructionParser.parseInstruction(disasm)
        except Exception as e:
            print("Failed to parse instruction!", disasm, e)
            return False

        base_name = parsed_instruction.base_name
        unique_id = parsed_instruction.get_key()
        if unique_id in self.corpus:
            return False

        self.base_instructions.add(base_name)
        if base_name not in self.base_map:
            self.base_map[base_name] = []
        self.base_map[base_name].append(unique_id)
        self.newly_discovered.add(unique_id)
        self.corpus[unique_id] = (inst, disasm)
        return True

    def dump_corpus(self, filename):
        result = open(filename, "w")
        for inst, disasm in sorted(self.corpus.values(), key=lambda x: x[1]):
            result.write(disasm + "  --- " + inst.hex() + "\n")
        result.close()

    def scan_opcode(self, base):
        # Usually opcode is the first 8 bits of an instruction.
        # Do a brute force scan to accelerate the instruction discovery process.

        # Stage 1
        discovered = 0
        instructions = inst_disasm_range(base, 0, 12, self.arch)
        for i, (inst, disasm) in enumerate(instructions):
            if len(disasm) == 0:
                continue
            print(i, disasm)
            is_new = self._insert_inst(inst, disasm=disasm)
            if is_new:
                discovered += 1
        return discovered

    def mutate_instructions(self):
        """
        Flip bits and disassmble the instructions to discover new instructions, determine modifier and operand bits.
        """

        old_discovered = self.newly_discovered
        self.newly_discovered = set()

        discovered = 0
        for unique_id in tqdm.tqdm(old_discovered):
            inst, disasm = self.corpus[unique_id]

            modifier_bits = []
            operand_type_bits = []
            print("Mutating", disasm)
            result = mutate_inst(inst, self.arch)

            for i_bit, inst, asm in result:
                if len(asm) == 0:
                    continue
                is_new = self._insert_inst(inst, disasm=asm)
                if is_new:
                    discovered += 1
        print(self.newly_discovered)
        return discovered


def analyze_instruction(inst, arch="SM90"):
    mutations = mutate_inst(inst, arch, end=14 * 8 - 2)
    asm = disassemble(inst, arch)

    parsed_inst = InstructionParser.parseInstruction(asm)
    generator = InstructionDescGenerator()
    result = """
    <style>
        .instruction-desc {
            font-weight: bold;
            padding: 5px;
            margin-top: 15px;
            margin-bottom: 15px;
        }

        .flat-operand-section {
            padding: 2px;
            margin: 2px;
            border-radius: 5px;
        }

    </style>

    """
    result += generator.generate(parsed_inst)

    mutation_set = InstructionMutationSet(inst, asm, mutations)
    mutation_set.analyze_second_stage()
    ranges = mutation_set.dump_encoding_ranges()
    print(ranges)
    result += generate_encoding_table(ranges)
    file = open("ranges_result.html", "w")
    file.write(result)
    file.close()


def distill_instruction(inst, arch):
    original_asm = disassemble(inst, arch)
    original_parsed = InstructionParser.parseInstruction(original_asm)

    # Make bits 0 until the instruction don't decode the same anymore.
    distilled = bytes(inst)
    for i in range(127, -1, -1):
        inst_ = bytearray(bytes(distilled))
        if (inst_[i // 8] >> (i % 8)) & 1 == 0:
            continue

        inst_[i // 8] = inst_[i // 8] & ~(1 << (i % 8))
        distill_asm = disassemble(inst_, arch)
        if len(distill_asm) == 0:
            continue

        distill_parsed = InstructionParser.parseInstruction(distill_asm)
        if original_parsed.get_key() != distill_parsed.get_key():
            continue

        distilled = bytes(inst_)
    return distilled


def distill_instruction_reverse(inst, arch):
    original_asm = disassemble(inst, arch)
    original_parsed = InstructionParser.parseInstruction(original_asm)

    # Make bits 0 until the instruction don't decode the same anymore.
    distilled = bytes(inst)
    for i in range(127, -1, -1):
        inst_ = bytearray(bytes(distilled))
        if (inst_[i // 8] >> (i % 8)) & 1 == 1:
            continue

        inst_[i // 8] = inst_[i // 8] | (1 << (i % 8))
        distill_asm = disassemble(inst_, arch)
        if len(distill_asm) == 0:
            continue
        try:
            distill_parsed = InstructionParser.parseInstruction(distill_asm)
        except Exception as e:
            print(distill_asm, e)
            continue
        if original_parsed.get_key() != distill_parsed.get_key():
            continue

        distilled = bytes(inst_)
    return distilled


if __name__ == "__main__":
    distilled = bytes.fromhex("48 79 00 00 00 00 00 00 00 00 80 03 00 ea 0f 00")
    distilled = distill_instruction_reverse(distilled, "SM90a")
    # analyze_instruction(distilled)

    decoder = ISADecoder([], "SM90a", "SM90")
    decoder.scan_opcode(distilled)
    decoder.dump_corpus("reverse_scan.txt")
