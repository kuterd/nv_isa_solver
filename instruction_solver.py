import re
import json
import tqdm
from enum import Enum
from typing import List
from collections import Counter

from disasm_utils import (
    Disassembler,
    set_bit_range2,
)
import table_utils
import parser
from parser import InstructionParser

DISASM = "/opt/cuda/bin/nvdisasm"

operand_colors = [
    "#FE8386",
    "#F5B7DC",
    "#BF91F3",
    "#C9F3FF",
    "#FBDA73",
    "#72fc44",
    "#4e56fc",
    "#fc9b14",
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


class EncodingRanges:
    def __init__(self, ranges, disassembler):
        self.ranges = ranges
        self.disassembler = disassembler

    def _count(self, type):
        result = 0
        for range in self.ranges:
            result += 1 if range.type == type else 0
        return result

    def operand_count(self):
        result = 0
        for range in self.ranges:
            if range.type == EncodingRangeType.OPERAND:
                result = max(result, range.operand_index + 1)
        return result

    def modifier_count(self):
        return self._count(EncodingRangeType.MODIFIER)

    def _find(self, type):
        return list(filter(lambda x: x.type == type, self.ranges))

    def encode(self, sub_operands, modifiers):
        result = bytearray(b"\0" * 16)
        modifier_i = 0
        for range in self.ranges:
            value = None
            if range.type == EncodingRangeType.CONSTANT:
                value = range.constant
            elif range.type == EncodingRangeType.OPERAND:
                value = sub_operands[range.operand_index]
            elif range.type == EncodingRangeType.MODIFIER:
                value = modifiers[modifier_i]
                modifier_i += 1
            if not value:
                continue
            set_bit_range2(result, range.start, range.start + range.length, value)
        return result

    def enumerate_modifiers(self):
        modifiers = self._find(EncodingRangeType.MODIFIER)
        operand_values = [0] * self.operand_count()

        analysis_result = []

        for i, modifier in enumerate(modifiers):
            insts = []
            for modi_i in range(pow(2, modifier.length)):
                modi_values = [0] * len(modifiers)
                modi_values[i] = modi_i
                insts.append(self.encode(operand_values, modi_values))
            disasms = self.disassembler.disassemble_parallel(insts)
            analysis_result.append([])
            comp = disasms[1]
            for i, asm in enumerate(disasms):
                try:
                    comp_modis = InstructionParser.parseInstruction(comp).modifiers
                    asm_modis = InstructionParser.parseInstruction(asm).modifiers
                except Exception:
                    continue
                name = analyze_modifiers_enumerate(comp_modis, asm_modis)
                analysis_result[-1].append((bin(i)[2:].zfill(modifier.length), name))
                comp = asm
        return analysis_result

    def generate_html_table(self):
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
        for erange in self.ranges:
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
                if erange.type == "operand_modifier" or erange.type == "modifier":
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


def analyze_modifiers_enumerate(original: List[str], mutated: List[str]):
    original = Counter(original)
    mutated = Counter(mutated)

    difference = Counter(mutated)
    difference.subtract(original)
    result = ""
    for name, count in difference.items():
        if count == 1:
            result += "." + name
    return result


def analyze_modifiers(original: List[str], mutated: List[str]):
    """
    Analyze a given list of modifiers and determine if the modifier bit can be a flag.
    Can have false positives for flag detection but will be corrected by second stage.
    """
    original = Counter(original)
    mutated = Counter(mutated)

    difference = Counter(mutated)
    difference.subtract(original)

    flag_candidate = None
    not_flag = False  # is it definetly not a flag.
    effected = False  # is a modifier field effected.
    for name, count in difference.items():
        if count == 0:
            # Modifier is uneffected
            continue
        effected = True
        if count <= 0:
            not_flag = True
            flag_candidate = None
            continue

        if count == 1 and not not_flag:
            if flag_candidate is None:
                flag_candidate = name
            else:
                flag_candidate = None
                not_flag = True

    return (effected, flag_candidate)


class InstructionMutationSet:
    def __init__(self, inst, disasm, mutations, disassembler):
        self.inst = inst
        self.disasm = disasm
        self.mutations = mutations
        self.disassembler = disassembler

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
                print(asm, e)
                continue
            # print(mutated_parsed.get_key())
            if parsed.get_key() != mutated_parsed.get_key():
                # NOTE: Should we only say this is a opcode bit if the base instruction is different.
                self.opcode_bits.add(i_bit)
                continue
            mutated_operands = mutated_parsed.get_flat_operands()

            if parsed.predicate != mutated_parsed.predicate:
                self.predicate_bits.add(i_bit)

            # Analyze operand values and operand modifiers.
            for i, (a, b) in enumerate(zip(mutated_operands, parsed_operands)):
                if not a.compare(b):
                    self.operand_value_bits.add(i_bit)
                    self.bit_to_operand[i_bit] = i
                else:
                    effected, flag = analyze_modifiers(b.modifiers, a.modifiers)
                    if effected:
                        self.bit_to_operand[i_bit] = i
                        self.operand_modifier_bits.add(i_bit)
                        print(a.modifiers, b.modifiers)
                    if flag:
                        self.operand_modifier_bit_flag[i_bit] = flag

            # Analyze instruction modifiers.
            effected, flag = analyze_modifiers(
                parsed.modifiers, mutated_parsed.modifiers
            )
            if effected:
                self.modifier_bits.add(i_bit)
            if flag:
                self.instruction_modifier_bit_flag[i_bit] = flag

    def compute_encoding_ranges(self):
        """
        Construct encoding ranges from the mutation set.

        """
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

        return EncodingRanges(result, self.disassembler)


def set_bit(array, i):
    bit_offset = i % 8
    # NOTE: Should this flip the bit instead?
    array[i // 8] ^= 1 << bit_offset


def analysis_disambiguate_flags(
    disassembler: Disassembler, mset: InstructionMutationSet
) -> bool:
    """
    Analysis pass to disambiguate flags from modifiers by fliping adjacent bits.
    TODO: Operand modifier/flag disambiguation
    """
    modifier_mutations = []

    for bit in mset.instruction_modifier_bit_flag:
        inst_ = bytearray(mset.inst)
        set_bit(inst_, bit)
        set_bit(inst_, bit + 1)
        modifier_mutations.append((inst_, bit, bit + 1))

        if bit - 1 not in mset.instruction_modifier_bit_flag:
            inst_ = bytearray(mset.inst)
            set_bit(inst_, bit)
            set_bit(inst_, bit - 1)
            modifier_mutations.append((inst_, bit, bit - 1))
    if len(modifier_mutations) == 0:
        return
    instructions, offsets, adj_offsets = zip(*modifier_mutations)

    disassembled = mset.disassembler.disassemble_parallel(instructions)
    changed = False
    for disasm, bit, adj in zip(disassembled, offsets, adj_offsets):
        if bit not in mset.instruction_modifier_bit_flag:
            continue  # Already eleminated.
        flag_name = mset.instruction_modifier_bit_flag[bit]
        if not disasm:
            continue
        try:
            parsed = InstructionParser.parseInstruction(disasm)
        except Exception:
            pass
        if not parsed:
            continue
        # If the flag name is not in the disassembled instruction, this is not really a flag.
        if flag_name not in parsed.modifiers:
            changed = True
            mset.modifier_bits.add(adj)
            del mset.instruction_modifier_bit_flag[bit]
            if adj in mset.instruction_modifier_bit_flag:
                del mset.instruction_modifier_bit_flag[adj]

    return changed


def analysis_extend_modifiers(
    disassembler: Disassembler, mset: InstructionMutationSet
) -> bool:
    """
    analysis pass to try to extend modifier fields.
    """
    ranges = mset.compute_encoding_ranges()
    modifier_ranges = ranges._find(EncodingRangeType.MODIFIER)
    changed = False

    def analyse_adj(modi_bit, adj):
        nonlocal changed

        array = bytearray(mset.inst)
        set_bit(array, modi_bit)
        original_asm = disassembler.disassemble(array)
        if len(original_asm) == 0:
            return
        original_parsed = InstructionParser.parseInstruction(original_asm)

        set_bit(array, adj)
        modi_asm = disassembler.disassemble(array)
        if len(modi_asm) == 0:
            return
        try:
            modi_parsed = InstructionParser.parseInstruction(modi_asm)
        except Exception:
            # TODO: Ideally this wouldn't happen.
            return

        if modi_parsed.get_key() != original_parsed.get_key():
            return
        # Check if there is any difference in modifiers.
        if modi_parsed.modifiers != original_parsed.modifiers:
            # Adjacent bit is a part of the modifier
            mset.modifier_bits.add(adj)
            if adj in mset.instruction_modifier_bit_flag:
                del mset.instruction_modifier_bit_flag[adj]
            changed = True

    for rng in modifier_ranges:
        # 1 0 0 0 1 usually works better.
        analyse_adj(rng.start, rng.start - 1)
        analyse_adj(rng.start + rng.length // 2, rng.start - 1)
        analyse_adj(rng.start + rng.length - 1, rng.start - 1)
        analyse_adj(rng.start, rng.start + rng.length)
        analyse_adj(rng.start + rng.length - 1, rng.start + rng.length)
        analyse_adj(rng.start + rng.length // 2, rng.start + rng.length)
    return changed


def analysis_modifier_coalescing(
    disassembler: Disassembler, mset: InstructionMutationSet
) -> bool:
    changed = False
    ranges = mset.compute_encoding_ranges()

    for i, rng in enumerate(ranges.ranges[1:]):
        if rng.length > 1:
            continue
        if (
            ranges.ranges[i].type != EncodingRangeType.MODIFIER
            or rng.type != EncodingRangeType.CONSTANT
        ):
            continue
        if (
            len(ranges.ranges) <= i + 2
            or ranges.ranges[i + 2].type != EncodingRangeType.MODIFIER
        ):
            continue
        for i in range(rng.start, rng.start + rng.length):
            changed = True
            mset.modifier_bits.add(i)
    return changed


INSTRUCTION_DESC_HEADER = """
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
        elif isinstance(op, parser.AttributeOperand):
            self.visitAttributeOperand(op)

    def begin_section(self, op):
        self.result += f"<span class='flat-operand-section' style='background-color:{operand_colors[op.flat_operand_index]}'>"

    def end_section(self):
        self.result += "</span>"

    def visitAttributeOperand(self, op):
        self.result += "a"
        self.visit(op.sub_operands[0])

    def visitDescOperand(self, op):
        self.result += "g" if op.g else ""
        self.result += "desc["
        self.visit(op.sub_operands[0])
        self.result += "]"
        if len(op.sub_operands) > 1:
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
    def __init__(self, corpus, disassembler):
        self.corpus = {}
        self.newly_discovered = set()
        self.base_instructions = set()
        self.base_map = {}
        self.disassembler = disassembler

        disasm = self.disassembler.disassemble_parallel(corpus)

        for inst, asm in zip(corpus, disasm):
            self._insert_inst(inst, asm)

        self.invalid_instr = set()

    def _insert_inst(self, inst, disasm=None):
        if disasm is None:
            # We loose way too much here during initilization.
            disasm = self.disassembler.disassemble(inst)
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
        instructions = self.disassembler.inst_disasm_range(base, 0, 12)
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
            result = self.disassembler.mutate_inst(inst)

            for i_bit, inst, asm in result:
                if len(asm) == 0:
                    continue
                is_new = self._insert_inst(inst, disasm=asm)
                if is_new:
                    discovered += 1
        print(self.newly_discovered)
        return discovered


def analysis_run_fixedpoint(
    disassembler: Disassembler, mset: InstructionMutationSet, fn
):
    change = True
    while change:
        change = fn(disassembler, mset)
        if change:
            print("analysis changed modifiers")


def analysis_pipeline(inst, disassembler):
    inst = disassembler.distill_instruction(inst)
    mutations = disassembler.mutate_inst(inst, end=14 * 8 - 2)
    asm = disassembler.disassemble(inst)

    parsed_inst = InstructionParser.parseInstruction(asm)
    generator = InstructionDescGenerator()

    html_result = generator.generate(parsed_inst)
    html_result += f"<p> distilled: {asm}</p>"

    mutation_set = InstructionMutationSet(inst, asm, mutations, disassembler)

    analysis_disambiguate_flags(disassembler, mutation_set)
    # analysis_run_fixedpoint(disassembler, mutation_set, analysis_extend_modifiers)
    # analysis_modifier_coalescing(disassembler, mutation_set)

    ranges = mutation_set.compute_encoding_ranges()
    html_result += ranges.generate_html_table()
    """
    modifiers = ranges.enumerate_modifiers()

    for i, rows in enumerate(modifiers):
        html_result += f"<p> Modifier Group {i}"
        builder = table_utils.TableBuilder()
        builder.tbody_start()

        for row in rows:
            builder.tr_start()
            for cell in row:
                builder.push(cell)
            builder.tr_end()
        builder.tbody_end()
        builder.end()

        html_result += builder.result + "</p>"
    """
    return html_result, ranges


if __name__ == "__main__":
    # distilled = bytes.fromhex("b573000e082a00000090010800e28300")
    # analyze_instruction(distilled)
    disassembler = Disassembler("SM90a")
    disassembler.load_cache("disasm_cache.txt")

    instructions = list(disassembler.find_uniques_from_cache().items())

    result = INSTRUCTION_DESC_HEADER + table_utils.INSTVIZ_HEADER

    for key, inst in instructions[:200]:
        print("Analyzing", key)
        html, ranges = analysis_pipeline(inst, disassembler)
        result += html

    with open("isa.html", "w") as file:
        file.write(result)

    disassembler.dump_cache("disasm_cache.txt")
    """
    distilled = distill_instruction_reverse(distilled, "SM90a")
    # analyze_instruction(distilled)

    decoder = ISADecoder([], "SM90a", "SM90")
    decoder.scan_opcode(distilled)
    decoder.dump_corpus("reverse_scan.txt")
    """
