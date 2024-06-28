import re
import json
import tqdm
from enum import Enum
from typing import List
from collections import Counter

from disasm_utils import Disassembler, set_bit_range2, get_bit_range2
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
    "#fc556e",
    "#256336",
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
        self,
        _type,
        start,
        length,
        operand_index=None,
        name=None,
        constant=None,
        group_id=None,
    ):
        self.type = _type
        self.start = start
        self.length = length
        self.operand_index = operand_index
        self.group_id = group_id
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
    def __init__(self, ranges, inst, disassembler):
        self.ranges = ranges
        self.disassembler = disassembler
        self.inst = inst

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
            seen = set()
            for modi_i in range(2**modifier.length):
                # Gray code
                # modi_i = modi_i ^ (modi_i >> 1)
                modi_values = [
                    get_bit_range2(self.inst, rng.start, rng.start + rng.length)
                    for rng in modifiers
                ]
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
                # name = ".".join(asm_modis)
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
                    if erange.group_id:
                        text += f" {erange.group_id}"

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
        if len(name) == 0 or count <= 0:
            continue
        result += ".".join([name] * count) + "."

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
        self.parsed = InstructionParser.parseInstruction(self.disasm)
        self.mutations = mutations
        self.disassembler = disassembler

        # TODO: Maybe combine this into one map.
        self.operand_type_bits = set()
        self.opcode_bits = set()
        self.operand_value_bits = set()
        self.operand_modifier_bits = set()
        self.operand_modifier_bit_flag = {}
        self.instruction_modifier_bit_flag = {}
        self.bit_to_operand = {}
        self.predicate_bits = set()

        self.modifier_bits = set()
        self.modifier_groups = {}

        self._analyze()

    def reset_modifier_groups(self):
        self.modifier_groups = {}

    def canonicalize_modifier_groups(self):
        """
        Canonicalize modifier groups by assigning groupless bit sequences groups
        """

        # Step 1: Assign a number to each range.
        max_group_id = None
        fill_mode = False
        fill_id = None

        bits = sorted(list(self.modifier_bits))
        for i, bit in enumerate(bits):
            if bit in self.modifier_groups:
                continue
                # When there is a discontinuity, we should change the group_id
            if fill_mode and i != 0 and bits[i - 1] != bit - 1:
                fill_mode = False

            if not fill_mode:
                max_group_id = max([0] + list(self.modifier_groups.values()))
                fill_mode = True
                fill_id = max_group_id + 1
                max_group_id = fill_id
            self.modifier_groups[bit] = fill_id

        # Step 2: Fix numbers
        max_num = 0
        num_map = {}
        bits = sorted(list(self.modifier_bits))
        for bit in bits:
            gid = self.modifier_groups[bit]
            if gid not in num_map:
                num_map[gid] = max_num + 1
                max_num += 1
            self.modifier_groups[bit] = num_map[gid]

    def _analyze(self):
        parsed_operands = self.parsed.get_flat_operands()
        self.key = self.parsed.get_key()
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
            if self.parsed.get_key() != mutated_parsed.get_key():
                # NOTE: Should we only say this is a opcode bit if the base instruction is different.
                self.opcode_bits.add(i_bit)
                continue
            # FIXME: This won't be able to handle '[R1].asd'
            mutated_operands = mutated_parsed.get_flat_operands()

            if self.parsed.predicate != mutated_parsed.predicate:
                self.predicate_bits.add(i_bit)

            operand_effected = False
            # Analyze operand values and operand modifiers.
            for i, (a, b) in enumerate(zip(mutated_operands, parsed_operands)):
                if not a.compare(b):
                    self.operand_value_bits.add(i_bit)
                    self.bit_to_operand[i_bit] = i
                    operand_effected = True
                else:
                    effected, flag = analyze_modifiers(b.modifiers, a.modifiers)
                    if effected:
                        self.bit_to_operand[i_bit] = i
                        self.operand_modifier_bits.add(i_bit)
                        operand_effected = True
                    if flag:
                        self.operand_modifier_bit_flag[i_bit] = flag
            if operand_effected:
                continue
            # Analyze instruction modifiers.
            effected, flag = analyze_modifiers(
                self.parsed.modifiers, mutated_parsed.modifiers
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
        self.canonicalize_modifier_groups()

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
                    new_range = EncodingRange(
                        EncodingRangeType.MODIFIER,
                        i,
                        1,
                        group_id=self.modifier_groups[i],
                    )
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
                and (
                    new_range.group_id is None
                    or new_range.group_id == current_range.group_id
                )
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

        return EncodingRanges(result, self.inst, self.disassembler)


def set_bit(array, i):
    bit_offset = i % 8
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
        return False
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
            continue
        if parsed.get_key() != mset.key:
            continue
        # If the flag name is not in the disassembled instruction, this is not really a flag.
        if flag_name not in parsed.modifiers:
            print("FLAG", flag_name, "removed", adj, bit)
            changed = True
            mset.modifier_bits.add(adj)
            del mset.instruction_modifier_bit_flag[bit]
            if adj in mset.instruction_modifier_bit_flag:
                del mset.instruction_modifier_bit_flag[adj]
            mset.reset_modifier_groups()

    return changed


def analysis_disambiguate_operand_flags(
    disassembler: Disassembler, mset: InstructionMutationSet
) -> bool:
    modifier_mutations = []
    for bit in mset.operand_modifier_bit_flag:
        inst_ = bytearray(mset.inst)
        set_bit(inst_, bit)
        set_bit(inst_, bit + 1)
        modifier_mutations.append((inst_, bit, bit + 1))
        if bit - 1 not in mset.operand_modifier_bit_flag:
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
        if bit not in mset.operand_modifier_bit_flag:
            continue
        flag_name = mset.operand_modifier_bit_flag[bit]
        if not disasm:
            continue
        try:
            parsed = InstructionParser.parseInstruction(disasm)
        except Exception:
            continue
        if parsed.get_key() != mset.key:
            continue
        mutated_operands = parsed.get_flat_operands()
        if flag_name not in mutated_operands[mset.bit_to_operand[bit]].modifiers:
            changed = True
            del mset.operand_modifier_bit_flag[bit]
            if adj in mset.operand_modifier_bit_flag:
                del mset.operand_modifier_bit_flag[adj]
    return changed


def analysis_operand_fix(
    disassembler: Disassembler, mset: InstructionMutationSet
) -> bool:
    """
    With operands like [UR10 + 0x1], a constant IMM of 0 changes the operand
    signature and won't be removed with distillation, causing a discontinuity
    in the operand or makes it look shorter than it actually is.
    """

    operands = mset.parsed.get_flat_operands()

    def mutate_test(operand_index, idx, adj):
        inst = bytearray(mset.inst)
        set_bit(inst, idx)
        set_bit(inst, adj)
        asm = disassembler.disassemble(inst)
        if len(asm) == 0:
            return
        try:
            parsed = InstructionParser.parseInstruction(asm)
        except Exception:
            return
        if parsed.get_key() != mset.key:
            return
        mutated_operands = parsed.get_flat_operands()
        if operands[operand_index] == mutated_operands[operand_index]:
            return
        mset.operand_value_bits.add(idx)
        mset.bit_to_operand[idx] = operand_index

    ranges = mset.compute_encoding_ranges()
    operand_ranges = ranges._find(EncodingRangeType.OPERAND)

    for i, rng in enumerate(operand_ranges):
        operand = operands[rng.operand_index]
        if not isinstance(operand, parser.IntIMMOperand) or not isinstance(
            operand.parent, parser.AddressOperand
        ):
            continue
        # Not 100% sure about this, what if the bit is between bytes?
        if rng.start % 8 != 0:
            mutate_test(rng.operand_index, rng.start - 1, rng.start)
        elif rng.length % 8 != 0:
            mutate_test(rng.operand_index, rng.start + rng.length, rng.start)


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

            changed = adj not in mset.modifier_bits
            mset.modifier_bits.add(adj)
            if adj in mset.instruction_modifier_bit_flag:
                del mset.instruction_modifier_bit_flag[adj]

    for rng in modifier_ranges:
        # 1 0 0 0 1 usually works better.
        analyse_adj(rng.start, rng.start - 1)
        # analyse_adj(rng.start + rng.length // 2, rng.start - 1)
        analyse_adj(rng.start, rng.start + rng.length)
        # analyse_adj(rng.start + rng.length // 2, rng.start + rng.length)
    if changed:
        mset.reset_modifier_groups()
    return changed


def analysis_modifier_coalescing(
    disassembler: Disassembler, mset: InstructionMutationSet
) -> bool:
    changed = False
    ranges = mset.compute_encoding_ranges()

    for i, rng in enumerate(ranges.ranges[1:]):
        if rng.length > 2:
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


def analysis_modifier_splitting(
    disassembler: Disassembler, mset: InstructionMutationSet
):
    """
    Split the modifier if there is independence between modifiers.

    """
    ranges = mset.compute_encoding_ranges()
    modifier_ranges = ranges._find(EncodingRangeType.MODIFIER)

    def analyse_adj(modi_bit, adj):
        inst = []
        array = bytearray(mset.inst)
        inst.append(array)

        array = bytearray(array)
        set_bit(array, modi_bit)
        inst.append(array)

        array = bytearray(array)
        set_bit(array, adj)
        inst.append(array)

        inst = disassembler.disassemble_parallel(inst)
        if "" in inst:
            return False
        try:
            orig, modi, adj = [InstructionParser.parseInstruction(asm) for asm in inst]
        except Exception:
            return False

        if len(set([orig.get_key(), modi.get_key(), adj.get_key()])) != 1:
            return False

        orig_difference = analyze_modifiers_enumerate(orig.modifiers, modi.modifiers)
        if (
            len(orig_difference) == 0
            or "." in orig_difference[:-1]
            or orig_difference.startswith("INVALID")
        ):
            return False
        # print("INDICATOR", orig_difference)
        orig_difference = orig_difference[:-1]
        if (
            orig_difference in adj.modifiers
            and adj.modifiers != modi.modifiers
            and adj.modifiers != orig.modifiers
        ):
            count_orig = Counter(modi.modifiers)[orig_difference]
            count_adj = Counter(adj.modifiers)[orig_difference]
            return count_orig == count_adj

    def split_range(rng, i):
        print("Splitting!", rng.group_id, "len", rng.length)
        next_group_id = max([0] + list(mset.modifier_groups.values())) + 1
        for i in range(i, rng.length):
            mset.modifier_groups[rng.start + i] = next_group_id

    for rng in modifier_ranges:
        for i in range(1, rng.length - 1):
            if (
                analyse_adj(rng.start, rng.start + i)
                or analyse_adj(rng.start + i - 1, rng.start + i)
                or analyse_adj(rng.start, rng.start + i)
            ):
                split_range(rng, i)
                return True

    return False


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


problem_modi_instructions = 0


def instruction_analysis_pipeline(inst, disassembler):
    inst = disassembler.distill_instruction(inst)
    asm = disassembler.disassemble(inst)

    mutations = disassembler.mutate_inst(inst, end=14 * 8 - 2)
    mutation_set = InstructionMutationSet(inst, asm, mutations, disassembler)
    parsed_inst = InstructionParser.parseInstruction(asm)
    analysis_run_fixedpoint(disassembler, mutation_set, analysis_disambiguate_flags)
    analysis_operand_fix(disassembler, mutation_set)
    analysis_disambiguate_operand_flags(disassembler, mutation_set)
    analysis_run_fixedpoint(disassembler, mutation_set, analysis_extend_modifiers)
    # analysis_modifier_coalescing(disassembler, mutation_set)
    analysis_run_fixedpoint(disassembler, mutation_set, analysis_modifier_splitting)
    ranges = mutation_set.compute_encoding_ranges()

    return inst, asm, parsed_inst, ranges


def analyse_and_generate_html(inst, disassembler):
    global problem_modi_instructions
    generator = InstructionDescGenerator()

    inst, asm, parsed_inst, ranges = instruction_analysis_pipeline(inst, disassembler)

    html_result = generator.generate(parsed_inst)
    html_result += f"<p> distilled: {asm}</p>"
    html_result += f"<p> key: {parsed_inst.get_key()}</p>"

    html_result += ranges.generate_html_table()
    modifiers = ranges.enumerate_modifiers()
    is_problem = False
    for i, rows in enumerate(modifiers):
        html_result += f"<p> Modifier Group {i + 1}"
        builder = table_utils.TableBuilder()
        builder.tbody_start()
        if len(rows) < 2:
            is_problem = True
        non_empty = False
        for row in rows:
            builder.tr_start()
            if len(row[1]) != 0 and "INVALID" not in row[1]:
                non_empty = True
            for cell in row:
                builder.push(cell)
            builder.tr_end()
        if not non_empty:
            is_problem = True
        builder.tbody_end()
        builder.end()

        html_result += builder.result + "</p>"
    if is_problem:
        problem_modi_instructions += 1
    return html_result, ranges


if __name__ == "__main__":
    # distilled = bytes.fromhex("b573000e082a00000090010800e28300")
    # analyze_instruction(distilled)
    disassembler = Disassembler("SM90a")
    disassembler.load_cache("disasm_cache.txt")

    instructions = disassembler.find_uniques_from_cache()
    # instructions = [("IMAD_R_R_I_R", instructions["IMAD_R_R_I_R"])]
    instructions = list(instructions.items())

    result = INSTRUCTION_DESC_HEADER + table_utils.INSTVIZ_HEADER
    print("Found", len(instructions), "instructions")
    instructions = sorted(instructions, key=lambda x: x[0])
    for key, inst in instructions:
        print("Analyzing", key)
        html, ranges = analyse_and_generate_html(inst, disassembler)
        result += html

    with open("isa.html", "w") as file:
        file.write(result)
    disassembler.dump_cache("disasm_cache.txt")
    print(
        "Detected",
        problem_modi_instructions,
        "problematic instructions of out",
        len(instructions),
    )
    """
    distilled = distill_instruction_reverse(distilled, "SM90a")
    # analyze_instruction(distilled)

    decoder = ISADecoder([], "SM90a", "SM90")
    decoder.scan_opcode(distilled)
    decoder.dump_corpus("reverse_scan.txt")
    """
