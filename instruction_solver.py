import re
import json
import tqdm
from enum import Enum
from typing import List
from collections import Counter

from disasm_utils import Disassembler, set_bit_range2, get_bit_range2
import table_utils
import parser
from parser import InstructionParser, Instruction
from concurrent import futures
from argparse import ArgumentParser

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
    YIELD_FLAG = "y"
    READ_BARRIER = "r-bar"
    WRITE_BARRIER = "w-bar"
    BARRIER_MASK = "b-mask"
    REUSE_MASK = "reuse"


class EncodingRange:
    def __init__(
        self,
        type,
        start,
        length,
        operand_index=None,
        name=None,
        constant=None,
        group_id=None,
    ):
        self.type = type
        self.start = start
        self.length = length
        self.operand_index = operand_index
        self.group_id = group_id
        self.name = name
        self.constant = constant

    def to_json_obj(self):
        return self.__dict__

    def to_json(self):
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_str):
        json_dict = json.loads(json_str)
        return cls(**json_dict)

    @classmethod
    def from_json_obj(cls, obj):
        return cls(**obj)

    def __repr__(self):
        return self.to_json()


class EncodingRanges:
    def __init__(
        self,
        ranges,
        inst,
    ):
        self.ranges = ranges
        self.inst = inst

    def to_json_obj(self):
        ranges = [rng.to_json_obj() for rng in self.ranges]
        return {"ranges": ranges, "inst": self.inst.hex()}

    def to_json(self):
        return json.dumps(self.to_json_obj())

    @classmethod
    def from_json_obj(cls, obj):
        ranges = [EncodingRange.from_json_obj(rng) for rng in obj["ranges"]]
        return cls(ranges, bytes.fromhex(obj["inst"]))

    @classmethod
    def from_json(cls, json_str):
        return EncodingRanges.from_json_obj(json.loads(json_str))

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

    def encode(self, sub_operands, modifiers, operand_modifiers={}):
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
            elif (
                range.type == EncodingRangeType.OPERAND_MODIFIER
                and range.operand_index in operand_modifiers
            ):
                value = operand_modifiers[range.operand_index]

            if not value:
                continue
            set_bit_range2(result, range.start, range.start + range.length, value)
        return result

    def enumerate_modifiers(self, disassembler, initial_values=None):
        # NOTE: Enumerating with invalid modifiers in the instruction might be
        #      causing problems for us!

        modifiers = self._find(EncodingRangeType.MODIFIER)
        operand_values = [0] * self.operand_count()

        analysis_result = []
        if initial_values:
            _modi_values = list(initial_values)
        else:
            _modi_values = [
                get_bit_range2(self.inst, rng.start, rng.start + rng.length)
                for rng in modifiers
            ]

        for modifier_i, modifier in enumerate(modifiers):
            insts = []
            for modi_val in range(2**modifier.length):
                modi_values = list(_modi_values)
                modi_values[modifier_i] = modi_val
                insts.append(self.encode(operand_values, modi_values))
            disasms = disassembler.disassemble_parallel(insts)
            analysis_result.append([])
            comp = disasms[1]

            replace_original = False
            for i, asm in enumerate(disasms):
                try:
                    comp_modis = InstructionParser.parseInstruction(comp).modifiers
                    asm_modis = InstructionParser.parseInstruction(asm).modifiers
                except Exception:
                    continue
                # FIXME: This doesn't work for some instructions with invalid modifiers!
                name = analyze_modifiers_enumerate(comp_modis, asm_modis)
                # Replace the modifier value if the default value fuzzing found for this modifier is invalid.
                if (
                    name.startswith("INVALID") or name.startswith("???")
                ) and i == get_bit_range2(
                    self.inst, modifier.start, modifier.start + modifier.length
                ):
                    replace_original = True
                analysis_result[-1].append((i, name))
                comp = disasms[0]
            if replace_original:
                for val, name in analysis_result[-1]:
                    # NOTE: Hopefully this will help with enumeration.
                    if "INVALID" not in name and "???" not in name:
                        _modi_values[modifier_i] = val
                        break

        return analysis_result

    def enumerate_operand_modifiers(self, disassembler):
        operand_modifiers = self._find(EncodingRangeType.OPERAND_MODIFIER)
        modifiers = self._find(EncodingRangeType.MODIFIER)
        result = {}
        modi_values = [
            get_bit_range2(self.inst, rng.start, rng.start + rng.length)
            for rng in modifiers
        ]
        operand_values = [0] * self.operand_count()

        for modifier in operand_modifiers:
            insts = []
            for modi_i in range(2**modifier.length):
                operand_modis = {}
                operand_modis[modifier.operand_index] = modi_i
                insts.append(self.encode(operand_values, modi_values, operand_modis))
            disasms = disassembler.disassemble_parallel(insts)
            current = []
            result[modifier.operand_index] = current
            comp = disasms[1]
            for i, asm in enumerate(disasms):
                try:
                    comp_operands = InstructionParser.parseInstruction(
                        comp
                    ).get_flat_operands()
                    asm_operands = InstructionParser.parseInstruction(
                        asm
                    ).get_flat_operands()
                except Exception:
                    continue
                name = analyze_modifiers_enumerate(
                    comp_operands[modifier.operand_index].modifiers,
                    asm_operands[modifier.operand_index].modifiers,
                )
                # name = ".".join(asm_modis)
                comp = asm
                current.append((i, name))
        return result

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

            if new_range is None:
                control_code_ranges = [
                    (EncodingRangeType.REUSE_MASK, 4),
                    (EncodingRangeType.BARRIER_MASK, 6),
                    (EncodingRangeType.WRITE_BARRIER, 3),
                    (EncodingRangeType.READ_BARRIER, 3),
                    (EncodingRangeType.YIELD_FLAG, 1),
                    (EncodingRangeType.STALL_CYCLES, 4),
                ]

                offset = 13 * 8 + 1
                for rtype, length in control_code_ranges:
                    if i >= offset and i < offset + length:
                        new_range = EncodingRange(rtype, i, 1)
                        break
                    offset += length

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

        return EncodingRanges(result, self.inst)


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


def generate_modifier_table(title, modifiers, rng):
    html_result = "<p>" + title
    builder = table_utils.TableBuilder()
    builder.tbody_start()
    for row in modifiers:
        builder.tr_start()
        builder.push(bin(row[0])[2:].zfill(rng.length))
        builder.push(row[1])
        builder.tr_end()
    builder.tbody_end()
    builder.end()

    html_result += builder.result + "</p>"
    return html_result


def counter_remove_zeros(counts):
    for name, count in list(counts.items()):
        if count == 0:
            del counts[name]


class InstructionSpec:
    """
    An instruction specification.
    """

    def __init__(self, disasm, parsed, ranges, modifiers, operand_modifiers):
        self.disasm = disasm
        self.parsed = parsed
        self.ranges = ranges
        self.modifiers = modifiers
        self.operand_modifiers = operand_modifiers

        self.empty_value = []
        self.all_modifiers = []
        for i, modifier_range in enumerate(modifiers):
            for value, name in modifier_range:
                self.all_modifiers.append((name[:-1], i, value))

    def to_json_obj(self):
        return {
            "disasm": self.disasm,
            "parsed": self.parsed.to_json_obj(),
            "ranges": self.ranges.to_json_obj(),
            "modifiers": self.modifiers,
            "operand_modifiers": self.operand_modifiers,
        }

    def to_json(self):
        return json.dumps(self.to_json_obj())

    @classmethod
    def from_json_obj(cls, obj):
        return cls(
            obj["disasm"],
            Instruction.from_json_obj(obj["parsed"]),
            EncodingRanges.from_json_obj(obj["ranges"]),
            obj["modifiers"],
            obj["operand_modifiers"],
        )

    @classmethod
    def from_json(cls, json_str):
        return InstructionSpec.from_json_obj(json.loads(json_str))

    def get_modifier_values(self, modifiers):
        # Greedy algorithm for choosing the correct modifier values.
        result = {}
        counts = Counter(modifiers)

        def score_match(modifier_group):
            _counts = Counter(counts)
            match = True
            for modifier in modifier_group:
                if len(modifier) == 0:
                    continue
                if modifier not in counts:
                    match = False
                    break
            if not match:
                return 0
            for modifier in modifier_group:
                _counts[modifier] -= 1
                counter_remove_zeros(_counts)
            score = len(counts) - len(_counts)
            return score

        change = True
        while len(counts) != 0 and change:
            change = False
            best_i = -1
            best_value = -1
            best_modi_group = None
            best_match = 0
            for modifier_group, i, value in self.all_modifiers:
                if i in result:
                    continue
                modifier_group = [
                    operand
                    for operand in modifier_group.split(".")
                    if len(operand) != 0
                ]
                score = score_match(modifier_group)
                if score > best_match:
                    best_i = i
                    best_value = value
                    best_match = score
                    best_modi_group = modifier_group
            if best_match != 0:
                change = True
                result[best_i] = best_value
                for modifier in best_modi_group:
                    counts[modifier] -= 1
                    counter_remove_zeros(counts)

        if len(counts) != 0:
            return None

        for operand_group, i, value in self.all_modifiers:
            if i in result:
                continue
            if len(operand_group) != 0:
                continue
            result[i] = value
        return result

    def get_minimal_modifiers(self):
        modifiers = []
        for modi_group in self.modifiers:
            if "" in [modi[1] for modi in modi_group]:
                continue
            modifiers.append(modi_group[0][1][:-1])
        return modifiers

    def encode_for_life_range(self, modifiers=[]):
        operands = self.parsed.get_flat_operands()
        operand_values = [0] * len(operands)
        reg_count = 0
        ureg_count = 0
        pred_count = 1
        modifiers = self.get_modifier_values(modifiers)
        for i, operand in enumerate(operands):
            if isinstance(operand, parser.RegOperand):
                if operand.reg_type == "R":
                    operand_values[i] = reg_count * 16 + 16
                    reg_count += 1
                elif operand.reg_type == "P":
                    operand_values[i] = pred_count
                    pred_count += 1
                elif operand.reg_type == "UR":
                    operand_values[i] = ureg_count * 4
                    ureg_count += 1
        return self.ranges.encode(operand_values, modifiers)

    def generate_html(self):
        """
        Generate html for this instruction.
        """
        desc_generator = InstructionDescGenerator()
        html_result = desc_generator.generate(self.parsed)
        html_result += f"<p> distilled: {self.disasm}</p>"
        html_result += f"<p> key: {self.parsed.get_key()}</p>"
        html_result += self.ranges.generate_html_table()

        modifier_ranges = self.ranges._find(EncodingRangeType.MODIFIER)
        for i, rows in enumerate(self.modifiers):
            title = f"Modifier Group {i + 1}"
            html_result += generate_modifier_table(title, rows, modifier_ranges[i])

        operand_modifier_ranges = self.ranges._find(EncodingRangeType.OPERAND_MODIFIER)
        operand_modifier_ranges = {
            rng.operand_index: rng for rng in operand_modifier_ranges
        }

        for operand, modifiers in self.operand_modifiers.items():
            title = f"Operand {operand} operand modifiers"

            html_result += generate_modifier_table(
                title, modifiers, operand_modifier_ranges[operand]
            )
        return html_result


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

    modifier_values = ranges.enumerate_modifiers(disassembler)

    operand_modifier_values = ranges.enumerate_operand_modifiers(disassembler)
    spec = InstructionSpec(
        asm, parsed_inst, ranges, modifier_values, operand_modifier_values
    )

    return spec


import sys

sys.path.append("life_range")
from life_range import analyse_inst

if __name__ == "__main__":
    arg_parser = ArgumentParser()
    arg_parser.add_argument("--arch", default="SM90a")
    arg_parser.add_argument("--cache_file", default="disasm_cache.txt")
    arg_parser.add_argument("--nvdisasm", default="nvdisasm")
    arg_parser.add_argument("--num_parallel", default=5, type=int)
    arguments = arg_parser.parse_args()

    disassembler = Disassembler(arguments.arch, nvdisasm=arguments.nvdisasm)
    disassembler.load_cache(arguments.cache_file)

    analysis_result = {}
    result = INSTRUCTION_DESC_HEADER + table_utils.INSTVIZ_HEADER
    while True:
        instructions = disassembler.find_uniques_from_cache()
        instructions = list(instructions.items())
        instructions = [
            (key, inst) for key, inst in instructions if key not in analysis_result
        ]
        if len(instructions) == 0:
            print("No new instruction found, exiting")
            break

        print("Found", len(instructions), "instructions")

        with futures.ThreadPoolExecutor(max_workers=arguments.num_parallel) as executor:
            instruction_futures = {}
            for key, inst in instructions:
                future = executor.submit(
                    instruction_analysis_pipeline, inst, disassembler
                )
                instruction_futures[key] = future

            for key, inst in instructions:
                spec = instruction_futures[key].result()
                analysis_result[key] = spec

    analysis_result = sorted(list(analysis_result.items()), key=lambda x: x[0])

    for key, spec in analysis_result:
        result += spec.generate_html()

    with open("isa.html", "w") as file:
        file.write(result)
    disassembler.dump_cache(arguments.cache_file)
