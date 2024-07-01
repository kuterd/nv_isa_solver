"""
Based on CuAssembler's parser.
"""

import json
from typing import Union
import re
from enum import Enum

p_InsPattern = re.compile(r"(?P<Pred>@!?U?P\w\s+)?\s*(?P<Op>[\w\.\?]+)(?P<Operands>.*)")

# Pattern for striping modifiers from an operand
# .*? for non-greedy match, needed for [R0.X4].A
p_ModifierPattern = re.compile(
    r"^(?P<PreModi>[~\-\|!]*)(?P<Main>.*?)\|?(?P<PostModi>(\.[0-9a-zA-Z_\?]+)*)\|?$"
)

# Match Label+Index (including translated RZ/URZ/PT)
# SBSet is the score board set for DEPBAR, translated before parsing
p_IndexedPattern = re.compile(
    r"\b(?P<RegType>R|UR|P|UP|B|SB|SBSET|SR|gsb)(?P<Index>\d+)$"
)

# Pattern for constant memory, some instructions have a mysterious space between two square brackets...
p_ConstMemType = re.compile(r"c\[(?P<Bank>0x\w+)\]\[(?P<Addr>[+-?\w\.]+)\]")

# Attributes
p_AttributeType = re.compile(r"a\[(?P<Addr>[+-?\w\.]+)\]")

# Pattern for constant memory, some instructions have a mysterious space between two square brackets...
p_URConstMemType = re.compile(r"cx\[(?P<URBank>UR\w+)\]\[(?P<Addr>[+-?\w\.]+)\]")

p_DescAddressType = re.compile(r"g?desc\[(?P<URIndex>UR\d+)\](?P<Addr>\[.*\])?$")

# RImmeAddr
p_RImmeAddr = re.compile(r"(?P<R>R\d+)\s*(?P<II>-?0x[0-9a-fA-F]+)")

c_OpPreModifierChar = {"!": "cNOT", "-": "cNEG", "|": "cABS", "~": "cINV"}

p_FIType = re.compile(
    r"^(?P<Value>((-?\d+)(\.\d*)?((e|E)[-+]?\d+)?)|([+-]?INF)|([+-]NAN)|-?(0[fF][0-9a-fA-F]+))(?P<ModiSet>(\.[a-zA-Z]\w*)*)$"
)

p_ConstTrDict = {
    r"(?<!\.)\bRZ\b": "R255",
    r"\bURZ\b": "UR63",
    r"\bPT\b": "P7",
    r"\bUPT\b": "UP7",
    r"\bSRZ": "SR_0",
    r"\bQNAN\b": "NAN",
}

# Functions that have position dependent modifiers, such as F2F.F16.F32 != F2F.F32.F16
c_PosDepFuncs = set(
    [
        "I2I",
        "F2F",
        "IDP",
        "HMMA",
        "IMMA",
        "XMAD",
        "IMAD",
        "IMADSP",
        "VADD",
        "VMAD",
        "VSHL",
        "VSHR",
        "VSET",
        "VSETP",
        "VMNMX",
        "VABSDIFF",
        "VABSDIFF4",
        "TLD4",
        "PSET",
        "PSETP",
    ]
)

c_ModiDTypes = set(
    [
        "S4",
        "S8",
        "S16",
        "S32",
        "S64",
        "U4",
        "U8",
        "U16",
        "U32",
        "U64",
        "F16",
        "F32",
        "F64",
    ]
)
c_ModiDTypesExt = c_ModiDTypes.union(
    set(["S24", "U24", "S16H0", "S16H1", "U16H0", "U16H1"])
)  # IMAD/IMADSP/IMUL(32I)* of sm_6x
c_ModiRGBA = set(["R", "G", "B", "A"])  # For TLD4
c_ModiLOP = set(["AND", "OR", "XOR", "NOT"])  # PSET/PSETP for sm_6x

# NOTE: position dependent opcode list is arch dependent,
c_PosDepModis = {
    "I2I": c_ModiDTypes,
    "F2F": c_ModiDTypes,
    "I2IP": c_ModiDTypes,
    "F2FP": c_ModiDTypes,
    "VADD": c_ModiDTypes,
    "VMAD": c_ModiDTypes,
    "VSHL": c_ModiDTypes,
    "VSHR": c_ModiDTypes,
    "VSET": c_ModiDTypes,
    "VSETP": c_ModiDTypes,
    "VMNMX": c_ModiDTypes,
    "VABSDIFF": c_ModiDTypes,
    "VABSDIFF4": c_ModiDTypes,
    "XMAD": c_ModiDTypesExt,
    "IMAD": c_ModiDTypesExt,
    "IMAD32I": c_ModiDTypesExt,
    "IMADSP": c_ModiDTypesExt,
    "IMUL": c_ModiDTypesExt,
    "IMUL32I": c_ModiDTypesExt,
    "PSET": c_ModiLOP,
    "PSETP": c_ModiLOP,
    "IDP": c_ModiDTypes,
    "HMMA": c_ModiDTypes,
    "IMMA": c_ModiDTypes,
    "TLD4": c_ModiRGBA,
}

# Patterns for assembly comments
p_cppcomment = re.compile(r"//.*$")  # cpp style line comments
p_ccomment = re.compile(r"\/\*.*?\*\/")  # c   style line
p_bracomment = re.compile(r"\(\*.*\*\)")  # notes for bra targets

# Pattern for matching white spaces
p_WhiteSpace = re.compile(r"\s+")

# Pattern for insignificant spaces, they will be collapsed first, and removed finally
# Spaces between words([0-9A-Za-z_]) will be kept, others will be removed
p_InsignificantSpace = re.compile(
    r"((?<=[\w\?]) (?![\w\?]))|((?<![\w\?]) (?=[\w\?]))|((?<![\w\?]) (?![\w\?]))"
)


class OperandType(str, Enum):
    UNIFORM_REG = "UNIFORM_REG"
    REG = "REG"
    BARRIER = "BARRIER"
    PREDICATE = "PREDICATE"
    UNIFORM_PREDICATE = "UNIFORM_PREDICATE"
    INT_IMM = "INT_IMMEDIATE"
    FLOAT_IMM = "FLAOT_IMMEDIATE"
    ADDRESS = "ADDRESS"
    CONSTANT_UR = "CONSTANT_UR"
    CONSTANT = "CONSTANT"
    DESC = "DESC"
    GDESC = "GDESC"


class Operand:
    def __init__(self, sub_operands=None, modifiers=None):
        self.sub_operands = sub_operands if sub_operands else []
        self.parent = None
        self.modifiers = modifiers if modifiers else []
        self.flat_operand_index = -1
        for op in self.sub_operands:
            op.parent = self
        # self.encoding_range = None

    @classmethod
    def from_json_obj(cls, obj):
        otype = obj["type"]

        if otype == "RegOperand":
            return RegOperand.from_json_obj(obj)
        elif otype == "AttributeOperand":
            return RegOperand.from_json_obj(obj)
        elif otype == "AddressOperand":
            return AddressOperand.from_json_obj(obj)
        elif otype == "IntIMMOperand":
            return IntIMMOperand.from_json_obj(obj)
        elif otype == "FloatIMMOperand":
            return FloatIMMOperand.from_json_obj(obj)
        elif otype == "ConstantMemOperand":
            return ConstantMemOperand.from_json_obj(obj)
        elif otype == "DescOperand":
            return DescOperand.from_json_obj(obj)

    # Get identifier for this operand.
    def get_operand_key(self):
        raise NotImplementedError

    def modifier_repr(self):
        return ".".join(self.modifiers)

    def flatten(self):
        result = []

        for op in self.sub_operands:
            result += op.flatten()
        if len(result) == 0:
            return [self]
        return result

    def compare(self, other):
        raise NotImplementedError

    def is_leaf(self):
        return len(self.sub_operands) == 0


class RegOperand(Operand):
    def __init__(self, reg_type, ident, modifiers=None):
        super().__init__(modifiers=modifiers)
        self.reg_type = reg_type
        self.ident = ident

    def __repr__(self):
        base = self.reg_type + "_" + self.ident
        m = ".".join(self.modifiers)
        if len(m) != 0:
            return base + "." + m
        return base

    def get_operand_key(self):
        return self.reg_type

    def compare(self, other):
        return self.ident == other.ident

    def to_json_obj(self):
        return {
            "type": type(self).__name__,
            "reg_type": self.reg_type,
            "ident": self.ident,
            "modifiers": self.modifiers,
        }

    @classmethod
    def from_json_obj(cls, obj):
        return cls(
            reg_type=obj["reg_type"], ident=obj["ident"], modifiers=obj["modifiers"]
        )


class AttributeOperand(Operand):
    def __init__(self, address, modifiers=None):
        super().__init__([address], modifiers=modifiers)

    def __repr__(self):
        return "a" + repr(self.sub_operands[0])

    def get_operand_key(self):
        return f"a[{self.sub_operands[0].get_operand_key()}]"

    def to_json_obj(self):
        return {
            "type": type(self).__name__,
            "sub_operands": [op.to_json_obj() for op in self.sub_operands],
            "modifiers": self.modifiers,
        }

    @classmethod
    def from_json_obj(cls, obj):
        return cls(obj["sub_operands"][0], modifiers=obj["modifiers"])


class AddressOperand(Operand):
    def __init__(self, operands, modifiers=None):
        super().__init__(operands, modifiers=modifiers)

    def __repr__(self):
        result = "+".join([a.__repr__() for a in self.sub_operands])
        return f"[{result}]"

    def get_operand_key(self):
        result = ""

        for op in self.sub_operands:
            # NOTE: What about IntIMM? We don't want to include it here probably.
            result += op.get_operand_key()
            pass
        return result

    def to_json_obj(self):
        return {
            "type": type(self).__name__,
            "sub_operands": [op.to_json_obj() for op in self.sub_operands],
            "modifiers": self.modifiers,
        }

    @classmethod
    def from_json_obj(cls, obj):
        return cls(obj["sub_operands"], modifiers=obj["modifiers"])


class IntIMMOperand(Operand):
    def __init__(self, constant):
        super().__init__()
        self.constant = constant

    def __repr__(self):
        return str(self.constant)

    def get_operand_key(self):
        return "I"

    def compare(self, other):
        return self.constant == other.constant

    def to_json_obj(self):
        return {"type": type(self).__name__, "constant": self.constant}

    @classmethod
    def from_json_obj(cls, obj):
        return cls(obj["constant"])


class FloatIMMOperand(Operand):
    def __init__(self, constant: str):
        super().__init__()
        self.constant = constant

    def __repr__(self):
        return self.constant

    def get_operand_key(self):
        return "FI"

    def compare(self, other):
        return self.constant == other.constant

    def to_json_obj(self):
        return {"type": type(self).__name__, "constant": self.constant}

    @classmethod
    def from_json_obj(cls, obj):
        return cls(obj["constant"])


class ConstantMemOperand(Operand):
    def __init__(self, bank, address, cx=False, modifiers=None):
        super().__init__([bank, address], modifiers=None)
        self.cx = cx

    def get_operand_key(self):
        result = "cx" if self.cx else "c"
        result += f"[{self.sub_operands[0].get_operand_key()}]"
        result += f"[{self.sub_operands[1].get_operand_key()}]"
        return result

    def __repr__(self):
        prefix = "cx" if self.cx else "c"
        return f"{prefix}[{repr(self.sub_operands[0])}]{repr(self.sub_operands[1])}"

    def to_json_obj(self):
        return {
            "type": type(self).__name__,
            "cx": self.cx,
            "sub_operands": [op.to_json_obj() for op in self.sub_operands],
        }

    @classmethod
    def from_json_obj(cls, obj):
        operands = obj["sub_operands"]
        return cls(operands[0], operands[1], modifiers=obj["modifiers"])


class DescOperand(Operand):
    def __init__(self, bank, address=None, g=False, modifiers=None):
        super().__init__([bank] + ([address] if address else []), modifiers=None)
        self.g = g

    def get_operand_key(self):
        result = "g" if self.g else ""
        result += "desc[" + self.sub_operands[0].get_operand_key() + "]"
        if len(self.sub_operands) > 1:
            result += "[" + self.sub_operands[1].get_operand_key() + "]"
        return result

    def __repr__(self):
        prefix = "g" if self.g else ""
        return (
            prefix + f"desc[{repr(self.sub_operands[0])}]{repr(self.sub_operands[1])}"
        )

    def to_json_obj(self):
        return {
            "type": type(self).__name__,
            "g": self.h,
            "sub_operands": [op.to_json_obj() for op in self.sub_operands],
        }

    @classmethod
    def from_json_obj(cls, obj):
        operands = obj["sub_operands"]
        return cls(
            operands[0],
            None if len(operands) == 1 else operands[1],
            modifiers=obj["modifiers"],
        )


class Instruction:
    def __init__(self, base_name, modifiers, predicate, operands):
        self.base_name = base_name
        self.modifiers = modifiers
        self.predicate = predicate
        self.operands = operands

    def get_key(self):
        return "_".join(
            [self.base_name] + [op.get_operand_key() for op in self.operands]
        )

    def __repr__(self):
        return f"{self.predicate} {self.base_name} {repr(self.modifiers)} {repr(self.operands)[1:-1]}"

    def get_flat_operands(self):
        result = []

        for operand in self.operands:
            result += operand.flatten()

        return result

    def to_json_obj(self):
        return {
            "base_name": self.base_name,
            "modifiers": self.modifiers,
            "predicate": self.predicate,
            "operands": [op.to_json_obj() for op in self.operands],
        }

    def to_json(self):
        return json.dumps(self.to_json_obj())

    @classmethod
    def from_json_obj(cls, obj):
        operands = [Operand.from_json_obj(op) for op in obj["operands"]]
        return cls(obj["base_name"], obj["modifiers"], obj["predicate"], operands)

    @classmethod
    def from_json(cls, jstr):
        return Instruction.from_json_obj(json.loads(jstr))


def stripComments(s):
    """Strip comments of a line.

    NOTE: cross line comments are not supported yet.
    """

    s = p_cppcomment.subn(" ", s)[
        0
    ]  # replace comments as a single space, avoid unwanted concatination
    s = p_ccomment.subn(" ", s)[0]
    s = p_bracomment.subn(" ", s)[0]
    s = re.subn(r"\s+", " ", s)[
        0
    ]  # replace one or more spaces/tabs into one single space

    return s.strip()


class _InstructionParser:
    def parseOperandAtom(self, operand):
        match = p_ModifierPattern.match(operand)  # split token to three parts
        if match is None:
            raise ValueError(f"Unknown token {operand}")
        pre = match.group("PreModi")
        pre = [c_OpPreModifierChar[c] for c in pre]
        post = match.group("PostModi").strip().split(".")
        post = [p for p in post if len(p) != 0]
        main = match.group("Main")
        return main, pre + post

    def _constTr(self, s):
        """Translate pre-defined constants (RZ/URZ/PT/...) to known or indexed values.

        Translate scoreboard sets {4,2} to SBSet
        """
        # strip all comments
        s = stripComments(s)

        for cm in p_ConstTrDict:
            s = re.sub(cm, p_ConstTrDict[cm], s)
        s = p_WhiteSpace.sub(" ", s)
        s = p_InsignificantSpace.sub("", s)

        return s.strip(" {};")

    def _parseConstMemory(self, op):
        match = p_ConstMemType.match(op)
        if match is None:
            raise ValueError(f"Failed to parse constant memory {op}")
        bank_id = int(match.group("Bank"), 16)
        address = self._parseAddress(match.group("Addr"))
        return ConstantMemOperand(IntIMMOperand(bank_id), address)

    def _parseURConstMemory(self, op):
        match = p_URConstMemType.match(op)
        if match is None:
            raise ValueError(f"Failed to parse constant memory {op}")
        bank = self._parseIndexedToken(match.group("URBank"))
        address = self._parseAddress(match.group("Addr"))

        return ConstantMemOperand(bank, address, cx=True)

    def _parseAttribute(self, op):
        match = p_AttributeType.match(op)
        if match is None:
            raise ValueError(f"Failed to parse attribute {op}")
        address = self._parseAddress(match.group("Addr"))
        return AttributeOperand(address)

    def _parseIndexedToken(self, s):
        """Parse index token such as R0, UR1, P2, UP3, B4, SB5, ...

        (RZ, URZ, PT should be translated In advance)"""

        tmain, modi = self.parseOperandAtom(s)
        match = p_IndexedPattern.match(tmain)
        if match is None:
            raise ValueError(f'Unknown indexedToken "{s}"')

        regType = match.group("RegType")
        value = match.group("Index")

        return RegOperand(regType, value, modi)
        # return regType, value, modi

    def _parseIntIMM(self, s):
        return IntIMMOperand(int(s, 16))

    def _parseFloatIMM(self, s):
        return FloatIMMOperand(s)

    def _parseAddress(self, s):
        """Parse operand type Address [R0.X8+UR4+-0x8]

        Zero immediate will be appended if not present.
        It's harmless if there is no such field, since the value will always be 0.
        """

        # Split sub operands.
        ss = re.sub(
            r"(?<![\[\+])-0x", "+-0x", s
        )  # NOTE: [R0-0x100] is illegal! should be [R0+-0x100]
        ss = ss.strip("[]").split("+")

        operands = []
        for ts in ss:
            if len(ts) == 0:
                continue
            if ts.startswith("0x") or ts.startswith("-0x"):
                operands.append(self._parseIntIMM(ts))
            else:
                operand = self._parseIndexedToken(ts)
                operands.append(operand)

        return AddressOperand(operands)

    def _parseDescAddress(self, s):
        match = p_DescAddressType.match(s)
        if match is None:
            raise ValueError("Invalid desc address operand: %s" % s)

        reg = self._parseIndexedToken(match.group("URIndex"))
        address = match.group("Addr")
        if address:
            address = self._parseAddress(address)
        return DescOperand(reg, address, g=False)

    def parseOperand(self, op_full):
        op, modi = self.parseOperandAtom(op_full)
        result = None
        if p_IndexedPattern.match(op):
            result = self._parseIndexedToken(op)
        elif op[0] == "[":
            result = self._parseAddress(op)
        elif op.startswith("c["):
            result = self._parseConstMemory(op)
        elif op.startswith("cx["):
            return self._parseURConstMemory(op)
        elif op.startswith("a["):
            return self._parseAttribute(op)
        elif op.startswith("0x"):
            result = self._parseIntIMM(op)
        elif p_FIType.match(op_full):
            # float and friends
            return self._parseFloatIMM(op_full)
        elif op.startswith("desc") or op.startswith("gdesc"):
            return self._parseDescAddress(op)
        elif op.startswith("COMP_STATUS"):
            result = RegOperand("COMP_STATUS", 0)
        elif op.startswith("TEX_"):
            result = RegOperand("TEX", op[4:])
        elif op.startswith("SR_"):
            result = RegOperand("SR", op[3:])
        elif op == "Rpc":
            result = RegOperand("PC", None)
        elif op == "PR":
            result = RegOperand("P", "R")
        elif op.startswith("INVALID"):
            result = RegOperand("SR", op)
        elif op in ["1D", "2D", "3D", "4D"]:
            result = RegOperand("D", op[0])
        elif op.startswith("ARRAY_"):
            result = RegOperand("ARRAY_D", op[6:])
        else:
            # Weird special register?
            pass
        # NOTE: Not sure if I want to do this like this!!
        result.modifiers += modi
        return result

    def parseInstruction(self, instruction):
        if instruction[-1] == ";":
            instruction = instruction[:-1]

        if "?PM" in instruction:
            instruction = instruction[:-4]

        instruction = self._constTr(instruction)
        match = p_InsPattern.match(instruction)
        if not match:
            raise ValueError(f"Couldn't parse {instruction}")

        pred_string = match.group("Pred")
        op = match.group("Op")
        tokens = op.split(".")
        base_op = tokens[0]

        # FIXME: This won't handle the DEPBAR instruction.
        operands = match.group("Operands").strip().split(",")
        operands = [op for op in operands if len(op) != 0]

        operands = [self.parseOperand(operand.strip()) for operand in operands]
        # NOTE: Should we parse pred string?
        return Instruction(base_op, tokens[1:], pred_string, operands)


InstructionParser = _InstructionParser()

if __name__ == "__main__":
    failed = 0
    success = 0
    failed_inst = []
    with open("test2.txt") as file:
        for line in file:
            asm = line.split("---")[0].strip()
            print(asm)
            try:
                inst = InstructionParser.parseInstruction(asm[:-1])
                print(inst)
                success += 1
            except Exception as e:
                failed += 1
                failed_inst.append(asm)
        print("Failed", failed, "Success", success)
        print("Failed instructions", failed_inst)
