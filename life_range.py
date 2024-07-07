import subprocess
from enum import Enum
import os
import tempfile
import sys

sys.path.append("cubin")
import cubin


class InteractionType(str, Enum):
    READ = "R"
    WRITE = "W"
    READWRITE = "RW"


def _process_range_output(output):
    # This code is very messy :(
    lines = output.split("\n")

    # Find function start postition in the output.
    start_index = next(
        (i for i, line in enumerate(lines) if ".text.test" in line), None
    )
    if start_index is None:
        return None

    lines = lines[start_index + 1 :]

    # Find table start
    index = next((i for i, line in enumerate(lines) if "//" in line), None)
    # Parse different register files that are used.
    reg_files = [e.strip() for e in lines[index + 1].split("|")[1:-1]]

    # Find register numbers in the header
    parts = lines[index + 2].strip()[2:].strip().split("|")[1:-1]
    parts = [[num for num in part.strip().split(" ")[1:]] for part in parts]

    # Parse table column lengths (dependent on the register number digit count)
    col_lengths = [[len(num) for num in part] for part in parts]
    parts = [[int(num) for num in part] for part in parts]
    asm_start_index = next(
        (i for i, line in enumerate(lines) if ".text.test:" in line), None
    )

    # Find register interactions
    lines = lines[asm_start_index + 1 :]
    line = lines[0]
    reg_interaction_data = [
        part[1:-1] for part in line[line.find("//") + 2 :].strip().split("|")[1:-1]
    ]
    reg_interactions = []
    for part, col_sizes in zip(reg_interaction_data, col_lengths):
        part = part.strip()
        part = part[part.find(" ") :]
        current = []
        reg_interactions.append(current)
        offset = 3
        for length in col_sizes[1:]:
            offset += length - 1
            if offset >= len(part):
                p = " "
            else:
                p = part[offset]
            offset += 2
            current.append(p)
    reg_interactions = [
        [(reg, rintr) for reg, rintr in zip(regs[1:], intr) if rintr != " "]
        for regs, intr in zip(parts, reg_interactions)
    ]
    reg_interactions = {
        file: interactions for file, interactions in zip(reg_files, reg_interactions)
    }
    asm_end_index = next((i for i, line in enumerate(lines) if "//" not in line), None)
    lines = lines[: asm_end_index - 1]

    chars = {
        ":": "USED",
        "^": InteractionType.WRITE,
        "v": InteractionType.READ,
        "x": InteractionType.READWRITE,
    }
    try:
        reg_interactions = {
            file: [(reg, chars[i]) for reg, i in interaction]
            for file, interaction in reg_interactions.items()
        }
    except Exception as e:
        print(output)
        print(e)
    return reg_interactions


def get_interaction_ranges(reg_interactions):
    if not reg_interactions:
        return None
    result = {}
    for file, interactions in reg_interactions.items():
        current = None
        length = 0
        intr_type = None
        result[file] = []

        def push():
            if current is not None:
                result[file].append((current, intr_type, length))

        for intr in interactions:
            if (
                current is not None
                and current + length == intr[0]
                and intr_type == intr[1]
            ):
                length += 1
            else:
                push()
                current = intr[0]
                intr_type = intr[1]
                length = 1
        push()
    return result


def get_live_ranges(filename, nvdisasm="nvdisasm"):
    result = subprocess.run(
        [nvdisasm, filename, "--print-life-ranges"], capture_output=True
    ).stdout.decode("ascii")
    return _process_range_output(result), result


def analyse_live_ranges(inst, archCode=90):
    bin = cubin.Cubin(arch=archCode)
    const_dict = {"name_list": [], "size_list": []}

    EXIT = bytes.fromhex("4d790000000000000000800300ea0f00")
    kernel = {
        "KernelData": inst + EXIT + b"\0" * 16 * 8,
        "ExitOffset": [],
        "BarCnt": 10,
        "RegCnt": 255,
        "SmemSize": 0,
    }
    # TODO: This is a bit ugly, clean this up.
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()

    bin.add_kernel(kernel, b"test", {"name_list": [], "size_list": [0]}, const_dict)

    bin.Write(tmp.name)

    result = get_live_ranges(tmp.name)
    os.remove(tmp.name)
    return result
