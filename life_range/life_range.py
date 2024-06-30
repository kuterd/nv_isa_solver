import subprocess
import cubin

DISASM = "nvdisasm"


def _process_range_output(output):
    # This code is very messy :(
    lines = output.split("\n")
    start_index = next(
        (i for i, line in enumerate(lines) if ".text.test" in line), None
    )
    lines = lines[start_index + 1 :]
    index = next((i for i, line in enumerate(lines) if "//" in line), None)
    reg_files = [e.strip() for e in lines[index + 1].split("|")[1:-1]]
    parts = lines[index + 2].strip()[2:].strip().split("|")[1:-1]
    parts = [[num for num in part.strip().split(" ")[1:]] for part in parts]
    col_lengths = [[len(num) for num in part] for part in parts]
    parts = [[int(num) for num in part] for part in parts]
    asm_start_index = next(
        (i for i, line in enumerate(lines) if ".text.test:" in line), None
    )
    lines = lines[asm_start_index + 1 :]
    line = lines[0]
    reg_interaction_data = [
        part[1:-1] for part in line[line.find("//") + 2 :].strip().split("|")[1:-1]
    ]
    reg_interaction_data[0] = reg_interaction_data[0][1:]
    reg_interactions = []
    for part, col_sizes in zip(reg_interaction_data, col_lengths):
        current = []
        reg_interactions.append(current)
        offset = 2
        for length in col_sizes:
            p = part[offset + length - 1]
            current.append(p)
            offset += length + 1
    reg_interactions = [
        [(reg, rintr) for reg, rintr in zip(regs, intr) if rintr != " "]
        for regs, intr in zip(parts, reg_interactions)
    ]
    reg_interactions = {
        file: interactions for file, interactions in zip(reg_files, reg_interactions)
    }
    asm_end_index = next((i for i, line in enumerate(lines) if "//" not in line), None)
    lines = lines[: asm_end_index - 1]

    chars = {":": "USED", "^": "W", "v": "R", "x": "RW"}

    reg_interactions = {
        file: [(reg, chars[i]) for reg, i in interaction]
        for file, interaction in reg_interactions.items()
    }
    return reg_interactions


def get_live_ranges(file_name):
    result = subprocess.run(
        [DISASM, file_name, "--print-life-ranges"], capture_output=True
    ).stdout.decode("ascii")
    return _process_range_output(result)


def analyse_inst(inst):
    bin = cubin.Cubin(arch=90)
    const_dict = {"name_list": [], "size_list": []}

    EXIT = bytes.fromhex("4d790000000000000000800300ea0f00")
    kernel = {
        "KernelData": inst + EXIT + b"\0" * 16 * 8,
        "ExitOffset": [],
        "BarCnt": 10,
        "RegCnt": 255,
        "SmemSize": 0,
    }
    bin.add_kernel(kernel, b"test", {"name_list": [], "size_list": [0]}, const_dict)
    bin.Write("test.cubin")

    result = get_live_ranges("test.cubin")
    return result
