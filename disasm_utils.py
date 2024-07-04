import subprocess
import tempfile
import tqdm
from parser import InstructionParser
import os
import multiprocessing


def _process_dump(dump):
    lines = dump.split("\n")[1:]
    result = []
    for line in lines:
        result.append(line[line.find("*/") + 2 :].strip())
    return "\n".join(result).strip()


class Disassembler:
    def __init__(self, arch, nvdisasm="nvdisasm", batch_size=None):
        self.cache = {}
        self.arch = arch
        self.nvdisasm = nvdisasm
        if batch_size is None:
            batch_size = multiprocessing.cpu_count()
        self.batch_size = batch_size

    def load_cache(self, filename):
        try:
            with open(filename) as file:
                for line in file:
                    asm, inst = line.split("---")
                    self.cache[bytes.fromhex(inst.strip())] = asm.strip()
        except FileNotFoundError:
            print("Cache could not be loaded")
            pass

    def dump_cache(self, filename):
        with open(filename, "w") as file:
            for inst, disasm in self.cache.items():
                file.write(disasm + " --- " + inst.hex() + "\n")

    # Find unuiqe instruction signatures from the cache.
    def find_uniques_from_cache(self):
        keys = {}
        for inst, disasm in self.cache.items():
            if len(disasm) == 0:
                continue
            try:
                key = InstructionParser.parseInstruction(disasm[:-1]).get_key()
            except Exception:
                print("Couldn't parse", disasm)
                continue

            # Some instructions can have modifiers that affect behaviour in the opcode!
            opcode = get_bit_range2(inst, 0, 12)
            key = f"{opcode}.{key}"
            if key in keys:
                continue
            keys[key] = inst
        return keys

    def disassemble(self, inst):
        inst = bytes(inst)
        if inst in self.cache:
            return self.cache[inst]

        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(inst)
        tmp.close()
        result = subprocess.run(
            [self.nvdisasm, tmp.name, "--binary", self.arch], capture_output=True
        )
        os.remove(tmp.name)
        result = _process_dump(result.stdout.decode("ascii"))
        self.cache[inst] = result
        return result

    def disassemble_parallel(self, array, disable_cache=False):
        if not disable_cache:
            result = [None] * len(array)
            idxes = []
            new_array = []
            for i, inst in enumerate(array):
                inst = bytes(inst)
                if inst in self.cache:
                    result[i] = self.cache[inst]
                    continue
                idxes.append(i)
                new_array.append(inst)
            uncached_results = self.disassemble_parallel(new_array, disable_cache=True)
            # print("Uncached", len(uncached_results), "out of", len(array))
            for i, asm in zip(idxes, uncached_results):
                result[i] = asm
            return result

        if len(array) > self.batch_size:
            result = []
            for i in tqdm.tqdm(range(0, len(array), self.batch_size)):
                result += self.disassemble_parallel(
                    array[i : i + self.batch_size], disable_cache=True
                )
            assert len(result) == len(array)
            return result

        processes = []
        tmp_files = []
        for i, inst in enumerate(array):
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp_files.append(tmp)
            tmp.write(inst)
            name = tmp.name
            tmp.close()

            process = subprocess.Popen(
                [self.nvdisasm, name, "--binary", self.arch],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            processes.append(process)

        results = []
        for process in processes:
            results.append(_process_dump(process.stdout.read().decode("ascii")))

        for tmp in tmp_files:
            os.remove(tmp.name)

        # Cache the instructions!
        for inst, disasm in zip(array, results):
            self.cache[bytes(inst)] = disasm

        return results

    def distill_instruction(self, inst):
        original_asm = self.disassemble(inst)
        original_parsed = InstructionParser.parseInstruction(original_asm)

        # Make bits 0 until the instruction don't decode the same anymore.
        distilled = bytes(inst)
        for i in range(127, -1, -1):
            inst_ = bytearray(bytes(distilled))
            if (inst_[i // 8] >> (i % 8)) & 1 == 0:
                continue

            inst_[i // 8] = inst_[i // 8] & ~(1 << (i % 8))
            distill_asm = self.disassemble(inst_)
            if len(distill_asm) == 0:
                continue

            try:
                distill_parsed = InstructionParser.parseInstruction(distill_asm)
            except Exception:
                continue
            if original_parsed.get_key() != distill_parsed.get_key():
                continue

            distilled = bytes(inst_)
        return distilled

    def mutate_inst(self, inst, start=0, end=16 * 8):
        idxes = []
        insts = []
        for i in range(start, end):
            inst_ = bytearray(bytes(inst))
            inst_[i // 8] = inst_[i // 8] ^ (1 << (i % 8))
            insts.append(inst_)
            idxes.append(i)
        return zip(idxes, insts, self.disassemble_parallel(insts))

    def inst_disasm_range(self, base, bit_start, bit_end):
        """
        Brute force a bit range.
        """
        instructions = []
        for i in range(pow(2, bit_end - bit_start + 1)):
            inst_bytes = bytearray(bytes(base))
            set_bit_range2(inst_bytes, bit_start, bit_end, i)
            instructions.append(inst_bytes)
        return zip(instructions, self.disassemble_parallel(instructions))


def set_bit_range(byte_array, start_bit, end_bit, value):
    length = end_bit - start_bit - 1
    for i in range(start_bit, end_bit):
        mask = 1 << (7 - (i % 8))
        if value & (1 << (length - i + start_bit)):
            byte_array[i // 8] |= mask
        else:
            byte_array[i // 8] &= ~mask


def set_bit_range2(byte_array, start_bit, end_bit, value):
    for i in range(start_bit, end_bit):
        mask = 1 << (i % 8)
        if value & (1 << (i - start_bit)):
            byte_array[i // 8] |= mask
        else:
            byte_array[i // 8] &= ~mask


def get_bit_range2(byte_array, start_bit, end_bit):
    result = 0
    for i in range(start_bit, end_bit):
        mask = 1 << (i % 8)
        v = (byte_array[i // 8] >> (i % 8)) & 1
        result |= v << (i - start_bit)
    return result


def dump_bitrange(inst):
    for i in range(8 * 8):
        if i % 8 == 0:
            print(" ", end="")
        print(7 - i % 8, end="")
    print("")
    for i in range(8 * 16):
        if i % 8 == 0:
            print("", end=" ")
        bit_index = 7 - i % 8
        byte_index = i // 8
        print((inst[byte_index] >> bit_index) & 1, end="")
        if i == 64 - 1:
            print("")
    print("\n")


def dump_bits(inst):
    for i in range(8 * 16):
        bit_index = 7 - i % 8
        byte_index = i // 8
        print((inst[byte_index] & (1 << (bit_index))) >> bit_index, end="")
        if i == 64 - 1:
            print("")
    print("\n")


def read_corpus(filename):
    file = open(filename, "r")
    entries = []
    for line in file:
        entries.append(bytes.fromhex(line.split("---")[1].strip()))
    file.close()
    return entries
