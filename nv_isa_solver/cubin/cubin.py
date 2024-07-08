# Taken from turingas by Yan Da (daadaada)

from .ELF import *
from struct import unpack, pack
from functools import reduce


class Cubin:
    def __init__(self, arch=70):
        self.header = Header()
        self.programs = []
        self.shstrtab = Section()
        self.strtab = Section()
        self.symtab = Section()

        self.sections = []

        # Symbol list?
        # (text, shared, constant0, constant3){n} {name}
        self.kern_syms = []
        self.name_syms = []

        self.sec_idx_dict = {}  # name : sec_idx
        self.sym_idx_dict = {}  # name : sym_idx
        self.sec_idx = 0
        self.sym_idx = 0
        # Add null section and null symbol at the begining
        _null_sec = Section()
        _null_sec.sh_type = 0  # NULL
        self.sections.append(_null_sec)
        self.sec_idx += 1

        self.kern_syms.append(Symbol())
        self.sym_idx += 1

        self.arch = arch
        self.Init(arch)

    def Init(self, arch):
        """
        Header information.
        Set flags/info for shstrtab/strtab/symtab.
        Init all programs.
        """
        # Update header information.
        self.header.phnum = 3
        self.header.flags |= (arch << 16) + arch

        # Setup sections.
        self.shstrtab.name = b".shstrtab"
        self.shstrtab.sh_type = 3  # SHT_STRTAB
        self.shstrtab.sh_align = 1
        self.sections.append(self.shstrtab)
        self.sec_idx_dict[b".shstrtab"] = self.sec_idx
        self.sec_idx += 1

        self.strtab.name = b".strtab"
        self.strtab.sh_type = 3
        self.strtab.sh_align = 1
        self.sections.append(self.strtab)
        self.sec_idx_dict[b".strtab"] = self.sec_idx
        self.sec_idx += 1

        self.symtab.name = b".symtab"
        self.symtab.sh_type = 2  # SHT_SYMTAB
        self.symtab.sh_entsize = Symbol.ENTRY_SIZE  # 24
        self.symtab.sh_link = 2  # TODO: Make sure it's strtab.
        self.sections.append(self.symtab)
        self.symtab.sh_align = 8
        self.sec_idx_dict[b".symtab"] = self.sec_idx
        self.sec_idx += 1

        # Init programs.
        self.p_hdr = Program(6, 5)  # (type, flags)
        self.p_hdr.filesz = 0xA8
        self.p_hdr.memsz = 0xA8
        self.p_progbits = Program(1, 5)
        self.p_nobits = Program(1, 6)
        self.programs.extend([self.p_hdr, self.p_progbits, self.p_nobits])

    def GenerateNvInfo(self, section, name):
        data = b""

        # FIXME (JO): There is apparently an EIATTR_REGCOUNT data entry in the .nv.info section.
        # It is missing here.

        # Entry size: 12. (bbhll) (BB, 2B, 4B, 4B)
        # EIATTR_MAX_STACK_SIZE (0x0423)
        kernel_symtab_idx = self.sym_idx_dict[name]  # TODO: Why?
        MAX_STACK_SIZE = 0
        data += pack("<bbhll", 0x4, 0x23, 0x8, kernel_symtab_idx, MAX_STACK_SIZE)

        # EIATTR_MIN_STACK_SIZE (0x0412)
        MIN_STACK_SIZE = 0
        data += pack("<bbhll", 0x4, 0x12, 0x8, kernel_symtab_idx, MIN_STACK_SIZE)

        # EIATTR_FRAME_SIZE (0x0411)
        FRAME_SIZE = 0
        data += pack("<bbhll", 0x4, 0x11, 0x8, kernel_symtab_idx, FRAME_SIZE)

        # Update section
        section.data = data

        # TODO: Update header information.
        section.name = b".nv.info"
        section.sh_size = len(data)
        section.sh_type = 0x70000000
        section.sh_link = self.sec_idx_dict[b".symtab"]
        section.sh_align = 4

    def GenerateNvInfoName(self, kernel, section, name, params):
        """
        params = {[nameof each param], [sizeof each param]}
        """
        data = b""
        size_params = reduce(lambda x, y: x + y, params["size_list"])
        # EIATTR_PARAM_CBANK (0x040a)
        kernel_symtab_idx = self.sym_idx_dict[name]
        data += pack("<bbhlhh", 0x4, 0x0A, 0x8, kernel_symtab_idx, 0x160, size_params)

        # EIATTR_CBANK_PARAM_SIZE (0x0319)
        data += pack("<bbH", 0x3, 0x19, size_params)

        # for each parameter:
        # EIATTR_KPARAM_INFO (0x0417); size: 0xc
        param_offset = size_params
        for ordinal, param in reversed(list(enumerate(params["size_list"]))):
            param_offset -= param
            param_flag = (
                ((param // 4) << 20) + 0x1F000 + 0x000
            )  # space (4bits) + logAlign (8bits); always 0
            data += pack(
                "<bbHIHHI", 0x04, 0x17, 0xC, 0x0, ordinal, param_offset, param_flag
            )  # Index: always 0 (4B)

        # EIATTR_MAXREG_COUNT (0x031b)
        data += pack("<bbH", 0x03, 0x1B, 0xFF)  # MAXREG_COUNT=0xff

        # EIATTR_EXIT_INSTR_OFFSETS (0x041c)
        size = len(kernel["ExitOffset"]) * 4
        data += pack("<bbH", 0x04, 0x1C, size)
        # Maybe more than one exit.
        for exit_offset in kernel["ExitOffset"]:
            data += pack("<I", exit_offset)

        section.data = data
        section.sh_size = len(data)
        section.name = b".nv.info." + name
        # TODO: Update flags
        section.sh_type = 0x70000000
        section.sh_link = self.sec_idx_dict[b".symtab"]
        section.sh_info = self.sec_idx_dict[b".text." + name]
        section.sh_align = 4

    def GenerateNvConst0(self, section, name, params):
        size = 0x160 + reduce(lambda x, y: x + y, params["size_list"])
        data = b"\x00" * size  # Init values for constant

        section.data = data
        section.sh_size = size
        section.name = b".nv.constant0." + name
        section.sh_flags = 2  # SHF_ALLOC
        section.sh_type = 1  # PROGBITS
        section.sh_info = self.sec_idx_dict[b".text." + name]
        section.sh_align = 4

    def GenerateNvConst3(self, section, consts):
        size = reduce(lambda x, y: x + y, consts["size_list"])
        data = b"\x00" * size  # Init values for constant

        section.data = data
        section.sh_size = size
        section.name = b".nv.constant3"
        section.sh_flags = 2  # SHF_ALLOC
        section.sh_type = 1  # PROGBITS
        section.sh_info = 0
        section.sh_align = 4

    def GenerateNvSmem(self, kernel, section, name, smem_size):
        data = b""  # Not sure why all kernels have this section.
        section.data = data
        section.sh_size = smem_size
        section.name = b".nv.shared." + name
        section.sh_flags = 3  # SHF_ALLOC
        section.sh_type = 8  # NOBITS
        section.sh_info = self.sec_idx_dict[b".text." + name]
        section.sh_align = 0x10

    def GenerateText(self, kernel, section, name):
        data = kernel["KernelData"]

        section.data = data

        # Other flags
        section.name = b".text." + name
        section.sh_type = 1  # PROGBITS
        section.sh_flags = 6 + (kernel["BarCnt"] << 20)
        section.sh_size = len(data)
        section.sh_link = self.sec_idx_dict[b".symtab"]
        section.sh_info = 4 + (kernel["RegCnt"] << 24)  # RegCnt
        section.sh_align = 128

    def CollectSyms(self, kernel, name, consts):
        text_sym_entry = Symbol()
        text_sym_entry.name = b".text." + name
        text_sym_entry.st_info = 3  # Bind local
        text_sym_entry.st_shndx = self.sec_idx_dict[b".text." + name]
        self.kern_syms.append(text_sym_entry)
        self.sym_idx_dict[b".text." + name] = self.sym_idx
        self.sym_idx += 1

        if kernel["SmemSize"] > 0:
            smem_sym_entry = Symbol()
            smem_sym_entry.name = b".nv.shared." + name
            smem_sym_entry.st_info = 3
            smem_sym_entry.st_shndx = self.sec_idx_dict[b".nv.shared." + name]
            self.kern_syms.append(smem_sym_entry)
            self.sym_idx_dict[b".nv.shared." + name] = self.sym_idx
            self.sym_idx += 1

        if len(consts["name_list"]) > 0:
            const_sym_entry = Symbol()
            const_sym_entry.name = b".nv.constant3"
            const_sym_entry.st_info = 3
            const_sym_entry.st_shndx = self.sec_idx_dict[b".nv.constant3"]
            self.kern_syms.append(const_sym_entry)
            self.sym_idx_dict[b".nv.constant3"] = self.sym_idx
            self.sym_idx += 1

        const_sym_entry = Symbol()
        const_sym_entry.name = b".nv.constant0." + name
        const_sym_entry.st_info = 3
        const_sym_entry.st_shndx = self.sec_idx_dict[b".nv.constant0." + name]
        self.kern_syms.append(const_sym_entry)
        self.sym_idx_dict[b".nv.constant0." + name] = self.sym_idx
        self.sym_idx += 1

        # Add name symbol
        # First user defined constant symbols
        # Next global (TODO)
        # Finally kernel name symbol
        offset = 0
        for i, c_name in enumerate(consts["name_list"]):
            name_sym_entry = Symbol()
            name_sym_entry.name = c_name.encode("ascii")
            name_sym_entry.st_info = 0x1  # STT_OBJECT, Local Binding
            name_sym_entry.st_other = 0
            name_sym_entry.st_size = consts["size_list"][i]
            name_sym_entry.st_shndx = self.sec_idx_dict[b".nv.constant3"]
            name_sym_entry.st_value = offset
            offset += name_sym_entry.st_size

            self.name_syms.append(name_sym_entry)
            self.sym_idx_dict[c_name] = self.sym_idx
            self.sym_idx += 1

        # Append the kernel name, which is a global symbol, at last
        name_sym_entry = Symbol()
        name_sym_entry.name = name
        name_sym_entry.st_info = 0x12  # FUNC
        name_sym_entry.st_other = 0x10
        name_sym_entry.st_size = len(kernel["KernelData"])
        name_sym_entry.st_shndx = self.sec_idx_dict[b".text." + name]
        self.name_syms.append(name_sym_entry)
        self.sym_idx_dict[name] = self.sym_idx
        self.sym_idx += 1

    def UpdateShstrtab(self):
        shstr = b""
        shstr_idx = 0
        for sec in self.sections:
            sec.sh_name = shstr_idx
            shstr += sec.name
            shstr += b"\x00"
            shstr_idx += len(sec.name) + 1
        self.shstrtab.data = shstr
        self.shstrtab.sh_size = shstr_idx

    def UpdateStrtab(self):
        strtab = b""
        strtab_idx = 0
        for sym in self.kern_syms:
            sym.st_name = strtab_idx
            strtab += sym.name
            strtab += b"\x00"
            strtab_idx += len(sym.name) + 1
        for sym in self.name_syms:
            sym.st_name = strtab_idx
            strtab += sym.name
            strtab += b"\x00"
            strtab_idx += len(sym.name) + 1
        self.strtab.data = strtab
        self.strtab.sh_size = strtab_idx

    def GenerateSymTab(self, name):
        ###############
        # Update symtab
        ###############
        for sym in self.kern_syms:
            self.symtab.data += sym.PackEntry()
        for sym in self.name_syms:
            self.symtab.data += sym.PackEntry()
        self.symtab.sh_size = len(self.symtab.data)
        self.symtab.sh_info = self.sym_idx_dict[name]

    def UpdateOffset(self):
        """
        1. sh_offset
        2. start of section headers
        3. start of program headers
        4. header idx of shstrtab
        """
        current_offset = 0
        current_offset += Header.HEADER_SIZE
        for i, sec in enumerate(self.sections):
            # The 1st section is a special null section
            if i == 0:
                sec.sh_offset = 0
                prev_sec = sec
                continue

            # Taking alignment into consideration
            misalign_bytes = current_offset & (sec.sh_align - 1)
            if misalign_bytes != 0:
                current_offset = (current_offset & ~(sec.sh_align - 1)) + sec.sh_align
                prev_sec.data += b"\x00" * (sec.sh_align - misalign_bytes)

            sec.sh_offset = current_offset
            if sec.sh_type != 8:
                current_offset += sec.sh_size

            prev_sec = sec

        self.header.shoff = current_offset
        self.header.shnum = len(self.sections)
        current_offset += Section.HEADER_SIZE * len(self.sections)
        self.header.phoff = current_offset
        self.header.phnum = len(self.programs)
        current_offset += Program.PHDR_SIZE * len(self.programs)

        self.header.shstrndx = self.sec_idx_dict[b".shstrtab"]

    # TODO: name of the kernel?
    def add_kernel(self, kernel, name, params, consts):
        # Only support *ONE* kernel per cubin file.
        """
        For each kernel:
          1. Create sections and update index
          2. Create symbols and update index
          3. Add .text.{name}
          4. Add .nv.shared.{name} (optional)
          5. Add entries in symbol table
          6. Add 3 entry to .nv.info.
        """
        #####################################
        # Add sections (record section index)
        #####################################
        _nv_info = Section()
        self.sections.append(_nv_info)
        self.sec_idx_dict[b".nv.info"] = self.sec_idx
        self.sec_idx += 1

        _nv_info_kernel = Section()
        self.sections.append(_nv_info_kernel)
        self.sec_idx_dict[b".nv.info." + name] = self.sec_idx
        self.sec_idx += 1

        # const3 is the user constant bank
        if len(consts["name_list"]) > 0:
            _nv_const3_kernel = Section()
            self.sections.append(_nv_const3_kernel)
            self.sec_idx_dict[b".nv.constant3"] = self.sec_idx
            self.sec_idx += 1

        # const0 is the kernel launch paramter bank
        _nv_const0_kernel = Section()
        self.sections.append(_nv_const0_kernel)
        self.sec_idx_dict[b".nv.constant0." + name] = self.sec_idx
        self.sec_idx += 1

        _text_kernel = Section()
        self.sections.append(_text_kernel)
        self.sec_idx_dict[b".text." + name] = self.sec_idx
        self.sec_idx += 1

        if kernel["SmemSize"] > 0:
            _nv_smem_kernel = Section()
            self.sections.append(_nv_smem_kernel)
            self.sec_idx_dict[b".nv.shared." + name] = self.sec_idx
            self.sec_idx += 1

        ###################
        # Add symbol entry.
        ###################
        self.CollectSyms(kernel, name, consts)

        ###############################
        # Generate section data (flags)
        ###############################
        # Add .nv.info
        self.GenerateNvInfo(_nv_info, name)
        # Add .nv.info.name
        self.GenerateNvInfoName(kernel, _nv_info_kernel, name, params)
        # Add .nv.constant3
        if len(consts["name_list"]) > 0:
            self.GenerateNvConst3(_nv_const3_kernel, consts)
        # Add .nv.constant0.name
        self.GenerateNvConst0(_nv_const0_kernel, name, params)
        # Add .text.name
        self.GenerateText(kernel, _text_kernel, name)
        # Add .nv.shared.name
        if kernel["SmemSize"] > 0:
            self.GenerateNvSmem(kernel, _nv_smem_kernel, name, kernel["SmemSize"])

        ########################
        # Update shstrtab/strtab
        ########################
        self.UpdateShstrtab()
        self.UpdateStrtab()

        ########################
        # Generate Symtab
        # Can only happens after strtab is generated
        ########################
        self.GenerateSymTab(name)

        #######################
        # Update offset
        #######################
        self.UpdateOffset()
        # Update program offset
        self.p_hdr.offset = self.header.phoff
        if len(consts["name_list"]) > 0:
            self.p_progbits.offset = self.sections[
                self.sec_idx_dict[b".nv.constant3"]
            ].sh_offset
            self.p_progbits.filesz = (
                self.sections[self.sec_idx_dict[b".nv.constant3"]].sh_size
                + self.sections[self.sec_idx_dict[b".nv.constant0." + name]].sh_size
            )
        else:
            self.p_progbits.offset = self.sections[
                self.sec_idx_dict[b".nv.constant0." + name]
            ].sh_offset
            self.p_progbits.filesz = self.sections[
                self.sec_idx_dict[b".nv.constant0." + name]
            ].sh_size

        self.p_progbits.memsz = self.p_progbits.filesz

    def to_binary(self):
        """
        Write data to binary stream
        """
        res = b""
        res += self.header.PackHeader()
        for sec in self.sections:
            res += sec.data
        for sec in self.sections:
            res += sec.PackHeader()
        for pro in self.programs:
            res += pro.PackHeader()
        return res

    def Write(self, path):
        """
        Write data to file.
        Order:
           1. Header.
           2. shstrtab, strtab, symtab, .nv.info.
           3. info_secs, const_secs, text_secs, smem_secs
           4. shdrs.
           5. phdrs.
        """
        with open(path, "wb") as file:
            file.write(self.header.PackHeader())
            for sec in self.sections:
                file.write(sec.data)
            for sec in self.sections:
                file.write(sec.PackHeader())
            for pro in self.programs:
                file.write(pro.PackHeader())
