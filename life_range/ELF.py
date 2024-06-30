# Taken from turingas by Yan Da (daadaada)

from struct import unpack, pack


class Section:
    HEADER_SIZE = 64

    def __init__(self):
        self.sh_name = 0
        self.sh_type = 0
        self.sh_flags = 0
        self.sh_addr = 0
        self.sh_offset = 0
        self.sh_size = 0
        self.sh_link = 0
        self.sh_info = 0
        self.sh_align = 0
        self.sh_entsize = 0
        self.name = b""
        self.data = b""

    def unpack_binary(self, data):
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_align,
            sh_entsize,
        ) = unpack("iiQQQQiiQQ", data)
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_align = sh_align
        self.sh_entsize = sh_entsize
        self.name = ""
        self.data = None

    def PackHeader(self):  # pack header
        return pack(
            "<IIQQQQIIQQ",
            self.sh_name,
            self.sh_type,
            self.sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_align,
            self.sh_entsize,
        )


class Program:
    PHDR_SIZE = 56

    def __init__(self, type_, flags):
        self.type = type_  # 1 - LOAD; 6 - PHDR
        self.flags = flags  # 0x4 - R; 0x2 - W; 0x1 - X;
        self.offset = 0  # To be updated latter
        self.vaddr = 0  # Always zero
        self.paddr = 0  # Always zero
        self.filesz = 0
        self.memsz = 0  # shared = 0
        self.align = 8  # Other value?

    def unpack_binary(self, data):
        # iiQQQQQQ
        (
            self.type,
            self.flags,
            self.offset,
            self.vaddr,
            self.paddr,
            self.filesz,
            self.memsz,
            self.align,
        ) = unpack("iiQQQQQQ", data)

    def PackHeader(self):
        return pack(
            "<IIQQQQQQ",
            self.type,
            self.flags,
            self.offset,
            self.vaddr,
            self.paddr,
            self.filesz,
            self.memsz,
            self.align,
        )


class Header:
    HEADER_SIZE = 64

    def __init__(self):
        self.ident = None
        self.type = 2  # EXEC
        self.machine = 190  # CUDA
        self.version = 101  # CUDA version
        self.entry = 0  # Always 0 for cubin
        self.phoff = 0
        self.shoff = 0
        self.flags = 0x0500
        self.ehsize = 64  # size of header
        self.phentsize = 56
        self.phnum = 0
        self.shentsize = 64
        self.shnum = 0
        self.shstrndx = 0

    def unpack_binary(self, data):
        self.ident = unpack("16B", data[:16])
        ei_mag0, ei_mag1, ei_mag2, ei_mag3, ei_class, ei_data, ei_version, ei_pad = (
            self.ident[:8]
        )
        if (
            ei_mag0 != 127
            or ei_mag1 != ord("E")
            or ei_mag2 != ord("L")
            or ei_mag3 != ord("F")
        ):
            raise Exception("Not an ELF file.\n")
        if ei_class != 2:
            raise Exception("Not a 64-bit ELF file\n")

        self.type, self.machine, self.version = unpack("hhi", data[16:24])
        self.entry, self.phoff, self.shoff, self.flags = unpack("qqqi", data[24:52])
        self.ehsize, self.phentsize, self.phnum = unpack("hhh", data[52:58])
        self.shentsize, self.shnum, self.shstrndx = unpack("hhh", data[58:64])
        arch = self.flags & 0xFF
        address_size = 64 if self.flags & 0x400 else 32

    def PackHeader(self):
        # ELF 64-bit, little endian, version01, ABI33, ABI version7, zero padding
        self.ident = (
            b"\x7fELF" + b"\x02" + b"\x01" + b"\x01" + b"\x33" + b"\7" + b"\0" * 7
        )
        return pack(
            "<16sHHIQQQIHHHHHH",
            self.ident,
            self.type,
            self.machine,
            self.version,
            self.entry,
            self.phoff,
            self.shoff,
            self.flags,
            self.ehsize,
            self.phentsize,
            self.phnum,
            self.shentsize,
            self.shnum,
            self.shstrndx,
        )


class Symbol:
    ENTRY_SIZE = 24

    def __init__(self):
        self.name = b""
        # iBBhqq 411288 = 24
        self.st_name = 0
        self.st_info = 0
        self.st_other = 0
        self.st_shndx = 0
        self.st_value = 0
        self.st_size = 0

    def unpack_binary(self, data):
        (
            self.st_name,
            self.st_info,
            self.st_other,
            self.st_shndx,
            self.st_value,
            self.st_size,
        ) = unpack("IBBHQQ", data)

    def PackEntry(self):
        return pack(
            "<IBBHQQ",
            self.st_name,
            self.st_info,
            self.st_other,
            self.st_shndx,
            self.st_value,
            self.st_size,
        )
