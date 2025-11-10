---
title: "Building a Minimal Viable Armv7 Emulator"
date: 2025-11-06
summary: "Emulating armv7 is surprisingly easy, even from scratch AND in Rust"
draft: true
tags:
  - arm
  - rust
---

After reading about the process the Linux kernel performs to execute binaries,
I thought: I want to write an armv7 emulator - [`stinkarm`](https://github.com/xnacly/stinkarm). Mostly to understand the ELF
format, the encoding of arm 32bit instructions, the execution of arm assembly
and how it all fits together (this will help me with the JIT for my programming
language I am currently designing). To fully understand everything: no
dependencies. And of course Rust, since I already have enough C projects going
on.

So I wrote the smallest binary I could think of:

```armasm
    .global _start  @ declare _start as a global
_start:             @ start is the defacto entry point
    mov r0, #161    @ first and only argument to the exit syscall
    mov r7, #1      @ syscall number 1 (exit)
    svc #0          @ trapping into the kernel (thats US, since we are translating)
```

To execute this arm assembly on my x86 system, I need to:

1. Parse the ELF, validate it is armv7 and statically executable (I don't want
   to write a dynamic dependency resolver and loader)
2. Map the segments defined in ELF into the host memory, forward memory access
3. Decode armv7 instructions and convert them into a nice Rust enum
4. Emulate the CPU, its state and registers
5. Execute the instructions and apply their effects to the CPU state
6. Translate and forward syscalls

Sounds easy? It is!

# Minimalist arm setup and smallest possible arm binary

Before I start parsing ELF I'll need a binary to emulate, so lets create a
makefile and nix flake, so the asm is converted into armv7 machine code in a
armv7 binary on my non armv7 system :^)

```makefile
all: examples/asm.elf

examples/asm.elf: examples/main.S
	arm-none-eabi-as -march=armv7-a $< -o main.o
	arm-none-eabi-ld -Ttext=0x8000 main.o -o $@
	rm main.o

clean:
	rm -f examples/asm.elf
```

```nix
{
  description = "stinkarm — ARMv7 userspace binary emulator for x86 linux systems";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            gcc-arm-embedded
            binutils
            qemu
          ];
        };
      });
}
```

# Parsing ELF

So there are some resources for parsing ELF, two of them I used a whole lot:

1. [`man elf`](https://linux.die.net/man/5/elf) _(remember to `export MANPAGER='nvim +Man!'`)_
2. [gabi.xinuos.com](https://gabi.xinuos.com/index.html)

At a high level, ELF (32bit, for armv7) consists of headers and segments, it
holds an Elf header, multiple program headers and the rest I don't care about,
since this emulator is only for static binaries, no dynamically linked support.

## Elf32_Ehdr

The ELF header is exactly 52 bytes long and holds all data I need to find the
program headers and whether I even want to emulate the binary I'm currently
parsing. These criteria are defined as members of the `Identifier` at the beg
of the header.

In terms of byte layout:

| bytes  | structure  |
| ------ | ---------- |
| 0..16  | Identifier |
| 16..18 | Type       |
| 18..20 | Machine    |
| 20..24 | version    |
| 24..28 | entry      |
| 28..32 | phoff      |
| 32..36 | shoff      |
| 36..40 | flags      |
| 40..42 | ehsize     |
| 42..44 | phentsize  |
| 44..46 | phnum      |
| 46..48 | shentsize  |
| 48..50 | shnum      |
| 50..52 | shstrndx   |

```shell
$ xxd -g1 -l52 examples/asm.elf
00000000: 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010: 02 00 28 00 01 00 00 00 00 80 00 00 34 00 00 00  ..(.........4...
00000020: dc 11 00 00 00 02 00 05 34 00 20 00 01 00 28 00  ........4. ...(.
00000030: 08 00 07 00                                      ....
```

```rust
/// Representing the ELF Object File Format header in memory, equivalent to Elf32_Ehdr in 2. ELF
/// header in https://gabi.xinuos.com/elf/02-eheader.html
///
/// Types are taken from https://gabi.xinuos.com/elf/01-intro.html#data-representation Table 1.1
/// 32-Bit Data Types:
///
/// | Elf32_ | Rust |
/// | ------ | ---- |
/// | Addr   | u32  |
/// | Off    | u32  |
/// | Half   | u16  |
/// | Word   | u32  |
/// | Sword  | i32  |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// initial bytes mark the file as an object file and provide machine-independent data with
    /// which to decode and interpret the file’s contents
    pub ident: Identifier,
    pub r#type: Type,
    pub machine: Machine,
    /// identifies the object file version, always EV_CURRENT (1)
    pub version: u32,
    /// the virtual address to which the system first transfers control, thus starting
    /// the process. If the file has no associated entry point, this member holds zero
    pub entry: u32,
    /// the program header table’s file offset in bytes. If the file has no program header table,
    /// this member holds zero
    pub phoff: u32,
    /// the section header table’s file offset in bytes. If the file has no section header table, this
    /// member holds zero
    pub shoff: u32,
    /// processor-specific flags associated with the file
    pub flags: u32,
    /// the ELF header’s size in bytes
    pub ehsize: u16,
    /// the size in bytes of one entry in the file’s program header table; all entries are the same
    /// size
    pub phentsize: u16,
    /// the number of entries in the program header table. Thus the product of e_phentsize and e_phnum
    /// gives the table’s size in bytes. If a file has no program header table, e_phnum holds the value
    /// zero
    pub phnum: u16,
    /// section header’s size in bytes. A section header is one entry in the section header table; all
    /// entries are the same size
    pub shentsize: u16,
    /// number of entries in the section header table. Thus the product of e_shentsize and e_shnum
    /// gives the section header table’s size in bytes. If a file has no section header table,
    /// e_shnum holds the value zero.
    pub shnum: u16,
    /// the section header table index of the entry associated with the section name string table.
    /// If the file has no section name string table, this member holds the value SHN_UNDEF
    pub shstrndx: u16,
}
```

The identifier is 16 bytes long and holds the previously mentioned info so I
can check if I want to emulate the binary, for instance the endianness and the
bit class, in the `TryFrom` implementation I strictly check what is parsed:

```rust
/// 2.2 ELF Identification: https://gabi.xinuos.com/elf/02-eheader.html#elf-identification
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identifier {
    /// 0x7F, 'E', 'L', 'F'
    pub magic: [u8; 4],
    /// file class or capacity
    ///
    /// | Name          | Value | Meaning       |
    /// | ------------- | ----- | ------------- |
    /// | ELFCLASSNONE  | 0     | Invalid class |
    /// | ELFCLASS32    | 1     | 32-bit        |
    /// | ELFCLASS64    | 2     | 64-bit        |
    pub class: u8,
    /// data encoding, endian
    ///
    /// | Name         | Value |
    /// | ------------ | ----- |
    /// | ELFDATANONE  | 0     |
    /// | ELFDATA2LSB  | 1     |
    /// | ELFDATA2MSB  | 2     |
    pub data: u8,
    /// file version, always EV_CURRENT (1)
    pub version: u8,
    /// operating system identification
    ///
    /// - if no extensions are used: 0
    /// - meaning depends on e_machine
    pub os_abi: u8,
    /// value depends on os_abi
    pub abi_version: u8,
    // padding bytes (9-15)
    _pad: [u8; 7],
}

impl TryFrom<&[u8]> for Identifier {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 16 {
            return Err("e_ident too short for ELF");
        }

        // I don't want to cast via unsafe as_ptr and as Header because the header could outlive the
        // source slice, thus we just do it the old plain indexing way
        let ident = Self {
            magic: bytes[0..4].try_into().unwrap(),
            class: bytes[4],
            data: bytes[5],
            version: bytes[6],
            os_abi: bytes[7],
            abi_version: bytes[8],
            _pad: bytes[9..16].try_into().unwrap(),
        };

        if ident.magic != [0x7f, b'E', b'L', b'F'] {
            return Err("Unexpected EI_MAG0 to EI_MAG3, wanted 0x7f E L F");
        }

        const ELFCLASS32: u8 = 1;
        const ELFDATA2LSB: u8 = 1;
        const EV_CURRENT: u8 = 1;

        if ident.version != EV_CURRENT {
            return Err("Unsupported EI_VERSION value");
        }

        if ident.class != ELFCLASS32 {
            return Err("Unexpected EI_CLASS: ELFCLASS64, wanted ELFCLASS32 (ARMv7)");
        }

        if ident.data != ELFDATA2LSB {
            return Err("Unexpected EI_DATA: big-endian, wanted little");
        }

        Ok(ident)
    }
```

`Type` and `Machine` are just enums encoding meaning in the Rust type system:

```rust
/// This member identifies the object file type.
///
/// https://gabi.xinuos.com/elf/02-eheader.html#contents-of-the-elf-header
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    None = 0,
    Relocatable = 1,
    Executable = 2,
    SharedObject = 3,
    Core = 4,
    LoOs = 0xfe00,
    HiOs = 0xfeff,
    LoProc = 0xff00,
    HiProc = 0xffff,
}

impl TryFrom<u16> for Type {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Type::None),
            1 => Ok(Type::Relocatable),
            2 => Ok(Type::Executable),
            3 => Ok(Type::SharedObject),
            4 => Ok(Type::Core),
            0xfe00 => Ok(Type::LoOs),
            0xfeff => Ok(Type::HiOs),
            0xff00 => Ok(Type::LoProc),
            0xffff => Ok(Type::HiProc),
            _ => Err("Invalid u16 value for e_type"),
        }
    }
}


#[repr(u16)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// This member’s value specifies the required architecture for an individual file.
/// https://gabi.xinuos.com/elf/02-eheader.html#contents-of-the-elf-header and https://gabi.xinuos.com/elf/a-emachine.html
pub enum Machine {
    EM_ARM = 40,
}

impl TryFrom<u16> for Machine {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            40 => Ok(Machine::EM_ARM),
            _ => Err("Unsupported machine"),
        }
    }
}
```

Since all of `Header`'s members implement `TryFrom` we can implement
`TryFrom<&[u8]> for Header` and propagate all occurring errors in member parsing
cleanly via `?`:

```rust
impl TryFrom<&[u8]> for Header {
    type Error = &'static str;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        if b.len() < 52 {
            return Err("not enough bytes for Elf32_Ehdr (ELF header)");
        }

        let header = Self {
            ident: b[0..16].try_into()?,
            r#type: le16!(b[16..18]).try_into()?,
            machine: le16!(b[18..20]).try_into()?,
            version: le32!(b[20..24]),
            entry: le32!(b[24..28]),
            phoff: le32!(b[28..32]),
            shoff: le32!(b[32..36]),
            flags: le32!(b[36..40]),
            ehsize: le16!(b[40..42]),
            phentsize: le16!(b[42..44]),
            phnum: le16!(b[44..46]),
            shentsize: le16!(b[46..48]),
            shnum: le16!(b[48..50]),
            shstrndx: le16!(b[50..52]),
        };

        match header.r#type {
            Type::Executable => (),
            _ => {
                return Err("Unsupported ELF type, only ET_EXEC (static executables) is supported");
            }
        }

        Ok(header)
    }
}
```

The attentive reader will see me using `le16!` and `le32!` for parsing bytes
into unsigned integers of different classes:

```rust
#[macro_export]
macro_rules! le16 {
    ($bytes:expr) => {{
        let b: [u8; 2] = $bytes
            .try_into()
            .map_err(|_| "Failed to create u16 from 2*u8")?;
        u16::from_le_bytes(b)
    }};
}

#[macro_export]
macro_rules! le32 {
    ($bytes:expr) => {{
        let b: [u8; 4] = $bytes
            .try_into()
            .map_err(|_| "Failed to create u32 from 4*u8")?;
        u32::from_le_bytes(b)
    }};
}
```

## Elf32_Phdr

For me, the most important fields in `Header` are `phoff` and `phentsize`,
since we can use these to index into the binary to locate the program headers.

```rust
/// Phdr, equivalent to Elf32_Phdr, see: https://gabi.xinuos.com/elf/07-pheader.html
///
/// All of its member are u32, be it Elf32_Word, Elf32_Off or Elf32_Addr
#[derive(Debug)]
pub struct Pheader {
    pub r#type: Type,
    /// offset to the segment, starting from file idx
    pub offset: u32,
    /// virtual address where the first byte of the segment lays
    pub vaddr: u32,
    /// On systems for which physical addressing is relevant, this member is reserved for the
    /// segment’s physical address. Because System V ignores physical addressing for application
    /// programs, this member has unspecified contents for executable files and shared objects.
    pub paddr: u32,
    /// This member gives the number of bytes in the file image of the segment; it may be zero.
    pub filesz: u32,
    /// This member gives the number of bytes in the memory image of the segment; it may be zero.
    pub memsz: u32,
    pub flags: Flags,
    /// Loadable process segments must have congruent values for p_vaddr and p_offset, modulo the page
    /// size. This member gives the value to which the segments are aligned in memory and in the
    /// file. Values 0 and 1 mean no alignment is required. Otherwise, p_align should be a
    /// positive, integral power of 2, and p_vaddr should equal p_offset, modulo p_align.
    pub align: u32,
}

impl Pheader {
    /// extracts Pheader from raw, starting from offset
    pub fn from(raw: &[u8], offset: usize) -> Result<Self, String> {
        let end = offset.checked_add(32).ok_or("Offset overflow")?;
        if raw.len() < end {
            return Err("Not enough bytes to parse Elf32_Phdr, need at least 32".into());
        }

        let p_raw = &raw[offset..end];
        let r#type = p_raw[0..4].try_into()?;
        let flags = p_raw[24..28].try_into()?;
        let align = le32!(p_raw[28..32]);

        if align > 1 && !align.is_power_of_two() {
            return Err(format!("Invalid p_align: {}", align));
        }

        Ok(Self {
            r#type,
            offset: le32!(p_raw[4..8]),
            vaddr: le32!(p_raw[8..12]),
            paddr: le32!(p_raw[12..16]),
            filesz: le32!(p_raw[16..20]),
            memsz: le32!(p_raw[20..24]),
            flags,
            align,
        })
    }
}
```

`Type` holds info about what type of segment the header defines:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum Type {
    /// The array element is unused; other members’ values are undefined. This type lets the
    /// program header table have ignored entries.
    NULL = 0,
    /// The array element specifies a loadable segment, described by p_filesz and p_memsz. The
    /// bytes from the file are mapped to the beginning of the memory segment. If the segment’s
    /// memory size (p_memsz) is larger than the file size (p_filesz), the “extra” bytes are
    /// defined to hold the value 0 and to follow the segment’s initialized area. The file size may
    /// not be larger than the memory size. Loadable segment entries in the program header table
    /// appear in ascending order, sorted on the p_vaddr member.
    LOAD = 1,
    /// The array element specifies dynamic linking information. See Section 8.3, Dynamic Section,
    /// for more information.
    DYNAMIC = 2,
    /// The array element specifies the location and size of a null-terminated path name to invoke
    /// as an interpreter. This segment type is meaningful only for executable files (though it may
    /// occur for shared objects); it may not occur more than once in a file. If it is present, it
    /// must precede any loadable segment entry. See Section 8.1, Program Interpreter, for more
    /// information.
    INTERP = 3,
    /// The array element specifies the location and size of auxiliary information. See Section
    /// 7.6, Note Sections, for more information.
    NOTE = 4,
    /// This segment type is reserved but has unspecified semantics. Programs that contain an array
    /// element of this type do not conform to the ABI.
    SHLIB = 5,
    /// The array element, if present, specifies the location and size of the program header table
    /// itself, both in the file and in the memory image of the program. This segment type may not
    /// occur more than once in a file. Moreover, it may occur only if the program header table is
    /// part of the memory image of the program. If it is present, it must precede any loadable
    /// segment entry.
    PHDR = 6,
    /// The array element specifies the Thread-Local Storage template. Implementations need not
    /// support this program table entry. See Section 7.7, Thread-Local Storage, for more
    /// information.
    TLS = 7,
    /// Values in this inclusive range are reserved for operating system-specific semantics.
    LOOS = 0x60000000,
    HIOS = 0x6fffffff,
    /// Values in this inclusive range are reserved for processor-specific semantics. If meanings
    /// are specified, the psABI supplement explains them.
    LOPROC = 0x70000000,
    HIPROC = 0x7fffffff,
}

impl TryFrom<&[u8]> for Type {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 4 {
            return Err("Elf32_Phdr.p_type requires exactly 4 bytes");
        }

        Ok(match le32!(value) {
            0 => Self::NULL,
            1 => Self::LOAD,
            2 => Self::DYNAMIC,
            3 => Self::INTERP,
            4 => Self::NOTE,
            5 => Self::SHLIB,
            6 => Self::PHDR,
            7 => Self::TLS,
            _ => return Err("Bad Elf32_Phdr.p_type value"),
        })
    }
}
```

`Flag` defines the
permission flags the segment should have once it is dumped into memory:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
/// See 7.4. Segment Permission https://gabi.xinuos.com/elf/07-pheader.html#segment-permissions
pub struct Flags(u32);

impl Flags {
    pub const NONE: Self = Flags(0x0);
    pub const X: Self = Flags(0x1);
    pub const W: Self = Flags(0x2);
    pub const R: Self = Flags(0x4);

    pub fn bits(self) -> u32 {
        self.0
    }
}

impl TryFrom<&[u8]> for Flags {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 4 {
            return Err("Not enough bytes for Elf32_Phdr.p_flags, need 4");
        }

        Ok(Self(le32!(value)))
    }
}

impl std::ops::BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Flags(self.0 | rhs.0)
    }
}
```

## Full ELF parsing 

Putting `Elf32_Ehdr` and `Elf32_Phdr` parsing together:

```rust
/// Representing an ELF32 binary in memory
///
/// This does not include section headers (Elf32_Shdr), but only program headers (Elf32_Phdr), see either `man elf` and/or https://gabi.xinuos.com/elf/03-sheader.html
#[derive(Debug)]
pub struct Elf {
    pub header: header::Header,
    pub pheaders: Vec<pheader::Pheader>,
}

impl TryFrom<&[u8]> for Elf {
    type Error = String;

    fn try_from(b: &[u8]) -> Result<Self, String> {
        let header = header::Header::try_from(b).map_err(|e| e.to_string())?;

        let mut pheaders = Vec::with_capacity(header.phnum as usize);
        for i in 0..header.phnum {
            let offset = header.phoff as usize + i as usize * header.phentsize as usize;
            let ph = pheader::Pheader::from(b, offset)?;
            pheaders.push(ph);
        }

        Ok(Elf { header, pheaders })
    }
}
```

The equivalent to `readelf -l`:

```text
Elf { 
    header: Header {
        ident: Identifier {
            magic: [127, 69, 76, 70],
            class: 1,
            data: 1,
            version: 1,
            os_abi: 0,
            abi_version: 0,
            _pad: [0, 0, 0, 0, 0, 0, 0] 
        },
        type: Executable,
        machine: EM_ARM,
        version: 1,
        entry: 32768,
        phoff: 52,
        shoff: 4572,
        flags: 83886592,
        ehsize: 52,
        phentsize: 32,
        phnum: 1,
        shentsize: 40,
        shnum: 8,
        shstrndx: 7 
    },
    pheaders: [
        Pheader { 
            type: LOAD,
            offset: 4096,
            vaddr: 32768,
            paddr: 32768,
            filesz: 12,
            memsz: 12,
            flags: Flags(5),
            align: 4096
        }
    ]
}
```

Or in the debug output of stinkarm:

```text
[     0.613ms] opening binary "examples/asm.elf"
[     0.721ms] parsing ELF...
[     0.744ms] \
ELF Header:
  Magic:              [7f, 45, 4c, 46]
  Class:              ELF32
  Data:               Little endian
  Type:               Executable
  Machine:            EM_ARM
  Version:            1
  Entry point:        0x8000
  Program hdr offset: 52 (32 bytes each)
  Section hdr offset: 4572
  Flags:              0x05000200
  EH size:            52
  # Program headers:  1
  # Section headers:  8
  Str tbl index:      7

Program Headers:
  Type       Offset   VirtAddr   PhysAddr   FileSz    MemSz  Flags  Align
  LOAD     0x001000 0x00008000 0x00008000 0x00000c 0x00000c    R|X 0x1000
```

# Dumping ELF segments into memory

Before putting each segment into its `Pheader::vaddr`, we have to understand,
that one doesn't simply `mmap` with `MAP_FIXED` or `MAP_NOREPLACE` into the
virtual address `0x8000`. The linux kernel won't let us, and rightfully so,
`man mmap` says:

> If addr is not NULL, then the kernel takes it as a hint about where to place
> the mapping;  on Linux,  the kernel will pick a nearby page boundary (but
> always above or equal to the value specified by /proc/sys/vm/mmap_min_addr) and
> attempt  to  create  the  mapping there.

And `/proc/sys/vm/mmap_min_addr` on my system is `u16::MAX` (2^16)-1=65535. So
mapping our segment to `0x8000` (32768) is not allowed:

```rust
let segment = sys::mmap::mmap(
    // this is only UB if dereferenced, its just a hint, so its safe here
    Some(unsafe { std::ptr::NonNull::new_unchecked(0x8000 as *mut u8) }),
    4096,
    sys::mmap::MmapProt::WRITE,
    sys::mmap::MmapFlags::ANONYMOUS
        | sys::mmap::MmapFlags::PRIVATE
        | sys::mmap::MmapFlags::NOREPLACE,
    -1,
    0,
)
.unwrap();
```

Running the above with our `vaddr` of `0x8000` results in:

```text
thread 'main' panicked at src/main.rs:33:6:
called `Result::unwrap()` on an `Err` value: "mmap failed (errno 1): Operation not permitted
(os error 1)"
```

It only works in elevated permission mode, which is something I dont want to
run my emulator in.

## Translating guest memory access to host memory access

The obvious fix is to not mmap below `u16::MAX` and let the kernel choose where
we dump our segment:

```rust
let segment = sys::mmap::mmap(
    None,
    4096,
    MmapProt::WRITE,
    MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
    -1,
    0,
).unwrap();
```

But this means the segment of the process to emulate is not at `0x8000`, but
anywhere the kernel allows. So we need to add a translation layer between guest
and host memory. If you're familiar with how virtual memory works, its similar
but one more indirection.

```rust
struct MappedSegment {
    host_ptr: *mut u8,
    len: u32,
}

pub struct Mem {
    maps: BTreeMap<u32, MappedSegment>,
}

impl Mem {
    pub fn new() -> Self {
        Self {
            maps: BTreeMap::new(),
        }
    }

    pub fn map_region(&mut self, guest_addr: u32, len: u32, host_ptr: *mut u8) {
        self.maps
            .insert(guest_addr, MappedSegment { host_ptr, len });
    }

    /// translate a guest addr to a host addr we can write and read from
    pub fn translate(&self, guest_addr: u32) -> Option<*mut u8> {
        // Find the greatest key <= guest_addr.
        let (&base, seg) = self.maps.range(..=guest_addr).next_back()?;
        if guest_addr < base + seg.len {
            let offset = guest_addr - base;
            Some(unsafe { seg.host_ptr.add(offset as usize) })
        } else {
            None
        }
    }

    pub fn read_u32(&self, guest_addr: u32) -> Option<u32> {
        let ptr = self.translate(guest_addr)?;
        unsafe { Some(u32::from_le(*(ptr as *const u32))) }
    }

    pub fn write_u32(&mut self, guest_addr: u32, value: u32) -> Result<(), &'static str> {
        let ptr = self.translate(guest_addr).ok_or_else(|| "hola")?;
        unsafe { *(ptr as *mut u32) = value.to_le() }
        Ok(())
    }

    /// dropping all segments, consumes self to make it single use and not allow any self usages
    /// after dropping
    pub fn destroy(self) {
        for (guest_addr, seg) in self.maps {
            if let Some(nnptr) = std::ptr::NonNull::new(seg.host_ptr) {
                if let Err(e) = sys::mmap::munmap(nnptr, seg.len as usize) {
                    eprintln!(
                        "Warning: failed to munmap guest segment @ {:#010x} (len={}): {:?}",
                        guest_addr, seg.len, e
                    );
                }
            }
        }
    }
}
```

This fix has the added benfit of allowing us to sandbox guest memory fully, so
we can validate each memory access before we allow a guest to host memory
interaction.

## Mapping segments with their permissions

# Decoding armv7

## Immediate instructions

## Syscalls

# Emulating the CPU

## Instruction dispatch

## Forwarding Syscalls

### The exception: `exit`
