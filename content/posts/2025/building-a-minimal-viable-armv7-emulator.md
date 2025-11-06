---
title: "Building a Minimal Viable Armv7 Emulator"
date: 2025-11-06
summary: "Emulating ARMv7 is suprisingly easy, even from scratch AND in Rust"
draft: true
tags:
  - arm
  - rust
---

After reading about the process the Linux kernel performs to execute binaries,
I thought: I want to write an armv7 emulator - `stinkarm`. Understand the ELF
format, the encoding of ARM 32bit instructions, the execution of arm assembly and
how it all fits together (this will help me with the JIT for my programming
language I am currently designing). Thus, no dependencies and of course Rust! I
already have enough C projects at the moment.

So I wrote the smallest binary I could think of:

```armasm
    .global _start  @ declare _start as a global
_start:             @ start is the defacto entry point
    mov r0, #161    @ first and only argument to the exit syscall
    mov r7, #1      @ exit syscall (1)
    svc #0          @ trapping into the kernel (thats US, since we are translating)
```

To execute this arm assembly on my x86 system, I need to:

1. Parse the ELF, validate it is armv7 and statically executable (I don't want
   to write a dynamic dependency resolver and loader)
2. Map the segments defined in ELF into the host memory, forward memory access
3. Emulate the CPU, its state and registers
4. Decode armv7 instructions and convert them into a nice Rust enum 
5. Execute the instructions and apply their effects to the CPU state
6. Translate and forward syscalls

Sounds easy? It is!

# Minimalist arm setup and smallest possible arm binary

Lets create a makefile and nix flake, so the asm is converted into armv7
machine code in a armv7 binary on my non armv7 system :^)

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

The elf header is exactly 52 bytes long and holds all data I need to find the
program headers and whether I even want to emulate the binary I'm are currently
parsing. These criteria are defined as members of the `Identifier` at the
start of the header.

In terms of byte layout:

| bytes  | structure                        |
| ------ | -------------------------------- |
| 0..16  | Identifier|
| 16..18 | Type                             |
| 18..20 | Machine                          |
| 20..24 | version                          |
| 24..28 | entry                            |
| 28..32 | phoff                            |
| 32..36 | shoff                            |
| 36..40 | flags                            |
| 40..42 | ehsize                           |
| 42..44 | phentsize                        |
| 44..46 | phnum                            |
| 46..48 | shentsize                        |
| 48..50 | shnum                            |
| 50..52 | shstrndx                         |

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

# Dumping ELF segments into memory

# Decoding ARMv7

## Immediate instructions

## Syscalls

# Emulating the CPU

## Instruction dispatch

## Forwarding Syscalls

### The exception: `exit`
