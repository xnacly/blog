---
title: "Building a Minimal Viable Armv7 Emulator from Scratch"
date: 2025-11-19
summary: "Emulating armv7 is surprisingly easy, even from scratch AND in Rust"
tags:
  - arm
  - rust
---

{{<callout type="Tip or TLDR - I built a tiny, zero dependency armv7 userspace emulator in Rust">}}
I wrote a minimal viable armv7 emulator in 1.3k lines of Rust without any
dependencies. It parses and validates a 32-bit arm binary, maps its segments,
decodes a subset of arm instructions, translates guest and host memory
interactions and forwards arm Linux syscalls into x86-64 System V syscalls.

It can run a armv7 hello world binary and does so in 1.9ms (0.015ms for raw
emulation without setup), while qemu takes 12.3ms (stinkarm is thus ~100-1000x
slower than native armv7 execution).
{{</callout>}}

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

_Open below if you want to see me write a build script and a nix flake:_
{{<rawhtml>}}

<details>
    <summary>
        <h3>Minimalist arm setup and smallest possible arm binary</h3>
    </summary>
{{</rawhtml>}}

Before I start parsing ELF I'll need a binary to emulate, so lets create a
build script called `bld_exmpl` (so I can write a lot less) and nix flake, so
the asm is converted into armv7 machine code in a armv7 binary on my non armv7
system :^)

```rust
// tools/bld_exmpl
use clap::Parser;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Build all ARM assembly examples into .elf binaries
#[derive(Parser)]
struct Args {
    /// Directory containing .S examples
    #[arg(long, default_value = "examples")]
    examples_dir: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let dir = Path::new(&args.examples_dir);

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("S") {
            let name = path.file_stem().unwrap().to_str().unwrap();
            let output = dir.join(format!("{}.elf", name));
            build_asm(&path, &output)?;
        }
    }

    Ok(())
}

fn build_asm(input: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Building {} -> {}", input.display(), output.display());

    let obj_file = input.with_extension("o");

    let status = Command::new("arm-none-eabi-as")
        .arg("-march=armv7-a")
        .arg(input)
        .arg("-o")
        .arg(&obj_file)
        .status()?;

    if !status.success() {
        return Err(format!("Assembler failed for {}", input.display()).into());
    }

    let status = Command::new("arm-none-eabi-ld")
        .arg("-Ttext=0x8000")
        .arg(&obj_file)
        .arg("-o")
        .arg(output)
        .status()?;

    if !status.success() {
        return Err(format!("Linker failed for {}", output.display()).into());
    }

    Ok(fs::remove_file(obj_file)?)
}
```

```toml
# Cargo.toml
[package]
name = "stinkarm"
version = "0.1.0"
edition = "2024"
default-run = "stinkarm"

[dependencies]
clap = { version = "4.5.51", features = ["derive"] }

[[bin]]
name = "stinkarm"
path = "src/main.rs"

[[bin]]
name = "bld_exmpl"
path = "tools/bld_exmpl.rs"
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
      }
  );
}
```

{{<rawhtml>}}

</details>
{{</rawhtml>}}

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

```text
+------------------------+--------+--------+----------------+----------------+----------------+----------------+----------------+--------+---------+--------+---------+--------+--------+
|       identifier       |  type  |machine |    version     |     entry      |     phoff      |     shoff      |     flags      | ehsize |phentsize| phnum  |shentsize| shnum  |shstrndx|
|          16B           |   2B   |   2B   |       4B       |       4B       |       4B       |       4B       |       4B       |   2B   |   2B    |   2B   |   2B    |   2B   |   2B   |
+------------------------+--------+--------+----------------+----------------+----------------+----------------+----------------+--------+---------+--------+---------+--------+--------+
           \|/
            |
            |
            v
+----------------+------+------+-------+------+-----------+------------------------+
|     magic      |class | data |version|os_abi|abi_version|          pad           |
|       4B       |  1B  |  1B  |  1B   |  1B  |    1B     |           7B           |
+----------------+------+------+-------+------+-----------+------------------------+
```

Most resources show C based examples, the rust ports are
below:

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
into unsigned integers of different classes (`le` is short for little endian):

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

```text
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
|      type      |     offset     |     vaddr      |     paddr      |     filesz     |     memsz      |     flags      |     align      |
|       4B       |       4B       |       4B       |       4B       |       4B       |       4B       |       4B       |       4B       |
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
```

For me, the most important fields in `Header` are `phoff` and `phentsize`,
since we can use these to index into the binary to locate the program headers (`Phdr`).

```rust
/// Phdr, equivalent to Elf32_Phdr, see: https://gabi.xinuos.com/elf/07-pheader.html
///
/// All of its member are u32, be it Elf32_Word, Elf32_Off or Elf32_Addr
#[derive(Debug)]
pub struct Pheader {
    pub r#type: Type,
    pub offset: u32,
    pub vaddr: u32,
    pub paddr: u32,
    pub filesz: u32,
    pub memsz: u32,
    pub flags: Flags,
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
    NULL = 0,
    LOAD = 1,
    DYNAMIC = 2,
    INTERP = 3,
    NOTE = 4,
    SHLIB = 5,
    PHDR = 6,
    TLS = 7,
    LOOS = 0x60000000,
    HIOS = 0x6fffffff,
    LOPROC = 0x70000000,
    HIPROC = 0x7fffffff,
}
```

`Flag` defines the
permission flags the segment should have once it is dumped into memory:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Flags(u32);

impl Flags {
    pub const NONE: Self = Flags(0x0);
    pub const X: Self = Flags(0x1);
    pub const W: Self = Flags(0x2);
    pub const R: Self = Flags(0x4);
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

Since the only reason for parsing the elf headers is to know where to put what
segment with which permissions, I want to quickly interject on why we have to
put said segments at these specific addresses. The main reason is that all
pointers, all offsets and pc related decoding has to be done relative to
`Elf32_Ehdr.entry`, here `0x8000`. The linker also generated all instruction
arguments according to this value.

Before mapping each segment at its `Pheader::vaddr`, we have to understand:
One doesn't simply `mmap` with `MAP_FIXED` or `MAP_NOREPLACE` into the virtual
address `0x8000`. The Linux kernel won't let us, and rightfully so, `man mmap`
says:

> If addr is not NULL, then the kernel takes it as a hint about where to place
> the mapping; on Linux, the kernel will pick a nearby page boundary (but
> always above or equal to the value specified by /proc/sys/vm/mmap_min_addr) and
> attempt to create the mapping there.

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
and host memory: (If you're familiar with how virtual memory works, its similar
but one more indirection)

```text
+--guest--+
| 0x80000 | ------------+
+---------+             |
                        |
                    Mem::translate
                        |
+------host------+      |
| 0x7f5b4b8f8000 | <----+
+----------------+
```

Putting this into rust:

- `map_region` registers a region of memory and allows `Mem`
  to take ownership for calling munmap on these segments
  once it goes out of scope
- `translate` takes a guest addr and translates it to a host addr

```rust
struct MappedSegment {
    host_ptr: *mut u8,
    len: u32,
}

pub struct Mem {
    maps: BTreeMap<u32, MappedSegment>,
}

impl Mem {
    pub fn map_region(&mut self, guest_addr: u32, len: u32, host_ptr: *mut u8) {
        self.maps
            .insert(guest_addr, MappedSegment { host_ptr, len });
    }

    /// translate a guest addr to a host addr we can write and read from
    pub fn translate(&self, guest_addr: u32) -> Option<*mut u8> {
        // Find the greatest key <= guest_addr.
        let (&base, seg) = self.maps.range(..=guest_addr).next_back()?;
        if guest_addr < base.wrapping_add(seg.len) {
            let offset = guest_addr.wrapping_sub(base);
            Some(unsafe { seg.host_ptr.add(offset as usize) })
        } else {
            None
        }
    }

    pub fn read_u32(&self, guest_addr: u32) -> Option<u32> {
        let ptr = self.translate(guest_addr)?;
        unsafe { Some(u32::from_le(*(ptr as *const u32))) }
    }
}
```

This fix has the added benfit of allowing us to sandbox guest memory fully, so
we can validate each memory access before we allow a guest to host memory
interaction.

## Mapping segments with their permissions

The basic idea is similar to the way a JIT compiler works:

1. create a `mmap` section with `W` permissions
2. write bytes from elf into section
3. zero rest of defined size
4. change permission of section with `mprotect` to the
   permissions defined in the `Pheader`

```rust
/// mapping applies the configuration of self to the current memory context by creating the
/// segments with the corresponding permission bits, vaddr, etc
pub fn map(&self, raw: &[u8], guest_mem: &mut mem::Mem) -> Result<(), String> {
    // zero memory needed case, no clue if this actually ever happens, but we support it
    if self.memsz == 0 {
        return Ok(());
    }

    if self.vaddr == 0 {
        return Err("program header has a zero virtual address".into());
    }

    // we need page alignement, so either Elf32_Phdr.p_align or 4096
    let (start, _end, len) = self.alignments();

    // Instead of mapping at the guest vaddr (Linux doesnt't allow for low addresses),
    // we allocate memory wherever the host kernel gives us.
    // This keeps guest memory sandboxed: guest addr != host addr.
    let segment = mem::mmap::mmap(
        None,
        len as usize,
        MmapProt::WRITE,
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
        -1,
        0,
    )?;

    let segment_ptr = segment.as_ptr();
    let segment_slice = unsafe { std::slice::from_raw_parts_mut(segment_ptr, len as usize) };

    let file_slice: &[u8] =
        &raw[self.offset as usize..(self.offset.wrapping_add(self.filesz)) as usize];

    // compute offset inside the mmapped slice where the segment should start
    let offset = (self.vaddr - start) as usize;

    // copy the segment contents to the mmaped segment
    segment_slice[offset..offset + file_slice.len()].copy_from_slice(file_slice);

    // we need to zero the remaining bytes
    if self.memsz > self.filesz {
        segment_slice
            [offset.wrapping_add(file_slice.len())..offset.wrapping_add(self.memsz as usize)]
            .fill(0);
    }

    // record mapping in guest memory table, so CPU can translate guest vaddr to host pointer
    guest_mem.map_region(self.vaddr, len, segment_ptr);

    // we change the permissions for our segment from W to the segments requested bits
    mem::mmap::mprotect(segment, len as usize, self.flags.into())
}

/// returns (start, end, len)
fn alignments(&self) -> (u32, u32, u32) {
    // we need page alignement, so either Elf32_Phdr.p_align or 4096
    let align = match self.align {
        0 => 0x1000,
        _ => self.align,
    };
    let start = self.vaddr & !(align - 1);
    let end = (self.vaddr.wrapping_add(self.memsz).wrapping_add(align) - 1) & !(align - 1);
    let len = end - start;
    (start, end, len)
}
```

Map is called in the emulators entry point:

```rust
let elf: elf::Elf = (&buf as &[u8]).try_into().expect("Failed to parse binary");
let mut mem = mem::Mem::new();
for phdr in elf.pheaders {
    if phdr.r#type == elf::pheader::Type::LOAD {
        phdr.map(&buf, &mut mem)
            .expect("Mapping program header failed");
    }
}
```

# Decoding armv7

We can now request a word (32bit) from our `LOAD` segment which contains
the `.text` section bytes one can inspect via `objdump`:

```text
$ arm-none-eabi-objdump -d examples/exit.elf

examples/exit.elf:     file format elf32-littlearm


Disassembly of section .text:

00008000 <_start>:
    8000:       e3a000a1        mov     r0, #161        @ 0xa1
    8004:       e3a07001        mov     r7, #1
    8008:       ef000000        svc     0x00000000
```

So we use `Mem::read_u32(0x8000)` and get `0xe3a000a1`.

Decoding armv7 instructions seems doable at a glance, but
it is a deeper rabbit-hole than I expected, prepare for a bit
shifting, implicit behaviour and intertwined meaning heavy
section:

Instructions are more or less grouped into four groups:

1. Branch and control
2. Data processing
3. Load and store
4. Other (syscalls & stuff)

Each armv7 instruction is 32 bit in size, (in general) its layout is as
follows:

```text
+--------+------+------+------+------------+---------+
|  cond  |  op  |  Rn  |  Rd  |  Operand2  |  shamt  |
|   4b   |  4b  |  4b  |  4b  |     12b    |   4b    |
+--------+------+------+------+------------+---------+
```

| bit range | name     | description                         |
| --------- | -------- | ----------------------------------- |
| 0..4      | cond     | contains `EQ`, `NE`, etc            |
| 4..8      | op       | for instance `0b1101` for `mov`     |
| 8..12     | rn       | source register                     |
| 12..16    | rd       | destination register                |
| 16..28    | operand2 | immediate value or shifted register |
| 28..32    | shamt    | shift amount                        |

## Rust representation

Since `cond` decides whether or not the instruction is
executed, I decided on the following struct to be the decoded
instruction:

```rust
#[derive(Debug, Copy, Clone)]
pub struct InstructionContainer {
    pub cond: u8,
    pub instruction: Instruction,
}

#[derive(Debug, Copy, Clone)]
pub enum Instruction {
    MovImm { rd: u8, rhs: u32 },
    Svc,
    LdrLiteral { rd: u8, addr: u32 },
    Unknown(u32),
}
```

These 4 instructions are enough to support both the minimal
binary at the intro and the asm hello world:

```armasm
    .global _start
_start:
    mov r0, #161
    mov r7, #1
    svc #0
```

```armasm
    .section .rodata
msg:
    .asciz "Hello, world!\n"

    .section .text
    .global _start
_start:
    ldr r0, =1
    ldr r1, =msg
    mov r2, #14
    mov r7, #4
    svc #0

    mov r0, #0
    mov r7, #1
    svc #0
```

## General instruction detection

Our decoder is a function accepting a word, the program counter (we need
this later for decoding the offset for `ldr`) and returning the
aforementioned instruction container:

```rust
pub fn decode_word(word: u32, caddr: u32) -> InstructionContainer
```

Referring to the diagram shown before, I know the first 4 bit are the
condition, so I can extract these first. I also take the top 3 bits to
identify the instruction class (load and store, branch or data
processing immediate):

```rust
// ...
let cond = ((word >> 28) & 0xF) as u8;
let top = ((word >> 25) & 0x7) as u8;
```

## Immediate mov

Since there are immediate moves and non immediate moves, both `0b000` and
`0b001` are valid top values we want to support.

```rust
// ...
if top == 0b000 || top == 0b001 {
    let i_bit = ((word >> 25) & 0x1) != 0;
    let opcode = ((word >> 21) & 0xF) as u8;
    if i_bit {
        // ...
    }
}
```

If the i bit is set, we can extract convert the opcode from its bits into
something I can read a lot better:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Op {
    // ...
    Mov = 0b1101,
}

static OP_TABLE: [Op; 16] = [
    // ...
    Op::Mov,
];

#[inline(always)]
fn op_from_bits(bits: u8) -> Op {
    debug_assert!(bits <= 0b1111);
    unsafe { *OP_TABLE.get_unchecked(bits as usize) }
}
```

We can now plug this in, match on the only ddi (data processing immediate)
we know and extract both the destination register (rd) and the raw
immediate value:

```rust
if top == 0b000 || top == 0b001 {
    // Data-processing immediate (ddi) (top 0b000 or 0b001 when I==1)
    let i_bit = ((word >> 25) & 0x1) != 0;
    let opcode = ((word >> 21) & 0xF) as u8;
    if i_bit {
        match op_from_bits(opcode) {
            Op::Mov => {
                let rd = ((word >> 12) & 0xF) as u8;
                let imm12 = word & 0xFFF;
                // ...
            }
            _ => todo!(),
        }
    }
}
```

From the examples before one can see the immediate value is prefixed with
`#`. To move the value `161` into `r0` we do:

```asm
mov r0, #161
```

Since we know there are only 12 bits available for the immediate the arm
engineers came up with rotation of the resulting integer by the remaining 4
bits:

```rust
#[inline(always)]
fn decode_rotated_imm(imm12: u32) -> u32 {
    let rotate = ((imm12 >> 8) & 0b1111) * 2;
    (imm12 & 0xff).rotate_right(rotate)
}
```

Plugging this back in results in us being able to fully decode `mov r0,#161`:

```rust
if top == 0b000 || top == 0b001 {
    let i_bit = ((word >> 25) & 0x1) != 0;
    let opcode = ((word >> 21) & 0xF) as u8;
    if i_bit {
        match op_from_bits(opcode) {
            Op::Mov => {
                let rd = ((word >> 12) & 0xF) as u8;
                let imm12 = word & 0xFFF;
                let rhs = decode_rotated_imm(imm12);
                return InstructionContainer {
                    cond,
                    instruction: Instruction::MovImm { rd, rhs },
                };
            }
            _ => todo!(),
        }
    }
}
```

As seen when `dbg!`-ing the cpu steps:

```text
[src/cpu/mod.rs:114:13] decoder::decode_word(word, self.pc()) =
InstructionContainer {
    cond: 14,
    instruction: MovImm {
        rd: 0,
        rhs: 161,
    },
}
```

## Load and Store

`ldr` is part of the load and store instruction group and is needed for
the accessing of `Hello World!` in `.rodata` and putting a ptr to it
into a register.

In comparison to immediate mov we have to do a little trick, since we
only want to match for load and store that matches:

- single register modification
- load and store with immediate

So we only decode:

```armasm
LDR Rd, [Rn, #imm]
LDR Rd, [Rn], #imm
@ etc
```

Thus we match with `(top >> 1) & 0b11 == 0b01` and start extracting a
whole bucket load of bit flags:

```rust
if (top >> 1) & 0b11 == 0b01 {
    let p = ((word >> 24) & 1) != 0;
    let u = ((word >> 23) & 1) != 0;
    let b = ((word >> 22) & 1) != 0;
    let w = ((word >> 21) & 1) != 0;
    let l = ((word >> 20) & 1) != 0;
    let rn = ((word >> 16) & 0xF) as u8;
    let rd = ((word >> 12) & 0xF) as u8;
    let imm12 = (word & 0xFFF) as u32;

    // Literal‑pool version
    if l && rn == 0b1111 && p && u && !w && !b {
        let pc_seen = caddr.wrapping_add(8);
        let literal_addr = pc_seen.wrapping_add(imm12);

        return InstructionContainer {
            cond,
            instruction: Instruction::LdrLiteral {
                rd,
                addr: literal_addr,
            },
        };
    }

    todo!("only LDR with p&u&!w&!b is implemented")
}
```

| bit | description                                      |
| --- | ------------------------------------------------ |
| p   | pre-indexed addressing, offset added before load |
| u   | add (1) vs subtract (0) offset                   |
| b   | word (0) or byte (1) sized access                |
| w   | (no=0) write back to base                        |
| l   | load (1), or store (0)                           |

`ldr Rn, <addr>` matches exactly `load`, base register is PC (`rn==0b1111`), pre-indexed
addressing, added offset, no write back and no byte sized access (`l &&
rn == 0b1111 && p && u && !w && !b`).

## Syscalls

Syscalls are the only way to interact with the Linux kernel (as far as I
know), so we definitely need to implement both decoding and forwarding.
Bits 27-24 are `1111` for system calls. The immediate value is
irrelevant for us, since the Linux syscall handler either way discards
the value:

```rust
if ((word >> 24) & 0xF) as u8 == 0b1111 {
    return InstructionContainer {
        cond,
        // technically arm says svc has a 24bit immediate but we don't care about it, since the
        // Linux kernel also doesn't
        instruction: Instruction::Svc,
    };
}
```

We can now fully decode all instructions for both the simple exit and
the more advanced hello world binary:

```text
[src/cpu/mod.rs:121:15] instruction = MovImm { rd: 0, rhs: 161, }
[src/cpu/mod.rs:121:15] instruction = MovImm { rd: 7, rhs: 1, }
[src/cpu/mod.rs:121:15] instruction = Svc
```

```text
[src/cpu/mod.rs:121:15] instruction = MovImm { rd: 0, rhs: 1, }
[src/cpu/mod.rs:121:15] instruction = LdrLiteral { rd: 1, addr: 32800, }
[src/cpu/mod.rs:121:15] instruction = MovImm { rd: 2, rhs: 14, }
[src/cpu/mod.rs:121:15] instruction = MovImm { rd: 7, rhs: 4, }
[src/cpu/mod.rs:121:15] instruction = Svc
[src/cpu/mod.rs:121:15] instruction = MovImm { rd: 0, rhs: 0, }
[src/cpu/mod.rs:121:15] instruction = MovImm { rd: 7, rhs: 1, }
[src/cpu/mod.rs:121:15] instruction = Svc
```

# Emulating the CPU

This is by FAR the easiest part, I only struggled with the double
indirection for `ldr` (I simply didn't know about it), but each problem
at its time :^).

```rust
pub struct Cpu<'cpu> {
    /// r0-r15 (r13=SP, r14=LR, r15=PC)
    pub r: [u32; 16],
    pub cpsr: u32,
    pub mem: &'cpu mut mem::Mem,
    /// only set by ArmSyscall::Exit to propagate exit code to the host
    pub status: Option<i32>,
}

impl<'cpu> Cpu<'cpu> {
    pub fn new(mem: &'cpu mut mem::Mem, pc: u32) -> Self {
        let mut s = Self {
            r: [0; 16],
            cpsr: 0x60000010,
            mem,
            status: None,
        };
        s.r[15] = pc;
        s
    }
```

Instantiating the cpu:

```rust
let mut cpu = cpu::Cpu::new(&mut mem, elf.header.entry);
```

## Conditional Instructions?

When writing the decoder I was confused by the 4 conditional bits. I always
though one does conditional execution by using a branch to jump over
instructions that shouldnt be executed. That was before I learned for arm,
both ways are supported (the armv7 reference says this feature should only
be used if there arent multiple instructions depending on the same
condition, otherwise one should use branches) - so I need to support this
too:

```rust
impl<'cpu> Cpu<'cpu> {
    #[inline(always)]
    fn cond_passes(&self, cond: u8) -> bool {
        match cond {
            0x0 => (self.cpsr >> 30) & 1 == 1, // EQ: Z == 1
            0x1 => (self.cpsr >> 30) & 1 == 0, // NE
            0xE => true,                       // AL (always)
            0xF => false,                      // NV (never)
            _ => false,                        // strict false
        }
    }
}
```

## Instruction dispatch

After implementing the necessary checks and setup for emulating the cpu, the
CPU can now check if an instruction is to be executed, match on the decoded
instruction and run the associated logic:

```rust
impl<'cpu> Cpu<'cpu> {
    #[inline(always)]
    fn pc(&self) -> u32 {
        self.r[15] & !0b11
    }

    /// moves pc forward a word
    #[inline(always)]
    fn advance(&mut self) {
        self.r[15] = self.r[15].wrapping_add(4);
    }

    pub fn step(&mut self) -> Result<bool, err::Err> {
        let Some(word) = self.mem.read_u32(self.pc()) else {
            return Ok(false);
        };

        if word == 0 {
            // zero instruction means we hit zeroed out rest of the page
            return Ok(false);
        }

        let InstructionContainer { instruction, cond } = decoder::decode_word(word, self.pc());

        if !self.cond_passes(cond) {
            self.advance();
            return Ok(true);
        }

        match instruction {
            decoder::Instruction::MovImm { rd, rhs } => {
                self.r[rd as usize] = rhs;
            }
            decoder::Instruction::Unknown(w) => {
                return Err(err::Err::UnknownOrUnsupportedInstruction(w));
            }
            i => {
                stinkln!(
                    "found unimplemented instruction, exiting: {:#x}:={:?}",
                    word,
                    i
                );
                self.status = Some(1);
            }
        }

        self.advance();

        Ok(true)
    }
}
```

## LDR and addresses in literal pools

While [Translating guest memory access to host memory
access](#translating-guest-memory-access-to-host-memory-access) goes into depth
on translating / forwarding guest memory access to host memory adresses, this
chapter will focus on the layout of literals in armv7 and how `ldr` indirects
memory access.

Lets first take a look at the ldr instruction of our hello world example:

```armasm
    .section .rodata
    @ define a string with the `msg` label
msg:
    @ asciz is like asciii but zero terminated
    .asciz "Hello world!\n"

    .section .text
    .global _start
_start:
    @ load the literal pool addr of msg into r1
    ldr r1, =msg
```

The `as`
[documentation](https://sourceware.org/binutils/docs/as.html#index-LDR-reg_002c_003d_003clabel_003e-pseudo-op_002c-ARM)
says:

> `LDR`
>
> ```armasm
> ldr <register>, = <expression>
> ```
>
> If expression evaluates to a numeric constant then a MOV or MVN instruction
> will be used in place of the LDR instruction, if the constant can be generated
> by either of these instructions. Otherwise the constant will be placed into the
> nearest literal pool (if it not already there) and a PC relative LDR
> instruction will be generated.

Now this may not make sense at a first glance, why would `=msg` be assembled
into an address to the address of the literal. But an `armv7` instruction can
not encode a full address, it is impossible due to the instruction being
restricted to an 8-bit value rotated right by an even number of bits. The ldr
instructions argument points to a literal pool entry, this entry is a 32-bit
value and reading it produces the actual address of `msg`.

When decoding we can see ldr points to a memory address (32800 or `0x8020`) in
the section we mmaped earlier:

```text
[src/cpu/mod.rs:121:15] instruction = LdrLiteral { rd: 1, addr: 32800 }
```

Before accessing guest memory, we must translate said addr to a host addr:

```text
+--ldr.addr--+
|   0x8020   |
+------------+
      |
      |             +-------------Mem::read_u32(addr)-------------+
      |             |                                             |
      |             |   +--guest--+                               |
      |             |   |  0x8020 | ------------+                 |
      |             |   +---------+             |                 |
      |             |                           |                 |
      +-----------> |                       Mem::translate        |
                    |                           |                 |
                    |   +------host------+      |                 |
                    |   | 0x7ffff7f87020 | <----+                 |
                    |   +----------------+                        |
                    |                                             |
                    +---------------------------------------------+
                                           |
+--literal-ptr--+                          |
|     0x8024    | <------------------------+
+---------------+
```

Or in code:

```rust
impl<'cpu> Cpu<'cpu> {
    pub fn step(&mut self) -> Result<bool, err::Err> {
        // ...
        match instruction {
            decoder::Instruction::LdrLiteral { rd, addr } => {
                self.r[rd as usize] = self.mem.read_u32(addr).expect("Segfault");
            }
        }
        // ...
    }
}
```

Any other instruction using a addr will have to also go through the
`Mem::translate` indirection.

## Forwarding Syscalls and other feature flag based logic

Since stinkarm has three ways of dealing with syscalls (`deny`, `sandbox`,
`forward`). I decided on handling the selection of the appropriate logic at cpu
creation time via a function pointer attached to the CPU as the
`syscall_handler` field:

```rust {hl_lines=8}
type SyscallHandlerFn = fn(&mut Cpu, ArmSyscall) -> i32;

pub struct Cpu<'cpu> {
    /// r0-r15 (r13=SP, r14=LR, r15=PC)
    pub r: [u32; 16],
    pub cpsr: u32,
    pub mem: &'cpu mut mem::Mem,
    syscall_handler: SyscallHandlerFn,
    pub status: Option<i32>,
}

impl<'cpu> Cpu<'cpu> {
    pub fn new(conf: &'cpu config::Config, mem: &'cpu mut mem::Mem, pc: u32) -> Self {
        // ... 

        // simplified, in stinkarm this gets wrapped if the user specifies
        // syscall traces via -lsyscalls or -v
        s.syscall_handler = match conf.syscalls {
            SyscallMode::Forward => translation::syscall_forward,
            SyscallMode::Sandbox => sandbox::syscall_sandbox,
            SyscallMode::Deny => sandbox::syscall_stub,
        };
        // ...
    }
}
```

### Calling conventions, armv7 vs x86

In our examples I obviously used the armv7 syscall calling convention. But this
convention differs from the calling convention of our x86 (technically its
x86-64 System V AMD64 ABI) host by a lot.

While armv7 uses `r7` for the syscall number and `r0-r5` for the syscall
arguments, x86 uses `rax` for the syscall id and `rdi`, `rsi`, `rdx`, `r10`,
`r8` and `r9` for the syscall arguments (`rcx` can't be used since `syscall`
clobbers it, thus Linux goes with `r10`).

Also the syscall numbers differ between armv7 and x86, `sys_write` is `1` on
x86 and `4` on armv7. If you are interested in either calling conventions,
syscall ids and documentation, do visit [The Chromium Projects- Linux System
Call
Table](https://www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/),
it is generated from Linux headers and fairly readable.

Table version:

| usage      | armv7 | x86-64 |
| ---------- | ----- | ------ |
| syscall id | r7    | rax    |
| return     | r0    | rax    |
| arg0       | r0    | rdi    |
| arg1       | r1    | rsi    |
| arg2       | r2    | rdx    |
| arg3       | r3    | r10    |
| arg4       | r4    | r8     |
| arg5       | r5    | r9     |

So something like writing `TEXT123` to stdout looks like this on arm:

```armasm
    .section .rodata
txt:
    .asciz "TEXT123\n"

    .section .text
    .global _start
_start:
    ldr r0, =1
    ldr r1, =txt
    mov r2, #8
    mov r7, #4
    svc #0
```

While it looks like the following on x86:

```asm
    .section .rodata
txt:
    .string "TEXT123\n"

    .section .text
    .global _start
_start:
    movq $1, %rax
    movq $1, %rdi
    leaq txt(%rip), %rsi
    movq $8, %rdx
    syscall
```

### Hooking the syscall handler up

After made the calling convention differences clear, the handling of a syscall
is simply to execute this handler and use `r7` to convert the armv7 syscall
number to the x86 syscall number:

```rust
impl<'cpu> Cpu<'cpu> {
    pub fn step(&mut self) -> Result<bool, err::Err> {
        // ...

        match instruction {
            // ...
            decoder::Instruction::Svc => {
                self.r[0] = (self.syscall_handler)(self, ArmSyscall::try_from(self.r[7])?) as u32;
            }
            // ...
        }
        // ...
    }
}
```

Of course for this to work the syscall has to be implemented and even
decodable. At least for the decoding, there is the `ArmSyscall` enum:

```rust
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum ArmSyscall {
    restart = 0x00,
    exit = 0x01,
    fork = 0x02,
    read = 0x03,
    write = 0x04,
    open = 0x05,
    close = 0x06,
}

impl TryFrom<u32> for ArmSyscall {
    type Error = err::Err;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => Self::restart,
            0x01 => Self::exit,
            0x02 => Self::fork,
            0x03 => Self::read,
            0x04 => Self::write,
            0x05 => Self::open,
            0x06 => Self::close,
            _ => return Err(err::Err::UnknownSyscall(value)),
        })
    }
}
```

By default the sandboxing mode is selected, but I will go into detail on both
sandboxing and denying syscalls later, first I want to focus on the
implementation of the translation layer from armv7 to x86 syscalls:

```rust
pub fn syscall_forward(cpu: &mut super::Cpu, syscall: ArmSyscall) -> i32 {
    match syscall {
        // none are implemented, dump debug print
        c => todo!("{:?}", c),
    }
}
```

### Handling the only exception: `exit`

Since exit means the guest wants to exit, we can't just forward this to the
host system, simply because this would exit the emulator before it would be
able to do cleanup and unmap memory regions allocated.

```rust
pub fn syscall_forward(cpu: &mut super::Cpu, syscall: ArmSyscall) -> i32 {
    match syscall {
        ArmSyscall::exit => {
            cpu.status = Some(cpu.r[0] as i32);
            0
        }
        // ...
    }
}
```

To both know we hit the exit syscall (we need to, otherwise the emulator
executes further) and propagate the exit code to the host system, we set the
`Cpu::status` field to `Some(r0)`, which is the argument to the syscall.

This field is then used in the emulator entry point / main loop:

```rust
fn main() {
    let mut cpu = cpu::Cpu::new(&conf, &mut mem, elf.header.entry);

    loop {
        match cpu.step() { /**/ }

        // Cpu::status is only some if sys_exit was called, we exit the
        // emulation loop
        if cpu.status.is_some() {
            break;
        }
    }

    let status = cpu.status.unwrap_or(0);
    // cleaning up used memory via munmap
    mem.destroy();
    // propagating the status code to the host system
    exit(status);
}
```

### Implementing: `sys_write`

The write syscall is not as spectacular as `sys_exit`: writing a `buf` of `len`
to a file descriptor.

| register | description                                               |
| -------- | --------------------------------------------------------- |
| rax      | syscall number (1 for write)                              |
| rdi      | file descriptor (0 for stdin, 1 for stdout, 2 for stderr) |
| rsi      | a pointer to the buffer                                   |
| rdx      | the length of the buffer `rsi` is pointing to             |

It is necessary for doing the O of I/O tho, otherwise there won't be any
`Hello, World!`s on the screen.

```rust
use crate::{cpu, sys};

pub fn write(cpu: &mut cpu::Cpu, fd: u32, buf: u32, len: u32) -> i32 {
    // fast path for zero length buffer
    if len == 0 {
        return 0;
    }

    // Option::None returned from translate indicates invalid memory access
    let Some(buf_ptr) = cpu.mem.translate(buf) else {
        // so we return 'Bad Address'
        return -(sys::Errno::EFAULT as i32);
    };

    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            // syscall number
            in("rax") 1_u64,
            in("rdi") fd as u64,
            in("rsi") buf_ptr as u64,
            in("rdx") len as u64,
            lateout("rax") ret,
            // we clobber rcx
            out("rcx") _,
            // and r11
            out("r11") _,
            // we don't modify the stack
            options(nostack),
        );
    }

    ret.try_into().unwrap_or(i32::MAX)
}
```

Adding it to `translation::syscall_forward` with it's arguments according to the
calling convention we established before:

```rust
pub fn syscall_forward(cpu: &mut super::Cpu, syscall: ArmSyscall) -> i32 {
    match syscall {
        // ...
        ArmSyscall::write => sys::write(cpu, cpu.r[0], cpu.r[1], cpu.r[2]),
        // ...
    }
}
```

Executing `helloWorld.elf` now results in:

```shell
$ stinkarm -Cforward example/helloWorld.elf
Hello, world!
$ echo $status
0
```

### Deny and Sandbox - restricting syscalls

The simplest sandboxing mode is to deny, the more complex is to allow
some syscall interactions while others are denied. The latter requires
checking arguments to syscalls, not just the syscall kind.

Lets start with the easier syscall handler: `deny`. Deny simply returns
`ENOSYS` to all invoked syscalls:

```rust
pub fn syscall_deny(cpu: &mut super::Cpu, syscall: ArmSyscall) -> i32 {
    if let ArmSyscall::exit = syscall {
        cpu.status = Some(cpu.r[0] as i32)
    };

    -(sys::Errno::ENOSYS as i32)
}
```

Thus executing the hello world and enabling syscall logs results in neither
`sys_write` nor `sys_exit` going through and `ENOSYS` being returned for both
in `r0`:

```text
$ stinkarm -Cdeny -lsyscalls examples/helloWorld.elf
148738 write(fd=1, buf=0x8024, len=14) [deny]
=ENOSYS
148738 exit(code=0) [deny]
=ENOSYS
```

`sandbox` at a high level is the same as deny, check for conditions before
executing a syscall, if they don't match, disallow the syscall:

```rust
pub fn syscall_sandbox(cpu: &mut super::Cpu, syscall: ArmSyscall) -> i32 {
    match syscall {
        ArmSyscall::exit => {
            cpu.status = Some(cpu.r[0] as i32);
            0
        }
        ArmSyscall::write => {
            let (r0, r1, r2) = (cpu.r[0], cpu.r[1], cpu.r[2]);
            // only allow writing to stdout, stderr and stdin
            if r0 > 2 {
                return -(sys::Errno::ENOSYS as i32);
            }

            sys::write(cpu, r0, r1, r2)
        }
        _ => todo!("{:?}", syscall),
    }
}
```

For instance we only allow writing to stdin, stdout and stderr, no other file
descriptors. One could also add pointer range checks, buffer length checks and
other hardening measures here. Emulating the hello world example with this mode
(which is the default mode):

```text
$ stinkarm -Csandbox -lsyscalls examples/helloWorld.elf
150147 write(fd=1, buf=0x8024, len=14) [sandbox]
Hello, world!
=14
150147 exit(code=0) [sandbox]
=0
```

# Fin

So there you have it, emulating armv7 in six steps:

1. parsing and validating a 32-bit armv7 Elf binary
2. mapping segments into host address space
3. decoding a non-trivial subset of armv7 instructions
4. handling program counter relative literal loads
5. translating memory interactions from guest to host
6. forwarding armv7 Linux syscalls into their x86-64 System V counterparts

Diving into the Elf and armv7 spec without any previous relevant experience,
except the asm module I had in uni, was a bit overwhelming at first. Armv7
decoding was by far the most annoying part of the project and I still don't
like the bizarre argument ordering for x86-64 syscalls.

The whole project is about 1284 lines of Rust, has zero dependencies[^1] and is
as far as I know working correctly[^2]. 

# Microbenchmark Performance

It executes a real armv7 hello world binary in ~0.015ms of guest execution-only
time, excluding process startup and parsing. The e2e execution with all stages
I outlined before, it takes about 2ms.

```text
$ stinkarm -v examples/helloWorld.elf
[     0.070ms] opening binary "examples/helloWorld.elf"
[     0.097ms] parsing ELF...
[     0.101ms] \
ELF Header:
  Magic:              [7f, 45, 4c, 46]
  Class:              ELF32
  Data:               Little endian
  Type:               Executable
  Machine:            EM_ARM
  Version:            1
  Entry point:        0x8000
  Program hdr offset: 52 (32 bytes each)
  Section hdr offset: 4696
  Flags:              0x05000200
  EH size:            52
  # Program headers:  1
  # Section headers:  9
  Str tbl index:      8

Program Headers:
  Type       Offset   VirtAddr   PhysAddr   FileSz    MemSz  Flags  Align
  LOAD     0x001000 0x00008000 0x00008000 0x000033 0x000033    R|X 0x1000

[     0.126ms] mapped program header `LOAD` of 51B (G=0x8000 -> H=0x7ffff7f87000)
[     0.129ms] jumping to entry G=0x8000 at H=0x7ffff7f87000
[     0.131ms] starting the emulator
153719 write(fd=1, buf=0x8024, len=14) [sandbox]
Hello, world!
=14
153719 exit(code=0) [sandbox]
=0
[     0.149ms] exiting with `0`
```

Comparing the whole pipeline (parsing elf, segment mapping, cpu setup, etc) to
`qemu` we arrive at the following micro benchmark results. To be fair, qemu
does a whole lot more than stinkarm, it has a jit, a full linux-user runtime, a
dynamic loader, etc.

```text
$ hyperfine "./target/release/stinkarm examples/helloWorld.elf" -N --warmup 10
Benchmark 1: ./target/release/stinkarm examples/helloWorld.elf
  Time (mean ± σ):       1.9 ms ±   0.3 ms    [User: 0.2 ms, System: 1.4 ms]
  Range (min … max):     1.6 ms …   3.4 ms    1641 runs

$ hyperfine "qemu-arm ./examples/helloWorld.elf" -N --warmup 10
Benchmark 1: qemu-arm ./examples/helloWorld.elf
  Time (mean ± σ):      12.3 ms ±   1.5 ms    [User: 3.8 ms, System: 8.0 ms]
  Range (min … max):     8.8 ms …  19.8 ms    226 runs
```

[^1]: except clap, I dont want to parse cli flags for the 20th time this year

[^2]: afaik, write me an email `contact at xnacly.me` if you found a bug please
