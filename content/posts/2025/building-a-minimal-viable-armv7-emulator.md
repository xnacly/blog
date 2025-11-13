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

```text
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
|      type      |     offset     |     vaddr      |     paddr      |     filesz     |     memsz      |     flags      |     align      |
|       4B       |       4B       |       4B       |       4B       |       4B       |       4B       |       4B       |       4B       |
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
```

For me, the most important fields in `Header` are `phoff` and `phentsize`,
since we can use these to index into the binary to locate the program headers.

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

Before putting each segment into its `Pheader::vaddr`, we have to understand,
that one doesn't simply `mmap` with `MAP_FIXED` or `MAP_NOREPLACE` into the
virtual address `0x8000`. The linux kernel won't let us, and rightfully so,
`man mmap` says:

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
- `translate` does what the diagram above shows

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
/// mapping applys the configuration of self to the current memory context by creating the
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

    // compute offset inside the mmaped slice where the segment should start
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

Decoding armv7 instructions seems doable at a glance, but
its a deeper rabbit-hole than i expected, prepare for a bit
shifting, implicit behaviour and intertwined meaning heavy
section:

Instructions are grouped into four top level sections:

1. Branch and control
2. Data processing
3. Load and store
4. Other (syscalls & stuff)

Each armv7 instruction is 32 bit in size, (in general) its
layout is as follows:

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

Since `cond` decides wheter or not the instruction is
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

## Immediate instructions

## Syscalls

# Emulating the CPU

## Instruction dispatch

## Forwarding Syscalls

### write

### The exception: `exit`
