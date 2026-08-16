---
title: "Making stinkarm stink way less, or more?"
summary: "removing overengineered memory translation, hardening and new table driven armv7 instr decoding"
date: 2026-05-10
draft: true
tags:
  - arm
  - rust
---

![acorn, armv7-a and stinkarm](/stinkarm/stinkarm.png)[^1]

[^1]:
    Both the pixel art heading and all the
    bullshit in this article is brainslob, nothing
    was produced by a clanker.

Its been a while, but about half a year ago I wrote an article about
implementing a userspace armv7 emulator from scratch, meaning I implemented:

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

Or as a list:

- elf(32) parsing, validation and interpretation
- decoding of a very small subset of armv7 instructions (only 3)
- executing said instructions, even conditional ones 🤓
- translating memory access from the guest into the host
- syscall forwarding (from armv7 to x86)
- syscall sandboxing (only a restricted syscall subset) and denying syscall execution

Do read [Building a Minimal Viable Armv7 Emulator from
Scratch](/posts/2025/building-a-minimal-viable-armv7-emulator/), since this
post doesnt go as deep into detail as the previous one (It's my first article
in 3 months I had enough motivation for writing :O). This is partially an
update, partially my toughts on decoding and emulating armv7-a and also a bit
of a devlog.

# Overly complex host to guest mem translation

On the first article, [~aengelke on
lobste.rs](https://lobste.rs/s/bv3570/building_minimal_viable_armv7_emulator),
had some comments, the one resonating the most was:

> [...]
> The Mem indirection seems pretty inefficient. When emulating 32-bit platforms
> on a 64-bit system, just mmap a 4 GiB region, the translation then becomes a
> single addition. Otherwise, having a small hash table of recently translated
> address regions can avoid more expensive searches -- memory accesses have a
> very high locality. The number of mappings is usually small, so binary search
> over a sorted array is simpler than a B-tree.
> [...]

So now i figured, why not improve on my implementation a bit, first with
replacing the complex allocation region based tracking with just allocating a
4gig slab in memory for the guest, mapping the process regions there and
handing out pointers into that region to the guest.

So, previously the memory translation worked as follows:

1. One takes a binary tree map of a guest starting addr to its host segment

   ```rust
   struct MappedSegment {
       host_ptr: *mut u8,
       len: u32,
   }

   pub struct Mem {
       maps: BTreeMap<u32, MappedSegment>,
   }
   ```

2. On ask for a region handout, specifically on mapping ELF segments with a
   starting addr, `map_region` is called:

   ```rust
   // in stinkarm::elf::pheader::Pheader::map:

   // record mapping in guest memory table, so CPU can translate guest vaddr to host pointer
   guest_mem.map_region(self.vaddr, len, segment_ptr);

   // in stinkarm::mem::Mem:

   pub fn map_region(&mut self, guest_addr: u32, len: u32, host_ptr: *mut u8) {
       self.maps
           .insert(guest_addr, MappedSegment { host_ptr, len });
   }
   ```

3. Since the cpu needs to fetch an instruction, there is `read_u32`, calling `translate`:

   ```rust
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


   // in stinkarm::cpu::Cpu:

   pub fn step(&mut self) -> Result<bool, err::Err> {
       let Some(word) = self.mem.read_u32(self.pc()) else {
           return Ok(false);
       };

       // [...]
   }
   ```

Of course this totally unnecessary work, we dont need to keep track of every
mapping/allocation/region by walking their ranges, we only need to make sure
the R/W interaction request is within bounds. Thus the new implementation is:

1. One takes a pointer and a size:

   ```rust
   pub struct Mem {
       ptr: NonNull<u8>,
       len: usize,
   }
   ```

2. When asked to map ELF segments, `stinkarm::mem::Mem::map_region` is called:

   ```rust
   // in stinkarm::elf::pheader::Pheader::map:
   guest_mem.map_region(self.vaddr, file_slice)?;

   // in stinkarm::mem::Mem:

   pub fn map_region(&mut self, guest_addr: u32, data: &[u8]) -> Result<(), String> {
       let dst = self
           .get_slice_mut(guest_addr, data.len())
           .ok_or_else(|| format!("guest region out of bounds at {guest_addr:#010x}"))?;
       dst.copy_from_slice(data);
       Ok(())
   }
   ```

3. When cpu requests a dword for decoding, it does so by invoking
   `stinkarm::mem::Mem::read32`, just as before, only this time with
   bounds checks:

   ```rust
   pub fn read_u32(&self, guest_addr: u32) -> Option<u32> {
       let bytes = self.get_slice(guest_addr, 4)?;
       Some(u32::from_le_bytes(bytes.try_into().unwrap()))
   }

   fn get_slice(&self, guest_addr: u32, len: usize) -> Option<&[u8]> {
       if !self.in_bounds(guest_addr, len) {
           return None;
       }

       Some(unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(guest_addr as usize), len) })
   }
   ```

# Hardening the existing implementation

I also noticed I have a lot of stuff that (even with the small surface of just
the `write.2` and `exit.2` syscalls, `ldr`, `mov` and `svc`) could enable
translating untrusted guest adresses into host mem access.

Preventing this via checking the validity of the address passed to `write.2`,
we do this while translating guest addresses to host memory space in
`stinkarm::mem::Mem` with a `in_bounds` call inside the `translate_range` call:

```rust
const NULL_PAGE_SIZE: u32 = 0x1000;

impl Mem {
    fn in_bounds(&self, guest_addr: u32, len: usize) -> bool {
        if guest_addr < NULL_PAGE_SIZE {
            return false;
        }

        let start = guest_addr as usize;
        let Some(end) = start.checked_add(len) else {
            return false;
        };

        end <= self.len
    }

    pub fn translate_range(&self, guest_addr: u32, len: usize) -> Option<*mut u8> {
        if !self.in_bounds(guest_addr, len) {
            return None;
        }

        Some(self.ptr.as_ptr().wrapping_add(guest_addr as usize))
    }
}
```

I added multiple tests for making sure I correctly catch writing a null
pointer, writing out of guest memory and loading elf segments at 0x0:

```armasm
    .section .rodata
msg:
    .ascii "ignored"

    .section .text
    .global _start
_start:
    mov r0, #1
    mov r1, #0
    mov r2, #7
    mov r7, #4
    svc #0

    mov r0, #0
    mov r7, #1
    svc #0
```

```armasm
    .section .rodata
msg:
    .ascii "ignored"

    .section .text
    .global _start
_start:
    mov r0, #1
    ldr r1, =0x08000000
    mov r2, #7
    mov r7, #4
    svc #0

    mov r0, #0
    mov r7, #1
    svc #0
```

# To DSL or not

Previously I hardcoded every opcode and its fields
to decode them into a rust representation, now only
the opcode is subject to decoding. This is achived
with a nice looking compiletime constant list of
patterns:

```rust
const DECODE_RULES: &[ArmRule] = &[
    arm_rule!(Svc {
        bits(27..24 = 0b1111),
    }),
    arm_rule!(Branch {
        bits(27..25 = 0b101),
    }),
    // LDR literal: `ldr Rt, [pc, #imm12]`.
    arm_rule!(LdrLiteral {
        bits(27..26 = 0b01), // load/store class
        bit(24 = 1),         // P: pre-indexed address
        bit(23 = 1),         // U: add positive offset
        bit(22 = 0),         // B: word transfer, not byte
        bit(21 = 0),         // W: no writeback
        bit(20 = 1),         // L: load, not store
        bits(19..16 = 15),   // Rn: base register is pc/r15
    }),
    // MOV immediate: data-processing immediate with opcode 1101.
    arm_rule!(MovImm {
        bits(27..25 = 0b001),
        bits(24..21 = Op::Mov as u32),
    }),
];
```

> If youre interested in ARMv7 instruction encoding I can recommend the [ARM®
> Architecture Reference Manual ARMv7-A and ARMv7-R
> edition](https://documentation-service.arm.com/static/5f8daeb7f86e16515cdb8c4e)

The macro itself builds a bit pattern that can then be used with a simple AND
bit instruction to detect:

```rust
macro_rules! arm_rule {
    ($kind:ident { $($field:ident($($args:tt)*)),* $(,)? }) => {
        ArmRule {
            kind: InstructionKind::$kind,
            mask: 0 $(| arm_mask!($field($($args)*)))*,
            value: 0 $(| arm_value!($field($($args)*)))*,
        }
    };
}

macro_rules! arm_mask {
    (bit($bit:literal = $value:expr)) => {
        1u32 << $bit
    };
    (bits($high:literal .. $low:literal = $value:expr)) => {
        ((1u32 << ($high - $low + 1)) - 1) << $low
    };
}

macro_rules! arm_value {
    (bit($bit:literal = $value:expr)) => {
        ($value as u32) << $bit
    };
    (bits($high:literal .. $low:literal = $value:expr)) => {
        ($value as u32) << $low
    };
}
```

`MovImm`'s definition does therefore produce (`Op::mov` is defined as
`0b1101`):

```rust
ArmRule {
    kind: InstructionKind::MovImm,
    mask: 0 
        | ((1u32 << (27 - 25 + 1)) - 1) << 25 
        | ((1u32 << (24 - 21 + 1)) - 1) << 21,
    value: 0 
        | (0b001 as u32) << 25 
        | ((Op::Mov as u32) as u32) << 21,
}


impl ArmRule {
    fn matches(&self, word: u32) -> bool {
        (word & self.mask) == self.value
    }
}
```

All rules are then iterated for each 32bit word and decoded:


```rust
pub fn decode_word(word: u32) -> Decoded {
    let cond = bits(word, 31, 28) as u8;
    let kind = DECODE_RULES
        .iter()
        .find(|rule| rule.matches(word))
        .map(|rule| rule.kind)
        .unwrap_or(InstructionKind::Unknown);

    Decoded {
        cond,
        kind,
        raw: word,
    }
}
```

I know a trie or something would probably be faster, but this is nice to read,
understandable and easy to maintain.


# Full decoding only on demand

Previous to the instruction DSL, I decoded all necessary values for all
instructions at all times, meaning short instructions would decode even if they
didnt match, just as a sideeffect of attempting to figure out what instruction.
The DSL allows only decoding the op code and letting the cpu decode only what
it needs via `decoder::{decode_word,bit,bits,sign_extend,rotated_imm}`, where
bit and bits enable partial access into the word, and decode_word returns the
op code, the condition and the raw word itself for further processing in the
cpu emulation:

```rust
/// fetch-decode-execute step, will only return false on exit svc
pub fn step(&mut self) -> Result<bool, err::Err> {
    // [...] fetch word

    let Decoded { kind, cond, raw } = decoder::decode_word(word);

    // [...]

    match kind {
        InstructionKind::MovImm => {
            let rd = decoder::bits(raw, 15, 12) as usize;
            let imm12 = decoder::bits(raw, 11, 0);
            // [...]
        }
        // [...]
        InstructionKind::LdrLiteral => {
            let rd = decoder::bits(raw, 15, 12) as usize;
            let imm12 = decoder::bits(raw, 11, 0);

            // [...]
        }
    }
}
```

Bits and bit access is obvious, sign_extend and rotated_imm maybe less so:

```rust
pub fn bits(word: u32, high: u8, low: u8) -> u32 {
    debug_assert!(high < 32);
    debug_assert!(low <= high);
    let width = high - low + 1;
    (word >> low) & ((1 << width) - 1)
}

pub fn bit(word: u32, bit: u8) -> bool {
    bits(word, bit, bit) != 0
}

pub fn sign_extend(value: u32, bits: u32) -> i32 {
    debug_assert!((1..=32).contains(&bits));

    let shift = 32 - bits;
    ((value << shift) as i32) >> shift
}

pub fn rotated_imm(imm12: u32) -> u32 {
    let rotate = ((imm12 >> 8) & 0b1111) * 2;
    (imm12 & 0xff).rotate_right(rotate)
}
```

# Supporting B and BL

B and BL are the unconditial branching instructions of the ARMv7 isa:

- Branching unconditionally:

    ```armasm
    .text
        .global _start
    _start:
        mov	r0, #0
        b	1f
        mov	r0, #1		@ must NOT execute
    1:
        mov	r7, #1
        svc	#0
    ```

- Branching unconditionally with link:

    ```armasm
    .text
        .global _start
    _start:
        mov	r0, #0
        bl	foo
        mov	r7, #1
        svc	#0
    foo:
        mov	r0, #42
        mov	r7, #1
        svc	#0
    ```

B and BL encode:

1. Conditionals, see [ARMv7 Condition code suffixes](https://support.arm.com/documentation/den0042/0100/Unified-Assembly-Language-Instructions/Instruction-set-basics/Conditional-execution?lang=en#md260-conditional-execution__tbl_cond_code_suffixes)
2. Instruction group (`101`)
3. Wheter or not to branch with link (`L`)
4. Target (imm24)

In bits:

```text
 31 30 29 28 27 26 25 24 23 .. 0
|cond       |1  0  1 |L | imm24 |
```

Meaning, its fairly easy to implement, see below. L instructs the emulator to
save the return addr to the **L**ink**R**egister (LR) and otherwise we just
decode the imm24, shift it 2 to the left and then sign extend it to 32 bit, add
it to the program counter and thats it:


```rust
InstructionKind::Branch => {
    let l = decoder::bit(raw, 24);
    // BL
    if l {
        // save return addr to LR (next addr though)
        self.r[14] = self.instr_addr().wrapping_add(4);
    }

    let imm24 = decoder::bits(raw, 23, 0);
    let imm26 = imm24 << 2;
    let imm32 = decoder::sign_extend(imm26, 26);

    self.r[15] = self.arm_pc().wrapping_add(imm32 as u32);
}
```

# Testing "frame(work)"

To test all the hardening stuff and every new instructions I intent to support,
i added a bit of tooling, specifically srun, its a small stinkarm wrapper to
build, link and execute assembly or c files:

```text
Build, link, and execute an ARM assembly or C file with stinkarm

Usage: srun [OPTIONS] <INPUT> [-- <EMULATOR_ARGS>...]

Arguments:
  <INPUT>             ARM assembly or C file to run
  [EMULATOR_ARGS]...  Extra arguments passed to stinkarm before the generated ELF path

Options:
      --text-addr <TEXT_ADDR>  Guest address used as the linker text address [default: 0x8000]
      --out-dir <OUT_DIR>      Directory for generated object and ELF files [default: target/srun]
      --dump-asm               Print the linked ARM disassembly before running the emulator
  -h, --help                   Print help
```

For instance previously I had to first assemble the `examples/branch.S` file,
then invoke stinkarm, now i can just:

```shell
cargo run --bin srun 
    # arguments for srun
    \ -- examples/helloWorld.S 
    # arguments for stink arm, log instructions and syscalls
    \ -- -linstructions -lsyscalls
```

```text
[     0.538ms] MovImm 1110 E3A00001
[     0.543ms] LdrLiteral 1110 E59F1014
[     0.545ms] MovImm 1110 E3A0200E
[     0.548ms] MovImm 1110 E3A07004
[     0.551ms] Svc 1110 EF000000
65174 write(fd=1, buf=0x8024, len=14) [sandbox]
Hello, world!
=14
[     0.567ms] MovImm 1110 E3A00000
[     0.570ms] MovImm 1110 E3A07001
[     0.573ms] Svc 1110 EF000000
65174 exit(code=0) [sandbox]
=0
```

So yeah, thats it, now please enjoy me bashing in a claude server rack: 

![claude](/stinkarm/claude-ze-fucker.png)
