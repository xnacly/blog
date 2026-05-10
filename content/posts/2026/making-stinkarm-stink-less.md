---
title: "Making stinkarm stink way less, or more?"
summary: "_start(), main(), table driven armv7 instr decoding, overengineered tooling and more"
date: 2026-05-10
draft: true
tags:
  - arm
  - rust
---

About half a year ago I wrote an article about implementing a userspace armv7
emulator from scratch, meaning I implemented:

- elf(32) parsing, validation and interpretation (into rust types)
- decoding of a very small subset of armv7 instructions
- executing said instructions, even conditional ones 🤓
- translating memory access from the guest into the host
- syscall forwarding (from armv7 to x86)
- syscall sandboxing (only a restricted syscall subset) and syscall deny

Do read [Building a Minimal Viable Armv7 Emulator from
Scratch](/posts/2025/building-a-minimal-viable-armv7-emulator/), since this
post doesnt go as deep into detail as the previous one.

# I overengineered the memory translation, its 32bit, just mmap 4Gigs

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

# Hardening the existing implementation

## Load at null

## Writing null

## Writing out of bounds

# To DSL or not, macros aint helping for the latter

Domain-specific language:

```rust
const DECODE_RULES: &[ArmRule] = &[
    arm_rule!(Svc {
        bits 27..24 = 0b1111,
    }),
    arm_rule!(Branch {
        bits 27..25 = 0b101,
    }),
    // LDR literal: `ldr Rt, [pc, #imm12]`.
    arm_rule!(LdrLiteral {
        bits 27..26 = 0b01, // load/store class
        bit 24 = 1,         // P: pre-indexed address
        bit 23 = 1,         // U: add positive offset
        bit 22 = 0,         // B: word transfer, not byte
        bit 21 = 0,         // W: no writeback
        bit 20 = 1,         // L: load, not store
        bits 19..16 = 15,   // Rn: base register is pc/r15
    }),
    // MOV immediate: data-processing immediate with opcode 1101.
    arm_rule!(MovImm {
        bits 27..25 = 0b001,
        bits 24..21 = Op::Mov as u32,
    }),
];
```
