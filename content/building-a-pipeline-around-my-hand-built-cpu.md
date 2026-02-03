---
title: "Building a Pipeline For My 8bit Cpu"
date: 2026-02-03
summary: "Assembler, disassembler and emulator for my own 8bit CPU"
draft: true
---

<!-- TODO: intro -->

Keep in mind all of this is a work in progress and I may iterate on the ideas
and the isa mentioned here.

# Defining the ISA

The `t8` processor is built around the idea of having four registers, each one
holding 8 bit:

| Register | Description          |
| -------- | -------------------- |
| AC       | Accumulator          |
| DEST     | Destination register |
| IR       | Instruction register |
| PC       | Program counter      |

The following instruction set is currently supported by the assembler, the
disassembler and the emulator:

| Mnemonic | Opcode | Operand | Description               |
| -------- | ------ | ------- | ------------------------- |
| NOP      | 0x0    | -       | No operation              |
| LOADI    | 0x1    | imm     | Load immediate into AC    |
| MOV      | 0x2    | -       | AC -> DEST                |
| ADD      | 0x3    | -       | DEST += AC                |
| SUB      | 0x4    | -       | DEST -= AC                |
| ST       | 0x5    | addr    | write AC into addr        |
| LD       | 0x6    | imm     | load byte at addr into AC |
| ROL1     | 0x7    | -       | Rotate AC left by 1 bit   |
| HALT     | 0x8    | -       | Stop CPU                  |
| JMP      | 0x9    | -       | PC = AC                   |

Instructions are encoded by setting the opcode in the upper 4 bits and an
immediate value in the lower 4 bits.

As a rust enum:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    NOP,
    LOADI { imm: u8 },
    MOV,
    ST { addr: u8 },
    LD { addr: u8 },
    ADD,
    SUB,
    ROL1,
    HALT,
    JMP,
}
```

So encoding and decoding is as simple as:

```rust
impl Instruction {
    pub fn encode(&self) -> Option<u8> {
        Some(match self {
            Instruction::NOP => 0x00,
            Instruction::LOADI { imm } => {
                (0x1 << 4) | if *imm > 0xF {
                    return None
                } else {
                    imm & 0xF
                }
            }
            Instruction::MOV => 0x2 << 4,
            Instruction::ADD => 0x3 << 4,
            Instruction::SUB => 0x4 << 4,
            Instruction::ST { addr } => {
                (0x5 << 4) | if *addr > 0xF {
                    return None
                } else {
                    addr & 0xF
                }
            }
            Instruction::LD { addr } => {
                (0x6 << 4) | if *addr > 0xF {
                    return None
                } else {
                    addr & 0xF
                }
            }
            Instruction::ROL1 => 0x70,
            Instruction::HALT => 0x80,
            Instruction::JMP => 0x90,
        })
    }

    pub fn decode(b: u8) -> Result<Self, &'static str> {
        let op = b >> 4;
        let imm = b & 0xF;
        Ok(match op {
            0x0 => Self::NOP,
            0x1 => Self::LOADI { imm },
            0x2 => Self::MOV,
            0x3 => Self::ADD,
            0x4 => Self::SUB,
            0x5 => Self::ST { addr: imm },
            0x6 => Self::LD { addr: imm },
            0x7 => Self::ROL1,
            0x8 => Self::HALT,
            0x9 => Self::JMP,
            _ => return Err("unknown operator"),
        })
    }
}

impl TryFrom<u8> for Instruction {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::decode(value)
    }
}
```

Thus something like `HALT` gets encoded as `0x80 (op=0x80, imm=0x0)`, while
`LOADI 5` is encoded as `0x15 (op=0x10, imm=0x5)`.

# Building a minimalist Assembler

An _assembler_ **assembles** ***assembly*** instructions into an executable :^). We aren't
talking ELF32 or anything (except a `t8cpu` magic identifier); It is just going
to be a list of bytes, each representing an instruction. For instance something
like:

```armasm
; test.t8
loop:
    LOADI loop
    JMP
```

Will assemble to:

```text
$ hexdump -C test.t8b
00000000  74 38 63 70 75 10 90                              |t8cpu..|
00000007
```

And disassemble to:

```armasm
; magic=t8cpu
; size=2

; 0000: 0x10 (op=0x10, imm=0x0)
MOV 0
; 0001: 0x90 (op=0x90, imm=0x0)
JMP
```

## The assembler pipeline

The pipeline consists of:

1. convert the concepts of the input file (labels, constants, instructions) into tokens
2. create an abstract syntax tree (AST) from these tokens
3. lower the AST to instructions
4. write the instructions encoded into a file

Lets use the below example for highlighting the output of each stage:

```armasm
; vim: filetype=asm
;
; simple example of blinking an io mapped led,
; either single or 8bit addressed via 1 byte led array.
;
; Assemble via: cargo run -p as examples/led.t8
; Emulate via: cargo run -p emu examples/led.t8.t8b

.const led 0xF
.const off 0
.const on 1

; Write 1 to LED
    LOADI on
    ST [led]        ; AC -> mem[0xF]

; Toggle LED off
    LOADI off
    ST [led]

; Demonstrate writing a pattern to multiple LEDs
    LOADI #0xD      ; AC = 0b1101
    ST [led]        ; write pattern to mem[0xF]

    HALT
```

For the _unassembled_ crowd, here are some (maybe unknown) concepts explained:

- `;` a line comment
- `[<literal>]`: treats `literal` as an addr
- `.const <name> <value>`: creates a constant of `name` resolving to `value`,
  all `name` usages are resolved to `value`
- `#<literal>`: a literal value

### Assembly to Tokens

The first step of tokenizing an input is of course to define a set of tokens
the set of bytes in our input should be resolved to:

```rust
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Token<'tok> {
    pub line: usize,
    pub col: usize,
    pub inner: TokenInner<'tok>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum TokenInner<'tok> {
    Eof,
    Ident(&'tok [u8]),
    /// .<builtin>
    Builtin(&'tok [u8]),
    /// \#
    Hash,
    /// [
    LeftBraket,
    /// ]
    RightBraket,
    /// :
    Colon,
    Number(u8),
}
```

### Tokens to AST

### Lowering the AST to Instructions

### Dumping encoded Instructions

## Put together

```armasm
; vim: filetype=asm
;
; simple example of blinking an io mapped led, either single or 8bit addressed
; via 1 byte led array.
;
; Assemble via: cargo run -p as examples/led.t8
; Emulate via: cargo run -p emu examples/led.t8.t8b

.const led 0xF
.const off 0
.const on 1

; Write 1 to LED
    LOADI on
    ST [led]        ; AC -> mem[0xF]

; Toggle LED off
    LOADI off
    ST [led]

; Demonstrate writing a pattern to multiple LEDs
    LOADI #0xD      ; AC = 0b1101
    ST [led]        ; write pattern to mem[0xF]

    HALT
```

# Disassembling

# Emulation and Memory mapped devices

# Side note: Good error messages

# Examples
