---
title: "Purple Gardens Register Allocator"
summary: "schalom"
date: 2026-10-22T15:10:03+02:00
draft: true
tags:
  - rust
  - pldev
---

> This is sort of a mix between a dev log and an explaination how purple gardens
> xralloc2 register allocator works and how it is integrated into its pipeline.

Register allocation is assigning the unlimited amount of virtual registers to
the limited set of storage resources hardware has, specifically the gprs
(general purpose registers), the fprs (floating point registers) and the stack
(see [CPU Registers x86](https://wiki.osdev.org/CPU_Registers_x86) for an
examplary overview).

THe simplest, yet somewhat non trivial example would be:

```garden
fn f(a:Int n:Int acc:Int) Int {
    match {
        n < 1 { a + acc }
        { f(a n-1 acc*n) }
    }
}
```

This is equiv to the following c code, which i "disassembled" from the very
well written [Linear scan register allocation on
SSA](https://bernsteinbear.com/blog/linear-scan/) article by Max Bernstein[^maxthegoat], in
which i didnt really understand the IR display, before translating it to c and
then to my own language (purple garden does not have loops 🤓):

[^maxthegoat]: Thats the [Z|Y]JIT guy btw

```c
long f(long a, long n) {
    long acc = 1;
    while (n >= 1) {
        acc = acc * n;
        n = n - 1;
    }
    return a + acc;
}
```

Feeding `f(a,n,acc: Int): Int` into purple gardens pipeline produces the
following, optimised immediate representation (using `-I`) [^optimised]:

[^optimised]:
    Optimised here means: inline immediates for comparisons and
    arithmetics, tailcalls and removed blocks just used for indirect returns

```llvm
;; f
fn f1(%v0:Int, %v1:Int, %v2:Int) -> Int {
        b0(%v0, %v1, %v2):
                %v4:Bool = ILt %v1, 1
                br %v4, b1(%v0, %v1, %v2), b2(%v0, %v1, %v2)
        b1(%v0, %v1, %v2):
                %v5:Int = IAdd %v0, %v2
                ret %v5
        b2(%v0, %v1, %v2):
                %v7:Int = ISub %v1, 1
                %v8:Int = IMul %v2, %v1
                tail f1(%v0, %v7, %v8)
}
```

## PUrple garden IR structure and notation

Purple gardens immediate representation is [static single assigment
(SSA)](https://en.wikipedia.org/wiki/Static_single-assignment_form) form based,
meaning each value / virtual register is assigned exactly once and all are
immutable. They are notated with `%vN`, for virtual register or value, whatever
you (the reader) like more.

Compared to many other ssa irs, pgir does not use phi nodes, it is made up of
blocks, where each block has a list of parameters, a terminator and a body of
instructions, where each instruction is in ssa form:

```llvm
; block with id N
; |
; v
  b2(%v0, %v1, %v2):
;    ^^^^^^^^^^^^^ parameters 0..2

;     value / virtual reg def
;      |        instr kind
;      |        |
;      v        v
      %v7:Int = ISub %v1, 1 ; <-- imm value
;         ^           ^ argument
;         |
;         instr result type

;     terminator with params
      tail f1(%v0, %v7, %v8)
```

Or in rust terms:

```rust
pub struct Block<'b, A: Allocator = Global> {
    pub id: Id,
    pub instructions: Vec<Instr<'b>, A>,
    pub params: ParamsId,
    pub term: Option<Terminator>,
    // [...]
}

pub enum Instr<'i> {
    BinImm {
        op: BinOp,
        dst: TypeId<'i>,
        lhs: Id,
        imm: i32,
    },
    // [...]
    Noop,
}

pub enum Terminator {
    Return {
        value: Option<Id>,
    },
    // [...]
    Tail {
        func: Id,
        args: ParamsId,
    },
    // [...]
}
```

Pretty easy right?

## Values and their lifetimes

The first step to do reg alloc, is livelyness analsis.

LEts look at the previous IR example, but this time with virtual register
lifetime annotations (when the cli is invoked with `-II`):

```llvm
;; f                                   %v0 %v1 %v2 %v4 %v5 %v7 %v8
b0(%v0, %v1, %v2):                     ;|   |   |
    %v4:Bool = ILt %v1, 1              ;|   |   |   |
    br %v4, b1(%v0, %v1, %v2), b2(...) ;|   |   |   |
b1(%v0, %v1, %v2):                     ;|   |   |
    %v5:Int = IAdd %v0, %v2            ;|   |   |       |
    ret %v5                            ;|   |   |       |
b2(%v0, %v1, %v2):                     ;|   |   |
    %v7:Int = ISub %v1, 1              ;|   |   |           |
    %v8:Int = IMul %v2, %v1            ;|   |   |           |   |
    tail f1(%v0, %v7, %v8)
```

This display enables a visual understanding of the livetimes of each value:

| value | lo  | hi  |
| ----- | --- | --- |
| v0    | 0   | 8   |
| v1    | 1   | 8   |
| v2    | 2   | 8   |
| v4    | 4   | 4   |
| v5    | 5   | 5   |
| v7    | 7   | 8   |
| v8    | 8   | 8   |
