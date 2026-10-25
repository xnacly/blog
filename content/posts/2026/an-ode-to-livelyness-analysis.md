---
title: "An ode to livelyness analysis"
summary: "Livelyness analysis performed on strict block based IR with ssa form instructions"
date: 2026-10-22T15:10:03+02:00
draft: true
tags:
  - rust
  - pldev
---

> Or a loveletter? Read this while listening to Ode to Joy

Register allocation is assigning the unlimited amount of virtual registers to
the limited set of storage resources hardware has, specifically the gprs
(general purpose registers), the fprs (floating point registers) and the stack
(see [CPU Registers x86](https://wiki.osdev.org/CPU_Registers_x86) for an
examplary overview). The first step in this odeal is livelyness analsis.

# A garden(ing) example

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
```

# PUrple garden IR structure and notation

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

# Values and their lifetimes

The first step to do reg alloc,

LEts look at the previous IR example, but this time with virtual register
lifetime annotations (when the cli is invoked with `-II`):

```llvm
```

This display enables a visual understanding of the livetimes of each value,
encoded as lo for start, and hi for last, both are ir instr indizes:

| value | lo  | hi  |
| ----- | --- | --- |
| v0    | 0   | 6   |
| v1    | 0   | 5   |
| v2    | 0   | 5   |
| v4    | 0   | 1   |
| v5    | 2   | 3   |
| v7    | 4   | 6   |
| v8    | 5   | 6   |
