---
title: "An ode to livelyness analysis"
summary: "Liveness analysis performed on strict block based IR with ssa form instructions"
date: 2026-10-22T15:10:03+02:00
draft: true
tags:
  - rust
  - pldev
---

> Or a loveletter? Read this while listening to Ode to Joy, also look at this awesome pixelart i did just for this article:
>
> ![livelyness analysis](/livelyness/icon.png)

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

# A short but sweet implementation:

With that out of the way the algorithm amounts to a simple:

1. walk blocks
2. visit terminator, observe all virtual register usages  
3. visit instructions in reverse, observe all virtual register definition and usages
4. visit parameters to block, observe each

## Observing

Where observing is defined as:

- with tuple `(lo,hi)` and `pos`
- if `hi==0`; set `hi=pos`
- `lo=pos`

In oxidised terms: 

```rust
/// observer Id := (lo,hi), always updates lo, only fills hi, if previously unset
fn observe<V: Allocator>(out: &mut Vec<(u32, u32), V>, id: Id, pos: u32) {
    let idx = id.0 as usize;
    if idx >= out.len() {
        out.resize(idx + 1, UNSET);
    }
    let e = &mut out[idx];
    if e.1 == 0 {
        e.1 = pos;
    }
    e.0 = pos;
}
```

## Helpers to help with defs and usages:

<!-- TODO: add def_of, for_each etc here -->

## Fully rusted:

A few quick context injectors:

- out is a reusable Vec allocated in the V allocator, thats why its reset and resized
- UNSET is used as the default empty value
- `for_each_use_of_term` and  `for_each_use_of_instr` calls Fn on each use of a virtual register in the given IR concept
- `Func::def_of` returns a definition of a virtual register, if it has one

```rust
pub fn live_set_into<V: Allocator>(&self, out: &mut Vec<(u32, u32), V>) {
    const UNSET: (u32, u32) = (u32::MAX, 0u32);

    out.clear();
    out.resize(self.next_id() as usize, UNSET);

    // observe defined as before


    let mut base = 0;
    for block in self.blocks.iter().filter(|b| !b.tombstone) {
        let block_offset = block.instructions.len();
        let offset = base;
        if let Some(term) = &block.term {
            self.for_each_use_of_term(term, |id| {
                // term is instruction count +1
                observe(out, id, (offset + block_offset + 1) as u32)
            });
        }

        for (i, instr) in block.instructions.iter().enumerate().rev() {
            // +1, so it cant start at 0, since thats where the params start :)
            let pos = (base + 1 + i) as u32;
            self.for_each_use_of_instr(instr, |id| observe(out, id, pos));
            if let Some(def) = Func::def_of(instr) {
                observe(out, def, pos)
            }
        }

        for &p in self.params(block.params) {
            observe(out, p, base as u32);
        }

        // params + instructions + terminator
        base += block_offset + 2;
    }
}
```
