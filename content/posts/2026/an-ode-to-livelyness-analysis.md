---
title: "An ode to livelyness analysis; SSA to registers"
summary: "Liveness analysis on block local SSA IR + a bit of ralloc for a vm and an x86 jit"
date: 2026-11-07
tags:
  - rust
  - pldev
---

> Or a loveletter? Read this while listening to Ode to Joy, also look at this awesome pixelart i did just for this article:
>
> ![livelyness analysis](/livelyness/icon.png)
> _its analyzing a life_ 🤓

I am currently working on register allocation for both my register based
bytecode virtual machine and my x86 just in time compiler, both for my
programming language [purple-garden](https://github.com/xnacly/purple-garden).

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

This is equiv to the following c code, which i "disassembled"
from the very well written [Linear scan register allocation on
SSA](https://bernsteinbear.com/blog/linear-scan/) article by Max
Bernstein[^maxthegoat], in which i didnt really understand the
IR display, before translating it to c and then to my own
language (purple garden does not have loops 🤓 so this is only
equiv when called with `f(a n 1)`):

[^maxthegoat]: Thats the [Z|Y]JIT guy btw, absolutely insane articles, everyone interested in anything compiler related should have read at least twice

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

Feeding `f(a,n,acc: Int): Int` into purple gardens pipeline
produces the following, optimised immediate representation
(using `-I`), this means some values were dead and thus removed [^optimised]:

[^optimised]:
    Optimised here means: inline immediates for comparisons and
    arithmetics, tailcalls and removed blocks just used for indirect returns

```llvm
fn f1(%v0:Int, %v1:Int, %v2:Int) -> Int {
        b0(%v0, %v1, %v2):
                %v4:Bool = ILt %v1, 1
                br %v4, b1(%v0, %v1, %v2), b2(%v0, %v1, %v2)
        b1(%v5, %v6, %v7):
                %v8:Int = IAdd %v5, %v7
                ret %v8
        b2(%v9, %v10, %v11):
                %v13:Int = ISub %v10, 1
                %v14:Int = IMul %v11, %v10
                tail f1(%v9, %v13, %v14)
}
```

# PUrple garden IR structure and notation

Purple gardens immediate representation is [static single assigment
(SSA)](https://en.wikipedia.org/wiki/Static_single-assignment_form) form based,
meaning each value / virtual register is assigned exactly once and all are
immutable. They are notated with `%vN`, for virtual register or value, whatever
you (the reader) like more.

Compared to many other ssa irs, pgir does not use phi nodes. I opted for block
params and terminators instead. It is made up of blocks, where each block has a
list of parameters, a terminator and a body of instructions, where each
instruction is in ssa form. All values are block local and the only
interblock dataflow is facilitated via block params and block terminators.

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

# Virtual registers / Values and their lifetimes

LEts look at the previous IR example, but this time with virtual register
lifetime annotations (when the cli is invoked with `-II`):

```llvm
fn f1(%v0:Int, %v1:Int, %v2:Int) -> Int {             %v0 %v1 %v2 %v4 %v5 %v7 %v8 %v9 %v10 %v11 %v13 %v14
    b0(%v0, %v1, %v2):                                |   |   |
        %v4:Bool = ILt %v1, 1                         |   |   |   |
        br %v4, b1(%v0, %v1, %v2), b2(%v0, %v1, %v2)  |   |   |   |
    b1(%v5, %v6, %v7):                                                |   |
        %v8:Int = IAdd %v5, %v7                                       |   |   |
        ret %v8                                                               |
    b2(%v9, %v10, %v11):                                                          |   |    |
        %v13:Int = ISub %v10, 1                                                   |   |    |    |
        %v14:Int = IMul %v11, %v10                                                |   |    |    |    |
        tail f1(%v9, %v13, %v14)                                                  |             |    |
}
```

This display enables a visual understanding of the livetimes of
each value, encoded as lo for start, and hi for last, the
following enables a non visual understanding: (The positions are
linearised: block params are at the block base, block instructions are
at block base+1+instr pos and terminators are at block base+instr count+1)

| value | lo  | hi  |
| ----- | --- | --- |
| %v0   | 0   | 2   |
| %v1   | 0   | 2   |
| %v2   | 0   | 2   |
| %v4   | 1   | 2   |
| %v5   | 3   | 4   |
| %v7   | 3   | 4   |
| %v8   | 4   | 5   |
| %v9   | 6   | 9   |
| %v10  | 6   | 8   |
| %v11  | 6   | 8   |
| %v13  | 7   | 9   |
| %v14  | 8   | 9   |

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
    let e = &mut out[idx];
    if e.1 == 0 {
        e.1 = pos;
    }
    e.0 = pos;
}
```

## Helpers to help with defs and usages:

Asking for defs and uses in instructions and terminators: 

### Extracting definitions 

What it says, `Func::def_of` returns a definition of a virtual register, if
`instr` has one:

```rust
impl Func<'_> {
    #[must_use]
    pub fn def_of(instr: &Instr<'_>) -> Option<Id> {
        match instr {
            Instr::Alloc { dst, .. }
            | Instr::Load { dst, .. }
            | Instr::AddrOf { dst, .. }
            | Instr::Bin { dst, .. }
            | Instr::BinImm { dst, .. }
            | Instr::LoadConst { dst, .. }
            | Instr::Call { dst, .. }
            | Instr::Sys { dst, .. }
            | Instr::Cast { dst, .. }
            | Instr::Lookup { dst, .. }
            | Instr::Assert { dst, .. } => Some(dst.id),
            Instr::Store { .. } | Instr::Noop => None,
        }
    }
}
```


### Calling f for each usage of value in an instruction

What it says, calling f for each value usage in an instruction

```rust
pub fn for_each_use_of_instr(&self, instr: &Instr<'_>, mut f: impl FnMut(Id)) {
    match instr {
        Instr::Bin { lhs, rhs, .. } => {
            f(*lhs);
            f(*rhs);
        }
        Instr::BinImm { lhs, .. } => f(*lhs),
        Instr::Call { args, .. } | Instr::Sys { args, .. } => {
            for &a in self.params(*args) {
                f(a);
            }
        }
        Instr::Cast { from, .. } => f(from.id),
        Instr::Lookup { subject, .. } => f(*subject),
        Instr::Store { src, base, .. } => {
            f(*src);
            f(*base);
        }
        Instr::Assert { cond, .. } => f(*cond),
        Instr::Load { base, .. } | Instr::AddrOf { base, .. } => f(*base),
        Instr::LoadConst { .. } | Instr::Noop | Instr::Alloc { .. } => {}
    }
}
```

### Calling f for each usage of value in a terminator

What it says, calling f for each value usage in a terminator

```rust
pub fn for_each_use_of_term(&self, term: &Terminator, mut f: impl FnMut(Id)) {
    match term {
        Terminator::Return {
            value: Some(id), ..
        } => f(*id),
        Terminator::Return { value: None, .. } => {}
        Terminator::Jump { params, .. } => {
            for &p in self.params(*params) {
                f(p);
            }
        }
        Terminator::Tail { args, .. } => {
            for &a in self.params(*args) {
                f(a);
            }
        }
        Terminator::Switch {
            subject,
            cases,
            default: (_, default_params),
            ..
        } => {
            f(*subject);
            for case in self.cases(*cases) {
                for &p in self.params(case.target.1) {
                    f(p);
                }
            }
            for &p in self.params(*default_params) {
                f(p);
            }
        }
        Terminator::Branch {
            cond,
            yes: (_, yes_params),
            no: (_, no_params),
            ..
        } => {
            f(*cond);
            for &p in self.params(*yes_params) {
                f(p);
            }
            for &p in self.params(*no_params) {
                f(p);
            }
        }
        Terminator::BranchCmpImm {
            lhs,
            yes: (_, yes_params),
            no: (_, no_params),
            ..
        }
        | Terminator::BranchCmp {
            lhs,
            yes: (_, yes_params),
            no: (_, no_params),
            ..
        } => {
            f(*lhs);
            if let Terminator::BranchCmp { rhs, .. } = term {
                f(*rhs);
            }
            for &p in self.params(*yes_params) {
                f(p);
            }
            for &p in self.params(*no_params) {
                f(p);
            }
        }
    }
}
```

## Fully rusted together:

A few quick context injectors:

- out is a reusable Vec allocated in the V allocator, thats why its reset and resized
- UNSET is used as the default empty value
- Func::next_id() returns the highest id defined in the function (self)+1

```rust
impl<A: Allocator> Func<'_, A> {
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
}
```

# Wiring liveset analysis into register allocation for the bytecode backend

Since we now know where what value is alive and where it is to be considered
dead we can pass this information to the register allocator and ask it for the
register or stack slot of any value we have to fit into hardware or virtual
machine constraints. 

## Prep and register allocation prepass

When compiling the IR to bytecode for the purple garden vm, the first step is
to compute the liveset, with the algorithm introduced before and then
performing the preallocation pass with the `Cc::prealloc` method:

```rust
impl<'cc, S: Allocator + Clone, A: Allocator + Clone> Cc<'cc, S, A> {
    fn cc<F: Allocator>(
        &mut self,
        fun: &'cc Func<'cc, F>,
        native: Option<&mut purple_garden_jit::CodeArena<impl Pages>>,
    ) {
        // [...]

        // compute liveset
        fun.live_set_into(&mut self.live_set);

        // walk the IR once before lowering, after this its just a simple
        // lookup
        self.prealloc(fun);

        // [...] iterate blocks

            // [...] iterate instructions

                // secret postprocessing of instructions which dst points to the stack
                if let Some(Location::Stack(slot)) =
                    Func::def_of(instruction).and_then(|dst| self.regalloc.location(dst))
                {
                    self.emit(Op::StoreSlot { slot, src: TMP });
                }
    }
}
```

## Lowering Bin ir ops

Bin is the baseline operator. The BinImm ops we see in our example (`ISub %v10,
1`) are optimisations (one less dispatch, less memory interactions) compiled in
the same way, just with an immediate rhs:

```rust {hl_lines=["8-11", "38-40"]}
impl<'cc, S: Allocator + Clone, A: Allocator + Clone> Cc<'cc, S, A> {
    fn instr<F: Allocator>(&mut self, owner: &'cc Func<'cc, F>, i: &'cc ir::Instr<'cc>) {
        match i {
            // [...] all the other IR instructions
            ir::Instr::Bin {
                op, dst, lhs, rhs, ..
            } => {
                // interacting with the register alloc prepass
                let dst = self.def_register(dst.id);
                let lhs = self.ensure_register(*lhs);
                let rhs = self.ensure_register(*rhs);

                macro_rules! emit_bins {
                    ($($name:ident),*) => {
                        match op {
                            $(
                                ir::BinOp::$name => {
                                    Op::$name {
                                        dst,
                                        lhs,
                                        rhs,
                                    }
                                },
                            )*
                        }
                    };
                }

                self.emit(emit_bins! {
                    IAdd, ISub, IMul, IDiv, IMod, IAnd, ILt, IGt, IEq,
                    DAdd, DSub, DMul, DDiv, DLt, DGt,
                    BEq, SEq
                });
            }
            ir::Instr::BinImm {
                op, dst, lhs, imm, ..
            } => {
                let dst = self.def_register(dst.id);
                let lhs = self.ensure_register(*lhs);
                let imm = *imm;

                macro_rules! emit_bin_imms {
                    ($($ir:ident => $op:ident),* $(,)?) => {
                        match op {
                            $(ir::BinOp::$ir => Op::$op { dst, lhs, imm },)*
                            _ => unreachable!("only integer immediate binops are represented as BinImm"),
                        }
                    };
                }

                self.emit(emit_bin_imms! {
                    IAdd => IAddI,
                    ISub => ISubI,
                    IMul => IMulI,
                    IDiv => IDivI,
                    IMod => IModI,
                    IAnd => IAndI,
                    IEq  => IEqI,
                    IGt  => IGtI,
                    ILt  => ILtI,
                });
            }
        }
    }
}
```

This is so clean and a nice use of rust macros, i love this, dont @me; lowering
all binary and binary with immediate value operations in 57 lines is where its
at.


## Ensuring and definining a register

Two helpers for making sure a requested virtual register is accessible to a
point where operations can be applied on it, the first one being ensure_register:

```rust
/// Translate virtual register into vm register, abstracts spilling, restoring and register
/// allocation in general away
fn ensure_register(&mut self, id: Id) -> u8 {
    match self.regalloc.location(id) {
        Some(Location::Reg(r)) => return r.num(),
        // requested value lives on the stack, we need to restore it and we use a temp
        // register
        Some(Location::Stack(slot)) => {
            let dst = self.next_tmp();
            self.emit(Op::LoadSlot { dst, slot });
            dst
        }
        None => unreachable!("%v{} has no location", id.0),
    }
}

fn next_tmp(&self) -> u8 {
    match self.buf.last() {
        Some(Op::LoadSlot { dst: SCRATCH, .. }) => TMP,
        _ => SCRATCH,
    }
}
```

This means if a value is requested and:

- the prepass assigned it to a register, thats perfect and we can simply use it
- or if its on the stack we have to ask the compiler state for a temporary
register and materialise the value into it

> Temporary registers in the virtual machine are defined as `SCRATCH` and `TMP`, respectively in the preamble of the virtual machines source code:
> 
> ```rust
> pub const REGISTER_COUNT: usize = 32;
> const SCRATCH: u8 = REGISTER_COUNT as u8 - 1;
> const TMP: u8 = SCRATCH - 1;
> 
> /// Every vm register but [`SCRATCH`] and [`TMP`], r0 last since xralloc2 hands
> /// out the lowest free one first, which also puts the caller-saved registers
> /// before the callee-saved ones.
> const POOL: [u8; TMP as usize] = {
>     let mut pool = [0; TMP as usize];
>     let mut i = 0;
>     while i < TMP as usize {
>         pool[i] = (TMP as usize - 1 - i) as u8;
>         i += 1;
>     }
>     pool
> };
> ```

Thusfar ensure is simple to understand, the other helper is def_register, which
means we, again, take the registers number, if it has one, otherwise we take
TMP, which our previously introduced (and probably not noticed by anyone)
snipped at the end of the codeblock in [Prep and register allocation prepass
](#prep-and-register-allocation-prepass) then "spills" into its slot on the
stack with the respective bytecode instruction.

```rust
/// The register an op writes `id` into, [`TMP`] if `id` lives in a slot: the block loop stores
/// it there after the op.
fn def_register(&self, id: Id) -> u8 {
    match self.regalloc.location(id) {
        Some(Location::Reg(r)) => r.num(),
        Some(Location::Stack(_)) => TMP,
        None => unreachable!("%v{} has no location", id.0),
    }
}
```

## All the bytes and the codes together:

Swapping `-I` for `-D` (with `--no-jit`, otherwise we would get machinecode 🤓), results in the following
virtual machine registers assigned to the ssa values:

```asm
00000000 <f>:
  0000:    ilt_imm r3, r1, #1        ; 4: n < 1 { a + acc }
  0001:    jmpf r3, 0004 <f.bb_0004>
  0002:    iadd r0, r0, r2
  0003:    ret
00000004 <f.bb_0004>:
  0004:    isub_imm r3, r1, #1       ; 5: { f(a n-1 acc*n) }
  0005:    imul r2, r2, r1
  0006:    mov r1, r3
  0007:    tail 0000 <f>
```

## JIT :O

For the crazy hackermans, here is the same example with the jit on, jit and bc
share IR, liveness analysis, register allocation and standard libary, aint that
fun?

```asm
0000000000000000 <jit_f>:
   0:   48 81 fa 01 00 00 00    cmp    $0x1,%rdx
   7:   49 c7 c0 00 00 00 00    mov    $0x0,%r8
   e:   41 0f 9c c0             setl   %r8b
  12:   4d 85 c0                test   %r8,%r8
  15:   0f 84 0b 00 00 00       je     26 <jit_f+0x26>
  1b:   48 01 ce                add    %rcx,%rsi
  1e:   48 89 f0                mov    %rsi,%rax
  21:   c3                      ret
  22:   cc                      int3
  23:   cc                      int3
  24:   cc                      int3
  25:   cc                      int3
  26:   49 89 d0                mov    %rdx,%r8
  29:   49 81 e8 01 00 00 00    sub    $0x1,%r8
  30:   49 89 c9                mov    %rcx,%r9
  33:   4c 0f af ca             imul   %rdx,%r9
  37:   4c 89 c2                mov    %r8,%rdx
  3a:   4c 89 c9                mov    %r9,%rcx
  3d:   e9 be ff ff ff          jmp    0 <jit_f>
  42:   c3                      ret
```

> Dont be mean to the x86 output, i know this could be shorter, the compare and
> jmp could be a single instr and there is a lot of dead code and long
> encodings, but this is my first jit and im glad it works at all :)

# Future work

The attentive reader may have figured out how i have described the inputs and
ouputs of the register allocator, respectively the liveset (and the pool of
regs) and assignment of virtual to physical register, but have not actually
shown or introduced the register allocator itself, or the results of the IR
design which forces the regalloc to treat all block transitions (jumps,
entries, returns) as edge moves and has to do extra work to resolve these.

If my motivation holds up i will write a follow up article about these topics,
but right now i am still in the process of "perfecting" the interactions
between my ir, my regalloc and my backends, so maybe stay tuned? I have an rss
feed if anyone is actually at the end of the abyss im screaming my incohesive
blabbering into.
