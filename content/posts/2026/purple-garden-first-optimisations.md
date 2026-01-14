---
title: "Poking holes into bytecode with peephole optimisations"
date: 2026-01-14
summary: "First optimizations I made while redesigning and semi-porting the purple-garden runtime from C to Rust"
tags: 
- pldev
- rust
---

This article highlights the first optimizations I made while redesigning and
semi-porting the runtime from C to Rust. These aren't benchmarked or verified,
since the virtual machine is currently under construction and will probably be
finished this week.

At a high level, purple-garden current works like this, with `2+3*4-1` as an
exemplary input:

```text
.
+- Tokenizer
|
]: Token(2) Token(+) Token(3)
]: Token(*)
]: Token(4) Token(-) Token(1)
|
 \
  +- Parsing (Tokens -> Abstract Syntax Tree)
  |
  ]: (Asteriks
  ]:   (Plus
  ]:     Integer("2")
  ]:     Integer("3")
  ]:   )
  ]:   (Minus
  ]:     Integer("4")
  ]:     Integer("1")
  ]:   )
  ]: )
  |
  |
<planned section start>
  \
   +- Planned IR and Optimisation Boundary
   |
  / \
  |  +- JIT Compiler (IR -> x86/ARM)
  |                           ^
  |                            \
  |                             \
  |                              \ 
  |                               \ 
  |                                \ 
<planned section end>               |Calls 
  |                                 |JIT'ed    
  \                                 |functions 
   +- Compiler (AST/IR -> bytecode) |
   |                                / 
   ]:  __entry:                    /
   ]:          load_imm r0, #2    |
   ]:          load_imm r1, #3    |
   ]:          add r2, r0, r1     |
   ]:          load_imm r1, #4    |
   ]:          load_imm r0, #1    |
   ]:          sub r3, r1, r0     |
   ]:          mul r0, r2, r3     |
   |                              |
   \                              |
    +- Peephole Optimiser         |
    |                             |
    ]:  __entry:                  |
    ]:          load_imm r2, #5   |
    ]:          load_imm r3, #3   |
    ]:          mul r0, r2, r3    |
    |                            /
    \                           /
     +- Baseline interpreter --+
     |
     ] [vm][0000] LoadImm { dst: 2, value: 5 }
     ] [vm][0001] LoadImm { dst: 3, value: 3 }
     ] [vm][0002] Mul { dst: 0, lhs: 2, rhs: 3 }
     |
     '
```

# Peephole Optimizations

[Peephole optimisations](https://en.wikipedia.org/wiki/Peephole_optimization)
are, as the name implies, optimisations performed on a small section of a
larger input. For a virtual machine, like purple-garden this means using a
window of size `3` (anything larger is no longer local[^1] subject to IR
optimisation, not peephole and will have happened before peephole optimisation
is reached in the compilation pipeline) and merging operators, rewriting
redundant or useless operations.

[^1]: fight me on this one, I make the rules, if WINDOW_SIZE > 3, I say that's
    no longer local :^)

So to summarize:

- peephole optimisations are done on the bytecode in a local setting (non-global)
- in this case they are fallback optimisations for things the IR optimisation
  rewriting missed
- these are local, single-pass, and meant only to catch what the IR opt didn't


# Purple garden implementation

> For purple garden specifics and questions regarding the runtime, do consult:
>
> - [purple-garden GitHub](https://github.com/xnacly/purple-garden)
> - [The Manchester Garbage Collector and purple-garden's runtime](/posts/2026/manchester-garbage-collector/)
> - [Redesign and Semi-port to Rust #15](https://github.com/xnacly/purple-garden/pull/15)

Peephole optimisations in purple-garden are intentionally kept single pass to
keep startup time cost as low as possible and to move heavy optimisation into
the IR.

This introduces the problem for recursive optimisations due to the result of a
previous optimisation, this is mitigated by peephole optimisations being the
fallback for the previous optimisation pipeline.

```rust
const WINDOW_SIZE: usize = 3;

/// Peephole optimisations
///
/// See:
/// - [Peephole optimization - Wikipedia]
/// (https://en.wikipedia.org/wiki/Peephole_optimization)
/// - [W. M. McKeeman "Peephole Optimization"]
/// (https://dl.acm.org/doi/epdf/10.1145/364995.365000)
pub fn bc(bc: &mut Vec<Op>) {
    for i in 0..=bc.len().saturating_sub(WINDOW_SIZE) {
        let window = &mut bc[i..i + WINDOW_SIZE];
        bc::const_binary(window);
        bc::self_move(window);
    }

    bc.retain(|op| !matches!(op, Op::Nop))
}

```

Since optimisations can both rewrite, replace and remove instructions, the
`Op::Nop` encodes removal by being the replacement for instructions that were
optimised away. These are then removed from the bytecode list after all
optimisations are applied.

## `self_move` 

"Self move" is a `mov` instruction having equivalent `dst` and `src`:

```asm
__entry:
    load_imm r0 #5
    load_imm r1 #5
    mov r1 r1 ; <-- basically NOP
    add r1 r0
```

If this pattern is encountered, the VM would waste processing power on running
a `NOP` instruction, to combat this, they are removed:

```asm
__entry:
    load_imm r0 #5
    load_imm r1 #5
    add r1 r0
```

This is achieved by iterating the window and replacing self `mov`s:

```rust
/// self_move removes patterns conforming to
///
///     Mov { dst: x, src: x },
///
/// where both dst == src
pub fn self_move(window: &mut [Op]) {
    for op in window.iter_mut() {
        if let Op::Mov { dst, src } = op {
            if dst == src {
                *op = Op::Nop;
                opt_trace!("self_move", "removed self_moving Mov");
            }
        }
    }
}
```

## `const_binary`

This optimisation refers to a binary instruction and both `lhs` and `rhs` are
created via `LoadImm` directly in the window beforehand:

```asm
__entry:
        load_imm r0, #2
        load_imm r1, #3
        add r2, r0, r1 ; <-- this is a compile time known result := 2+3=5
        load_imm r1, #4
        load_imm r0, #1
        sub r3, r1, r0 ; <-- this is a compile time known result := 4-1=3
        mul r0, r2, r3
```

In this example `add`, `sub` and `mul` are constant. The optimisation itself
applies to all arithmetics. Thus after optimising:

```asm
__entry:
        load_imm r2, #5
        load_imm r3, #3
        mul r0, r2, r3
```

This looks like the optimiser pass missed the `load_imm`, `load_imm`, `mul`
pattern, but this implementation is non recursive, recursive constant folding
is subject to IR optimisation, which comes before peephole optimisation, thus
this case will not happen once the IR and the IR optimiser is done. Overflow is
currently handled silently using wrapping arithmetic; this could and probably
will be changed to trigger a compile-time error in the future.

```rust
/// const_binary fuses
///
///     LoadImm{ dst: a, value: x },
///     LoadImm{ dst: b, value: y },
///     bin { dst, lhs: a, rhs: b }
///
/// into
///
///     LoadImm { dst, value: x bin y }
///
/// where bin := Add | Sub | Mul | Div
pub fn const_binary(window: &mut [Op]) {
    let [
        Op::LoadImm { dst: a, value: x },
        Op::LoadImm { dst: b, value: y },
        op,
    ] = window
    else {
        return;
    };

    let (dst, result) = match *op {
        Op::Add { dst, lhs, rhs } 
            if lhs == *a && rhs == *b => (dst, x.wrapping_add(*y)),
        Op::Sub { dst, lhs, rhs } 
            if lhs == *a && rhs == *b => (dst, x.wrapping_sub(*y)),
        Op::Mul { dst, lhs, rhs } 
            if lhs == *a && rhs == *b => (dst, x.wrapping_mul(*y)),
        Op::Div { dst, lhs, rhs } 
            if lhs == *a && 
                rhs == *b && *y != 0 => (dst, x.wrapping_div(*y)),
        _ => return,
    };

    window[0] = Op::LoadImm { dst, value: result };
    window[1] = Op::Nop;
    window[2] = Op::Nop;

    opt_trace!("const_binary", "fused a constant binary op");
}
```


## Observability

```rust
macro_rules! opt_trace {
    ($optimisation:literal, $text:literal) => {
        #[cfg(feature = "trace")]
        println!("[opt::{}]: {}", $optimisation, $text);
    };
}
```

The `opt_trace!` macro is used through out the optimisation pipeline for
enabling insights into decision making and performed optimisations.

```rust
opt_trace!("const_binary", "fused two imm loads and an add");
```

Results in _`[opt::const_binary]: fused a constant binary op`_, when the
runtime is compiled with `--features=trace`.


# Integration and flag guard

Since startup time is one of the most important parts of a fast runtime (for
me!), peephole optimisation is guarded behind `-O1` at this time:

```rust
// all error handling is hidden
fn main() {
    // [...] tokenizing, parsing, further setup

    let mut cc = cc::Cc::new();
    cc.compile(&ast);

    if args.opt >= 1 {
        opt::bc(&mut cc.buf);
    }

    let mut vm = cc.finalize();

    // [...] other flags and running the VM
}
```

Running something like `2+3*4-1` through the full pipeline:

```shell
cargo run \
    # compile with tracing prints included
    --features trace \
    -- \
    # args for purple-garden

    # print the abstract syntax tree
    --ast
    # disassemble the produced bytecode
    --disassemble \ 
    # set optimisation level
    -O1 \
    # specify input, if not set just 
    # pass a file to execute in as an argument
    -r="2+3*4-1"
```

```text
(Asteriks
  (Plus
    Integer("2")
    Integer("3")
  )
  (Minus
    Integer("4")
    Integer("1")
  )
)
Cc::cc(Asteriks)
Cc::cc(Plus)
Cc::cc(Integer("2"))
RegisterAllocator::alloc(r0)
Cc::cc(Integer("3"))
RegisterAllocator::alloc(r1)
RegisterAllocator::alloc(r2)
RegisterAllocator::free(r0)
RegisterAllocator::free(r1)
Cc::cc(Minus)
Cc::cc(Integer("4"))
RegisterAllocator::alloc(r1)
Cc::cc(Integer("1"))
RegisterAllocator::alloc(r0)
RegisterAllocator::alloc(r3)
RegisterAllocator::free(r1)
RegisterAllocator::free(r0)
RegisterAllocator::alloc(r0)
RegisterAllocator::free(r2)
RegisterAllocator::free(r3)
[opt::const_binary]: fused a constant binary op
[opt::const_binary]: fused a constant binary op
__entry:
        load_imm r2, #5
        load_imm r3, #3
        mul r0, r2, r3
[vm][0000] LoadImm { dst: 2, value: 5 }
[vm][0001] LoadImm { dst: 3, value: 3 }
[vm][0002] Mul { dst: 0, lhs: 2, rhs: 3 }
```

# Testing

To ensure correctness for the expected optimisation case, tests are necessary.
These tests validate pattern rewriting, not full program semantic equivalence.

```rust
#[cfg(test)]
mod bc {
    use crate::op::Op;

    #[test]
    fn self_move() {
        let mut bc = vec![
            Op::Mov { src: 64, dst: 64 },
            Op::Mov { src: 64, dst: 64 },
            Op::Mov { src: 64, dst: 64 },
        ];
        crate::opt::bc::self_move(&mut bc);
        assert_eq!(bc, vec![Op::Nop, Op::Nop, Op::Nop])
    }

    #[test]
    fn const_binary() {
        let mut bc = vec![
            Op::LoadImm { dst: 0, value: 1 },
            Op::LoadImm { dst: 1, value: 2 },
            Op::Add {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
            Op::LoadImm { dst: 0, value: 1 },
            Op::LoadImm { dst: 1, value: 2 },
            Op::Sub {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
            Op::LoadImm { dst: 0, value: 3 },
            Op::LoadImm { dst: 1, value: 5 },
            Op::Mul {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
            Op::LoadImm { dst: 0, value: 64 },
            Op::LoadImm { dst: 1, value: 8 },
            Op::Div {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
        ];

        for i in 0..=bc.len().saturating_sub(3) {
            crate::opt::bc::const_binary(&mut bc[i..i + 3]);
        }

        bc.retain(|op| *op != Op::Nop);
        assert_eq!(
            bc,
            vec![
                Op::LoadImm { dst: 0, value: 3 },
                Op::LoadImm { dst: 0, value: -1 },
                Op::LoadImm { dst: 0, value: 15 },
                Op::LoadImm { dst: 0, value: 8 },
            ]
        )
    }
}
```
