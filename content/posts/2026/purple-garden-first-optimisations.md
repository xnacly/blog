---
title: "Purple Garden - First Optimizations"
date: 2026-01-14T15:34:17+01:00
summary: "First optimizations made while porting the runtime from c to rust"
draft: true
tags: 
- Pldev
- Rust
---

This article highlights the first optimizations made while porting the runtime
from C to Rust.

# Peephole Optimizations

<!-- TODO: -->

So to summarize:

- peephole optimisations are done on the bytecode in a local setting
- in this case they are fallback optimisations for things the IR optimisation
  rewriting missed


# Purple garden implementation

> For purple garden specifics and questions regarding the runtime, do consult:
> - [purple-garden github](https://github.com/xnacly/purple-garden)
> - [The Manchester Garbage Collector and purple-garden's runtime](/posts/2026/manchester-garbage-collector/)

To make these peephole optimisations fast, a single pass is needed to apply all
optimisations one after the other. This introduces the problem for recursive
optimisations due to the result of a previous optimisation, this is mitigated
by peephole optimisations being the fallback for the previous optimisation
pipeline.

```rust
const WINDOW_SIZE: usize = 3;
pub fn bc(bc: &mut Vec<Op>) {
    for i in 0..bc.len() {
        if let Some(window) = bc.get_mut(i..i + WINDOW_SIZE) {
            bc::const_add(window);
            bc::self_move(window);
        }
    }

    bc.retain(|op| !matches!(op, Op::Nop))
}
```

Since optimisations can both rewrite, replace and remove instructions, the
`Op::Nop` encodes removal by being the replacement for instructions that were
optimised away. These are then removed from the bytecode list after all
optimisations are applied.

## `self_move` 

```asm
__entry:
    load_imm r0 #5
    load_imm r1 #5
    mov r1 r1 ; <-- basically NOP
    add r1 r0
```

If this pattern is encountered, the vm wastes processing on running a `NOP`
instruction, to combat this, they are removed:

```asm
__entry:
    load_imm r0 #5
    load_imm r1 #5
    add r1 r0
```

This is archived by iterating the window and replacing self movs:

```rust
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

## `const_add`

These optimisations are fall backs for IR optimisation. However, some
optimisations can be missed or left over. Consider the following:

```asm
__entry:
        load_imm r0, #2
        load_imm r1, #3
        add r2, r0, r1
        load_imm r1, #4
        load_imm r0, #1
        sub r3, r1, r0
        mul r0, r2, r3
```

In this example all `add`, `sub` and `mul` are technically constant. Since this
is only intended for `add`, only those are folded. The optimisation itself
still applies to at least arithmetics. For addition it results in `load_imm r2,
#5`:

```asm
__entry:
        load_imm r2, #5
        load_imm r1, #4
        load_imm r0, #1
        sub r3, r1, r0
        mul r0, r2, r3
```

```rust
pub fn const_add(window: &mut [Op]) {
    if let [
        Op::LoadImm { dst: a, value: x },
        Op::LoadImm { dst: b, value: y },
        Op::Add { dst, lhs, rhs },
    ] = window
    {
        if lhs == a && rhs == b {
            window[0] = Op::LoadImm {
                dst: *dst,
                value: *x + *y,
            };
            window[1] = Op::Nop;
            window[2] = Op::Nop;
            opt_trace!("const_add", "fused two imm loads and an add");
        }
    }
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
enabling insides into decision making and performed optimisations.

```rust
opt_trace!("const_add", "fused two imm loads and an add");
```

Results in _`[opt::const_add]: fused two imm loads and an add`_, when the runtime
is compiled with `--features=trace`.

## Testing

To ensure correctness for the expected optimisation case, tests are necessary:

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
    fn const_add() {
        let mut bc = vec![
            Op::LoadImm { dst: 0, value: 1 },
            Op::LoadImm { dst: 1, value: 2 },
            Op::Add {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
        ];
        crate::opt::bc::const_add(&mut bc);
        assert_eq!(
            bc,
            vec![Op::LoadImm { dst: 0, value: 3 }, Op::Nop, Op::Nop,]
        )
    }
}
```

# Integration and flag guard

Since startup time is one of the most important parts of a fast runtime (for
me!), peephole optimisation is guarded behind `-O1` at this time:

```rust
// all error handling is hidden
fn main() {
    // [...] lexing, parsing, further setup

    let mut cc = cc::Cc::new();
    cc.compile(&ast);

    if args.opt >= 1 {
        opt::bc(&mut cc.buf);
    }

    let mut vm = cc.finalize();

    // [...] other flags and running the vm
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
[opt::const_add]: fused two imm loads and an add
__entry:
        load_imm r2, #5
        load_imm r1, #4
        load_imm r0, #1
        sub r3, r1, r0
        mul r0, r2, r3
[vm][0000] LoadImm { dst: 2, value: 5 }
[vm][0001] LoadImm { dst: 1, value: 4 }
[vm][0002] LoadImm { dst: 0, value: 1 }
[vm][0003] Sub { dst: 3, lhs: 1, rhs: 0 }
[vm][0004] Mul { dst: 0, lhs: 2, rhs: 3 }
```
