---
title: "Making array indexing a bit less costly for purple garden"
summary: "Using twos complement to only assert once per idx attempt, instead of twice"
date: 2026-11-15
draft: true
tags:
  - rust
  - pldev
---

Arrays must be indexable, this index has to adhere to being `0<=i<=|a|`; where
`||` is the length of the array `a`. Checking this is regarded as a bounds
check ([wikipedia -Bounds
checking](https://en.wikipedia.org/wiki/Bounds_checking))

# The obligatory gardening example

Lets consider the following
[purple-garden](https://github.com/xnacly/purple-garden) snippet:

```garden
import "io"
fn at(xs:Array<Int> i:Int) Int {
    // just here to stop inlining :)
    io.println(i)
    xs.[i]
}
io.println(at([1 2 3] 1))
```

Disregarding the `io.println` calls and the seemingly unnecessary indirection of
indexing via `at` [^opt-workaround], we can inspect the resulting intermedite
representation of `at`:

```llvm
// at
fn f1(%v0:Array<Int>, %v1:Int) -> Int {
    b0(%v0, %v1):
        ; just here to stop inlining
        %v2:Void = Sys io.println_int(%v1)

        ; load first word of array, which is its length
        %v3:Int = Load %v0+0

        ; assert idx > -1
        %v5:Bool = IGt %v1, -1
        %v6:Void = Assert(InBounds) %v5

        ; assert len > idx
        %v7:Bool = ILt %v1, %v3
        %v8:Void = Assert(InBounds) %v7

        ; calculate offset by type size (8)
        %v10:Int = IMul %v1, 8
        ; add offset to arr ptr 
        %v11:Ptr = IAdd %v0, %v10
        ; fetch arrayptr+offset+1 (skipping length word)
        %v12:Int = Load %v11+8
        ret %v12
}
```

# Rethinking TWO assertions

- talk about two complement repr
- how to merge two assertions into one via (i as u64) < len

# New IR node, new bytecode operation

# Support in the jit

# Benchmark(s)

## Baseline
## Postwork

[^opt-workaround]: i added, so the preexisting optimisation
    passes dont fuse the whole thing into a single load of the imm value at the
    idx of the arr: 

    ```llvm
    // entry
    fn f0() -> Void {
        b0():
            %v2:Int = 1
            %v16:Void = Sys io.println_int(%v2)
            ret %v16
    }
    ```
