---
title: "The Manchester Garbage Collector for purple-garden"
summary: "A deep dive into purple-garden's hybrid garbage collector and its implementation"
date: 2026-01-02T17:51:42+01:00
draft: true
tags:
  - c
  - pldev
---

Recently, while in Manchester, I designed and implemented the [mgc - manchester
garbage collector #10](https://github.com/xnacly/purple-garden/pull/10) for
purple-garden. This article is a deep dive into its inner workings and why it
is designed in the way it is.

# Init

While garbage collection in gneral is a widely researched subject, the
combindation of multiple garbage collection approaches can yieal improved
results compared to the single components. The manchester garbage collector
(mgc) is such a composite of several paradigms: allocation into preallocated
memory regions, mark & sweep like reachability analysis and semi-space copying.

Combining these approaches enables fast allocation, low-latency for allocations
and reduced fragmentation.

# Purple-garden

`mgc` is specifically engineered for the purple-garden runtime. Purple-garden
is a minimalist scripting language, designed and implemented with a focus on
performance and a low memory profile, see:
[xnacly/purple-garden](https://github.com/xnacly/purple-garden).

```nix
fn greeting :: greetee { std::println("hello world to:" greetee) }
greeting(std::env::get("USER")) # hello world to: $USER

var v = "Hello World"
std::println(std::runtime::type(v) std::len(v)) # str 11
```


Purple garden is focussed on embeddablity and ease of use as a scripting
language. For this, it has a small memory footprint, a high performance runtime
and a minimalist, yet useful standard library. It is implemented in C as a
register-based bytecode compiler and virtual machine.

While the above example doesn't allocate memory (in the runtime itself) and
therefore isn't a great example for this article, it is still a great example
what purple garden is about. 

A better example for some runtime heap pressure is the following recursive
string concatenation:

```nix
fn f :: n {
    match {
        n < 100000 {
            f(n+1)
            var s1 = std::str::append("a" "b")
            var s2 = std::str::append("c" "d")
            var pair = std::str::append(s1 s2)
        }
        { std::println(n) }
    }
}
f(0)
std::runtime::gc::cycle()
```

Since `f` does not allocate enough memory to trigger the garbage collector, see
[Triggering Garbage Collection](#triggering-garbage-collection), we manually
trigger a collection via `std::runtime::gc::cycle()`. Also, purple garden uses
a separate allocator for call frames to reduce gc pressure. For more extensive
pressuring benchmarks see [Stress](#Stress).

# Garbage collection stages

The mgc is divided in three stages, each requiring the runtime to stop for the
duration of the collection. All stages together form a collection cycle.


## Mark

To manage allocations in said virtual machine, the garbage collector defines a
set of starting points which it uses to walk all reachable allocations and
marking them as reachable. This set is called a root set. In purple-garden
(pg), this root set consists of the current registers and the variable table
holding local variable bindings. Since variables in higher scopes are
considered alive, even while they aren't in scope, the garbage collector has to
take parent scopes into account. For instance in the following example, if the
gc runs after `z()`: `a` and `b` are alive, while `c` isn't anymore and can be
cleaned up safely:

```nix
# alive
var a = allocating() 
fn z { 
    # dead
    var c = allocating()
}
# alive
var b = allocating() 
z()
```

## Copy

## Rewriting references

# Keeping track of values

# Differentiating heap and non-heap values

# Zero cost abstractions and small Values

# Dynamicly growable bump allocation

# String abstraction

# Triggering garbage collection

# Tuning

# Comparing mgc to other gc idioms and other reasonings

# (non-)Portability to Rust

<!-- TODO: -->

- mention why a rust port is currently in the work, see notebook
- mention why its not really portable, since std::collections requires inner
  containers to not be moved 

# Stress
