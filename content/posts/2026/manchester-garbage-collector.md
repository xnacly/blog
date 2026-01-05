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
duration of the collection. All stages together form a collection cycle, see
below:

```text
+-------------+
|  Roots Set  |
| (VM regs,   |
| globals...) |
+------+------+
       |
       v
+-------------+
|  Mark Phase |
| Mark all    |
| live objects|
+------+------+
       |
       v              Copy
+-------------------+ live     +-------------------+
|   Old Bump Space  | objects  |   New Bump Space  |
|  (old allocator)  | -------> |  (new allocator)  |
+-------------------+          +-------------------+
       |
       v
+--------------+
| Reset Old    |
| Bump Alloc   |
| (len=0,pos=0)|
+------+-------+
       |
       v
+-------------+
| Swap Alloc  |
| old <-> new |
+-------------+
```


## Mark

To manage allocations in said virtual machine, the garbage collector defines a
set of starting points which it uses to walk all reachable allocations and
marking them as reachable. This set is called a root set. In purple-garden
(pg), this root set consists of the current registers and the variable table
holding local variable bindings. Since variables in higher scopes are
considered alive, even while they aren't in scope, the garbage collector has to
take parent scopes into account. This is implemented by walking the root set
recursively, setting the mark bit on all reachable objects.

For instance in the following example, if the gc runs after `z()`: `a` and `b`
are alive, while `c` isn't anymore and can be cleaned up safely:

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

Once the alive subset `A` of currently allocated set `M` is determined, said
values in `A` can be safely copied from the previously used memory region
(from-space) to the new space (to-space). Both spaces are backed by bump
allocator which are implemented as a segmented list of memory regions allocated
through `mmap`.

After copying the from-space is reset, but not deallocated. Then from-space and
to-space are swapped, so from-space is now the to-space, and vise versa.

## Rewriting references

Since the copy and move to new memory locations invalidates previously held
references, rewriting said references to point to the newly copied memory
regions is necessary.

For this, the previously established root set needs to be walked again and all
references updated.

# Reference implementation

Putting the above concepts into reality and C, is the content of the next
chapters.


```c
typedef struct {
  // from-space
  Allocator *old;
  // to-space
  Allocator *new;
  void *vm;
  GcHeader *head;
  size_t allocated;
  size_t allocated_since_last_cycle;
} Gc;

Gc gc_init(size_t gc_size) {
  size_t half = gc_size / 2;
  return (Gc){
      .old = bump_init(half, 0),
      .new = bump_init(half, 0),
      .head = NULL,
  };
}
```

Allocator is a simple struct abstracting allocation away, for instance for a
bump allocator:

```c
typedef struct {
  // Allocator::ctx refers to an internal allocator state and owned memory
  // areas, for instance, a bump allocator would attach its meta data (current
  // position, cap, etc) here
  void *ctx;
  Stats (*stats)(void *ctx);
  void *(*request)(void *ctx, size_t size);
  void (*reset)(void *ctx);
  void (*destroy)(void *ctx);
} Allocator;
```

## Keeping track of values

For the garbage collector to know which regions it handed out, these regions
are allocated with a metadata header. Said header consists of:

```c
typedef struct GcHeader {
  unsigned int marked : 1;
  unsigned int type : 3;
  uintptr_t forward;
  uint16_t size;
  struct GcHeader *next;
} GcHeader;
```

The type bits identify the payload as one of:

```c
typedef enum {
  // just bytes
  GC_OBJ_RAW = 0b000,
  // a string with a reference to an inner string, can be allocated or not
  GC_OBJ_STR = 0b001,
  // list has zero or more children
  GC_OBJ_LIST = 0b010,
  // map holds allocated buckets with owned children
  GC_OBJ_MAP = 0b011,
} ObjType;
```

So an allocation looks like the following:

```text
       allocation 
      (raw pointer)
            |
            |
            v
 +----------------------+
 | GcHeader             | <-- header
 +----------------------+
 |                      |
 | payload (size B)     | <-- data handed out as ptr to the user
 |                      |
 +----------------------+
```

Each GcHeader is 32B, thus each heap allocation has this overhead.


```c
void *gc_request(Gc *gc, size_t size, ObjType t) {
  void *allocation = gc->old->request(gc->old->ctx, size + sizeof(GcHeader));
  void *payload = (char *)allocation + sizeof(GcHeader);
  GcHeader *h = (GcHeader *)allocation;
  h->type = t;
  h->marked = 0;
  h->size = size;
  h->next = gc->head;
  gc->head = h;
  gc->allocated_since_last_cycle += size;
  gc->allocated += size;
  return (void *)payload;
}
```

## Differentiating heap and non-heap values

For purple garden, neither booleans, doubles or integers require heap
allocation. Strings which are known at compile time are simply windows into the
initial input the interpreter gets. Thus some marker for distinguishing between
heap values and non heap values is necessary via `Value.is_heap`:

```c
typedef enum {
  V_NONE,
  V_STR,
  V_DOUBLE,
  V_INT,
  V_TRUE,
  V_FALSE,
  V_ARRAY,
  V_OBJ,
} ValueType;

typedef struct List {
  size_t cap;
  size_t len;
  Value *arr;
} List;

typedef struct MapEntry {
  uint32_t hash;
  Value value;
} MapEntry;

typedef struct Map {
  size_t cap;
  size_t len;
  MapEntry *buckets;
} Map;

typedef struct Value {
  unsigned int is_heap : 1;
  unsigned int type : 3;
  union {
    Str string;
    List *array;
    Map *obj;
    double floating;
    int64_t integer;
  };
} Value;
```

## Zero cost abstractions and small Values

## Dynamicly growable bump allocation

## String abstraction

## Triggering garbage collection

## Tuning

# Comparing mgc to other gc idioms and other reasonings

# Stress / Benchmark

# (non-)Portability to Rust

I'm currently in the process of rewriting purple garden in Rust for a plethora
of reasons (these are not that easy to understand if one hasn't worked on a
language runtime before):

- less abstractions, since I had to handroll hashing, hashmaps, arrays,
  arraylists, which I can just replace with `std::collection`
- better and shorter bytecode compiler, since rust just allows me to `Vec<Op>`
  with better append and inserts than in my impls
- better bytecode format and less wasted bytes for each instruction, since this
  allows me to have things like a single byte for `RET` and multiple bytes for
  things like `ADD rA, rB` via: 

    ```rust
    enum Op<'vm> {
        Add {
            dst: u8,
            lhs: u8,
            rhs: u8,
        },
        // [...]
        Ret {
            /// used for peephole optimisation, merging multiple RET into a single
            /// RET with a count
            times: u8,
        },
    }
    ```

- way better error handling in each component of the runtime, since the current
  C interpreter just aborts via assertions
- easier compile time value interning via rust hashmaps (I had three hashmaps
  for three different types), now I just use `std::collections::HashMap`
- the `ARGS` instruction for encoding both register offset and count for
  arguments to builtin and user defined function calls is no longer necessary,
  since both `SYS` and `CALL` encode their offset and arg count in their
  instruction: 

    ```rust
    enum Op<'vm> {
        // [...]
        Call {
            func: u16,
            args_start: u8,
            args_len: u8,
        },
        Sys {
            ptr: BuiltinFn<'vm>,
            args_start: u8,
            args_len: u8,
        },
    }
    ```

- Builtin functions for `SYS` no longer require type erasure, casting,
  indirection in the compiler, since I wasnt able to store a 64bit ptr in a
  word, so the compiler created an array of pointers to builtins and the
  bytecode encoded an index into said array the vm could use to call the
  correct builtin, this is now just a fn ptr, see above and below:

    ```rust
    type BuiltinFn<'vm> = fn(&mut Vm<'vm>, &[Value]);
    ```

The single downside is now:

The garbage collector can no longer be compacting and moving, since
`std::collections` adts aren't movable and also own their memory, so I'd have
to implement these on my own, which I don't want to right now, maybe in the
future. So the garbage collector will just be a heap walking, marking and
calling `drop` for cleanup of dead values.
