---
title: "The Manchester Garbage Collector and purple-garden's runtime"
summary: "A deep dive into purple-garden's runtime and semispace copying garbage collector with explicit root enumeration and bump allocation"
date: 2026-01-02T17:51:42+01:00
tags:
  - c
  - pldev
---

Recently, while in Manchester, I designed and implemented the [mgc - manchester
garbage collector #10](https://github.com/xnacly/purple-garden/pull/10) for
purple-garden. This article is a deep dive into its inner workings and why it
is designed in the way it is.

# Intro

While garbage collection in general is a widely researched subject, the
combination of multiple garbage collection techniques can yield improved
results compared to relying on a single strategy. The manchester garbage
collector (mgc) is such a composite of several paradigms: allocation into
preallocated memory regions, reachability analysis via recursive root set
tracing and compacting semi-space copying. At the same time this is not novel,
but specifically engineered for this runtime.

Combining these approaches enables fast allocation, low allocation latency and
reduced fragmentation.

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


Purple-garden is focussed on embeddablity and ease of use as a scripting
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
a separate allocator for call frames to reduce gc pressure.

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
to-space are swapped, so from-space is now the to-space, and vice versa.

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

## Keeping track of allocations

For the garbage collector to know which regions, of what size and which type it
handed out, each region is allocated with a metadata header. Said header
consists of:

```c
typedef struct GcHeader {
  unsigned int marked : 1;
  unsigned int type : 3;
  uintptr_t forward;
  uint16_t size;
  struct GcHeader *next;
} GcHeader;
```

The 3 type bits identify the payload as either raw bytes, a string, a list or a
map, see below. The header also holds a forwarding pointer for reference
rewriting, the size of the corresponding payload (Object sizes are capped at
64KB; this matches current runtime needs) and a pointer to the next
allocation. This enables a heap scan in the sense of iterating a linked list of
headers, helping in the rewriting process.

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

Each `GcHeader` is 32B, thus each heap allocation has an added overhead of 32B. 

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

As explained before, after marking all available objects, these alive objects
are copied. This process also involves walking the chained list of headers, but
is restricted to those with `GcHeader.marked` toggled. Each object is copied into
`to-space` and the `GcHeader.forward` field is set to the new memory region. 

## (Almost) Zero cost abstractions and small Values

Values in the purple garden runtime use three bits for encoding their type:

```c
typedef enum {
  V_NONE,   // zero value, comparable to rusts Option::None
  V_STR,    // string view
  V_DOUBLE, // floating point number
  V_INT,    // integer

  V_TRUE,   // booleans
  V_FALSE,

  V_ARRAY,  // containers / adts
  V_OBJ,
} ValueType;
```

A union for storing the data for each type (excluding true and false, since
these do not require further data). `Str` for the custom string abstraction,
List for the dynamically growing array, Map for the hash map, a double and an
`int64_t`.

```c
typedef struct Value {
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

And a singular bit for marking a value as optional: `is_some`, making each type
optionally representable:


```c {hl_lines=[3]}
typedef struct Value {
  unsigned int type : 3;
  unsigned int is_some : 1;
  union {
    Str string;
    List *array;
    Map *obj;
    double floating;
    int64_t integer;
  };
} Value;
```

Using a bit tag on `Value` itself results in the valid states of all types
except `V_NONE` combined with `is_some` equal to true and false. While the type
`V_NONE` can only be combined with `is_some` being false. This invariant is
checked in the runtime and there is a specific function for determining whether an
instance of `Value` is optionally available:

```c
inline bool Value_is_opt(const Value *v) {
  return v->type == V_NONE || v->is_some;
}
```

The big advantage of this approach is enabling a zero allocation, zero copy and
zero indirection optional implementation in the runtime, since each and all
values can be turned into an optional value by setting the `Value.is_some` bit.
If optionality were implemented via `V_OPTION` and with `Value.inner` being the
value while `Value.is_some` would indicate if said option were holding
something, this would always require an allocation, due to the recursive nature
of this implementation.


```nix
# optionals
var opt_none = std::None()
var opt_some = std::Some([])
std::opt::or(opt_none "anything else") # -> "anything else"
std::opt::unwrap(opt_some) # -> []
std::opt::expect(opt_some "would panic with this message") # -> []
std::opt::is_some(opt_some) # -> true 
std::opt::is_none(opt_none) # -> true 
```

Standard library functions interacting with optionals are in `std::opt` and
many functions in other packages are returning or accepting optional values.
Functions in this package are trivial to implement with this value design, for
instance `std::opt::{some, none, or}`:

```c
static void pg_builtin_opt_some(Vm *vm) {
  Value inner = ARG(0);
  inner.is_some = true;
  RETURN(inner);
}

// INTERNED_NONE is a static Value instance thats always available to the runtime

static void pg_builtin_opt_none(Vm *vm) { RETURN(*INTERNED_NONE); }

static void pg_builtin_opt_or(Vm *vm) {
  Value lhs = ARG(0);
  Value rhs = ARG(1);
  ASSERT(Value_is_opt(&lhs), "Or: lhs wasnt an Optional");
  if (!lhs.is_some) {
    RETURN(rhs);
  } else {
    lhs.is_some = false;
    RETURN(lhs);
  }
}
```

The design also allows for numeric Value instances without allocations, trading
smaller Value sizes for less heap allocations in hot paths of the runtime.

## Differentiating heap and non-heap values

For purple garden, neither booleans, doubles or integers require heap
allocation. Strings which are known at compile time are simply windows into the
initial input the interpreter gets, therefore not heap allocated via `gc_alloc`
and not subject to marking or collection.

Thus a marker for distinguishing between heap values and non heap values is
necessary: `Value.is_heap`. Only values with this bit toggled are considered
for marking, collection and passed to both the copy and rewrite phases of the
garbage collector.

```c {hl_lines=[2]}
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

## Dynamically growable bump allocation

{{<callout type="Info - Growable bump allocators">}}
For an in depth commentary on bump allocation, growable chunks, mmap and
segmented lists build on top of these concepts, see the C part of my recent
article: [Porting a Segmented List From C to
Rust](/posts/2025/porting-a-segmented-list-from-c-to-rust/): [C
Implementation](/posts/2025/porting-a-segmented-list-from-c-to-rust/#c-implementation).
{{</callout>}}

Since allocations are expensive due to them requiring a system interaction via
syscalls, purple garden is designed to reduce syscalls as much as possible. To
achieve this, a growing bump allocator is used. Upon getting a request the bump
allocator cant satisfy, the allocator itself requests a new chunk of memory
from the operating system. This chunk is double the size of the previous one,
while the first chunk is as large as the page size of the system it is running
on.

## String abstraction

Since c style strings suck due to them not having a length associated at all
times, purple garden has a string abstraction built-in. It iterates on the
computationally expensive c string interactions by making hashing and length
first class citizen. `Str` is a view into a buffer it doesn't manage, it holds
a pointer to a buffer, a length and a hash. Its backing storage is immutable.
`Str` is cheap to copy and therefore kept by value, not by reference in `Value`.

```c
typedef struct __Str {
  uint64_t hash;
  uint32_t len;
  const uint8_t *p;
} Str;
```

`Str.length` is computed at creation time. A static string that's know when
compiling the runtime (things like error messages or string representations of
value type names), is passed to the `STRING` macro:

```c
#define STRING(str)                                                            \
  ((Str){.len = sizeof(str) - 1, .p = (const uint8_t *)str, .hash = 0})
```

For strings included in the input to the runtime, the runtime executes. A
different approach is used, for instance, consider something like:

```nix
std::println("Hello" "World")
```

In this example both sizes and hash of `"Hello"` and `"World"` are known as
soon as the lexer determines them to be string tokens. Abusing this fact and
the fact, that all characters of a string have to be walked, both the length
and the hash are computed while the lexer recognises strings:

```c
// ! error handling omitted for clarity
string: {
    // skip "
    l->pos++;
    size_t start = l->pos;
    uint64_t hash = FNV_OFFSET_BASIS;

    char cc = l->input.p[l->pos];
    for (; cc > 0 && cc != '"'; l->pos++, cc = l->input.p[l->pos]) {
        hash ^= cc;
        hash *= FNV_PRIME;
    }

    Token *t = CALL(a, request, sizeof(Token));
    *t = (Token){0};
    t->type = T_STRING;
    t->string = (Str){
        .p = l->input.p + start,
        .len = l->pos - start,
        .hash = hash,
    };

    l->pos++;
    return t;
}
```

Hashing is done via
[FNV-1a](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1a_hash).
Computing hashes of strings created at runtime, a complementary `Str_hash`
function is provided:

```c
inline uint64_t Str_hash(const Str *str) {
  uint64_t hash = FNV_OFFSET_BASIS;
  for (size_t i = 0; i < str->len; i++) {
    hash ^= (uint64_t)str->p[i];
    hash *= FNV_PRIME;
  }
  return hash;
}
```

There is a small internal API built on top of this abstraction:

```c
char Str_get(const Str *str, size_t index);
Str Str_from(const char *s);
Str Str_slice(const Str *str, size_t start, size_t end);
Str Str_concat(const Str *a, const Str *b, Allocator *alloc);
bool Str_eq(const Str *a, const Str *b);
void Str_debug(const Str *str);
int64_t Str_to_int64_t(const Str *str);
double Str_to_double(const Str *str);
```

While the `str` standard library package exposes `str::append`, `str::lines`
and `str::slice`:

```nix
std::str::append("Hello" " World") # Hello World
std::str::slice("Hello" 0 2) # hel
std::str::slice("Hello" 1 2) # el
std::str::lines("hello\nworld") # [hello world]
```

## Triggering garbage collection

Since allocation latency is more important for short live scripts, triggering
and checking for the memory usage to surpass the garbage collection threshold
on allocation or worse, on each bytecode instruction can slow the virtual
machine down substantially and thus introduce latency in both execution and
allocation speeds.

To circumvent this, the threshold check is only performed after leaving a
scope, this has the benefit of omitting all objects one would have to consider
as alive in the scope before the vm left said scope. Triggering the gc cycle by
piggy backing on control flow and memory usage makes the gc behaviour easier to
reason about.

```c
    case OP_RET: {
      Frame *old = vm->frame;
      if (vm->frame->prev) {
        vm->pc = vm->frame->return_to_bytecode;
        vm->frame = vm->frame->prev;
      }

      // [...] free lists for stack frames and stuff

      if (!vm->config.disable_gc &&
          vm->gc->allocated >= (vm->config.gc_size * vm->config.gc_limit)) {
        gc_cycle(vm->gc);
      }
      break;
    }
```

The `runtime` standard library exposes a `gc` package for both
`std::runtime::gc::stats` and triggering a garbage collection cycle manually:
`std::runtime::gc::cycle()`, as shown in the initial example at the start of
this article. The implementation and usage for the latter is shown below.

```c static void pg_builtin_runtime_gc_cycle(Vm *vm) {
  if (!vm->config.disable_gc) {
    gc_cycle(vm->gc);
  }
}
```

```nix
var combination = std::str::append("Hello" " " "World")
std::println(combination)
std::runtime::gc::cycle()
```

## Marking a Value

As previously explained, only values with `is_heap` should be considered roots
and to be managed by the gc. Thus `mark` has an early exit condition:

```c
static inline void mark(Gc *gc, const Value *val) {
  if (!val || !val->is_heap) {
    return;
  }

  // [...]
}
```

Since `Str` wraps the underlying gc managed buffer (`GC_OBJ_RAW`) while not
being allocated itself, this has to be handled differently from `V_ARRAY` and
`V_OBJ`:

```c
static inline void mark(Gc *gc, const Value *val) {
  // [...]

  void *payload = NULL;
  switch ((ValueType)val->type) {
  case V_STR:
    GcHeader *raw = (GcHeader *)((uint8_t *)val->string.p - sizeof(GcHeader));
    raw->marked = true;
    break;
    return;
  case V_ARRAY:
    payload = (void *)val->array;
    break;
  case V_OBJ:
    payload = (void *)val->obj;
    break;
  default:
    return;
  }

  // [...]
}
```

The payload of arrays and objects is allocated, thus they are casted and
assigned. If the resulting payload is less than `sizeof(GcHeader)` either a
heap corruption or a gc bug occured, thus we assert. Then an exit condition for
already marked headers is created.

```c
static inline void mark(Gc *gc, const Value *val) {
  // [...]

  ASSERT((uintptr_t)payload > sizeof(GcHeader),
         "payload too small, GC logic bug, this shouldnt happen");

  GcHeader *h = (GcHeader *)((char *)payload - sizeof(GcHeader));
  if (!h || h->marked) {
    return;
  }

  h->marked = 1;

  // [...]
```

Since we already handled a string, we can now switch on the `GcHeader->type`
bits and recursively mark each member of an array and each value of an object.

```c
static inline void mark(Gc *gc, const Value *val) {
  // [...]

  switch ((ObjType)h->type) {
  case GC_OBJ_LIST: {
    List *l = (List *)payload;
    for (size_t i = 0; i < l->len; i++) {
      mark(gc, &l->arr[i]);
    }
    break;
  }
  case GC_OBJ_MAP:
    Map *m = (Map *)payload;
    for (size_t i = 0; i < m->cap; i++) {
      MapEntry e = m->buckets[i];
      mark(gc, &e.value);
    }
  default:
    return;
  }
}
```

## Letting mark loose on registers and call frames

Since we need to mark our root set in `gc_cycle` and our root set consists of
both the registers, the variables in the current and all previous call frames,
we need to call mark on each:

```c
void gc_cycle(Gc *gc) {
  if (!gc->allocated_since_last_cycle) {
    return;
  }
  gc->allocated_since_last_cycle = 0;
  Vm *vm = ((Vm *)gc->vm);
  for (size_t i = 0; i < REGISTERS; i++) {
    const Value *ri = vm->registers + i;
    mark(gc, ri);
  }

  for (Frame *f = vm->frame; f; f = f->prev) {
    for (size_t i = 0; i < f->variable_table.cap; i++) {
      MapEntry *me = &f->variable_table.buckets[i];
      if (me->hash) {
        mark(gc, &me->value);
      }
    }
  }

  // [...]
}
```

## Copying marked GcHeader

After marking each `Value` and `GcHeader` referenced by the root set, we copy
those to the `to-space` / `new` allocator. We also rebuild the `GcHeader` chain
of copied headers.

```c
void gc_cycle(Gc *gc) {
    // [...]

  GcHeader *new_head = NULL;
  size_t new_alloc = 0;
  for (GcHeader *h = gc->head; h; h = h->next) {
    if (!h->marked) {
      continue;
    }

    void *buf = CALL(gc->new, request, h->size + sizeof(GcHeader));
    GcHeader *nh = (GcHeader *)buf;
    void *new_payload = (char *)buf + sizeof(GcHeader);
    memcpy(nh, h, sizeof(GcHeader) + h->size);
    nh->next = new_head;
    new_head = nh;
    h->forward = (uintptr_t)new_payload;
    nh->forward = 0;
    nh->marked = 0;
    new_alloc += h->size;
  }

    // [...]
}
```

## Forwarding pointers and Rewriting references

> `mark` and `rewrite_nested` are subject to blowing the stack up, both will
> use a work list in the future

Each `GcHeader.forward` is then used to update all references to the newly
copied regions:

```c
static inline void *forward_ptr(void *payload) {
  if (!payload) {
    return NULL;
  }

  GcHeader *old = (GcHeader *)((char *)payload - sizeof(GcHeader));
  if (!old) {
    // not a gc object, hitting this is a bug
    unreachable();
  }

  if (old->type < GC_OBJ_RAW || old->type > GC_OBJ_MAP) {
    // either already in newspace or not a heap object; return payload unchanged
    return payload;
  }

  if (old->forward) {
    return (void *)old->forward;
  }

  // normally this would be unreachable, but since pg doesnt clear registers
  // after insertions into adts or the variable table, references to heap data
  // can be both in the variable table and registers at the same time, thus
  // allowing for multiple forward_ptr calls since there are multiple references
  // to a single point in memory. This results in double forwarding and other
  // shenanigans. Just returning the payload if no forward was found is correct
  // and a fix.
  return payload;
}
```

`rewrite` is really as simple as it gets:

```c
static inline void rewrite(Gc *gc, Value *v) {
  if (!v->is_heap) {
    return;
  }

  switch ((ValueType)v->type) {
  case V_STR:
    v->string.p = (const uint8_t *)forward_ptr((void *)v->string.p);
    break;
  case V_ARRAY:
    v->array = (List *)forward_ptr((void *)v->array);
    break;
  case V_OBJ:
    v->obj = (Map *)forward_ptr((void *)v->obj);
    break;
  default:
    return;
  }
}
```

`rewrite_nested` iterates on `rewrite` by nesting the process for objects and
arrays:

```c
void rewrite_nested(Gc *gc, Value *v) {
  rewrite(gc, v);

  switch (v->type) {
  case V_ARRAY:
    for (size_t i = 0; i < v->array->len; i++) {
      rewrite_nested(gc, &v->array->arr[i]);
    }
    break;
  case V_OBJ:
    for (size_t i = 0; i < v->obj->cap; i++) {
      MapEntry *me = &v->obj->buckets[i];
      if (me->hash) {
        rewrite_nested(gc, &me->value);
      }
    }
    break;
  default:
    break;
  }
}
```

Put together in `gc_cycle`, starting with the registers, each entry in each
variable table of each frame and each header in the `GcHeader` chain, all
`Value`s are rewritten. 

```c
void gc_cycle(Gc *gc) {
  // [...]

  for (size_t i = 0; i < REGISTERS; i++) {
    Value *ri = &vm->registers[i];
    rewrite(gc, ri);
  }

  for (Frame *f = vm->frame; f; f = f->prev) {
    for (size_t i = 0; i < f->variable_table.cap; i++) {
      MapEntry *me = &f->variable_table.buckets[i];
      if (me->hash) {
        rewrite_nested(gc, &me->value);
      }
    }
  }

  for (GcHeader *h = new_head; h; h = h->next) {
    switch (h->type) {
    case GC_OBJ_LIST: {
      List *l = (List *)((uint8_t *)h + sizeof(GcHeader));
      for (size_t i = 0; i < l->len; i++) {
        rewrite_nested(gc, &l->arr[i]);
      }
      break;
    }
    case GC_OBJ_MAP: {
      Map *m = (Map *)((uint8_t *)h + sizeof(GcHeader));
      for (size_t i = 0; i < m->cap; i++) {
        MapEntry *me = &m->buckets[i];
        if (me->hash) {
          rewrite_nested(gc, &me->value);
        }
      }
      break;
    }
    case GC_OBJ_STR: {
      Str *str = (Str *)((uint8_t *)h + sizeof(GcHeader));
      str->p = forward_ptr((void *)str->p);
      break;
    }
    default:
      break;
    }
  }

  // [...]
}
```

## Bookkeeping after collection

```c
void gc_cycle(Gc *gc) {
  // [...]
  gc->head = new_head;
  SWAP_STRUCT(gc->old, gc->new);
  CALL(gc->new, reset);
  gc->allocated = new_alloc;
}
```

After mark, copy and rewrite, the chain is attached to `Gc.head`,

The `from` and `to`-space swap places via `SWAP_STRUCT`:

```c
#define SWAP_STRUCT(A, B)                                                      \
  do {                                                                         \
    _Static_assert(__builtin_types_compatible_p(typeof(A), typeof(B)),         \
                   "SWAP_STRUCT arguments must have identical types");         \
                                                                               \
    typeof(A) __swap_tmp = (A);                                                \
    (A) = (B);                                                                 \
    (B) = __swap_tmp;                                                          \
  } while (0)
```

The new (new, since the previous old allocator is now the new allocator)
allocator is reset with `CALL`, which is a macro:

```c
#define CALL(SELF, METHOD, ...) (SELF)->METHOD((SELF)->ctx, ##__VA_ARGS__)
```

Expanding to `(gc->new)->reset((gc->new)->ctx);`. 

## Tuning

As the virtual machine is configurable via the `VmConfig` structure, so is the
garbage collector:

```c
typedef struct {
  // defines the maximum amount of memory purple garden is allowed to allocate,
  // if this is hit, the vm exits with a non zero code
  uint64_t max_memory;
  // define gc heap size in bytes
  uint64_t gc_size;
  // gc threshold in percent 5-99%
  double gc_limit;
  // disables the garbage collector
  bool disable_gc;

  // [...]
} Vm_Config;
```

This configuration is passed to `Vm_new` and attached to the `Vm` structure. It
allows for fully disabling the garbage collector, setting a total size for the
gc heap, and a threshold of the gc heap size in percent at which the gc should
start a cycle.

For non embedding purposes, specifically for simply running the interpreter,
each option, its short name, its default value, its type and its description is
defined in the list of cli flags the purple garden binary accepts:

```c
#define CLI_ARGS                                                               \
  X(gc_max, 0, GC_MIN_HEAP * 64l, LONG,                                        \
    "set hard max gc space in bytes, default is GC_MIN_HEAP*64")               \
  X(gc_size, 0, GC_MIN_HEAP * 2l, LONG, "define gc heap size in bytes")        \
  X(gc_limit, 0, 70.0, DOUBLE,                                                 \
    "instruct memory usage amount for gc to start collecting, in percent "     \
    "(5-99%)")                                                                 \
  X(no_gc, 0, false, BOOL, "disable garbage collection")                       
```

Producing a nice help text via a modified `6cl` library (omitted all other
options for clarity):

```text
usage ./build/purple_garden_debug: [ +gc_max <1638400>] [ +gc_size <51200>]
                                   [ +gc_limit <70>] [ +no_gc]
                                   // [...]
                                   <file.garden>

Option:
          +gc_max <1638400>
                set hard max gc space in bytes, default is GC_MIN_HEAP*64
          +gc_size <51200>
                define gc heap size in bytes
          +gc_limit <70>
                instruct memory usage amount for gc to start collecting, in
                percent (5-99%)
          +no_gc
                disable garbage collection
          // [...]

          +h/+help
                help page and usage
Examples:
        ./build/purple_garden_debug +gc_max 1638400 +gc_size 51200 \
                                    +gc_limit 0 +no_gc
```

If the user sets these, the main purple garden entry point uses these cli
options to set the `VmConfig`:

```c
Vm vm = Vm_new(
  (Vm_Config){
      .gc_size = a.gc_size,
      .gc_limit = a.gc_limit,
      .disable_gc = a.no_gc,
      .max_memory = a.gc_max,
      .disable_std = a.no_std,
      .no_env = a.no_env,
  }, pipeline_allocator, &gc);
```

# Comparing mgc to other gc idioms and other reasoning

The obvious question at this point is of purpose and complexity. Why design a
garbage collector leveraging multiple paradigms when seemingly each paradigm on
its own could suffice?

## Why Bump allocation instead of malloc

First and foremost, keeping allocations fast is crucial for this kind of
runtime. For this only bump allocation is an option, simply because syscalls
are slow, multiple for many small objects are even slower and hot paths would
explode. Due to purple garden being optimised for allocation and not
deallocation, an alternative to bump allocation is out of the question.

## Why Copying, Compacting and resetting whole Heap regions instead of single value dealloc

Since this restricts the collection of objects due to bump allocation
disallowing the deallocation of single objects, a copy to-space, from-space
collection approach is the most evident. Copying also has the benefit of bulk
reclamation and reduced fragmentation, especially compared to single-object
deallocation. 

## Why Register and variable tracing vs heap scanning

The root set is absolute and known at all times. Knowing these values
determining reachability is the most efficient implementation, especially
compared to walking the whole gc heap. Why waste cycles for scanning the heap
if all root values are known at all times and headers are chained?

## Why not X

On the other side of the initial question is a list of concepts some garbage
collectors of famous runtimes employ. These were purposely omitted, both for
keeping the garbage collector safe from feature creep and due to the runtime
being single thread, the gc being stop the world and in general me disallowing
concurrent mutations of any state, especially the gc state and root set:

- **write barriers**/**incremental**: Only necessary for concurrent collectors,
  but purple garden is single-threaded and stop-the-world. All objects are
  known at collection time.
- **generational**: optimised for long-lived objects, but purple-garden is an
  embeddable scripting language, it is designed and engineered for being cheap
  and quick to spin up for something like a plugin programming behaviour
  running on each event or entity in a game. It is specifically targeted for
  short lived execution and thus allocations.
- **RC**/**ARC**: large runtime overhead and cycles need extra non trivial
  detection logic, which would slow hot paths down
- **escape analysis**: optimises for reducing heap allocation, but mgc makes
  allocations extra cheap, plus purple gardens bytecode is compiled from its
  abstract syntax tree into a compact format, there is no immediate
  representation with enough lifetime info for performing escape analysis

# Gc invariants and assumptions

This is a short list included for completeness, violating one of these
invariants results in undefined behavior.

1. depends on registers not being cleared
2. values not being duplicated incorrectly
3. `Value.type=V_STR` and `Value.is_heap=1` to mean the string is heap
   allocated, else its 'allocated' by the lexer (technically by mmaping the
   input into process memory, but you get the gist)
4. vm discipline around setting `Value.is_heap`

# (non-)Portability to Rust and Design Improvements

I'm currently in the process of rewriting purple garden in Rust for a plethora
of reasons (these are not that easy to understand if one hasn't worked on a
language runtime before):

- less abstractions, since I had to hand roll hashing, hash maps, arrays,
  array lists, which I can just replace with `std::collection`
- better and shorter bytecode compiler, since rust just allows me to `Vec<Op>`
  with better append and inserts than in my implementations
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
- easier compile time value interning via rust hash maps (I had three hash maps
  for three different types), now I just use `std::collections::HashMap`
- the `ARGS` instruction for encoding both register offset and count for
  arguments to builtin and user defined function calls is no longer necessary,
  since both `SYS` and `CALL` encode their offset and argument count in their
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
  indirection in the compiler, since I wasn't able to store a 64bit pointer in
  a word, so the compiler created an array of pointers to a builtin and the
  bytecode encoded an index into said array the vm could use to call the
  correct builtin, this is now just a fn pointer, see above for the reference
  in the bytecode and below for the definition:

    ```rust
    type BuiltinFn<'vm> = fn(&mut Vm<'vm>, &[Value]);
    ```
