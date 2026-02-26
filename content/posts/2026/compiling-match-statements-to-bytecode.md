---
title: "Compiling Match Statements to Bytecode"
summary: "Full pipeline deep dive for purple garden: AST, BB SSA IR, Bytecode, Optimisations"
date: 2026-02-26T15:13:56+01:00
draft: true
tags:
- rust
- pldev
---

I like Gos headless switch statements as a replacement for if-if-else-else
chains:

```go
import ("time"; "fmt")
t := time.Now()
switch {
case t.Hour() < 12:
    fmt.Println("Good morning!")
case t.Hour() < 17:
    fmt.Println("Good afternoon.")
default:
    fmt.Println("Good evening.")
}
```

So i decided purple garden will have these as the singular control structure,
for instance the above would be the following:

```python
import ("time" "io")
let t = time.now()
let greeting = match {
    t.hour() < 12 { "morning" }
    t.hour() < 17 { "afternoon" }
    { "evening" }
}
io.println("Good" greeting)
```


# Match statments

Below is the easiest and most useless match statement there is, for converting
a boolean to its integer representation:

```python
match {
    true { 1 }
    { 0 }
}
```

The general format is a conditional case evaluating to a boolean and a body.
All bodies must resolve to the same type and a default branch is required.

# Pipeline Architecture

Purple gardens architecture revolves around an intermediate representation
based on a list of functions holding a list of blocks. Each block has a list of
inputs params, a list of instructions and a singular terminator. Said
instructions are SSA based and the blocks containing them are basic blocks,
meaning each value is defined immutability and exactly once. This also means
params to blocks and params in terminators are explicit (this enables ommission
of phi nodes).

The IR sits in the intersection of the abstract syntax tree produced by parsing
the tokenized input and the three backends (currently only the bytecode backend
targeting the typed register based virtula machine is implemented). This
architecture enables decoupled codegen and a list of optimisations.

# Parsing

As shown in the intro, the match stmt follows the following format:

```text
match {
    <cond> { <body> }
    { <default> }
}

Expr      ::= ...
Block     ::= "{" Expr "}"
MatchStmt ::= "match" "{" (Expr Block)+ Block "}
```

Pg uses a combination of recursive descent and pratt parsing. I will focus on
the former here, since the latter doesnt apply.

```text
match   + Parser::parser
match    \_ Parser::parser
match     \_ Parser::parse_prefix
match      \_ Parser::parse_match
True       |\_ Parser::parse_expr
           | |
I("1")     |  \_ Parser::parse_prefix
I("1")     |   \_ Parser::parse_expr
           |
I("0")      \_ Parser::parse_prefix
I("0")       \_ Parser::parse_expr
```

As shown above, the call stack for our example shows all function calls
necessary to build the abstract syntax tree:

```lisp
(match
 (True I("1"))
 (I("0"))
)
```

Below I included the implementation of `Parser::parse_match`:

```rust
    fn parse_match(&mut self) -> Result<Node<'p>, PgError> {
        self.next()?;
        let mut cases = vec![];
        let mut default = None;
        let tok = self.cur().clone();

        self.expect(Type::CurlyLeft)?;
        while self.cur().t != Type::CurlyRight {
            /// default case
            if self.cur().t == Type::CurlyLeft {
                let default_token = self.cur().clone();
                self.expect(Type::CurlyLeft);
                let mut default_body = vec![];
                while self.cur().t != Type::CurlyRight {
                    default_body.push(self.parse_prefix()?);
                }
                self.expect(Type::CurlyRight);
                default = Some((default_token, default_body));
            } else {
                let condition_token = self.cur().clone();
                let condition = self.parse_expr(0)?;
                self.expect(Type::CurlyLeft);
                let mut body = vec![];
                while self.cur().t != Type::CurlyRight {
                    body.push(self.parse_prefix()?);
                }
                self.expect(Type::CurlyRight);
                cases.push(((condition_token, condition), body));
            }
        }
        self.expect(Type::CurlyRight)?;

        let Some(default) = default else {
            return Err(PgError::with_msg(
                "Missing match default branch",
                "A match statement requires a default branch",
                &tok,
            ));
        };

        Ok(Node::Match {
            id: self.next_id(),
            cases,
            default,
        })
    }
```

# Typechecking

The purple garden type system is primitive, non-generic and based on equality.
This design enables a single pass type checker with a very simple environment
and an even simpler caching of already computed types.

For a match statment, the typechecker:

1. Makes sure all conditions resolve to a `bool`
2. Makes sure all branches evaluates to the same type
3. This type is then recorded as the canonical type for this match statment

Thus in a tracing build, the typechecker prints:

```text
[34.475µs] (match
 (
  True
  I("1")
 )
 (
  I("0")
 )
)
 resolved to Int
[59.101µs] Finished type checking
```

Not conforming to the previously layed out constraints results in a pretty
printed error diagnostic:

```text
-> err: Non bool match condition
   Match conditions must be Bool, got Int instead

008 | match {
009 |     5 { 1 }
            ~ here
010 |     { 0 }
```

Not only for non bool conditions, but also for differing types in different
branches:

```text
-> err: Incompatible match case return type
   Match cases must resolve to the same type, but got Int and Bool

008 | match {
009 |     true { false }
               ~ here
010 |     { 5 }
```

The implementation is as easy as it sounds, it follows the steps mentioned
before.

```rust
Node::Match { id, cases, default } => {
    // short circuit for empty matches
    if cases.is_empty() {
        return Ok(Type::Void);
    }

    let case_count = cases.len();

    let mut branch_types: Vec<Option<(&Token, Type)>> =
        vec![const { None }; case_count];

    // 1. 
    for (i, ((condition_token, condition), body)) in cases.iter().enumerate() {
        let condition_type: Type = self.node(condition)?;

        // 1. check for condition
        if condition_type != Type::Bool {
            return Err(PgError::with_msg(
                "Non bool match condition",
                format!(
                    "Match conditions must be Bool, got {} instead",
                    condition_type
                ),
                condition_token,
            ));
        }

        // 2. collect type of the body
        let branch_return_type = self.block_type(body)?;
        branch_types[i] = Some((condition_token, branch_return_type));
    }

    // 2. canonical type is the type the default body resolves to
    let first_type = self.block_type(&default.1)?;

    // 2. check the types are all the same
    for cur in &branch_types {
        let Some((tok, ty)) = cur else { unreachable!() };

        if ty != &first_type {
            return Err(PgError::with_msg(
                "Incompatible match case return type",
                format!(
                    "Match cases must resolve to the same type, but got {} and {}",
                    first_type, ty
                ),
                *tok,
            ));
        };
    }

    // 3. record the resulting type
    self.map.insert(*id, first_type.clone());

    // 3. propagate to the caller
    first_type
}
```

# Lowering to BB SSA IR

<!-- TODO: -->

```text
// entry
fn f0() -> void {
b0():
b1():
        %v0:Bool = true
        br %v0, b2(), b3()
b2():
        %v1:Int = 1
        jmp b4(%v1)
b3():
        %v2:Int = 0
        jmp b4(%v2)
b4(%v2):
}
```

# Lowering to Bytecode
<!-- TODO: -->

```asm
00000000 <entry>:
  0000:    load_global r0, 1    ; true
  0001:    jmpf r0, 3 <entry+0x1>
  0002:    jmp 6 <entry+0x6>
  0003:    load_imm r1, #1
  0004:    mov r2, r1
  0005:    jmp 8 <entry+0x8>
  0006:    load_imm r2, #0
  0007:    jmp 8 <entry+0x8>
```

# Real example: factorial
<!-- TODO: -->

```python
fn factorial(n:int a:int) int {
    match {
        n == 0 { a }
        { factorial(n-1 n*a) }
    }
}
factorial(16 1)
```

```lisp
(fn factorial (n:Int a:Int)
  (match
   ((DoubleEqual n I("0")) a)
   ((factorial 
       (Minus n I("1"))
      (Asteriks n a)
    ))
   )
  )->Int
(factorial I("16") I("1"))
```

```text
// factorial
fn f1(%v0, %v1) -> Int {
b0(%v0, %v1):
b1(%v0, %v1):
        %v2:Int = 0
        %v3:Bool = eq %v0, %v2
        br %v3, b2(%v0, %v1), b3(%v0, %v1)
b2(%v0, %v1):
        jmp b4(%v1)
b3(%v0, %v1):
        %v4:Int = 1
        %v5:Int = sub %v0, %v4
        %v6:Int = mul %v0, %v1
        %v7 = f1(%v5, %v6)
        jmp b4(%v7)
b4(%v7):
        ret %v7
}

// entry
fn f0() -> void {
b0():
        %v0:Int = 16
        %v1:Int = 1
        %v2 = f1(%v0, %v1)
}
```

```asm
00000000 <factorial>:
  0000:    load_imm r2, #0
  0001:    eq r3, r0, r2
  0002:    jmpf r3, 4 <factorial+0x2>
  0003:    jmp 6 <factorial+0x6>
  0004:    mov r7, r1
  0005:    jmp 14 <factorial+0xE>
  0006:    load_imm r4, #1
  0007:    sub r5, r0, r4
  0008:    mul r6, r0, r1
  0009:    mov r0, r5
  000a:    mov r1, r6
  000b:    call 0 <factorial>
  000c:    mov r7, r0
  000d:    jmp 14 <factorial+0xE>
  000e:    mov r0, r7
  000f:    ret

00000010 <entry>:
  0010:    load_imm r0, #16
  0011:    load_imm r1, #1
  0012:    call 0 <factorial>
  0013:    mov r2, r0
```

# Optimisations

```rust
// purple_garden::opt

pub fn ir(ir: &mut [crate::ir::Func]) {
    for fun in ir {
        ir::indirect_jump(fun);
        ir::tailcall(fun);
    }
}
```

```rust
fn main() {
    // [...]

    if args.opt >= 1 {
        opt::ir(&mut ir);
    }

    // [...]
}
```

## Removing Useless Blocks

The `indirect_jump` optimisation removes blocks that do nothing except
terminate into another block, for instance `b2` in `factorial`:

```text
fn f1(%v0, %v1) -> Int {
b0(%v0, %v1):
b1(%v0, %v1):
        %v2:Int = 0
        %v3:Bool = eq %v0, %v2
        br %v3, b2(%v0, %v1), b3(%v0, %v1)
b2(%v0, %v1):
        jmp b4(%v1)
b3(%v0, %v1):
        %v4:Int = 1
        %v5:Int = sub %v0, %v4
        %v6:Int = mul %v0, %v1
        %v7 = f1(%v5, %v6)
        jmp b4(%v7)
b4(%v7):
        ret %v7
}
```

- `b2` has no instructions
- `b2` has an unconditional terminator
- `b2`s terminators target is another block
- `b2` is not the function entry

Thus it can be fully omited, requiring the branch terminator pointing to `b2`
to point instead to `b4`:

```diff
diff --git a/base b/opt
index acd9cae..7f1ecab 100644
--- a/base
+++ b/opt
@@ -4,9 +4,9 @@ b0(%v0, %v1):
 b1(%v0, %v1):
         %v2:Int = 0
         %v3:Bool = eq %v0, %v2
-        br %v3, b2(%v0, %v1), b3(%v0, %v1)
+        br %v3, b4(%v1), b3(%v0, %v1)
 b2(%v0, %v1):
-        jmp b4(%v1)
+        <tombstone>
 b3(%v0, %v1):
         %v4:Int = 1
         %v5:Int = sub %v0, %v4
```

The tombstone is a marker for the codegen backends to skip generating code for
a 'dead' block and enables stable block ids, which are useful for codegen and
further optimisations on alive blocks.

```rust
// purple_garden::bc
impl<'cc> Cc<'cc> {
    fn cc(&mut self, fun: &'cc Func<'cc>) 
        -> Result<Option<reg::Reg>, PgError> {
        // [...] prep

        for block in &fun.blocks {
            if block.tombstone {
                continue;
            }

            // [...] codegen
        }
}
```

## Tail call optimisation

Since factorial with an accumulator is embarrassingly
[tailcallable](https://en.wikipedia.org/wiki/Tail_call)[^1], we need a pass to make
it.

<!-- TODO: show pass -->
<!-- TODO: show fN_tail IR instead of fN -->
<!-- TODO: show bytecode result -->

With an even more fun example:

```python
fn killstack(n:int) int {
    match {
        n < 1000000 { killstack(n+1) }
        { 0 }
    }
}
killstack(1)
```

[^1]: It even is THE example when looking into LLVMs tailcall pass: https://gist.github.com/vzyrianov/19cad1d2fdc2178c018d79ab6cd4ef10#examples
