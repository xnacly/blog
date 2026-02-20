---
title: "Compiling Match Statements to Bytecode"
summary: "Full pipeline deepdive for the new match stmt: AST, EBB SSA IR, bytecode"
date: 2026-02-19T18:13:56+01:00
draft: true
tags:
- rust
- pldev
---

# Purple garden Match Statements

```python
match {
    true { 1 }
    { 0 }
}
```

# Purple garden Architecture

- EBB SSA IR
- backends:
    - purple garden virtual machine (register based, statically typed)
    - x86 JIT
    - aarch64 JIT

# Parsing

```lisp
(match
 (
  True
  I("1")
 )
 (
  I("0")
 )
)
```

# Typechecking
# Lowering to Extended Basic Blocks (EBB) Static Single Assignment (SSA) IR

```text
// entry
fn f0() -> void {
b0:
b1:
        %v1:Bool = true
        br %v1, b2, b3
b2:
        %v2:Int = 1
        jmp b4(%v2)
b3:
        %v3:Int = 0
        jmp b4(%v3)
b4(%v0:Int):
}
```

# Lowering to Bytecode

```asm
00000000 <entry>:
  0000:    load_global r1, 1    ; True
  0001:    jmpf r1, 3 <entry+0x1>
  0002:    jmp 6 <entry+0x6>
  0003:    load_imm r2, #1
  0004:    mov r0, r2
  0005:    jmp 9 <entry+0x9>
  0006:    load_imm r3, #0
  0007:    mov r0, r3
  0008:    jmp 9 <entry+0x9>
```

# Real example: factorial

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
   (
    (DoubleEqual
      n
      I("0")
    )
    a
   )
   (
    (factorial
      (Minus
        n
        I("1")
      )
      (Asteriks
        n
        a
      )
    )
   )
  )
)->Int
(factorial
  I("16")
  I("1")
)
```

```text
// factorial
fn f1(%v0:Int, %v1:Int) -> Int {
b0:
b1:
        %v3:Int = 0
        %v4:Bool = eq %v0, %v3
        br %v4, b2, b3
b2:
        jmp b4(%v1)
b3:
        %v5:Int = 1
        %v6:Int = sub %v0, %v5
        %v7:Int = mul %v0, %v1
        %v8 = f1(%v6, %v7)
        jmp b4(%v8)
b4(%v2:Int):
        ret %v2
}

// entry
fn f0() -> void {
b0:
        %v0:Int = 16
        %v1:Int = 1
        %v2 = f1(%v0, %v1)
}
```

```asm
00000000 <factorial>:
  0000:    load_imm r3, #0
  0001:    eq r4, r0, r3
  0002:    jmpf r4, 4 <factorial+0x2>
  0003:    jmp 6 <factorial+0x6>
  0004:    mov r2, r1
  0005:    jmp 15 <factorial+0xF>
  0006:    load_imm r5, #1
  0007:    sub r6, r0, r5
  0008:    mul r7, r0, r1
  0009:    mov r0, r6
  000a:    mov r1, r7
  000b:    call 0 <factorial>
  000c:    mov r8, r0
  000d:    mov r2, r8
  000e:    jmp 15 <factorial+0xF>
  000f:    mov r0, r2
  0010:    ret

00000011 <entry>:
  0011:    load_imm r0, #16
  0012:    load_imm r1, #1
  0013:    call 0 <factorial>
  0014:    mov r2, r0
```

# Optimisations (Future)

- merging noop extended basic blocks
- ...
