---
title: "Revisiting and Optimising go-iso8601-duration"
summary: "5.33x faster runtime due to zero allocations, less calls and better assumptions"
date: 2026-04-06
draft: true
tags:
    - go
---


While looking through my repos, an issue in
[go-iso8601-duration](https://github.com/xnacly/go-iso8601-duration), which I
previously missed, popped up, informing me of a missing license in the last
release, resulting in missing documentation for the v1.1.0 release (Since the
gopkg website doesnt render documentation for non licensed projects).

Since I had to do a new release either way, I took the opportunity and
benchmarked the current state. -go/)).

# Benchmarks and a Baseline

I reused the cases previously employed for checking each branch of the FSM to
establish some micro benchmarks. But then again how do you not micro benchmark
a duration parsing routine (I tried my best). For the FSM and a rant about the
ISO org,  see my previous article: [Handrolling ISO8601 Duration Support for
Go](https://xnacly.me/posts/2025/handrolling-iso8601-support-for-go)

```go
var testcases = []struct {
	str string
	dur Duration
}{
	{"P0D", Duration{}},
	{"PT15H", Duration{hour: 15}},
	{"P1W", Duration{week: 1}},
	{"P15W", Duration{week: 15}},
	{"P1Y15W", Duration{year: 1, week: 15}},
	{"P15Y", Duration{year: 15}},
	{"P15Y3M", Duration{year: 15, month: 3}},
	{"P15Y3M41D", Duration{year: 15, month: 3, day: 41}},
	{"PT15M", Duration{minute: 15}},
	{"PT15M10S", Duration{minute: 15, second: 10}},
	{
		"P3Y6M4DT12H30M5S",
		Duration{
			year:   3,
			month:  6,
			day:    4,
			hour:   12,
			minute: 30,
			second: 5,
		},
	},
}

func BenchmarkDuration(b *testing.B) {
	for _, i := range testcases {
		b.Run(i.str, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, _ = From(i.str)
			}
		})
	}
}
```

```text
goos: linux
goarch: amd64
pkg: github.com/xnacly/go-iso8601-duration
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkDuration/P0D-16                24741985                48.10 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/PT15H-16              18533790                63.26 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/P1W-16                24164163                48.64 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/P15W-16               20793126                58.09 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/P1Y15W-16             13904265                84.21 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/P15Y-16               19943671                59.35 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/P15Y3M-16             14227842                83.24 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/P15Y3M41D-16          10262575                115.6 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/PT15M-16              18228138                63.90 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/PT15M10S-16           12289743                95.84 ns/op            8 B/op          1 allocs/op
BenchmarkDuration/P3Y6M4DT12H30M5S-16   6758479                 177.3 ns/op            8 B/op          1 allocs/op
PASS
ok      github.com/xnacly/go-iso8601-duration   13.952s
```

# Replacing the numBuffer with a running int64

The first weird detail I noticed, was previous me using `bytes.Buffer` to store
the single characters making up the numbers for parsing the numeric value of
each designator, for instance `593` in `P593W`, when a running `int64`  would
suffice. 

```go{hl_lines=[13,16,19,24]}
func From(s string) (Duration, error) {
	var duration Duration
    curState := stateStart
    var col uint8
    numBuf := *bytes.NewBuffer(make([]byte, 0, 8))

	for {
        // ...
        switch curState {
        // ...
		case stateTNumber:
			if unicode.IsDigit(b) {
				numBuf.WriteRune(b)
				curState = stateTNumber
			} else if strings.ContainsRune(timeDesignators, b) {
				if numBuf.Len() == 0 {
					return duration, wrapErr(MissingNumber, col)
				}
				num, err := numBufferToNumber(numBuf)
				if err != nil {
					return duration, err
				}
                // using the number
				numBuf.Reset()
				curState = stateTDesignator
			} else {
				return duration, wrapErr(UnknownDesignator, col)
			}
        }
    }
}
```

Especially since the `byte.Buffer` interactions require multiple
function calls for writing, a call for reading and allocations for the
underlying buffer, while the final number parsing itself in `numBufferToNum`
forming a second pass of the integer characters. 

```go{hl_lines=3}
func numBufferToNumber(buf bytes.Buffer) (int64, error) {
	var i int64
	for _, n := range buf.Bytes() {
		digit := int64(n - '0')
		if i > (math.MaxInt64-digit)/10 {
			return 0, DesignatorNumberTooLarge
		}
		i = (i * 10) + digit
	}

	return i, nil
}
```

For this problem, all of this is totally unnecessary and can
be fused into a running `int64` temporary value, updating
value on seeing numeric bytes and then using the integer
when creating the designators field of the
`goiso8601duration.Duration` struct:

```diff
diff --git a/duration.go b/duration.go
index 80a3b4c..4506457 100644
--- a/duration.go
+++ b/duration.go
@@ -128,7 +128,8 @@ func From(s string) (Duration, error) {
 
 	curState := stateStart
 	var col uint8
-	numBuf := *bytes.NewBuffer(make([]byte, 0, 8))
+	var num int64
+	var hasNum bool
 	r := strings.NewReader(s)
 
 	for {
@@ -171,23 +172,25 @@ func From(s string) (Duration, error) {
 			if b == 'T' {
 				curState = stateT
 			} else if unicode.IsDigit(b) {
-				numBuf.WriteRune(b)
+				num = (num * 10) + int64(b-'0')
+				hasNum = true
 				curState = stateNumber
 			} else {
 				return duration, wrapErr(MissingNumber, col)
 			}
 		case stateNumber:
 			if unicode.IsDigit(b) {
-				numBuf.WriteRune(b)
+				digit := int64(b - '0')
+				if num > (math.MaxInt64-digit)/10 {
+					return duration, DesignatorNumberTooLarge
+				}
+				num = (num * 10) + digit
+				hasNum = true
 				curState = stateNumber
 			} else if strings.ContainsRune(defaultDesignators, b) {
-				if numBuf.Len() == 0 {
+				if !hasNum {
 					return duration, wrapErr(MissingNumber, col)
 				}
-				num, err := numBufferToNumber(numBuf)
-				if err != nil {
-					return duration, err
-				}
 				switch b {
 				case 'Y':
 					if duration.year != 0 {
@@ -210,30 +213,36 @@ func From(s string) (Duration, error) {
 					}
 					duration.day = num
 				}
-				numBuf.Reset()
+				num = 0
 				curState = stateDesignator
 			} else {
 				return duration, wrapErr(UnknownDesignator, col)
 			}
 		case stateT, stateTDesignator:
 			if unicode.IsDigit(b) {
-				numBuf.WriteRune(b)
+				digit := int64(b - '0')
+				if num > (math.MaxInt64-digit)/10 {
+					return duration, DesignatorNumberTooLarge
+				}
+				num = (num * 10) + digit
+				hasNum = true
 				curState = stateTNumber
 			} else {
 				return duration, wrapErr(MissingNumber, col)
 			}
 		case stateTNumber:
 			if unicode.IsDigit(b) {
-				numBuf.WriteRune(b)
+				digit := int64(b - '0')
+				if num > (math.MaxInt64-digit)/10 {
+					return duration, DesignatorNumberTooLarge
+				}
+				num = (num * 10) + digit
+				hasNum = true
 				curState = stateTNumber
 			} else if strings.ContainsRune(timeDesignators, b) {
-				if numBuf.Len() == 0 {
+				if !hasNum {
 					return duration, wrapErr(MissingNumber, col)
 				}
-				num, err := numBufferToNumber(numBuf)
-				if err != nil {
-					return duration, err
-				}
 				switch b {
 				case 'H':
 					if duration.hour != 0 {
@@ -251,7 +260,7 @@ func From(s string) (Duration, error) {
 					}
 					duration.second = num
 				}
-				numBuf.Reset()
+				num = 0
 				curState = stateTDesignator
 			} else {
 				return duration, wrapErr(UnknownDesignator, col)
```

The above diff shows:

1. Parsing number via `num` while iterating (no more second pass numeric parsing)
2. Overflow checks, analog to the previous version, returing `DesignatorNumberTooLarge` on occurrence
3. No more calls to `numBuf.{WriteRune,Reset,Bytes}` in the hotpath, or anywhere
4. No allocations anymore

Benchmarks show an average improvement of ~45%:

```text
goos: linux
goarch: amd64
pkg: github.com/xnacly/go-iso8601-duration
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkDuration/P0D-16                45560650                25.55 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15H-16              34413621                35.08 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P1W-16                46468417                25.84 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15W-16               37708790                31.77 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P1Y15W-16             26145358                45.38 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y-16               37434289                31.84 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y3M-16             26251488                45.27 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y3M41D-16          18727663                63.59 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15M-16              33159258                35.16 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15M10S-16           21954288                53.80 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P3Y6M4DT12H30M5S-16   10706078                111.9 ns/op            0 B/op          0 allocs/op
PASS
ok      github.com/xnacly/go-iso8601-duration   13.605s
```

# Throwing unicode.IsDigit away for '0' <= b && b >= '9'

The least impactful change is inlining `unicode.IsDigit`,
but only the ascii (<= MaxLatin1) portion, since the filter
out the non-ascii inputs.

```go
package unicode

// IsDigit reports whether the rune is a decimal digit.
func IsDigit(r rune) bool {
	if r <= MaxLatin1 {
		return '0' <= r && r <= '9'
	}
	return isExcludingLatin(Digit, r)
}
```

This change results in ~6% faster runtime:

```text
goos: linux
goarch: amd64
pkg: github.com/xnacly/go-iso8601-duration
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkDuration/P0D-16                47473572                24.55 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15H-16              35477791                32.96 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P1W-16                48368948                24.96 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15W-16               40997600                29.37 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P1Y15W-16             28936015                41.42 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y-16               39383282                30.27 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y3M-16             27719198                42.48 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y3M41D-16          20594792                58.53 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15M-16              34655841                33.56 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15M10S-16           24108157                50.88 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P3Y6M4DT12H30M5S-16   11649555               102.50 ns/op             0 B/op          0 allocs/op
PASS
ok      github.com/xnacly/go-iso8601-duration   13.601s
```


# Replacing strings.Reader with for-range rune iteration

```text
go test ./... -bench=. -cpuprofile=cpu
go tool pprof -http :8080 cpu
```

![flamegraph1](/revisiting-goiso8601duration/flamegraph1.png)

While the next section targets `strings.ContainsRune`, this section focuses on
`strings.(*Reader).ReadRune`. Specifically requesting a new rune.

```go
for {
    b, size, err := r.ReadRune()
    if err != nil {
        if err != io.EOF {
            return duration, wrapErr(UnexpectedReaderError, col)
        } else {
            // other error handling here
        }
    }
    if size > 1 {
        return duration, wrapErr(UnexpectedNonAsciiRune, col)
    }
    col++

    switch curState {
     // ...
    }
}
```

Each iteration requires a `ReadRune` call, multiple branches
for error handling and ascii checking, since i want to error
on non ascii inputs.

This is simply not necessary, since I can iterate over the
runes of the input string using a for-range loop, check for
ascii validity with `r <= unicode.MaxASCII`:

```diff
diff --git a/duration.go b/duration.go
index e4083bb..52eec76 100644
--- a/duration.go
+++ b/duration.go
@@ -2,11 +2,11 @@ package goiso8601duration
 
 import (
 	"encoding/json"
-	"io"
 	"math"
 	"strconv"
 	"strings"
 	"time"
+	"unicode"
 )
 
 // constants for roundtripping between time.Duration and Duration
@@ -112,33 +112,13 @@ func From(s string) (Duration, error) {
 	}
 
 	curState := stateStart
-	var col uint8
 	var num int64
 	var hasNum bool
-	r := strings.NewReader(s)
-
-	for {
-		b, size, err := r.ReadRune()
-		if err != nil {
-			if err != io.EOF {
-				return duration, wrapErr(UnexpectedReaderError, col)
-			} else if curState == stateP {
-				// being in stateP at the end (io.EOF) means we havent
-				// encountered anything after the P, so there were no numbers
-				// or states
-				return duration, wrapErr(UnexpectedEof, col)
-			} else if curState == stateNumber || curState == stateTNumber {
-				// if we are in the state of Number or TNumber we had a number
-				// but no designator at the end
-				return duration, wrapErr(MissingDesignator, col)
-			} else {
-				curState = stateFin
-			}
-		}
-		if size > 1 {
+
+	for col, b := range s {
+		if b > unicode.MaxASCII {
 			return duration, wrapErr(UnexpectedNonAsciiRune, col)
 		}
-		col++
 
 		switch curState {
 		case stateStart:
@@ -254,6 +234,19 @@ func From(s string) (Duration, error) {
 			return duration, nil
 		}
 	}
+
+	if curState == stateP {
+		// being in stateP at the end (io.EOF) means we havent
+		// encountered anything after the P, so there were no numbers
+		// or states
+		return duration, wrapErr(UnexpectedEof, len(s))
+	} else if curState == stateNumber || curState == stateTNumber {
+		// if we are in the state of Number or TNumber we had a number
+		// but no designator at the end
+		return duration, wrapErr(MissingDesignator, len(s))
+	} else {
+		return duration, nil
+	}
 }
 
 func (i Duration) Apply(t time.Time) time.Time {
```

Thus reducing the hot path complexity by multiple function calls, branches and
the bullshit `strings.(*Reader).ReadRune` does:

```go
package strings

// ReadRune implements the [io.RuneReader] interface.
func (r *Reader) ReadRune() (ch rune, size int, err error) {
	if r.i >= int64(len(r.s)) {
		r.prevRune = -1
		return 0, 0, io.EOF
	}
	r.prevRune = int(r.i)
	ch, size = utf8.DecodeRuneInString(r.s[r.i:])
	r.i += int64(size)
	return
}
```

These changes result in ~38% runtime reduction:

```text
goos: linux
goarch: amd64
pkg: github.com/xnacly/go-iso8601-duration
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkDuration/P0D-16                71080273                16.55 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15H-16              59493799                19.94 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P1W-16                70588683                16.73 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15W-16               62168469                18.98 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P1Y15W-16             43747168                28.85 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y-16               63284880                19.99 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y3M-16             38357061                29.42 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P15Y3M41D-16          28748721                41.85 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15M-16              53639156                20.78 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/PT15M10S-16           37592148                31.97 ns/op            0 B/op          0 allocs/op
BenchmarkDuration/P3Y6M4DT12H30M5S-16   16793139                71.17 ns/op            0 B/op          0 allocs/op
PASS
ok      github.com/xnacly/go-iso8601-duration   13.434s
```

# Removing duplicate Branching in Designator validitiy checks

Lets look at the flamegraph again:

![flamegraph2](/revisiting-goiso8601duration/flamegraph2.png)

The offender `strings.ContainsRune`. The previous implementation employed a
duplicate check for making sure non numeric chars match the expected characters
at a given FSM state:

```go
```

# Replace rune based for-range with []byte

Since this isnt a function call, we cant view its affect in the flamegraph
directly, but we can hone in on `go-iso8601-duration.From` in the graph and
then switch to the `source`-view, showing us a total time taken in the rune
loop and the MaxASCII check:

Before

```text
108        1.65s      1.65s           	for col, b := range s { 
109        320ms      320ms           		if b > unicode.MaxASCII { 
```

Replacing this with a []byte cast and thus omitting the MaxASCII check:

```diff
diff --git a/duration.go b/duration.go
index ba295d7..440e71a 100644
--- a/duration.go
+++ b/duration.go
@@ -6,7 +6,6 @@ import (
        "strconv"
        "strings"
        "time"
-       "unicode"
 )

 // constants for roundtripping between time.Duration and Duration
@@ -105,11 +104,7 @@ func From(s string) (Duration, error) {
        var num int64
        var hasNum bool

-       for col, b := range s {
-               if b > unicode.MaxASCII {
-                       return duration, wrapErr(UnexpectedNonAsciiRune, col)
-               }
-
+       for col, b := range []byte(s) {
                switch curState {
                case stateStart:
                        switch b {
```

Results in 200ms less time spent in the loop:

```text
107        1.47s      1.47s           	for col, b := range []byte(s) { 
```

Running the whole suite results in ~8.6% faster runtime:

```text
goos: linux
goarch: amd64
pkg: github.com/xnacly/go-iso8601-duration
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkDuration/P0D-16                120725466                9.931 ns/op           0 B/o       0 allocs/op
BenchmarkDuration/PT15H-16              92520681                11.67 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/P1W-16                100000000               10.15 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/P15W-16               100000000               10.26 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/P1Y15W-16             82810779                14.83 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/P15Y-16               120902158               10.29 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/P15Y3M-16             75393909                15.68 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/P15Y3M41D-16          56214748                22.31 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/PT15M-16              91787005                12.85 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/PT15M10S-16           53683030                19.45 ns/op            0 B/o       0 allocs/op
BenchmarkDuration/P3Y6M4DT12H30M5S-16   28636116                42.47 ns/op            0 B/op      0 allocs/op
PASS
ok      github.com/xnacly/go-iso8601-duration   14.860s
```

This is easily explainable when looking at the assembly output. While `for col, r := range s` compiles to:

{{<rawhtml>}}
<iframe width="800px" height="400px" src="https://godbolt.org/e#g:!((g:!((g:!((h:codeEditor,i:(filename:'1',fontScale:14,fontUsePx:'0',j:1,lang:go,selection:(endColumn:25,endLineNumber:6,positionColumn:25,positionLineNumber:6,selectionStartColumn:25,selectionStartLineNumber:6,startColumn:25,startLineNumber:6),source:'//+Type+your+code+here,+or+load+an+example.%0Apackage+p%0A%0Afunc+run(s+string)+int+%7B%0A++++runningResult+:%3D+0%0A++++for+col,+r+:%3D+range+s+%7B%0A++++++++runningResult+%2B%3D+int(r)+%2B+col%0A++++%7D%0A++++return+runningResult%0A%7D%0A'),l:'5',n:'0',o:'Go+source+%231',t:'0')),k:48.22469528351881,l:'4',n:'0',o:'',s:0,t:'0'),(g:!((h:compiler,i:(compiler:gl1260,filters:(b:'0',binary:'1',binaryObject:'1',commentOnly:'0',debugCalls:'1',demangle:'0',directives:'0',execute:'1',intel:'0',libraryCode:'0',trim:'1',verboseDemangling:'0'),flagsViewOpen:'1',fontScale:14,fontUsePx:'0',j:1,lang:go,libs:!(),options:'',overrides:!(),selection:(endColumn:54,endLineNumber:35,positionColumn:54,positionLineNumber:35,selectionStartColumn:54,selectionStartLineNumber:35,startColumn:54,startLineNumber:35),source:1),l:'5',n:'0',o:'+x86-64+gc+1.26.0+(Editor+%231)',t:'0')),k:51.77530471648117,l:'4',n:'0',o:'',s:0,t:'0')),l:'2',n:'0',o:'',t:'0')),version:4"></iframe>
{{</rawhtml>}}

`for col, r := range []byte(s)` compiles to a third of the instructions:

{{<rawhtml>}}
<iframe width="800px" height="400px" src="https://godbolt.org/e#g:!((g:!((g:!((h:codeEditor,i:(filename:'1',fontScale:14,fontUsePx:'0',j:1,lang:go,selection:(endColumn:1,endLineNumber:11,positionColumn:1,positionLineNumber:11,selectionStartColumn:1,selectionStartLineNumber:11,startColumn:1,startLineNumber:11),source:'//+Type+your+code+here,+or+load+an+example.%0Apackage+p%0A%0Afunc+run(s+string)+int+%7B%0A++++runningResult+:%3D+0%0A++++for+col,+r+:%3D+range+%5B%5Dbyte(s)+%7B%0A++++++++runningResult+%2B%3D+int(r)+%2B+col%0A++++%7D%0A++++return+runningResult%0A%7D%0A'),l:'5',n:'0',o:'Go+source+%231',t:'0')),k:48.22469528351881,l:'4',n:'0',o:'',s:0,t:'0'),(g:!((h:compiler,i:(compiler:gl1260,filters:(b:'0',binary:'1',binaryObject:'1',commentOnly:'0',debugCalls:'1',demangle:'0',directives:'0',execute:'1',intel:'0',libraryCode:'0',trim:'1',verboseDemangling:'0'),flagsViewOpen:'1',fontScale:14,fontUsePx:'0',j:1,lang:go,libs:!(),options:'',overrides:!(),selection:(endColumn:1,endLineNumber:1,positionColumn:1,positionLineNumber:1,selectionStartColumn:1,selectionStartLineNumber:1,startColumn:1,startLineNumber:1),source:1),l:'5',n:'0',o:'+x86-64+gc+1.26.0+(Editor+%231)',t:'0')),k:51.77530471648117,l:'4',n:'0',o:'',s:0,t:'0')),l:'2',n:'0',o:'',t:'0')),version:4"></iframe>
{{</rawhtml>}}

Most noticably, the latter lacks the call to `runtime.decoderune` for each
iteration:

```asm
        PCDATA  $1, $0
        CALL    runtime.decoderune(SB)
```

So this change not only shaves off 2/3 of the instructions, but it also removes
the per iteration utf8 decoding. This is possible because the FSM only needs to
operate on ASCII inputs, allowing the loop to treat the string as raw bytes
rather than decoding runes.

# Hoisting overflow checks from each numeric change to field creation

Previously the FSM validates the running int64 value wouldnt exceed the valid
representation on each numeric character occurence:

```go
case stateT, stateTDesignator:
    if '0' <= b && b <= '9' {
        digit := int64(b - '0')
        if num > (math.MaxInt64-digit)/10 {
            return duration, DesignatorNumberTooLarge
        }
        num = (num * 10) + digit
        hasNum = true
        curState = stateTNumber
    } else {
        return duration, wrapErr(MissingNumber, col)
    }
```

To reduce branches in the hot path I decided to test moving this overflow
checking to the location where the duration fields are created and the value is
actually used, however this requires widening the running int64 to uint64:

```diff
- var num int64
+ var num uint64

  case stateT, stateTDesignator:
          if '0' <= b && b <= '9' {
-                 digit := int64(b - '0')
-                 if num > (math.MaxInt64-digit)/10 {
-                         return duration, DesignatorNumberTooLarge
-                 }
-                 num = (num * 10) + digit
+                 num = (num * 10) + uint64(b-'0')
                  hasNum = true
                  curState = stateTNumber
          } else {
```

And finally re-adding the check to the usage site:

```diff
+ if num > math.MaxInt64 {
+         return duration, DesignatorNumberTooLarge
+ }
```

This was done to have less branches in the hot path for numbers, thus has
little to no impact on shorter inputs, still a average ~5% improvement, tho:

```text
goos: linux
goarch: amd64
pkg: github.com/xnacly/go-iso8601-duration
cpu: AMD Ryzen 7 3700X 8-Core Processor
BenchmarkDuration/P0D-16                100000000               10.01 ns/op
BenchmarkDuration/PT15H-16              100000000               11.81 ns/op
BenchmarkDuration/P1W-16                100000000               10.19 ns/op
BenchmarkDuration/P15W-16               120588932               9.779 ns/op
BenchmarkDuration/P1Y15W-16             86265106                13.76 ns/op
BenchmarkDuration/P15Y-16               122859478               9.910 ns/op
BenchmarkDuration/P15Y3M-16             77137617                14.32 ns/op
BenchmarkDuration/P15Y3M41D-16          60263616                20.74 ns/op
BenchmarkDuration/PT15M-16              96869085                12.30 ns/op
BenchmarkDuration/PT15M10S-16           63139969                18.33 ns/op
BenchmarkDuration/P3Y6M4DT12H30M5S-16   29586862                39.14 ns/op
PASS
ok      github.com/xnacly/go-iso8601-duration   14.812s
```

> This change results in a contract change compared to `v.1.1.0`, since
> previously the overflow check fired on each number, now it only fires on
> exceeding the valid int64 size on usage. Overflowing uint64 is not handled.

# Highlighting Improvements

| Benchmark        | Baseline (ns) | Improved (ns) | delta (ns) | % Faster | Speedup (x) |
| ---------------- | ------------- | ------------- | ---------- | -------- | ----------- |
| P0D              | 64.26         | 
| PT15H            | 76.69         | 
| P1W              | 64.10         | 
| P15W             | 74.35         | 
| P1Y15W           | 95.39         | 
| P15Y             | 74.44         | 
| P15Y3M           | 96.33         | 
| P15Y3M41D        | 123.7         | 
| PT15M            | 76.61         | 
| PT15M10S         | 104.8         | 
| P3Y6M4DT12H30M5S | 188.7         | 
