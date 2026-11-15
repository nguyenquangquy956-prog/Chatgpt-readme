# iOS Kernel PoC & Reverse-Engineering Research

> **Project handoff / working notebook**  
> Last consolidated: 2026-11-14  
> Scope: static analysis of Apple ARM64 kernelcache code, comparison across builds, and evidence tracking.  
> **Status:** investigation in progress. This document records observed disassembly and current hypotheses; it does not claim a confirmed CVE root cause or a working exploit.

---

## 1. Project purpose

This project investigates selected iOS kernel paths using offline kernelcache analysis. The current thread focuses on a code path involving:

- ARM64 control flow and authenticated indirect calls;
- two candidate handler targets (Handler A / Handler B);
- temporary/scratch metadata construction;
- `mbuf`-related flag checks;
- status-code dispatch and its jump-table targets;
- comparison of the relevant code between two kernelcache builds;
- determining whether a suspected CVE is actually explained by a missing validation, a changed validation, or a different logic flaw.

The guiding rule is to distinguish **what the machine code proves** from **what names or semantics we infer**. Addresses are build-specific and must not be reused against another kernelcache without re-deriving them.

## 2. Environment and target

| Item | Recorded value |
|---|---|
| Device | iPhone 14 Plus (`iPhone14,8`) |
| SoC | Apple A15 |
| OS under investigation | iOS 27.0.1 |
| OS build | `24A446` |
| Host environment | Ubuntu |
| Compiler/toolchain context | Theos, Clang 19 |
| SDK noted in project context | iOS SDK 16.5 |
| Main analysis directory | `~/ios_kernel_poc/` |
| Related research directory | `~/ios_exploit_research/` |
| Build-diff directory | `~/ios27-diff/` |

### Kernelcache inputs

| Label | Path / identity | Role |
|---|---|---|
| `KC` | `kc_27.0.1/kernelcache.dec` | Earlier/baseline kernelcache (called `b1` in prior notes) |
| `KC_B3` | `27.2/24B119__iPhone14,8/kernelcache.release.iPhone14,8` | Later comparison kernelcache (called `b3`) |

**Important:** The exact build/device identity of every input must be verified from the local files and extraction metadata before interpreting addresses. `KC_B3` is the file used for most of the disassembly excerpts below. Do not assume a virtual address from `KC_B3` is valid in `KC`.

## 3. Repository and tooling inventory

Files and scripts observed in the working context:

- `kc_tool.py` — kernelcache VA/file-offset mapping, ARM64 disassembly, direct branch/BL caller search, and ADRP+ADD xref search.
- `disasm_robust.py` — range-based disassembly helper used for address windows and data-gap reporting.
- `fix_compare.py` — comparison helper (exact current behavior should be checked in the local source).
- `align_diff.py` — alignment/diff helper (exact current behavior should be checked in the local source).
- `php_u1_fuzz.py` — PHP unserialization fuzzing artifact noted in the broader research workspace; it is separate from the kernelcache findings in this README.

Related directories:

```text
~/ios_kernel_poc/
~/ios_exploit_research/
~/ios27-diff/
```

### `kc_tool.py` command interface

The observed usage is:

```text
kc_tool.py [-h] kc {dis,callers,bl,xref} ...
```

The kernelcache path must come **before** the subcommand. This was the cause of the initial argparse errors.

Correct examples:

```bash
python3 kc_tool.py "$KC_B3" xref 0xfffffff00adcf1b0
python3 kc_tool.py "$KC_B3" callers 0xfffffff00a568174
python3 kc_tool.py "$KC_B3" bl 0xfffffff00a564f74
python3 kc_tool.py "$KC_B3" dis 0xfffffff00a672534
```

Incorrect form (missing kernelcache positional argument):

```bash
python3 kc_tool.py xref 0xfffffff00adcf1b0
```

Range disassembly examples:

```bash
python3 disasm_robust.py "$KC_B3" \
  0xfffffff00a7933c0 \
  0xfffffff00a793460

python3 disasm_robust.py "$KC_B3" \
  0xfffffff00a672520 \
  0xfffffff00a672570
```

Use the environment variables only after confirming they point to the intended files:

```bash
printf 'KC=%s\nKC_B3=%s\n' "$KC" "$KC_B3"
file "$KC" "$KC_B3"
sha256sum "$KC" "$KC_B3"
```

`kc_tool.py` was observed to use Capstone and a hard-coded segment map. Validate that map against the exact kernelcache being analyzed. A stale segment map can produce plausible-looking but incorrect VA/file-offset conversions.

## 4. Evidence and confidence convention

Use these labels in future notes:

- **[CONFIRMED]** Directly visible in the supplied disassembly or reproducible tool output.
- **[STRONG INFERENCE]** Follows from multiple instructions/control-flow edges, but needs surrounding callers/callees or symbols for semantic naming.
- **[HYPOTHESIS]** Plausible interpretation that still needs validation.
- **[UNRESOLVED]** Current evidence is insufficient.

A function's role must not be inferred solely from a nearby string, one call site, or an address. A status constant is not semantically identified until its producer, consumer, and relevant switch/table case are traced.

## 5. Main findings

### 5.1 Data xrefs to the two global addresses

The initial `kc_tool.py` search produced:

```text
[*] 1 ADRP+ADD xref(s) -> 0xfffffff00adcf1b0
    xref @ 0xfffffff00a672534  (fileoff 0x366e534)

[*] 0 ADRP+ADD xref(s) -> 0xfffffff00ad950860
```

A broader data-xref pass later produced:

```text
[*] 1 data xref(s) -> 0xfffffff00adcf1b0
    ADRP+ADD @ 0xfffffff00a672534 (fileoff 0x366e534)

[*] 45 data xref(s) -> 0xfffffff00ad95860
```

The `0xfffffff00ad95860` references include both `ADRP+LDR` and `ADRP+ADD` forms. Examples:

```text
0xfffffff00a46ea68
0xfffffff00a46eb0c
0xfffffff00a47c5c4
0xfffffff00a564e84
0xfffffff00a584db8
0xfffffff00a5ca26c
0xfffffff00a5ca73c
0xfffffff00a672528
0xfffffff00a6728cc
0xfffffff00a699f98
0xfffffff00a69a028
0xfffffff00a6b12b4
0xfffffff00a6b4ce4
0xfffffff00a793228
0xfffffff00a79339c
0xfffffff00a7934d0
0xfffffff00a79352c
0xfffffff00a8357d8
0xfffffff00a83627c
0xfffffff00a836a6c
0xfffffff00a836b48
0xfffffff00a836d1c
0xfffffff00a8370c4
0xfffffff00a837d98
0xfffffff00a8390ec
0xfffffff00a8391f8
0xfffffff00a8396f0
0xfffffff00a839c64
0xfffffff00a83a1b4
0xfffffff00a83ae08
0xfffffff00a83b774
0xfffffff00a83b7cc
0xfffffff00a83b820
0xfffffff00a83bff4
0xfffffff00a83c118
0xfffffff00a83c174
0xfffffff00a83c210
0xfffffff00a83c380
0xfffffff00a83c4ec
0xfffffff00a83c88c
0xfffffff00a83c978
0xfffffff00a83ca04
0xfffffff00a83cb20
0xfffffff00a88f624
0xfffffff00a88fe88
```

**Interpretation status:**

- `0xfffffff00adcf1b0` has one observed ADRP+ADD reference in this search, at `0xfffffff00a672534`.
- `0xfffffff00ad95860` has many observed references and is read at several sites as a 32-bit value at offset `+0x860` from the page base.
- Prior analysis treated `0xfffffff00ad95860` as a global mode/feature selector that gates alternate preprocessing paths. This is an **inference**, not a symbolically confirmed name. Identify the global by tracing its initialization, all writers, and all readers before assigning a definitive semantic label.

### 5.2 Consumer around `0xfffffff00a672520`

Observed `KC_B3` disassembly:

```asm
0xfffffff00a672520: ldr      x0, [x27, #0xb0]
0xfffffff00a672524: cbz      x0, #0xfffffff00a67254c
0xfffffff00a672528: adrp     x8, #0xfffffff00ad95000
0xfffffff00a67252c: ldr      w8, [x8, #0x860]
0xfffffff00a672530: cbnz     w8, #0xfffffff00a672d50
0xfffffff00a672534: adrp     x8, #0xfffffff00adcf000
0xfffffff00a672538: add      x8, x8, #0x1b0
0xfffffff00a67253c: movz     w9, #0x1
0xfffffff00a672540: [data]   080129f8
0xfffffff00a672544: bl       #0xfffffff00a78f188
0xfffffff00a672548: cbnz     x0, #0xfffffff00a672544
0xfffffff00a67254c: str      xzr, [x27, #0xb0]
0xfffffff00a672550: ldr      x9, [sp, #0xf8]
0xfffffff00a672554: ldr      x12, [sp, #0xa8]
0xfffffff00a672558: ldr      x8, [x27, #0xb0]
0xfffffff00a67255c: cbnz     x8, #0xfffffff00a670378
0xfffffff00a672560: b        #0xfffffff00a67062c
```

**[CONFIRMED]** The code tests a global 32-bit value loaded from `[ADRP_base + 0x860]`. If nonzero, it branches to `0xfffffff00a672d50`; if zero, it materializes `0xfffffff00adcf1b0` in `x8`, sets `w9=1`, executes an instruction word displayed as data by the disassembler, then calls `0xfffffff00a78f188` in a loop while `x0 != 0`.

**[UNRESOLVED]** The exact type and semantics of the data at `0xfffffff00adcf1b0`, the instruction at `0xfffffff00a672540`, and the callee at `0xfffffff00a78f188` require further decoding and cross-reference analysis. Do not label this as a lock, reference counter, or object without confirming the called routine and global layout.

### 5.3 Second consumer around `0xfffffff00a6728b0`

Observed:

```asm
0xfffffff00a6728c0: ldr      x8, [sp, #0xc0]
0xfffffff00a6728c4: ldr      x0, [x27, #0xb0]
0xfffffff00a6728c8: cbz      x0, #0xfffffff00a6728f4
0xfffffff00a6728cc: adrp     x8, #0xfffffff00ad95000
0xfffffff00a6728d0: ldr      w8, [x8, #0x860]
0xfffffff00a6728d4: cbnz     w8, #0xfffffff00a672c74
0xfffffff00a6728d8: mov      x19, x0
0xfffffff00a6728dc: ldr      w0, [sp, #0x90]
0xfffffff00a6728e0: bl       #0xfffffff00a564f74
0xfffffff00a6728e4: mov      x0, x19
0xfffffff00a6728e8: bl       #0xfffffff00a78f188
0xfffffff00a6728ec: cbnz     x0, #0xfffffff00a6728e8
0xfffffff00a6728f0: ldr      x8, [sp, #0xc0]
0xfffffff00a6728f4: cbz      x8, #0xfffffff00a67290c
```

Another branch at `0xfffffff00a672c74` sets up arguments and calls `0xfffffff00a7933f4`:

```asm
0xfffffff00a672c74: ldr      x1, [x27, #0xb8]
0xfffffff00a672c78: movz     w2, #0x6
0xfffffff00a672c7c: ldr      w3, [sp, #0x90]
0xfffffff00a672c80: movz     x4, #0
0xfffffff00a672c84: movz     w5, #0
0xfffffff00a672c88: bl       #0xfffffff00a7933f4
0xfffffff00a672c8c: b        #0xfffffff00a6728f0
```

**[CONFIRMED]** The global mode test influences whether this path uses the `0xfffffff00a564f74` route or the `0xfffffff00a7933f4` route.

**[UNRESOLVED]** The complete caller-level meaning of the `x27` fields and stack arguments is not yet established.

## 6. Handler selection and PAC

### 6.1 Relevant helper: `0xfffffff00a567f04`

Observed disassembly includes:

```asm
0xfffffff00a567f04: hint     #0x1b
0xfffffff00a567f08: stp      x24, x23, [sp, #-0x40]!
...
0xfffffff00a567f1c: mov      x19, x2
0xfffffff00a567f20: mov      x20, x0
0xfffffff00a567f24: tst      w1, #2
0xfffffff00a567f28: adrp     x16, #0xfffffff00a441000
0xfffffff00a567f2c: add      x16, x16, #0x410
0xfffffff00a567f30: movz     x17, #0xd2bc
0xfffffff00a567f34: [data]   3002c1da
0xfffffff00a567f38: mov      x8, x16
0xfffffff00a567f3c: adrp     x16, #0xfffffff00a441000
0xfffffff00a567f40: add      x16, x16, #0x488
0xfffffff00a567f44: movz     x17, #0xd2bc
0xfffffff00a567f48: [data]   3002c1da
0xfffffff00a567f4c: csel     x22, x16, x8, eq
...
```

The 32-bit instruction word `0xDAC10230` (little-endian bytes shown as `30 02 c1 da`) decodes as an ARM64 pointer-authentication instruction in the `PACIA` family: pointer authentication using key A and modifier in `x17`. In this sequence, the two candidate code addresses are:

- Handler A candidate: `0xfffffff00a441410` (`0xfffffff00a441000 + 0x410`)
- Handler B candidate: `0xfffffff00a441488` (`0xfffffff00a441000 + 0x488`)
- Modifier loaded into `x17`: `0xd2bc`

**[CONFIRMED]** The code forms two addresses, applies the same PACIA-form instruction to each, and uses `csel x22, x16, x8, eq` to choose one according to the flags set by `tst w1, #2`.

**[STRONG INFERENCE]** Since `tst w1, #2` sets Z when bit 1 is clear, `csel ..., eq` selects the second candidate (`x16`, address `0xfffffff00a441488`) when bit 1 is clear, and the first candidate (`x8`, address `0xfffffff00a441410`) when bit 1 is set. This must be checked against the complete control-flow/data-flow context before attaching semantic labels “A” and “B”.

A separate prior note reported that a call site with `w1=6` selected Handler A (`0xfffffff00a441410`). That is consistent with bit 1 being set, but the full call setup and downstream invocation should be rechecked before treating the mapping as globally true.

### 6.2 Do not overclaim PAC behavior

The bytes and register setup support identifying a PACIA-family operation. They do **not**, by themselves, establish:

- what the pointed-to functions do;
- whether the pointers are later authenticated at a particular call site;
- whether the modifier is a discriminator, context value, or part of a larger ABI convention;
- whether PAC is related to the suspected vulnerability.

Trace the pointer from the selection to its eventual use, and inspect the destination functions before assigning handler semantics.

## 7. Scratch metadata construction

The helper beginning at `0xfffffff00a568174` is a substantial routine. The observed prologue and early body:

```asm
0xfffffff00a568174: hint     #0x1b
0xfffffff00a568178: sub      sp, sp, #0x150
...
0xfffffff00a568194: mov      x19, x5
0xfffffff00a568198: mov      x20, x4
0xfffffff00a56819c: mov      x23, x3
0xfffffff00a5681a0: mov      x22, x2
0xfffffff00a5681a4: mov      x24, x1
0xfffffff00a5681a8: mov      x21, x0
...
0xfffffff00a5681bc: mov      x0, x1
0xfffffff00a5681c0: bl       #0xfffffff00a564f74
0xfffffff00a5681c4: movi     v0.2d, #0
0xfffffff00a5681c8: str      wzr, [sp, #0xf0]
0xfffffff00a5681cc: stp      q0, q0, [sp, #0xd0]
0xfffffff00a5681d0: stp      q0, q0, [sp, #0xb0]
0xfffffff00a5681d4: stp      q0, q0, [sp, #0x90]
0xfffffff00a5681d8: stp      q0, q0, [sp, #0x70]
0xfffffff00a5681dc: stp      q0, q0, [sp, #0x50]
0xfffffff00a5681e0: stp      q0, q0, [sp, #0x30]
0xfffffff00a5681e4: stp      q0, q0, [sp, #0x10]
0xfffffff00a5681e8: str      w24, [sp, #0xac]
0xfffffff00a5681ec: cbz      x22, #0xfffffff00a568220
0xfffffff00a5681f0: strh     w23, [sp, #0xb2]
...
0xfffffff00a568204: add      x0, x23, #0xa4
0xfffffff00a568208: movz     w1, #0x40
0xfffffff00a56820c: bl       #0xfffffff00a76d3ec
0xfffffff00a568210: add      x0, x23, #0xa4
0xfffffff00a568214: movz     w1, #0x40
0xfffffff00a568218: bl       #0xfffffff00a1d14a0
0xfffffff00a56821c: strb     w0, [sp, #0xb0]
```

Additional later excerpt from the same routine:

```asm
0xfffffff00a568220: ...
0xfffffff00a568230: bl       #0xfffffff00a567f04
...
0xfffffff00a5682a0: cmp      w2, #1
...
0xfffffff00a5682c0: ldr      x8, [x3, #0x30]
...
0xfffffff00a56830c: mov      x22, x3
0xfffffff00a568310: add      x20, x1, #4
...
0xfffffff00a568320: mov      x21, x1
...
0xfffffff00a568354: ldr      w20, [x1]
...
0xfffffff00a56836c: sub      w9, w20, #1
0xfffffff00a568370: cmp      w9, w8
0xfffffff00a568374: b.hs     #0xfffffff00a568570
```

**[CONFIRMED]**

- A `0x150`-byte stack frame is allocated.
- Multiple SIMD stores zero stack-resident regions, consistent with zero-initialization of a temporary structure.
- Values are written at stack offsets including `+0xac`, `+0xb2`, and `+0xb0`.
- A 64-byte (`0x40`) operation is invoked twice on a stack buffer at `sp + 0x10 + 0xa4` (effective address `sp + 0xb4` in the shown sequence; preserve the actual register arithmetic when reconstructing the full layout).
- The routine calls `0xfffffff00a567f04`, which contains the PACIA/handler-selection sequence above.
- It later loads a 32-bit value from an input pointer and performs a bounds-style comparison against a global value before branching.

**[UNRESOLVED]** The exact C structure layout, field names, ownership rules, and meaning of the helper calls have not been proven. The phrase “scratch metadata” is a working label for the temporary stack structure, not a confirmed Apple type name.

A prior analysis note also recorded metadata fields at offsets `+0x50` and `+0x52` and a `0x18`-byte copy in a related helper path. Treat that as a separate observation until the relevant full instruction range and base pointer are aligned. Do not merge those offsets with the stack offsets above without proving they refer to the same structure.

## 8. `mbuf`-related flag checks

The routine around `0xfffffff00a568174` and its associated helper paths were noted to inspect fields/flags at:

- offset `0x74`, bit 18;
- offset `0x74`, bit 21;
- offset `0x74`, bit 10;
- offset `0xcf`, bit 5.

These checks were visible in a later part of the routine, including instructions of the form:

```asm
ldr      w8, [x20, #0x74]
tbnz     w8, #0x12, ...
tbnz     w8, #0x15, ...
tbnz     w8, #0xa, ...
ldrb     w8, [x20, #0xcf]
tbz      w8, #5, ...
```

**[CONFIRMED]** The code branches on those bit positions in fields at those offsets from the register then holding the object pointer (`x20` in the excerpt).

**[STRONG INFERENCE]** The object is plausibly an `mbuf` or an mbuf-associated structure because of the surrounding project path and field usage. However, offsets alone do not prove the exact structure identity. Confirm using matching XNU headers, symbols, nearby call sites, or known layout for the exact target build.

**[UNRESOLVED]** The meaning of each bit, the direction of each branch, and whether the checks enforce preconditions, select a data path, or handle exceptional packet states remain to be mapped instruction-by-instruction.

## 9. Wrapper/dispatch helper family around `0xfffffff00a7933f4`

### 9.1 Entry around `0xfffffff00a7933f8`

Observed:

```asm
0xfffffff00a7933f8: stp      x20, x19, [sp, #-0x20]!
0xfffffff00a7933fc: stp      x29, x30, [sp, #0x10]
0xfffffff00a793400: add      x29, sp, #0x10
0xfffffff00a793404: mov      x9, x2
0xfffffff00a793408: mov      x8, x1
0xfffffff00a79340c: tbnz     w2, #1, #0xfffffff00a793464
0xfffffff00a793410: tbz      w9, #0, #0xfffffff00a7934a8
0xfffffff00a793414: ldr      x6, [x0, #0x58]
...
```

This routine checks bits in its third argument (`w2`) and second argument (`w1`/`w9`) and conditionally takes different helper paths.

### 9.2 Branches to two helper implementations

At `0xfffffff00a79347c`:

```asm
bl       #0xfffffff00a568174
```

At `0xfffffff00a7934a0`:

```asm
bl       #0xfffffff00a567d08
```

The wrapper then calls `0xfffffff00a78f188` in a loop:

```asm
0xfffffff00a7934a4: mov      x0, x19
0xfffffff00a7934a8: bl       #0xfffffff00a78f188
0xfffffff00a7934ac: cbnz     x0, #0xfffffff00a7934a8
```

A further branch at `0xfffffff00a7935b8` also calls `0xfffffff00a568174`, and at `0xfffffff00a793594` another branch calls `0xfffffff00a567d08`.

**[CONFIRMED]** `0xfffffff00a7933f4` is part of a wrapper/helper family that selects between at least two processing helpers based on argument bits and object state. The helpers are `0xfffffff00a568174` and `0xfffffff00a567d08`.

**[UNRESOLVED]** It is not yet justified to name these as protocol handlers, packet handlers, allocators, or validators. Their argument mapping and return semantics need complete analysis.

### 9.3 Object layout checks in adjacent helper

At `0xfffffff00a7935d0`, an adjacent routine reads:

```asm
ldr      x8, [x0, #0x10]
ldrh     w9, [x0, #0x1e]
...
add      x10, x0, #0xe0
...
cmp      x8, x10
```

Depending on bit 0 of the 16-bit field at `x0+0x1e`, it chooses either `x0+0xe0` or the pointer at `x0+0x20`, then compares that result with the pointer at `x0+0x10`. It subsequently checks a requested length/size and updates the pointer at `x0+0x10` after alignment arithmetic.

**[STRONG INFERENCE]** This looks like an inline-versus-external-buffer or storage-boundary check, but the structure identity and field names are not established.

## 10. Status dispatch and status semantics

A status-dispatch routine was inspected around `0xfffffff00a564f74`. The code performs range checks and uses relative jump tables. The excerpt begins:

```asm
0xfffffff00a564f74: hint     #0x22
0xfffffff00a564f78: movz     w8, #0x205, lsl #16
0xfffffff00a564f7c: cmp      w0, w8
0xfffffff00a564f80: b.gt     #0xfffffff00a564fdc
...
0xfffffff00a564fb8: adrp     x17, #0xfffffff00a566000
0xfffffff00a564fbc: add      x17, x17, #0x30
0xfffffff00a564fc0: ldrsw    x16, [x17, x16, lsl #2]
0xfffffff00a564fc4: adr      x17, #0xfffffff00a564fc4
0xfffffff00a564fc8: add      x16, x17, x16
0xfffffff00a564fcc: br       x16
```

Another dispatcher window around `0xfffffff00a565060` shows the same general pattern: compare/range-check the input status, load a signed relative offset from a table, add it to the table-relative PC, and branch indirectly.

A prior calculation recorded:

- status value: `0x02070033`
- calculated jump-table destination: `0xfffffff00a565af0`

**[CONFIRMED only as a recorded calculation]** `0xfffffff00a565af0` was calculated as the target for status `0x02070033` in the inspected dispatcher.

**[UNRESOLVED]** The semantic meaning of status `0x02070033`, and the behavior of the case body at `0xfffffff00a565af0`, are not yet established. The target must be revalidated from the exact jump-table entry and dispatcher base in the same kernelcache. The case body must then be disassembled far enough to identify its return value, side effects, and callers.

### Required status-case workflow

1. Confirm the dispatcher input register and width (`w0` in the excerpt).
2. Reconstruct the relevant table index calculation exactly.
3. Read the signed 32-bit table entry from the exact table VA/file offset.
4. Calculate the target using the PC base used by the instruction sequence.
5. Disassemble the case target and follow all branches to its return.
6. Identify who creates/passes the status value.
7. Compare the same case in the other kernelcache build.
8. Only then assign a semantic label.

Do not infer an `errno`, `kern_return_t`, network status, or protocol meaning from the hexadecimal value alone.

## 11. Handler semantics: current status

| Item | Status | Evidence / next proof needed |
|---|---|---|
| PACIA instruction | **Confirmed instruction family** | Word `0xDAC10230` / bytes `30 02 c1 da`; decode and register flow show pointer-authentication operation using key A |
| Handler A candidate | **Address confirmed; semantics unresolved** | `0xfffffff00a441410`; inspect function entry, callers, and authenticated use |
| Handler B candidate | **Address confirmed; semantics unresolved** | `0xfffffff00a441488`; inspect function entry, callers, and authenticated use |
| Handler A/B selection | **Strong inference** | `tst w1,#2` followed by `csel ... eq`; validate complete data flow and call-site argument values |
| Scratch metadata construction | **Partially confirmed** | `0x150` stack frame, zeroed regions, writes at stack offsets; map full structure and helper effects |
| `mbuf` flag checks | **Bit tests confirmed; field semantics unresolved** | offsets `0x74` bits 18/21/10 and `0xcf` bit 5; correlate with exact XNU layout |
| Status dispatch target | **Recorded calculation, revalidate** | status `0x02070033` → `0xfffffff00a565af0`; inspect table entry and target body |
| Handler semantics | **Unresolved** | Need function bodies, callers, arguments, side effects, and return conventions |
| Status case semantics | **Unresolved** | Need case target disassembly and status producer/caller chain |
| CVE root cause | **Unresolved** | Earlier comparison found validation present in both b1 and b3; no confirmed missing-check explanation |

## 12. CVE root-cause assessment

An earlier working theory was that a validation difference between the baseline and later kernelcache might explain the suspected CVE. That theory was subsequently downgraded.

**Current conclusion: the CVE root cause is not established.**

Prior notes report that relevant validation exists in both `b1` and `b3`. This means the simple claim “the later build added the missing validation” is not supported by the current evidence. The vulnerability, if the target behavior is indeed CVE-related, may instead involve:

- a difference in the exact predicate or its inputs;
- a check that is present but occurs too late;
- a mismatch between validated length/metadata and the object actually consumed;
- a lifetime/ownership or state-transition issue;
- a handler-selection or status-path difference;
- a condition only reachable under a specific flag combination;
- a difference outside the currently inspected function window.

These are investigation branches, **not conclusions**. Do not publish a root-cause statement until the vulnerable and fixed builds are compared at the semantic level, including callers, data structures, and all relevant paths.

### Minimum evidence needed for a defensible root cause

- Exact affected and fixed build identifiers.
- Reproducible mapping of the same logical function across both kernelcaches.
- A complete control-flow comparison, not only byte diff.
- Identification of all relevant inputs and their provenance.
- Demonstration of the faulty invariant or missing/incorrect check.
- Confirmation that the fix changes that invariant/path.
- A clear explanation of reachability and impact, without relying on an exploit demonstration.

## 13. Build comparison notes

Current comparison labels:

- `b1`: earlier baseline kernelcache (`kc_27.0.1/kernelcache.dec`).
- `b3`: later comparison kernelcache (`27.2/24B119__iPhone14,8/kernelcache.release.iPhone14,8`).

Prior analysis explicitly cautioned that validation was present in both versions, so the root-cause theory was downgraded from “missing validation added in fixed build” to **unresolved**.

For every comparison, record:

```text
Logical function:
b1 VA:
b3 VA:
b1 file offset:
b3 file offset:
Function boundary evidence:
Changed instructions:
Changed control-flow edges:
Changed data references:
Input/field differences:
Behavioral consequence:
Confidence:
```

Do not compare raw VAs as if they were stable symbols. Align functions using surrounding control flow, callers, constants, and instruction patterns.

## 14. Reproducibility log: key addresses

All addresses below are from the `KC_B3` analysis unless otherwise stated.

| Address | Current role / note |
|---|---|
| `0xfffffff00adcf1b0` | Global/data target; one ADRP+ADD xref at `0xfffffff00a672534` |
| `0xfffffff00ad95860` | Global/data target; 45 data xrefs; read at `+0x860` in multiple paths |
| `0xfffffff00a672520` | Consumer of object at `[x27+0xb0]`; global mode test |
| `0xfffffff00a672534` | ADRP+ADD reference to `0xfffffff00adcf1b0` |
| `0xfffffff00a6728cc` | Second global mode read |
| `0xfffffff00a672c74` | Alternate path sets up args and calls `0xfffffff00a7933f4` |
| `0xfffffff00a564f74` | Status/range dispatcher or status helper; semantics pending |
| `0xfffffff00a565060` | Additional dispatcher/jump-table region |
| `0xfffffff00a565af0` | Recorded target for status `0x02070033`; revalidate |
| `0xfffffff00a567f04` | PACIA/handler selection helper |
| `0xfffffff00a568174` | Large scratch/metadata helper; 0x150-byte stack frame |
| `0xfffffff00a567d08` | Alternate helper selected by wrapper |
| `0xfffffff00a568174` | Helper called by wrapper at multiple sites |
| `0xfffffff00a568220` | Continuation of scratch helper; additional checks/calls |
| `0xfffffff00a6728e0` | Calls `0xfffffff00a564f74` in one branch |
| `0xfffffff00a7933f4` | Wrapper/dispatcher family entry |
| `0xfffffff00a7933f8` | Branching helper body |
| `0xfffffff00a79347c` | Calls `0xfffffff00a568174` |
| `0xfffffff00a7934a0` | Calls `0xfffffff00a567d08` |
| `0xfffffff00a7935b8` | Another call to `0xfffffff00a568174` |
| `0xfffffff00a7935d0` | Adjacent object storage/bounds-style helper |
| `0xfffffff00a78f188` | Repeatedly called helper; semantics not yet identified |
| `0xfffffff00a441410` | Handler A candidate |
| `0xfffffff00a441488` | Handler B candidate |

## 15. Prior observed xref/caller results

- `0xfffffff00adcf1b0`: one ADRP+ADD xref at `0xfffffff00a672534`, file offset `0x366e534`.
- `0xfffffff00ad950860`: zero ADRP+ADD xrefs in the initial narrow search. This is not inconsistent with later results for `0xfffffff00ad95860`; note the different target address (`...5860` vs `...0860`).
- `0xfffffff00ad95860`: 45 data xrefs in the broader search.
- `0xfffffff00a568174`: three direct branch sites reported:
  - `0xfffffff00a793348` (file offset `0x378f348`)
  - `0xfffffff00a79347c` (file offset `0x378f47c`)
  - `0xfffffff00a7935b8` (file offset `0x378f5b8`)
- `0xfffffff00a564f74`: 14 direct branch sites reported, including:
  - `0xfffffff00a5678f4`
  - `0xfffffff00a567c30`
  - `0xfffffff00a567d5c`
  - `0xfffffff00a5681c0`
  - `0xfffffff00a584dc8`
  - `0xfffffff00a6728e0`
  - `0xfffffff00a6b12c8`
  - `0xfffffff00a6b4cf8`
  - `0xfffffff00a7933b0`
  - `0xfffffff00a7934e4`
  - `0xfffffff00a793540`
  - `0xfffffff00a83b830`
  - `0xfffffff00a83c224`
  - `0xfffffff00a88fe98`

## 16. Working methodology / research skill profile

This section is a reusable protocol for continuing the project consistently.

### 16.1 Static-analysis workflow

1. **Fingerprint inputs first.** Record OS build, device model, kernelcache filename, SHA-256, extraction method, and segment map.
2. **Normalize addresses.** Record VA, file offset, segment, and build label together.
3. **Start from a concrete reference.** Use xrefs, callers, branch targets, constants, and known code patterns.
4. **Disassemble a bounded window.** Include enough bytes before and after the target to capture prologue, branch conditions, and epilogue.
5. **Reconstruct data flow.** Track AArch64 argument registers (`x0`–`x7`), return register (`x0`/`w0`), stack slots, and callee-saved registers.
6. **Reconstruct control flow.** Record branch conditions, fallthroughs, loops, indirect branches, and jump-table calculations.
7. **Identify structure fields cautiously.** Offset observations are not field names. Correlate with matching headers/symbols and exact-build layouts.
8. **Compare builds semantically.** Align logical functions, not raw addresses; distinguish code movement from behavior changes.
9. **Track uncertainty.** Every claim gets an evidence label and a concrete next verification step.
10. **Preserve raw output.** Keep original command lines and disassembly excerpts alongside summaries.

### 16.2 ARM64 details to preserve

- `ADRP` computes a page-relative address; pair it with the following instruction before declaring a global reference.
- `ADRP+LDR` and `ADRP+ADD` are distinct reference forms. A narrow xref scanner may miss one form or other address-generation patterns.
- `BL` is a call; `B` is an unconditional branch. A tool's “direct branch” result may include both unless explicitly filtered.
- `TST` updates condition flags. Interpret a following `CSEL` using the exact condition code and flag state.
- `TBZ` / `TBNZ` test a bit and branch when clear/set, respectively.
- `LDRSW` sign-extends a 32-bit table entry; relative jump-table offsets are signed.
- `PACIA`-family instructions sign/authenticate pointers with key A depending on the exact opcode. Confirm exact encoding and data flow; do not infer the full pointer-authentication scheme from a mnemonic alone.
- Disassemblers may mark literal data, embedded instructions, or unusual encodings as `[data]`. Decode raw words separately before interpreting them.

### 16.3 Evidence hygiene

For each important conclusion, save:

- exact command;
- exact input file and hash;
- output excerpt;
- address range;
- relevant raw instruction words;
- reasoning from instruction to conclusion;
- confidence level;
- what would falsify the conclusion.

Avoid silently turning a tentative label into a fact in later notes.

## 17. Next research tasks

Recommended order:

1. **Verify the PAC helper end-to-end.** Disassemble both handler candidates at `0xfffffff00a441410` and `0xfffffff00a441488`; find all uses of the selected pointer and identify the actual call/authentication instruction.
2. **Resolve the wrapper arguments.** Trace all callers of `0xfffffff00a7933f4`; create an argument table for `x0`–`x7`, including flag bits and object provenance.
3. **Finish the scratch structure map.** Disassemble the complete `0xfffffff00a568174` routine through its epilogue; map each stack offset and helper call.
4. **Validate the mbuf identity.** Compare the observed offsets with the exact matching XNU definitions or symbols for the target build.
5. **Resolve status `0x02070033`.** Re-read the jump-table entry, verify `0xfffffff00a565af0`, and trace the case body and status producer.
6. **Trace global `0xfffffff00ad95860`.** Find its initialization and writers; determine whether it is a feature gate, mode selector, or something else.
7. **Compare b1 and b3 by logical function.** Record changed predicates, argument flow, and ordering of checks.
8. **Reassess CVE hypothesis only after steps 1–7.** Keep root cause marked unresolved until a specific violated invariant and fixing change are demonstrated.

## 18. Known caveats

- The pasted disassembly excerpts are partial windows, not complete function bodies.
- Several functions are identified only by address; no authoritative symbol names were established in the available evidence.
- The `mbuf` label is a contextual inference pending layout confirmation.
- The Handler A/B semantic labels are placeholders for two candidate addresses, not confirmed Apple function names.
- The status `0x02070033` mapping to `0xfffffff00a565af0` is a prior calculation and must be independently revalidated.
- `0xfffffff00ad950860` and `0xfffffff00ad95860` are different addresses. Do not conflate them.
- The earlier conclusion that validation appears in both baseline and later builds weakens the simplest missing-validation theory but does not disprove a vulnerability.
- No exploitability, reachability, or CVE attribution is established by this static-analysis notebook.

## 19. Change log

### 2026-11-14 — consolidated findings

- Recorded target environment and working directories.
- Captured `kc_tool.py` argument-order correction: kernelcache path precedes subcommand.
- Recorded xrefs to `0xfffffff00adcf1b0` and `0xfffffff00ad95860`.
- Documented the global mode check at `0xfffffff00a672528` / `0xfffffff00a6728cc`.
- Recorded PACIA-family encoding `30 02 c1 da`, modifier `0xd2bc`, and candidate handler addresses.
- Recorded scratch stack-frame initialization and metadata-related writes.
- Recorded `mbuf`-candidate field/bit checks.
- Documented wrapper branches to `0xfffffff00a568174` and `0xfffffff00a567d08`.
- Recorded the status dispatcher and the pending status `0x02070033` case.
- Downgraded the CVE root-cause claim to unresolved because validation was reported in both compared builds.

---

## 20. How to continue in a fresh ChatGPT project

Paste or attach this README and ask the assistant to:

1. Treat this document as the project handoff, not as proof that every hypothesis is correct.
2. Preserve the confidence labels and unresolved items.
3. Ask for the relevant raw disassembly or local file when a conclusion depends on missing bytes.
4. Verify exact build identity before reusing any address.
5. Never invent symbol names, structure fields, CVE attribution, or handler semantics.
6. Update the README with dated findings and exact evidence whenever a new conclusion is reached.

**Primary principle:** evidence first, semantic interpretation second, vulnerability attribution last.

---

# 21. Cập nhật notebook đã xác minh — 2026-11-15

> Phần này được bổ sung từ notebook người dùng cung cấp ngày 2026-11-15. Khi nội dung phần này mâu thuẫn với ghi chú cũ ở các mục 1–20, **phần 21 và 22 là trạng thái mới hơn**. Không xóa lịch sử sai lệch; giữ lại để truy nguyên quá trình sửa.

## 21.1 Fingerprint build và nguồn gốc kernelcache

| Nhãn | File | Build | Darwin / XNU | SHA-256 của Mach-O đã giải nén | Trạng thái |
|---|---|---|---|---|---|
| `KC` / b1 | `~/ios27-diff/27.0.1/24A446__iPhone14,8/kernelcache.release.iPhone14,8` (đồng nhất với `~/ios_exploit_research/kc_27.0.1/kernelcache.dec`) | `24A446` / iOS 27.0.1 | `27.0.0`, `xnu-13432.2.10~2` | `c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445` | **[CONFIRMED]** Theo xác minh IPSW được ghi trong notebook |
| `KC_B3` / b3 | `~/ios27-diff/27.2/24B119__iPhone14,8/kernelcache.release.iPhone14,8` | `24B119` / iOS 27.2 | `27.2.0`, `xnu-13432.42.3~28` | `c81fb9d291cb4e0d8cca512724079da21bc3d6460d37d6f3a4831116af8b410a` | **[CONFIRMED]** Theo xác minh IPSW được ghi trong notebook |
| Đối chứng | `~/ios_exploit_research/kc_27.2/24B5099f__iPhone14,8/kernelcache.release.iPhone14,8` | `24B5099f` | `27.2.0`, `xnu-13432.40.177.0.3~16` | `194c314c1af1e03af427d042a8bdfecef8401b010a04ccfe14eca231f003bca3` | **[CONFIRMED]** Theo notebook; chưa có landmark b3 |
| Đối chứng | IPSW `24B5084k`; chưa có Mach-O trên máy | `24B5084k` | `27.2.0`, `xnu-13432.40.144.0.1~55` | `7f7e770e99fcd7be8694ae62ae9ed9ee5160b83b7f336ba75c1136f015b593d5` | **[CONFIRMED]** Hash được ghi từ IPSW; chưa có file local để disassemble |

Quy trình nguồn gốc được ghi nhận:

- Build lấy từ `BuildManifest.plist` trong IPSW (`ProductBuildVersion`), không suy ra từ tên thư mục.
- Kernelcache trong IPSW là `kernelcache.release.iphone14b`, payload IM4P/LZFSE (`bvx2`); giải nén bằng `ipsw kernel dec -o <directory>`, đầu ra có `kernelcache.im4p.decompressed`.
- Darwin/XNU revision lấy từ chuỗi `Darwin Kernel Version` trong Mach-O.
- IPSW được ghi nhận trong `~/Downloads`: `iPhone14,8_27.0.1_24A446_Restore.ipsw`, `iPhone14,8_27.2_24B5084k_Restore.ipsw`, `iPhone14,8_27.2_24B5099f_Restore.ipsw`, `iPhone14,8_27.2_24B119_Restore.ipsw`.

**[CONFIRMED theo notebook]** `KC_B3` là build `24B119`, không phải `24A446`. Mọi VA cần được xem là build-specific; ghi đồng thời build, VA và file offset. Không tái sử dụng VA giữa b1 và b3 nếu chưa ánh xạ lại.

Tool fingerprint được ghi nhận:

| Công cụ | SHA-256 / phiên bản |
|---|---|
| `kc_tool.py` | `949e0e79520c969f1d89d83ddc3c4e7e14e0fc9b3f7f1fd9601a71eab78bf6b2` |
| `disasm_robust.py` | `1bfb19f40dc9dc9f957989b82104b710b272908cac9b940fbef687277ace4658` |
| `ipsw` | `/usr/local/bin/ipsw`, `3.1.745` |

## 21.2 Quy tắc decode và các lỗi thao tác đã ghi nhận

- `kc_tool.py` nhận kernelcache path trước subcommand: `python3 kc_tool.py "$B" xref <VA>`.
- `[data]` chỉ nói disassembler không decode word tại vị trí đó; không tự chứng minh đó là data hay code. Kiểm tra alignment, byte gốc, ngữ cảnh control-flow và endian trước khi diễn giải.
- Byte được in theo thứ tự little-endian. Ví dụ `08 01 2a b8` tương ứng word `0xb82a0108`.
- Không dùng placeholder như `ENTRY` làm địa chỉ thật.
- Heredoc dài có thể bị shell trộn lệnh; kiểm tra file bằng `cat -A` hoặc editor trước khi chạy.
- Không dùng `sed` xóa `#0x...` trong disassembly vì sẽ xóa mất offset field. `norm_fn2.py` được ghi nhận là giữ toán hạng offset.
- `grep -c` đếm số dòng khớp, không phải số lệnh gọi.

Các lệnh đã ghi nhận:

```bash
python3 kc_tool.py "$B" xref 0xfffffff00ad95860
python3 kc_tool.py "$B" callers 0xfffffff00a564b1c
python3 kc_tool.py "$B" dis <start> <end>
python3 kc_tool.py "$B" bl <va>
python3 disasm_robust.py "$B" 0xfffffff00a793450 0xfffffff00a7934d0
```

## 21.3 Gate `0xfffffff00ad95860` và các atomic RMW

- **[CONFIRMED theo output được ghi]** `0xfffffff00ad95860` có 45 data xrefs trong `KC_B3`; phần lớn được phát hiện qua `ADRP+LDR`.
- **[CONFIRMED]** `0xfffffff00a564e8c` chứa word `0xB82A0108`, decode thành `LDADD w10, w8, [x8]`; theo register setup được ghi, `w10 = -1`, `x8 = &0xfffffff00ad95860`. Đây là atomic read-modify-write cộng `-1` vào ô nhớ. Giá trị cũ được ghi vào `w8`; notebook ghi nhận không có kiểm tra giá trị cũ tại site này.
- **[CONFIRMED]** `0xfffffff00a672540` chứa word `0xF8290108`, decode thành `LDADD x9, x8, [x8]`; theo register setup, `x9 = 1`, `x8 = 0xfffffff00adcf1b0`. Đây là atomic RMW cộng `1` vào bộ đếm ở `0xadcf1b0`, không phải gate.
- **[CONFIRMED]** `0xfffffff00a8357ec` chứa `LDADD x21, x8, [x8]`, với địa chỉ đích được ghi là `0xadcf958`. Site này cập nhật một global khác, không phải `0xad95860`.
- **[CONFIRMED]** Ở consumer `0xfffffff00a672520`, gate khác 0 đi nhánh `0xa672d50`; gate bằng 0 đi đường tăng `0xadcf1b0`, gọi helper lặp tại `0xa78f188`, rồi clear `[x27,#0xb0]` tại `0xa67254c`.
- **[UNRESOLVED]** Chưa xác định được mọi writer/increment site của gate. Những `LDADD` dùng page `0xad95000` nhưng base register khác (`x9`, `x24`, `x28`) cần truy ngược register để xác nhận địa chỉ hiệu dụng.
- **[UNRESOLVED]** Chưa xác định gate là cờ trạng thái, bộ đếm, hay một trường đồng bộ hóa khác.

**Phân tích bổ sung:** `LDADD` xác nhận một atomic RMW, nhưng tự nó không chứng minh counter có invariant không âm, không chứng minh có guard chống underflow, và không chứng minh lifetime của object được bảo vệ. Cần xác định toàn bộ writers, giá trị cũ có được sử dụng ở nơi khác không, thứ tự bộ nhớ của opcode cụ thể, và quan hệ giữa gate với `obj+0x14`. Không được kết luận “race”, “underflow”, hay “free bị chặn vĩnh viễn” chỉ từ một phép giảm.

## 21.4 Hàm giảm gate `0xfffffff00a564b1c`

- **[CONFIRMED]** Entry bắt đầu bằng `hint #0x1b` / PAC prologue được ghi nhận tại `0xa564b1c`; `ret` cuối ở `0xa564e94`.
- **[CONFIRMED theo caller output]** Có một lời gọi trực tiếp đã tìm thấy: `0xfffffff00a469f2c` (file offset `0x3465f2c`).
- **[UNRESOLVED]** Chưa đọc caller `0xa469f2c`, chưa xác định hàm chứa nó và điều kiện gọi.

**Lưu ý địa chỉ:** `0xa564b1c` là entry của hàm giảm gate được khảo sát; `0xa564f74` là entry của routine dispatcher/status khác. Không được gộp hai hàm chỉ vì địa chỉ gần nhau.

## 21.5 Wrapper `0xfffffff00a7933f4` và vòng cleanup

- **[CONFIRMED theo disassembly đã ghi]** `0xa7933f4` là wrapper có các nhánh phụ thuộc bit của `w2` và `w1`.
- **[CONFIRMED]** Theo phân tích CFG được cung cấp, các đường chính chọn helper `0xa568174`, helper `0xa567d08`, hoặc bỏ qua hai helper; sau đó đi tới vòng `bl 0xa78f188; cbnz x0`.
- **[CONFIRMED]** Caller tại `0xa672d6c` dựng `w2 = 6` và `w3 = 0x02070033`; bit 1 của `w2` được set, nên nhánh wrapper tương ứng chọn helper `0xa568174` theo CFG đã ghi.
- **[CONFIRMED]** Các loop call tới `0xa78f188` được ghi tại `0xa7934a8`, `0xa7934ec`, `0xa793548`, `0xa7935c0`.
- **[CONFIRMED]** Một số word `[data]` ngay sau `ret` được decode thành `RETAB` (`0xD65F0FFF`). Cần giữ chúng là instruction bytes đã decode, không gán nhầm vào CFG nếu không có edge tới.

**[STRONG INFERENCE]** Wrapper có dạng chọn xử lý phụ tùy flags, sau đó cleanup/release theo vòng lặp. Tên `m_freem` là giả thuyết có hình dạng tương tự, chưa phải symbol đã xác nhận.

## 21.6 Helper `0xfffffff00a568174`: phạm vi hàm và provenance dữ liệu

- **[CONFIRMED]** Prologue cấp phát stack frame `0x150` byte và zero-init nhiều vùng bằng SIMD stores.
- **[CONFIRMED]** Cửa sổ 0x800 byte được khảo sát không có `BL` trực tiếp tới `0xa78f188` hoặc `0xa78f628`, và không có `BLR` trong cửa sổ đó.
- **[CONFIRMED]** Có nhiều `ret` và các nhánh vượt qua `ret` đầu tiên tại `0xa568890`; do đó không được dùng `ret` đầu tiên làm ranh giới hàm. Các địa chỉ `0xa568d08`, `0xa568d18`, `0xa568dec` vẫn nằm trong vùng được ghi nhận là thân hàm.
- **[CONFIRMED]** Tại `0xa568468`, routine ghi `x8` vào `[x21,#0x40]`. Giá trị `x8` được lấy từ `[sp+8]` sau lời gọi `0xa207330(&sp+8,&sp+4)`, rồi tính theo biểu thức được ghi: `([x21+0x48] - [x26+0x818]) + x8`.
- **[STRONG INFERENCE]** Phép toán trên có dạng chuyển đổi/điều chỉnh một giá trị theo base tương đối. Chưa đủ cơ sở để gọi nó là pointer relocation, offset rebasing hay timestamp propagation tại store này.

### Helper nguồn `0xfffffff00a207330`

- **[CONFIRMED]** `x20 = x0` tại `0xa207358`; `str x9,[x20]` tại `0xa2073f0` ghi giá trị 64-bit vào `*arg0`.
- **[CONFIRMED theo chuỗi lệnh được ghi]** Helper đọc `[x21,#0x1b8]`, đọc tiếp `[x8,#0x58]`, đọc system register `s3_4_c15_c10_6`, cộng các giá trị, gọi `0xa207474` với constant lấy từ `0xad9a3f0`, rồi thực hiện phép cộng 128-bit trước khi store.
- **[STRONG INFERENCE]** Giá trị ghi ra có dạng timestamp/counter đã scale và offset, không phải con trỏ trực tiếp tới object đầu vào. Vì vậy H-B2 bị bác bỏ **đối với store cụ thể này**, không phải đối với toàn bộ stores trong `0xa568174`.
- **[UNRESOLVED]** Cần đọc `0xa207474`, xác minh ý nghĩa system register và đối chiếu constant trước khi nâng kết luận timestamp lên `[CONFIRMED]`.

## 21.7 Helper `0xfffffff00a567d08`

- **[CONFIRMED]** Helper ghi vào object nhận ở `arg0` (`x19 = x0` theo ghi chú): `str x22,[x19,#0x10]`, `str w10,[x19,#0x18]`, `str x23,[x19,#0x10]`, `str w24,[x19,#0x18]`.
- **[CONFIRMED]** Có lời gọi trực tiếp tới `0xa354958`, được ghi nhận là copy helper.
- **[CONFIRMED trong cửa sổ đã kiểm tra]** Không thấy lời gọi trực tiếp tới `0xa78f188` trong cửa sổ 0x800.
- **[UNRESOLVED]** Chưa biết ý nghĩa trường `+0x10`, `+0x18`, semantics của `0xa354958`, và ownership của object.

## 21.8 PAC và lựa chọn Handler A/B

- **[CONFIRMED]** Word `0xDAC10230` (byte little-endian `30 02 c1 da`) tại `0xa567f34` và `0xa567f48` được decode là `PACIA x16,x17`; `x17` được nạp `0xd2bc`.
- **[CONFIRMED]** `tst w1,#2` kết hợp `csel x22,x16,x8,eq` chọn địa chỉ candidate `0xa441410` khi bit 1 set và `0xa441488` khi bit 1 clear, theo luồng cờ được ghi.
- **[UNRESOLVED]** Chưa disassemble thân hai candidate handler, chưa tìm đầy đủ mọi use của `x22`, và chưa xác định call/authentication site cuối cùng.
- **[UNRESOLVED]** ABI, semantic name và vai trò bảo mật của hai handler chưa được chứng minh.

## 21.9 So sánh cặp hàm b1/b3 có hình dạng free-chain

- **[CONFIRMED theo phép so sánh được ghi]** Hàm tại `0xa74f6b4` trong b1 (`24A446`) và `0xa78f188` trong b3 (`24B119`) có cửa sổ 211 lệnh giống hoàn toàn sau chuẩn hóa bằng `norm_fn2.py`; phần thân tới `ret` đầu tiên gồm 305 lệnh cũng khớp.
- **[CONFIRMED theo output được ghi]** 14 lời gọi `BL` theo thứ tự giống nhau; lời gọi cuối là đệ quy về entry tương ứng.
- **[CONFIRMED theo output được ghi]** Wrapper b1 `0xa74fb54` và wrapper b3 `0xa78f628` có dạng `cbz x0; bl entry; cbnz x0`.
- **[CONFIRMED theo ghi chú]** Khác biệt còn lại ở vùng sau thân gồm chuỗi `ADRP; ADD; ADRP; STR [x9,#imm]; RET`, với global address/offset thay đổi theo cấp số `0x50`.
- **[STRONG INFERENCE]** Hai entry là cùng logical function qua hai build; wrapper có hình dạng lặp trên chain cho tới khi pointer trả về null.
- **[HYPOTHESIS]** Hình dạng phù hợp với `m_freem` trong XNU. Chỉ nâng lên `[CONFIRMED]` sau khi đối chiếu source/symbol đúng revision (`xnu-13432.2.10~2` và `xnu-13432.42.3~28`) và ABI/call-site.

Không được suy ra double-free hoặc UAF từ tên giả định `m_freem`, từ loop, hoặc từ một lần gọi cleanup. Cần chứng minh ownership, chain traversal, các alias còn sống và lần truy cập sau khi release.

## 21.10 Các `[data]` đã decode

- **[CONFIRMED theo log được cung cấp]** `decode_atomic.py` đã xử lý 30 dòng unique sau khi loại trùng do cửa sổ chồng nhau; trong đó có 26 atomic instruction và 2 `RETAB` (hai loại số đếm không cộng thành 30 vì log có thể bao gồm các nhóm/entry khác; cần giữ output gốc để đối chiếu).
- Các mẫu được ghi gồm `LDADD x9,x8,[x8]`, `LDADD w9,w8,[x8]`, `LDADD x8,x8,[x9]` và `LDADD x21,x8,[x8]` tại các vùng `0xa47…`, `0xa5c…`, `0xa672…`, `0xa835…`, `0xa836…`–`0xa83c…`.
- **[UNRESOLVED]** Chưa có bảng đầy đủ cho từng site gồm raw bytes, decoded mnemonic, effective address, giá trị source register, giá trị old-value destination, memory ordering variant và vai trò (read/write/init).

## 21.11 Đánh giá lại giả thuyết

| ID | Giả thuyết | Trạng thái mới | Bằng chứng còn thiếu |
|---|---|---|---|
| H-B1 | Free trùng qua `0xa568174` | **Giảm mạnh; chưa bác bỏ hoàn toàn** | Xác định phạm vi hàm chính xác, phân tích mọi callee và indirect edge trong toàn bộ CFG; không thấy `BL` trực tiếp trong cửa sổ không loại trừ free ở callee |
| H-B2 | Con trỏ dẫn xuất từ arg0 được lưu vào struct sống lâu | **Bị bác bỏ cho store từ `0xa207330`; vẫn mở cho stores khác** | Phân loại toàn bộ writes trong `0xa568174`, xác định provenance và escape của từng giá trị |
| H-C | Đọc `[x27+0xb0]` sau khi đã free | **Chưa kiểm tra** | Phân tích mọi đường CFG sau `str xzr,[x27,#0xb0]` và mọi alias/phiên bản của pointer |
| H-D | Gate giảm không guard, làm đường cleanup bị chặn | **Vẫn mở; chưa đủ chứng cứ** | Tìm mọi writer/increment, kiểm tra old-value, guard, signedness, memory ordering và caller conditions |

**Đánh giá tổng thể:** chưa có bằng chứng đủ để kết luận UAF, double-free, underflow, race, hay CVE root cause. Kết quả hiện tại củng cố mô hình có một global gate, một counter riêng, các đường xử lý phụ thuộc flags và một vòng cleanup; ngữ nghĩa của từng thành phần vẫn cần đối chiếu source và caller/callee.

---

# 22. Phân tích phần còn lại và kế hoạch xác minh

Phần này là phân tích thứ tự công việc còn lại, dựa trên evidence log ngày 2026-11-15. Đây là kế hoạch kiểm chứng tĩnh, không phải kết quả chạy mới.

## 22.1 Ưu tiên 1 — caller của hàm giảm gate tại `0xa469f2c`

**Mục tiêu:** xác định ai gọi `0xa564b1c`, điều kiện gọi, và provenance của object/giá trị đi vào hàm.

Cần thu thập:

1. Disassembly đủ rộng quanh `0xa469f2c`, bao gồm setup `x0`–`x7`, nhánh điều kiện trước `BL`, và các lệnh sau call.
2. Function boundary của caller bằng prologue/epilogue, branch target, unwind/function-start metadata nếu có.
3. Mọi caller của caller và các điều kiện state/lifetime dẫn tới call.
4. Giá trị cũ do `LDADD` trả về ở `w8` có được dùng ở các lệnh tiếp theo hay bị bỏ qua.

**Tiêu chí kết luận:** chỉ xác nhận đây là đường giảm gate sau khi call-site và data flow khớp; không suy ra decrement là hợp lệ hay lỗi chỉ từ caller đơn lẻ.

## 22.2 Ưu tiên 2 — call graph đầy đủ của `0xa568174`

**Mục tiêu:** kiểm tra H-B1 một cách có hệ thống mà không dựa vào việc tìm chuỗi `BL` đơn thuần.

Cần thu thập:

1. Function boundary chính xác; nhiều `ret` và branch vượt qua `ret` đầu tiên khiến heuristic “ret đầu tiên là hết hàm” không dùng được.
2. CFG đầy đủ, gồm conditional branch, tail branch, indirect branch, shared epilogue và mọi vùng code sau các `ret` nội bộ.
3. Danh sách direct callees và từng callee window; ghi rõ VA/file offset/build.
4. Indirect-call sites (`BLR`/`BR`) nếu có trong function extent đã xác minh, và provenance của function pointer.
5. Call graph đệ quy/gián tiếp tối thiểu một cấp cho các callee có khả năng release object; phân biệt direct call, tail call và helper wrapper.

**Điểm cần giữ:** việc cửa sổ 0x800 không có `BLR` chỉ áp dụng cho đúng cửa sổ đó; không chứng minh toàn bộ routine hoặc callees không có indirect call. Tương tự, không có `BL` trực tiếp tới free candidate không loại trừ một callee gọi tiếp helper release.

## 22.3 Ưu tiên 3 — bảng write/provenance cho arg0 trong `0xa568174`

Tạo bảng cho mọi store có base hoặc source register phụ thuộc `x21` (được lưu từ `x0` ở prologue), các bản sao của `x21`, và giá trị được load từ object đó:

| PC | Instruction | Base/source provenance | Offset/target | Giá trị ghi | Có escape khỏi frame? | Ghi chú |
|---|---|---|---|---|---|---|
| ... | `STR/STRB/STRH/STP/...` | ... | ... | ... | ... | ... |

Theo dõi cả alias qua `MOV`, `ADD`, `LDR`, stack spill/reload và callee arguments. Không coi mọi giá trị số học có nguồn từ arg0 là pointer; cần phân loại pointer, scalar, timestamp, length, flags và offset. Store tại `0xa568468` phải được ghi riêng với provenance từ `0xa207330`.

**Tiêu chí bác bỏ H-B2:** chỉ bác bỏ toàn bộ giả thuyết khi không còn store nào đưa pointer hoặc giá trị pointer-derived ra khỏi stack frame/object lifetime liên quan; một store timestamp đơn lẻ chỉ bác bỏ một nhánh cụ thể.

## 22.4 Ưu tiên 4 — phân loại mọi atomic site liên quan gate

Không tìm chỉ bằng địa chỉ page. Với từng `LDADD`/atomic site, ghi:

| PC | Raw word | Decode | `Rn` effective address | `Rs` input | `Rt` old value | Memory order | Vai trò |
|---|---|---|---|---|---|---|---|
| `0xa564e8c` | `0xB82A0108` | `LDADD w10,w8,[x8]` | `0xad95860` theo ghi chú | `-1` | `w8` | cần xác minh opcode variant | decrement candidate |
| `0xa672540` | `0xF8290108` | `LDADD x9,x8,[x8]` | `0xadcf1b0` theo ghi chú | `+1` | `x8` | cần xác minh opcode variant | counter increment |
| `0xa8357ec` | `0xF8350108` | `LDADD x21,x8,[x8]` | `0xadcf958` theo ghi chú | `x21` | `x8` | cần xác minh opcode variant | cập nhật global khác |

Với các site khác, truy ngược toàn bộ định nghĩa `Rn` ngay trước atomic instruction; không suy địa chỉ từ `ADRP` đơn lẻ nếu base register đã bị ghi đè. Phân biệt plain `LDADD` với biến thể acquire/release (`LDADDA`, `LDADDL`, `LDADDAL`) bằng encoding chính xác. Tạo danh sách writer và reader riêng.

**Tiêu chí xác định gate:** ít nhất một site được chứng minh có effective address đúng `0xad95860`; sau đó phân loại mọi read/write/initialization site. Không gộp `0xadcf1b0` hoặc `0xadcf958` vào gate.

## 22.5 Ưu tiên 5 — đối chiếu source XNU đúng revision

Cần dùng source revision tương ứng, không dùng header XNU mới nhất để áp ngược:

- b1: `xnu-13432.2.10~2`.
- b3: `xnu-13432.42.3~28`.

Đối chiếu:

1. `struct mbuf` và macro/bit definitions tương ứng các offset `+0x74`, `+0xcf`.
2. `m_free` và `m_freem`: signature, return convention, chain traversal và ownership semantics.
3. Các helper/call site liên quan tới buffer storage, inline/external data và length checks.
4. Compiler/build configuration có thể làm thay đổi layout hoặc inline behavior.

**[UNRESOLVED]** Cho đến khi source revision và binary layout khớp, `mbuf`, `m_free`, `m_freem` vẫn là tên giả thuyết. Nếu source không đủ để map, cần symbol/DSYM hoặc layout evidence đúng build.

## 22.6 Ưu tiên 6 — hoàn tất các nhánh phân tích còn lại

| Nhánh | Bằng chứng cần lấy | Kết quả cần ghi |
|---|---|---|
| Handler A/B | Disassembly entry, callers, data flow từ `x22`, indirect call/auth instruction | ABI, target thực tế, side effects; không đặt tên nếu thiếu symbol |
| Status `0x02070033` | Raw table entry, signed offset, PC base, target body, status producer | Xác nhận hoặc bác bỏ target `0xa565af0`; semantics chỉ sau khi trace producer/consumer |
| H-C | CFG sau `str xzr,[x27,#0xb0]`, reads/writes/aliases của field | Có hay không đường đọc pointer cũ sau clear/release |
| Global gate | Init sites, writers, readers, atomic variants, caller conditions | Cờ/counter/state variable; invariant nếu có |
| b1 ↔ b3 | Function mapping, CFG, input provenance, field layout, call ordering | Phân biệt code movement với behavior change |

## 22.7 Thứ tự thực hiện tối ưu

1. Xác minh caller `0xa469f2c` và hàm giảm gate.
2. Xác định function boundary/CFG của `0xa568174`.
3. Lập bảng stores và provenance của arg0.
4. Lập inventory mọi atomic site và xác nhận writer của gate.
5. Đối chiếu XNU source đúng revision để xác minh `mbuf` và free routines.
6. Hoàn thiện Handler A/B và status `0x02070033`.
7. Kiểm tra H-C trên toàn CFG.
8. Chỉ sau đó so sánh b1/b3 theo logical function và invariant.

Thứ tự này ưu tiên các dữ kiện có thể thu hẹp nhanh giả thuyết ownership/gate trước khi mở rộng sang attribution CVE. Không cần chạy hoặc phát triển exploit để hoàn tất mục tiêu phân tích nguyên nhân gốc.

## 22.8 Những gì chưa thể kết luận từ notebook hiện tại

- Chưa chứng minh `0xa78f188` là `m_free` hay `m_freem`.
- Chưa chứng minh `0xad95860` là counter, flag hay lock/state gate.
- Chưa chứng minh phép decrement tại `0xa564e8c` có thể underflow hoặc gây lỗi lifetime.
- Chưa chứng minh `0xa568174` gọi free trực tiếp hoặc gián tiếp.
- Chưa chứng minh có read-after-free tại `[x27,#0xb0]`.
- Chưa xác minh function extent của `0xa568174` bằng metadata độc lập.
- Chưa xác minh ý nghĩa của `0x02070033` hoặc handler A/B.
- Chưa chứng minh vulnerable/fixed build pair hoặc CVE attribution.

## 22.9 Evidence files được ghi nhận

| File | Nội dung |
|---|---|
| `callers_F_B.txt` | Một direct caller của `0xa564b1c`: `0xa469f2c` |
| `x9_a207330.txt` | Register/data-flow của helper ghi `*arg0` |
| `long2_bl_counts.txt` | Kết quả tìm direct BL trong cửa sổ dài quanh `0xa568174` |
| `atomic_decoded_B.txt` | Các atomic/data words đã decode |
| `writes_a568174.txt` | File dự kiến cho inventory store; cần tạo/hoàn thiện |

Các tên file trên là tên artifact trong môi trường nghiên cứu của người dùng; nội dung file chưa được đính kèm trong phiên này và chưa được đọc độc lập.

## 22.10 Change log — 2026-11-15

- Sửa định danh build: `KC_B3` là `24B119` / iOS 27.2; ghi thêm XNU revision và SHA-256.
- Thêm build đối chứng `24B5099f` và `24B5084k`.
- Ghi nhận atomic decrement candidate tại `0xa564e8c` và phân biệt với counter `0xadcf1b0` tại `0xa672540` cùng global `0xadcf958` tại `0xa8357ec`.
- Tách rõ hàm `0xa564b1c` khỏi status dispatcher `0xa564f74`.
- Bổ sung caller duy nhất đã tìm thấy `0xa469f2c` cho hàm giảm gate.
- Cập nhật phân tích wrapper `0xa7933f4`, các helper `0xa568174` / `0xa567d08`, và vòng lặp `0xa78f188`.
- Ghi nhận store từ `0xa207330` có dạng timestamp/counter đã scale; chỉ đóng H-B2 cho store đó.
- Bổ sung kết quả normalize b1/b3 cho cặp hàm `0xa74f6b4` / `0xa78f188`; giữ `m_freem` ở mức `[HYPOTHESIS]`.
- Cập nhật trạng thái H-B1/H-B2/H-C/H-D và lập kế hoạch xác minh có thứ tự.
- Không nâng bất kỳ kết luận nào thành UAF, double-free, underflow, CVE root cause hay exploitability.

# 23. Kết quả xác minh ưu tiên 1 — phân biệt init routine và gate callback

**Ngày:** 2026-11-15  
**Build:** `24B119` / iOS 27.2 / `KC_B3`  
**Kernelcache:** `~/ios27-diff/27.2/24B119__iPhone14,8/kernelcache.release.iPhone14,8`  
**SHA-256:** `c81fb9d291cb4e0d8cca512724079da21bc3d6460d37d6f3a4831116af8b410a`

Phần này cập nhật kết quả từ disassembly trực tiếp trên kernelcache B3. Nó hiệu chỉnh cách gọi tên trong mục 21.4 và thu hẹp bước tiếp theo của mục 22.1. Các kết luận chỉ áp dụng cho build và VA nêu trên.

## 23.1 Kết luận quan trọng: `0xa564b1c` không phải entry chứa atomic decrement

**[CONFIRMED]** `0xfffffff00a564b1c` là một routine khởi tạo riêng:

- Prologue tại `0xa564b1c`: `hint #0x1b`, cấp phát stack frame `0x30`.
- Đọc byte trạng thái tại `[0xadce938]`; nếu chưa khởi tạo thì ghi `1` và clear global head tại `[0xadce940]`.
- Gọi `0xa45a360`; nhánh còn lại ghi log lỗi rồi return.
- Direct caller duy nhất đã tìm thấy vẫn là `BL` tại `0xa469f2c`.

**[CONFIRMED]** Atomic decrement ở `0xa564e8c` thuộc một callback entry khác, bắt đầu tại `0xfffffff00a564e54`, không thuộc routine `0xa564b1c`. Vì vậy, mô tả cũ “caller `0xa469f2c` của hàm giảm gate” là không chính xác: `0xa469f2c` gọi initializer `0xa564b1c`, không gọi trực tiếp callback cập nhật gate.

## 23.2 Caller chain của initializer

Disassembly B3 xác nhận chuỗi sau:

```text
0xfffffff00a6da6f0  BL 0xfffffff00a469c34
0xfffffff00a469f2c  BL 0xfffffff00a564b1c
```

- **[CONFIRMED]** `0xa469c34` có prologue PAC và là routine chứa call-site `0xa469f2c`.
- **[CONFIRMED]** Đã tìm thấy một direct `BL` tới `0xa469c34`, tại `0xa6da6f0`.
- **[STRONG INFERENCE]** Vị trí này nằm trong chuỗi khởi tạo kernel: `0xa6da680` thực hiện nhiều lời gọi initializer liên tiếp, bao gồm `0xa469c34`.
- **[UNRESOLVED]** Chưa xác định tên semantic của `0xa469c34`, object/state cấp cao hơn mà nó khởi tạo, hoặc provenance đầy đủ của mọi register tại call-site. Không suy ra argument chỉ từ register state sau một `BL` trước đó.

## 23.3 Callback entry chứa phép cập nhật gate

Entry được xác định tại `0xfffffff00a564e54`:

```asm
0xa564e54  hint  #0x22
0xa564e58  cmp   w1, #0x95
0xa564e5c  b.ne  0xa564e90
0xa564e60  ldr   x8, [x0, #0x10]
0xa564e64  ldr   w9, [x8, #0x14]
0xa564e68  cbz   w2, 0xa564e74
0xa564e6c  movz  w10, #1
0xa564e70  b     0xa564e7c
0xa564e74  cbz   w9, 0xa564e90
0xa564e78  movn  w10, #0
0xa564e7c  add   w9, w9, w10
0xa564e80  str   w9, [x8, #0x14]
0xa564e84  adrp  x8, #0xfffffff00ad95000
0xa564e88  add   x8, x8, #0x860
0xa564e8c  .word 0xB82A0108   // LDADD w10, w8, [x8]
0xa564e90  movz  w0, #0
0xa564e94  ret
```

Diễn giải dữ liệu:

- `w1 != 0x95`: callback return 0, không cập nhật hai biến đếm.
- `w1 == 0x95` và `w2 != 0`: `w10 = +1`; tăng field 32-bit tại `[[x0+0x10]+0x14]`, sau đó atomic-add `+1` vào global `0xfffffff00ad95860`.
- `w1 == 0x95` và `w2 == 0`: nếu field local bằng 0 thì return; nếu khác 0 thì `w10 = -1`, giảm field local và atomic-add `-1` vào global `0xfffffff00ad95860`.
- Giá trị cũ của global được trả về trong `w8` bởi `LDADD`, nhưng không được sử dụng trong phần còn lại của entry.
- Encoding là plain `LDADD`, không phải biến thể có hậu tố acquire/release (`LDADDA`, `LDADDL`, `LDADDAL`).

**[CONFIRMED]** Callback thực hiện cập nhật cùng một delta trên local 32-bit field và global 32-bit atomic variable. Nhánh giảm có guard trên local field; không có kiểm tra giá trị cũ của global trong đoạn callback này.

**[STRONG INFERENCE]** Cấu trúc này phù hợp với một local reference/accounting count được phản ánh vào aggregate gate. Chưa đủ bằng chứng để đặt tên chính thức cho field, xác định ownership invariant, hay chứng minh global gate không thể underflow trong mọi interleaving.

## 23.4 Provenance của callback pointer và registry record

Tại registration site `0xa564dc4..0xa564de4`:

```asm
0xa564dc4  adrp  x16, #0xfffffff00a564000
0xa564dc8  add   x16, x16, #0xe54       // x16 = callback entry
0xa564dcc  movz  x17, #0xfee3
0xa564dd0  PACIA x16, x17               // raw word 0xDAC10230
0xa564dd4  mov   x4, x16
0xa564dd8  movz  w1, #0x95
0xa564ddc  movz  w2, #0xe4
0xa564de0  movz  x3, #0
0xa564de4  bl    0xfffffff00a4416a0
```

**[CONFIRMED]** `0xa564e54` được materialize thành function pointer, ký bằng `PACIA` với modifier `x17 = 0xfee3`, rồi truyền qua `x4` vào helper `0xa4416a0`. Cùng call-site truyền `w1 = 0x95`, khớp với discriminator mà callback kiểm tra.

Data flow trong helper `0xa4416a0`:

- `x19 = x0`, `x22 = x1`, `x21 = x2`, `x24 = x3`, `x23 = x4`.
- Khi dựng record mới, helper ghi `w22` vào `[record+0x14]`.
- Helper ghi `x19` và `x24` tại `[record+0x28]` / `[record+0x30]`.
- Helper ghi callback pointer `x23` vào `[record+0x38]`.
- Record được nối vào list gốc qua field `[x19+0xc0]`.

**[CONFIRMED]** `0xa4416a0` là một registration/list helper có lưu key `0x95` và authenticated callback pointer tại offset `+0x38` của record. Đã tìm thấy 13 direct `BL` call-sites tới helper này; call-site `0xa564de4` là một trong số đó.

**Lưu ý:** `w2 = 0xe4` ở call-site là tham số của registration helper; không được đồng nhất nó với `w2` runtime mà callback sử dụng để chọn increment/decrement.

## 23.5 Call graph và trạng thái xác minh

| Hạng mục | Kết quả |
|---|---|
| Direct caller của `0xa564b1c` | Một call-site: `0xa469f2c` |
| Caller của routine chứa `0xa469f2c` | `0xa6da6f0 -> 0xa469c34` |
| Direct `BL` tới callback `0xa564e54` | Không tìm thấy |
| Data xref tới callback `0xa564e54` | Một `ADRP+ADD` tại `0xa564dc4` |
| Registration helper | `0xa4416a0`, lưu key và callback pointer vào record/list |
| Runtime dispatcher gọi callback key `0x95` | **[UNRESOLVED]** |
| Ý nghĩa chính xác của local field `+0x14` | **[UNRESOLVED]** |
| Invariant và lifetime bảo vệ global gate | **[UNRESOLVED]** |

Không có direct `BL` tới `0xa564e54` là phù hợp với việc callback được truyền gián tiếp qua registry; điều này không chứng minh callback không được gọi. Các scan indirect-call diện rộng hiện chưa xác định được dispatcher khớp modifier `0xfee3` và record tương ứng. Một số callback-like sites khác trong binary sử dụng discriminator khác; không gộp chúng vào call graph này.

## 23.6 Điều chỉnh giả thuyết và thứ tự tiếp theo

- **H-D:** đã xác định rõ hơn một writer của global `0xad95860`: callback `0xa564e54` có nhánh tăng/giảm và local-zero guard. H-D vẫn mở vì chưa có toàn bộ writer/reader, caller event và invariant.
- **H-B1/H-B2/H-C:** không thay đổi trạng thái chỉ từ phát hiện callback này.
- Không có cơ sở nâng kết quả thành underflow, race, UAF, double-free, CVE root cause hay exploitability.

Thứ tự tiếp theo được điều chỉnh:

1. Tìm dispatcher/consumer của registry record: truy từ root/list `[x19+0xc0]`, key `[record+0x14] = 0x95`, callback `[record+0x38]`, và PAC modifier `0xfee3`. Ưu tiên các `AUTIA`/`BLRAA` hoặc wrapper authenticated-call có data flow phù hợp; không chỉ tìm `BL`.
2. Xác định sự kiện nào truyền runtime `w2 = 0` hoặc nonzero vào callback và object đi vào `x0`.
3. Lập inventory đầy đủ mọi reader/writer của `0xad95860`; phân biệt `LDADD` tại địa chỉ này với counter/global khác.
4. Sau đó quay lại function extent/CFG và write-provenance của `0xa568174`, rồi đối chiếu XNU revision.

## 23.7 Commands và artifacts dùng để tái lập

```bash
B="$HOME/ios27-diff/27.2/24B119__iPhone14,8/kernelcache.release.iPhone14,8"
python3 ~/ios_kernel_poc/disasm_robust.py "$B" 0xfffffff00a469e00 0xfffffff00a46a100
python3 ~/ios_kernel_poc/disasm_robust.py "$B" 0xfffffff00a564b00 0xfffffff00a564c20
python3 ~/ios_kernel_poc/disasm_robust.py "$B" 0xfffffff00a564d80 0xfffffff00a564e98
python3 ~/ios_kernel_poc/kc_tool.py "$B" bl 0xfffffff00a564b1c
python3 ~/ios_kernel_poc/kc_tool.py "$B" callers 0xfffffff00a469c34
python3 ~/ios_kernel_poc/kc_tool.py "$B" xref 0xfffffff00a564e54
```

Các artifacts cũ như `callers_F_B.txt`, `gate_add_site.txt`, `atomic_decoded_B.txt` vẫn giữ nguyên; section này bổ sung kết quả disassembly trực tiếp và không sửa các log lịch sử.


# 24. Xác minh indirect callback dispatcher và provenance của `w2`

**Ngày:** 2026-11-15  
**Build:** iOS 27.2 / `24B119` / `KC_B3`  
**Kernelcache SHA-256:** `c81fb9d291cb4e0d8cca512724079da21bc3d6460d37d6f3a4831116af8b410a`

Phần này cập nhật mục 23. Trọng tâm là tìm call-site gián tiếp thật sự của callback `0xfffffff00a564e54`, sau khi đã có registration record tại `0xa4416a0`.

## 24.1 Kết luận chính

**[CONFIRMED]** Đã tìm thấy hai call-site `BLRAA` dùng modifier `0xfee3`, đọc callback pointer ở offset `+0x38` và key ở offset `+0x14` của record. Hai call-site truyền hai giá trị `w2` khác nhau vào cùng kiểu callback:

| Hướng cập nhật | Call-site | Callback register | Key source | `w2` | Kết quả tại callback `0xa564e54` |
|---|---:|---|---|---:|---|
| Tăng | `0xa43f55c` | `BLRAA x23, x17` | `[x20+0x14]` | `3` | `w2 != 0` → `+1` |
| Giảm | `0xa43a49c` | `BLRAA x24, x17` | `[x8+0x14]` | `0` | `w2 == 0` → `-1` nếu local count khác 0 |

Ở cả hai call-site:

- `x17 = 0xfee3`, khớp modifier được dùng để `PACIA` callback pointer ở registration site `0xa564dd0`.
- Callback pointer lấy từ record `+0x38`, khớp field mà helper `0xa4416a0` ghi ở `0xa4416a0`.
- `w1` lấy từ record `+0x14`, khớp key `0x95` mà callback kiểm tra.
- `x0` là object/owner được truyền vào callback; callback đi tiếp qua `[x0+0x10]` để tới local counter.

Như vậy, provenance của `w2` đã được xác định ở hai nhánh đã tìm thấy: giá trị nonzero cụ thể là `3` cho nhánh tăng, và `0` cho nhánh giảm. **[UNRESOLVED]** Chưa xác định caller cấp cao nhất kích hoạt từng routine, cũng chưa chứng minh hai call-site này là toàn bộ call-site của runtime.

## 24.2 Nhánh tăng: routine `0xa43f44c` → callback `0xa564e54` (call-site tại `0xa43f55c`)

Function entry là `0xfffffff00a43f44c` (prologue PAC tại `0xa43f44c`); call path lấy record ở các lệnh `0xa43f4fc..0xa43f504`. Ở nhánh đọc record:

```asm
0xa43f4fc  ldr   x25, [x2, #0xc0]
0xa43f500  ldr   x23, [x20, #0x38]   // callback pointer
0xa43f504  ldr   w22, [x20, #0x14]  // callback key
...
0xa43f54c  mov   x0, x2              // owner object
0xa43f550  mov   x1, x22             // record key
0xa43f554  movz  w2, #3
0xa43f558  movz  x17, #0xfee3
0xa43f55c  .word 0xd73f0af1          // BLRAA x23, x17
```

GNU AArch64 disassembler xác nhận word `0xd73f0af1` là `BLRAA x23, x17`.

Các điều kiện trước call-site gồm:

- Entry kiểm tra `[x1+0x28] == x2`; sau đó giữ record trong `x20` và owner trong `x2`.
- Callback pointer phải khác null (`cbz x23` bỏ qua call).
- Nhánh gọi đi qua phần so sánh record/list và kiểm tra lock/TLS; không phải mọi lần vào routine đều gọi callback.

**[CONFIRMED]** Khi call-site này chạy, callback nhận `x0=owner`, `w1=record key`, `w2=3`. Vì callback chỉ phân biệt zero/nonzero, `3` đi vào nhánh tăng local count và atomic-add `+1` lên `0xfffffff00ad95860`.

**[CONFIRMED]** Entry `0xa43f44c` có hai direct callers: `0xa43dd94` và `0xa43e338`. Ở `0xa43dd94`, caller truyền `x0=x19`, `x1=x21`, `x2=x22`; ở `0xa43e338`, caller truyền `x0=x23`, `x1=x21`, `x2=x20`. Ý nghĩa event cấp cao hơn vẫn chưa được đặt tên.

## 24.3 Call-site giảm: `0xa43a264` → callback `0xa564e54`

Routine liên quan bắt đầu tại `0xfffffff00a43a264`. Data flow record/callback được dựng trước call-site:

```asm
0xa43a29c  mov   x21, x1
...
0xa43a344  ldr   x9, [x21, #0xc0]
0xa43a348  cmp   x9, x8
0xa43a34c  cset  w25, eq
0xa43a350  ldr   x24, [x8, #0x38]   // callback pointer
0xa43a354  cbz   x24, ...
0xa43a358  ldr   w22, [x8, #0x14]  // callback key
...
0xa43a488  cbz   x24, ...
0xa43a48c  mov   x0, x21             // owner object
0xa43a490  mov   x1, x22             // record key
0xa43a494  movz  w2, #0
0xa43a498  movz  x17, #0xfee3
0xa43a49c  .word 0xd73f0b11          // BLRAA x24, x17
```

GNU AArch64 disassembler xác nhận word `0xd73f0b11` là `BLRAA x24, x17`.

**[CONFIRMED]** Call-site truyền `w2=0`. Trong callback `0xa564e54`, nhánh zero kiểm tra local field tại `[[x0+0x10]+0x14]`: nếu local field bằng zero thì return và không đụng tới global; nếu khác zero thì cộng `-1` vào local field và thực hiện `LDADD -1` lên global gate.

### 24.3.1 Direct caller map

Direct call-site inventory (không phải tên semantic của event):

- `0xa43a264` được gọi từ `0xa439ef0`, `0xa43dd78`, `0xa43e2dc`, `0xa43e31c`, `0xa441a5c`.
- Function entry `0xa43f44c` được gọi từ `0xa43dd94`, `0xa43e338`.
- Trong wrapper region quanh `0xa43dd78..0xa43dd94`, routine `0xa43a264` được gọi trước; khi return `w0 == 0`, control-flow tiếp tục tới `0xa43f44c`.
- Trong wrapper region quanh `0xa43e31c..0xa43e338`, có cùng dạng kiểm tra kết quả rồi gọi `0xa43f44c` ở nhánh phù hợp.

Điều này xác nhận hai routine nằm trong cùng một số caller workflows, nhưng không đủ để đặt tên lifecycle state hoặc khẳng định mọi invocation đều tạo một cặp `-1/+1`.

**[CONFIRMED]** Caller-argument samples: `0xa439ef0` truyền `x0=x20`, `x1=x22`, `x2=x21`; `0xa43e31c` truyền `x1=x20`, `x2=x22`; `0xa441a5c` truyền `x0=x26`, `x1=x19`. Ý nghĩa event cấp cao hơn vẫn chưa được đặt tên; không suy ra tên semantic chỉ từ delta `0`.

## 24.4 Hai callback path và `0xa43f724` là hai nhánh phân tích khác nhau

Một điểm cần hiệu chỉnh so với giả thuyết ở mục 23.5: trong vùng disassembly đã kiểm tra, `0xa43f724` không phải call-site `BLRAA` của callback `0xa564e54`.

- `0xa43f724` đọc root/list qua object `+0xc0`, so key ở record `+0x14`, rồi thực hiện logic xử lý payload/state. Trong cửa sổ đã scan `[0xa43f724, 0xa4405bc)`, không tìm thấy cặp `MOVZ x17,#0xfee3` + authenticated `BLRAA`; đây là giới hạn của cửa sổ scan, không phải khẳng định về một function extent đã xác lập.
- Các callback call-site có field layout tương ứng mà hiện đã xác minh được là `0xa43f55c` và `0xa43a49c`.
- `0xa567f04`/Handler A/B là một tầng dispatch khác, dùng PAC modifier `0xd2bc` cho static handler pointer. Không gộp PAC domain `0xd2bc` với callback-record modifier `0xfee3`.

**Kết luận cập nhật:** callback-record dispatch đã được tìm thấy ở hai nhánh lifecycle/record-management với `w2=3` và `w2=0`; `0xa43f724` tiếp tục là một consumer xử lý key `0x95`, nhưng chưa có bằng chứng nó gọi callback pointer `+0x38`.

## 24.5 Call graph đã xác minh

```text
registration:
0xa564dc4  materialize 0xa564e54
0xa564dd0  PACIA x16, x17       ; x17 = 0xfee3
0xa564de4  BL 0xa4416a0         ; key = 0x95
             record+0x14 = key
             record+0x38 = signed callback pointer
             owner+0xc0 = list root

positive callback path:
0xa43f500  LDR x23, [record+0x38]
0xa43f504  LDR w22, [record+0x14]
0xa43f554  w2 = 3
0xa43f55c  BLRAA x23, x17        ; x17 = 0xfee3
             ↓
0xa564e54  w1 == 0x95, w2 != 0 → local +1, global LDADD +1

negative callback path:
0xa43a350  LDR x24, [record+0x38]
0xa43a358  LDR w22, [record+0x14]
0xa43a494  w2 = 0
0xa43a49c  BLRAA x24, x17        ; x17 = 0xfee3
             ↓
0xa564e54  w1 == 0x95, w2 == 0 → local -1 if nonzero, global LDADD -1
```

Đây là call graph dựa trên static register/data-flow, không phải trace runtime. Sự trùng khớp key, field offsets và PAC modifier là bằng chứng mạnh rằng hai call-site có thể dispatch record callback đã đăng ký; để xác nhận đúng instance ở runtime vẫn cần trace record allocation/linkage hoặc dynamic trace.

## 24.6 Mức độ kết luận sau cập nhật

| Hạng mục | Trạng thái mới |
|---|---|
| Callback entry và delta logic | **[CONFIRMED]** `0xa564e54` |
| Callback registration (`PACIA`, key `0x95`, record `+0x38`) | **[CONFIRMED]** `0xa564de4` → `0xa4416a0` |
| Indirect call dùng modifier `0xfee3`, pointer `+0x38` | **[CONFIRMED]** hai call-site: `0xa43f55c`, `0xa43a49c` |
| Provenance `w2` cho nhánh tăng | **[CONFIRMED]** call-site truyền `3` |
| Provenance `w2` cho nhánh giảm | **[CONFIRMED]** call-site truyền `0` |
| `x0` object ở hai call-site | **[CONFIRMED]** owner object được truyền vào callback |
| Direct callers của hai routine callback-path | **[CONFIRMED]** 2 callers của `0xa43f44c`; 5 callers của `0xa43a264`. Semantic event vẫn **[UNRESOLVED]** |
| Runtime record instance có đúng callback `0xa564e54` | **[STRONG INFERENCE]**, chưa dynamic-confirmed |
| Có phải đây là toàn bộ callback caller trong build | **[UNRESOLVED]** |

---

# 25. Function extent và CFG chính xác của `0xa568174`

## 25.1 Boundary

**[CONFIRMED]** Function extent của `0xfffffff00a568174` là:

```text
start = 0xfffffff00a568174
end   = 0xfffffff00a56826c   ; exclusive
size  = 0xf8 bytes
```

- `0xa568264` là return instruction `RETAB` (raw bytes `ff 0f 5f d6`).
- `0xa568268` là nhánh stack-check failure gọi `0xaa4c590`.
- Function kế tiếp bắt đầu tại `0xa56826c` với `hint #0x1b` và prologue mới (`sub sp,sp,#0xf0`).

Do đó, các đoạn disassembly cũ kéo dài tới `0xa568894` hoặc xa hơn đã đi qua nhiều function; không được xem toàn bộ cửa sổ đó là một CFG duy nhất. Nội dung mục 21.6 về function extent phải được đọc theo boundary mới này.

## 25.2 Register mapping và side effects trực tiếp

Ngay sau prologue, function lưu đối số ban đầu:

| Register đầu vào | Register giữ | Vai trò được chứng minh trong function |
|---|---|---|
| `x0` | `x21` | object đầu vào; được chuyển nguyên vẹn làm `x0` cho `0xa567f04` |
| `x1` | `x24` | đối số đầu vào; được chuyển qua `x0` cho `0xa564f74`, đồng thời low 32-bit được lưu ở stack scratch `+0xac` |
| `x2` | `x22` | điều kiện có/không dựng scratch metadata; nếu khác 0 sẽ được lưu vào stack |
| `x3` | `x23` | low 16-bit được lưu tại stack scratch `+0xb2` khi nhánh `x2 != 0` |
| `x4` | `x20` | được OR với bit `2` trước khi chuyển thành `w1` cho `0xa567f04` |
| `x5` | `x19` | được chuyển thành `x3` cho `0xa567f04` |

Function gọi:

1. `0xa5681bc`: `BL 0xa564f74` với `x0 = original x1`.
2. Nếu `original x2 != 0`: gọi `0xa76d3ec`, rồi `0xa1d14a0`, sử dụng vùng output stack `sp+0xb4`, kích thước `0x40`; kết quả byte được lưu ở `sp+0xb0`.
3. `0xa568230`: gọi `0xa567f04` với `x0=original x0`, `w1=original w4 | 2`, `x2=sp+0x10`, `x3=original x5`.

Scratch area `sp+0x10` được zero-initialize bằng các store vector theo từng block; function lưu thêm các field metadata tại `sp+0xac`, `sp+0xb0`, `sp+0xb2` và các vùng tạm liên quan.

**[CONFIRMED]** Trong body của `0xa568174`, các store được quan sát là stack-local/saved-register/canary/scratch writes. Không có direct store vào object qua `x21`/`x20`, cũng không có reference trực tiếp tới global `0xad95860` trong function body. Các side effect sâu hơn có thể xảy ra bên trong callee và không được quy trực tiếp cho caller này.

## 25.3 Direct callers

`kc_tool.py bl 0xa568174` tìm thấy đúng ba direct `BL` call-site:

- `0xa793348`
- `0xa79347c`
- `0xa7935b8`

Call-site `0xa793348` là một caller bổ sung so với inventory ngắn ở các ghi chú trước. Ba site nằm trong wrapper/loop region bắt đầu quanh `0xa793...`; không suy ra semantic tên của wrapper chỉ từ địa chỉ.

## 25.4 Quan hệ với Handler A/B

`0xa568174` luôn dựng `w1 = original_w4 | 2` trước khi gọi `0xa567f04`. Theo nhánh lựa chọn trong `0xa567f04`, bit 1 bật chọn Handler A (`0xa441410`) thay vì Handler B (`0xa441488`) cho các invocation đi qua parent này.

Điều này không biến `0xa568174` thành writer của gate `0xad95860`; parent chỉ dựng scratch và dispatch tiếp. Không gộp đường Handler A/B với callback-record `BLRAA` dùng modifier `0xfee3` nếu chưa có edge/data-flow trực tiếp chứng minh chúng cùng một callback instance.

## 25.5 Điều chỉnh hồ sơ function

- **[CONFIRMED]** Boundary mới: `[0xa568174, 0xa56826c)`.
- **[CONFIRMED]** Có ba direct callers, trong đó có `0xa793348`.
- **[CONFIRMED]** Parent dựng scratch metadata và gọi `0xa567f04` với bit `2` được bật.
- **[CONFIRMED]** Không có direct write vào object/global gate trong body parent.
- **[UNRESOLVED]** Ý nghĩa chính thức của từng đối số và object layout mà wrapper nhận vẫn cần source hoặc caller-level data-flow sâu hơn.

---

# 26. Audit lại static references tới global gate `0xad95860`

`kc_tool.py xref <kernelcache> 0xfffffff00ad95860` hiện trả về **45 static xrefs**:

- **44 `ADRP+LDR`**: load 32-bit value ở offset `+0x860` của page `0xad95000`.
- **1 `ADRP+ADD`** tại `0xa564e84`: materialize địa chỉ để callback thực hiện atomic update tại `0xa564e8c`.

Kết quả phân loại trong `gate_access_kind.txt` cũng cho thấy 44 access instruction là `READ` và một access `OTHER` (address construction). Đây là inventory của direct static references theo cách dò `ADRP` trong tool hiện tại, không phải chứng minh rằng binary không có alias access khác.

**[CONFIRMED]** Direct writer đã gắn chắc với đúng địa chỉ `0xad95860` vẫn là `LDADD` tại `0xa564e8c`. Những atomic instructions trong file `gate_atomics.txt` là 28 candidate records được thu theo proximity/context của pass cũ; không được tự động quy toàn bộ chúng thành writer của `0xad95860` nếu chưa chứng minh base register của từng atomic operand trỏ đúng địa chỉ này.

Cần giữ riêng ba khái niệm:

1. Static xref tới địa chỉ global.
2. Load value từ global.
3. Atomic/store instruction thực sự ghi vào đúng memory operand của global.

Đếm proximity hoặc cùng function không thay thế được register provenance cho memory operand. Do đó inventory reader/writer tổng thể vẫn **[INCOMPLETE]**.

---

# 27. Change log và hướng tiếp theo

## 27.1 Các điều chỉnh so với README (5)

1. Mục 23.5 ghi runtime dispatcher là unresolved đã được cập nhật: hiện có hai indirect `BLRAA` call-site dùng `0xfee3`, record `+0x38` và key `+0x14`; `w2=3` và `w2=0` đều đã có provenance static.
2. Không xem `0xa43f724` là call-site trực tiếp của callback `0xa564e54`; function extent này không chứa authenticated call phù hợp với modifier `0xfee3`.
3. Function `0xa568174` được giới hạn đúng tới `0xa56826c`; không gộp disassembly các function kế tiếp vào cùng CFG.
4. Caller inventory của `0xa568174` được bổ sung call-site `0xa793348`.
5. Các atomic site chỉ được gắn vào gate sau khi chứng minh memory operand; không suy luận dựa trên độ gần địa chỉ.

## 27.2 Pending

1. Phân tích sâu caller contexts của `0xa439ef0`, `0xa43dd78`, `0xa43e2dc`, `0xa43e31c`, `0xa441a5c` và hai caller `0xa43dd94`, `0xa43e338`; xác định điều kiện/event cấp cao phát ra callback delta `0` và `3`.
2. Xác nhận runtime record instance ở `0xa4416a0` có callback `0xa564e54` và theo dõi owner object `x0` qua allocation, link, detach.
3. Với từng 44 load xref của `0xad95860`, kiểm tra full basic block/function và phân loại read semantics; tiếp tục tìm write/atomic access qua alias registers.
4. Tiếp tục write-provenance cho `0xa568174` callees và các caller tại `0xa793348`, `0xa79347c`, `0xa7935b8`.
5. Đối chiếu XNU đúng revision `xnu-13432.42.3~28`. Repository tag public/local hiện chưa cung cấp source revision trùng build; không dùng revision cũ làm bằng chứng source-level tương đương.
6. Không kết luận underflow, race, UAF, double-free, CVE root cause hoặc exploitability chỉ từ call graph tĩnh này.

## 27.3 Commands tái lập

```bash
B="$HOME/ios27-diff/27.2/24B119__iPhone14,8/kernelcache.release.iPhone14,8"
P="$HOME/ios_kernel_poc"

# Callback record positive path (w2=3)
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a43f44c 0xfffffff00a43f638

# Callback record negative path (w2=0)
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a43a264 0xfffffff00a43a5b0

# Callback entry and registration
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a564e54 0xfffffff00a564e98
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a564dcc 0xfffffff00a564df0
python3 "$P/kc_tool.py" "$B" xref 0xfffffff00a564e54
python3 "$P/kc_tool.py" "$B" bl 0xfffffff00a4416a0

# Exact extent and callers of a568174
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a568174 0xfffffff00a56826c
python3 "$P/kc_tool.py" "$B" bl 0xfffffff00a568174

# Gate static references
python3 "$P/kc_tool.py" "$B" xref 0xfffffff00ad95860
```

**README (5) được giữ nguyên.** README (6) là bản sao mới với các cập nhật của mục 24–27; không thay thế source README.

---

# 28. Caller-level phân loại callback delta `0` / `3`

Phần này bổ sung caller context cho các call-site còn Pending ở mục 27.2. Tên event cấp cao vẫn để unresolved; các kết luận dưới đây chỉ mô tả data-flow và branch condition nhìn thấy trong `KC_B3`.

## 28.1 Hai helper có vai trò đối xứng ở mức call graph

| Helper | Call-site đã xác minh | Dữ liệu callback | Kết luận tĩnh |
|---|---|---|---|
| `0xa43a264` | `0xa439ef0`, `0xa43dd78`, `0xa43e2dc`, `0xa43e31c`, `0xa441a5c` | `w2=0` tại dispatch bên trong helper | Detach/removal path; có thể gọi callback giảm |
| `0xa43f44c` | `0xa43dd94`, `0xa43e338` | `w2=3` tại dispatch bên trong helper | Attach/link path; có thể gọi callback tăng |

Ở `0xa43a264`, callback dispatch nằm tại `0xa43a49c`: `x0=x21`, `x1=key`, `w2=0`, `x17=0xfee3`, `BLRAA x24,x17`. Ở `0xa43f44c`, dispatch nằm tại `0xa43f55c`: `x0=x2`, `x1=key`, `w2=3`, `x17=0xfee3`, `BLRAA x23,x17`. Đây là cùng ABI callback đã mô tả ở mục 24, không phải Handler A/B path dùng modifier `0xd2bc`.

## 28.2 Caller `0xa439c20` — detach phụ thuộc identity của associated object

Call-site `0xa439ef0` thuộc function bắt đầu tại `0xa439c20`.

Ngay trước call:

```asm
0xa439ed0  ldr  x8, [x20, #0x80]
0xa439ed4  cbz  x8, 0xa439ef4
0xa439ed8  ldr  x8, [x8, #0x28]
0xa439edc  cmp  x8, x22
0xa439ee0  b.ne 0xa439ef4
0xa439ee4  mov  x0, x20
0xa439ee8  mov  x1, x22
0xa439eec  mov  x2, x21
0xa439ef0  bl   0xa43a264
```

**[CONFIRMED]** `0xa43a264` chỉ được gọi khi object tại chuỗi `[x20+0x80]+0x28` tồn tại và bằng `x22`. Vì vậy callback delta `0` ở đây không được phát ra vô điều kiện: nó phụ thuộc vào identity match của object hiện được gắn với `x20`.

Không có bằng chứng tại call-site này để đặt tên event ngoài mô tả “conditional detach”.

## 28.3 Caller `0xa43db68` — tìm registration record rồi detach/attach

`0xa43dd78` và `0xa43dd94` nằm trong cùng function bắt đầu `0xa43db68`. Register mapping ở function entry: `x19` giữ object/context đầu vào, `x21` giữ selector đầu vào, `x22` giữ đối số thứ ba.

Function kiểm tra object ở `[x19+0x80]`, field `+0x14`, và object liên kết tại `+0x28`; sau đó duyệt list bắt đầu từ `[object+0xc0]`. Mỗi record có key ở `+0x14`; nhánh quanh `0xa43dd28–0xa43dd44` còn xử lý riêng key `0x95` cùng một flag của owner.

Khi tìm được candidate record/object:

- `0xa43dd78` gọi `0xa43a264` với `x0=x19`, `x1=associated object`, `x2` giữ đối số thứ ba của function.
- Nếu detach trả về `0`, nhánh `0xa43dd88–0xa43dd94` gọi `0xa43f44c` với `x0=x19`, `x1=matched record`, `x2=associated object`.
- Nếu attach thành công, đường đi tiếp tục qua logging/state update và helper `0xa43f674`; nếu không, function đi vào nhánh cleanup khác.

**[CONFIRMED]** Đây là một chuỗi detach-then-attach có điều kiện ở cấp machine-code. Việc hai helper được gọi liên tiếp không tự chứng minh đây là một “replace event” theo tên API; nhãn đó vẫn là giả thuyết.

## 28.4 Caller `0xa43e030` — hai nhánh detach và một nhánh attach

Function bắt đầu tại `0xa43e030`. Entry checks gồm:

- bit 6 của `[x0+0x134]` phải clear;
- `(w1_at_+0x78 & 7) == 2`;
- field `[x1+0x7c]` phải nonzero;
- sau đó duyệt callback records từ `[x1+0xc0]`, đối chiếu key tại record `+0x14`, và kiểm tra các state fields liên quan.

Ba call-site được xác minh:

| VA | Argument setup ngay trước BL | Ý nghĩa ở mức control flow |
|---|---|---|
| `0xa43e2dc` | `x0=x9`, `x1=x23`; `x2` là giá trị được giữ từ context | Conditional detach của object/record pair đang được duyệt |
| `0xa43e31c` | `x0=x23`, `x1=x21` | Detach trong nhánh tiếp theo; kết quả được lưu tại `w8` và kiểm tra ngay sau call |
| `0xa43e338` | `x0=x23`, `x1=x21`, `x2=x20` | Attach helper chỉ được gọi khi nhánh điều kiện tại `0xa43e328` cho phép |

**[CONFIRMED]** `0xa43e338` là positive attach call-site thứ hai của `0xa43f44c`. Việc `0xa43e31c` và `0xa43e338` cùng nằm trong một function không đủ để kết luận mọi lần detach đều được theo sau bởi attach; branch tại `0xa43e328` có thể chuyển sang cleanup path.

## 28.5 Caller `0xa4418c0` — owner-list teardown

Function bắt đầu `0xa4418c0` duyệt linked list tại `[x19+0xc0]`. Trong loop:

```asm
0xa441960  ldr  x8, [x21]
0xa441964  str  x8, [x19, #0xc0]
0xa441968  str  xzr, [x21]
0xa44196c  ldr  x26, [x21, #8]
...
0xa441a5c  bl   0xa43a264
0xa441a68  str  w8, [x26, #0x134]
0xa441a70  bl   0xa439b24
```

Call-site `0xa441a5c` có `x0=x26`, `x1=x19`; `x2` đến từ `[result+0x18]` của helper được gọi ở `0xa441a48`. Trước khi gọi detach helper, node hiện tại đã bị bỏ khỏi head của owner list và `node->next` đã được clear.

**[CONFIRMED]** Đây là một teardown/unlink path ở mức list topology, sau đó gọi detach helper và tiếp tục xử lý state của associated object. **[UNRESOLVED]** Chưa có bằng chứng tại đoạn này xác định chính xác allocator/free cuối cùng của node; không gán nhãn “free” chỉ từ unlink.

---

# 29. Registration record: allocation, layout và lifecycle tĩnh

## 29.1 Registration helper `0xa4416a0`

`kc_tool.py bl 0xfffffff00a4416a0` trả về **13 direct BL callers**, trong đó có call-site `0xa564de4` của registration path key `0x95`.

Trong helper:

- `x19` giữ owner object đầu vào.
- `w22` giữ key.
- `x24` giữ associated-object argument.
- `x23` giữ callback pointer.
- Allocation được gọi qua `0xa2216c4` với descriptor address `0xfffffff007c70000+0xa90` và `w1=0x8004`. API/allocator identity chưa được xác minh từ symbol.
- Owner linked-list root nằm ở `[x19+0xc0]`; helper tìm duplicate key trước khi chèn record.

Các field được ghi trực tiếp trong nhánh insertion:

| Offset | Initialization evidence | Ghi chú |
|---:|---|---|
| `+0x00` | `str x11,[x0]` hoặc `str xzr,[x0]` | Next pointer trong owner list |
| `+0x10` | `str w8,[x0,#0x10]`, `w8=1` tại `0xa441850` | State/validity field; tên semantics chưa biết |
| `+0x14` | `str w22,[x0,#0x14]` | Key; callback path đang xét dùng `0x95` |
| `+0x18` | `str d0,[x0,#0x18]` | 64-bit metadata/vector initialization |
| `+0x20` | `str w9,[x0,#0x20]` | Metadata length/value |
| `+0x28` | `stp x19,x24,[x0,#0x28]` | Owner và associated-object fields |
| `+0x38` | `str x23,[x0,#0x38]` | Callback pointer |

Sau khi initialize record, helper chèn nó vào list rooted at `owner+0xc0`, rồi gọi `0xa47d408` với owner trong `x0`.

**[CONFIRMED — STATIC]** Callback record layout, allocation call-site, key field, callback-pointer field và list insertion đều có instruction-level provenance. **[NOT RUNTIME-CONFIRMED]** Chưa quan sát được địa chỉ record thực tế, allocation instance hay owner object cụ thể trong runtime.

## 29.2 Callback lifecycle có thể nối từ register tới detach

Static path hiện có đủ mắt xích sau:

1. `0xa564de4` gọi registration helper `0xa4416a0` với key `0x95`, associated object và callback pointer đã ký PAC.
2. `0xa4416a0` cấp phát record, ghi key tại `+0x14`, owner/associated values tại `+0x28`, callback pointer tại `+0x38`, rồi thêm vào owner list `+0xc0`.
3. `0xa43f44c` là attach helper; khi record/callback conditions thỏa, nó dispatch callback với `w2=3` và modifier `0xfee3`.
4. `0xa43a264` là detach helper; khi record/callback conditions thỏa, nó dispatch callback với `w2=0` và modifier `0xfee3`.
5. `0xa4418c0` duyệt owner list, unlink node khỏi head trước khi gọi detach helper tại `0xa441a5c`.

Đây là lifecycle tĩnh của registration record, không phải runtime trace. Thứ tự unlink trước callback không tự chứng minh race, UAF, double-free hay memory-safety defect; các giả thuyết đó cần lifetime/refcount/locking evidence bổ sung.

---

# 30. `0xa568174` callers, Handler A/B routing và gate consumers

## 30.1 Direct caller contexts của `0xa568174`

Caller inventory đã xác minh chính xác ba BL site: `0xa793348`, `0xa79347c`, `0xa7935b8`.

| Caller | Wrapper context từ disassembly | Argument flow nổi bật |
|---|---|---|
| `0xa793348` | Loop qua linked nodes bắt đầu từ `[x0+8]`; đọc metadata tại `+0x58` để chọn flags | `x0=x26`, `x1=x19`, `x2=x20`, `x3=x5`, `x4` chọn giữa `w24` và `w2`, `x5=x22`; sau call tiếp tục loop trên `x26` |
| `0xa79347c` | Nhánh `w2` bit 1 set của wrapper `0xa7933f4` | `x0` là object được giữ tại `x19`; các args được remap từ `x3/x4/x5` và flags `w2`; sau call cleanup bằng `0xa78f188` |
| `0xa7935b8` | Nhánh `w3` bit 1 set của wrapper `0xa793514` | `x0` được lưu ở stack; `x1/x2/x3/x4/x5` remap từ wrapper inputs; sau call cleanup bằng `0xa78f188` |

Các caller này chứng minh `0xa568174` được gọi từ ba wrapper/iteration contexts khác nhau. Chưa có symbol/source names đủ chắc để gán mỗi wrapper cho một loại object/event cụ thể.

## 30.2 Handler A/B selector chính xác hơn

`0xa567f04` PAC-authenticates hai handler addresses bằng modifier `0xd2bc`:

- Handler A candidate: `0xfffffff00a441410`.
- Handler B candidate: `0xfffffff00a441488`.
- `tst w1,#2` quyết định `CSEL` tại `0xa567f4c`: bit 1 set chọn candidate A; bit 1 clear chọn candidate B.
- Parent `0xa568174` truyền flags có dạng `w4 | 2`, do đó bit 1 luôn được bật trên call path này; nhánh parent hiện quan sát được chọn Handler A.
- Handler indirect call cuối của helper dùng modifier `0xd2bc`; không được nhập chung với callback-record `BLRAA` modifier `0xfee3`.

Handler A tại `0xa441410` xây dựng stack argument structure từ linked values (`LDRSW [x2,#0x18]` trong loop), điều chỉnh thêm `x4` khi `x3` khác null, rồi gọi `0xa43f724` với `w3=1`. Ý nghĩa API/source-level của structure và `0xa43f724` vẫn chưa được xác minh.

## 30.3 Gate `0xad95860` trong wrapper family

Ba read-site trong cùng wrapper family có branch outcome rõ ràng:

- `0xa79339c`: load gate; `CBNZ` sang `.a7933cc`; chỉ khi gate bằng zero mới gọi `0xa564f74` tại `0xa7933b0`, sau đó lặp cleanup qua `0xa78f188`.
- `0xa7934d0`: cùng mẫu; zero path gọi `0xa564f74` tại `0xa7934e4`, rồi cleanup loop.
- `0xa79352c`: cùng mẫu; zero path gọi `0xa564f74` tại `0xa793540`, rồi cleanup loop.
- `0xa793228`: cũng đọc global; gate khác zero chuyển sang nhánh `.a793274`, còn gate zero gọi `0xa7920f8` trước khi tail-branch sang `0xa566400`.

**[CONFIRMED]** Global này không chỉ được đọc ở các consumer đã khảo sát tại mục 5; nó còn trực tiếp điều khiển nhánh trong một wrapper family quanh `0xa793...`. Ở ba site `.79339c/.7934d0/.79352c`, giá trị zero cho phép đi qua status dispatcher `0xa564f74` và cleanup loop; nonzero bypasses nhánh đó.

**[UNRESOLVED]** Không gán tên “active callback count”, “disable switch” hay một API semantic cụ thể chỉ dựa trên branch pattern. Mối liên hệ được xác minh hiện tại là: callback tại `0xa564e54` cập nhật global bằng atomic add/subtract; một số wrapper đọc global đó để quyết định có vào dispatcher/cleanup path hay không.

---

# 31. Xác minh chính xác target build và kernel revision

Metadata cục bộ của IPSW và kernelcache đã đối chiếu trực tiếp:

| Evidence | Giá trị |
|---|---|
| IPSW `BuildManifest.plist` — `ProductVersion` | `27.2` |
| IPSW `BuildManifest.plist` — `ProductBuildVersion` | `24B119` |
| IPSW `SupportedProductTypes` | `iPhone14,8` |
| `ipsw kernel version` trên `KC_B3` | `Darwin Kernel Version 27.2.0` |
| Kernel build timestamp | `Tue Oct 13 21:26:30 PDT 2026` |
| Kernel source version banner | `xnu-13432.42.3~28` |
| Architecture/platform suffix | `RELEASE_ARM64_T8110` |
| `KC_B3` SHA-256 | `c81fb9d291cb4e0d8cca512724079da21bc3d6460d37d6f3a4831116af8b410a` |

**[CONFIRMED]** Revision string `xnu-13432.42.3~28` khớp trực tiếp banner trong kernelcache target `24B119`; không còn chỉ là suy luận từ build lân cận `24B115`.

**[NOT YET SOURCE-MAPPED]** Chưa có local XNU source checkout/tag chứng minh file/line-level equivalence với revision này. Kernel banner xác minh revision được dùng để build target, nhưng không tự cung cấp source tree đầy đủ hoặc source cho proprietary/platform-specific components.

---

# 32. Change log — 2026-11-15 (README 7)

1. Hoàn tất caller-level static context cho năm detach call-sites và hai attach call-sites ở mục 28.
2. Ghi nhận registration record layout và owner-list insertion tại `0xa4416a0`; nối lifecycle tĩnh tới teardown function `0xa4418c0`.
3. Bổ sung direct-caller argument flow cho ba callers của `0xa568174`.
4. Xác nhận parent `0xa568174` ép bit selector 1, nên call path đã khảo sát chọn Handler A; giữ riêng modifier `0xd2bc` và callback modifier `0xfee3`.
5. Phân loại bốn gate checks ở wrapper family `0xa793...` nhưng không đặt tên semantic cho global counter.
6. Xác minh trực tiếp IPSW product/build và kernel banner `xnu-13432.42.3~28` trên target `24B119`.
7. README (5) và README (6) được giữ nguyên; README (7) copy toàn bộ README (6) rồi chỉ append nội dung mới.

## 32.1 Pending tiếp theo

1. Runtime trace: xác định record instance được tạo ở `0xa4416a0`, callback PAC pointer thực tế và owner lifetime qua register → attach → unlink → detach.
2. Tiếp tục phân loại toàn bộ 44 gate reads theo function-level branch effects; đối chiếu các wrapper ở `0xa835...`, `0xa836...`, `0xa839...`, `0xa83...` và `0xa88...`.
3. Audit alias writes/atomic sites bằng register provenance; hiện direct writer được xác minh vẫn chỉ là `LDADD` tại `0xa564e8c`.
4. Disassemble/trace callee `0xa43f724`, Handler B `0xa441488`, và các status cases của `0xa564f74` để làm rõ scratch/dispatch semantics.
5. Kiểm tra locking/refcount/owner lifetime trước khi đánh giá memory-safety hypotheses; không suy ra race/UAF/underflow/double-free/CVE root cause từ static graph hiện có.
6. Tìm source snapshot thật sự khớp `xnu-13432.42.3~28`; nếu không có, tiếp tục dùng disassembly của đúng kernelcache thay vì gán source lines từ revision khác.

## 32.2 Commands tái lập chính

```bash
B="$HOME/ios27-diff/27.2/24B119__iPhone14,8/kernelcache.release.iPhone14,8"
P="$HOME/ios_kernel_poc"

# Caller-level detach/attach contexts
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a439c20 0xfffffff00a43a264
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a43db68 0xfffffff00a43e000
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a43e030 0xfffffff00a43e6fc
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a4418c0 0xfffffff00a441c5c

# Registration helper and caller count
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a4416a0 0xfffffff00a4418b8
python3 "$P/kc_tool.py" "$B" bl 0xfffffff00a4416a0

# Parent/helper and exact direct callers
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a567f04 0xfffffff00a568174
python3 "$P/kc_tool.py" "$B" callers 0xfffffff00a568174
python3 "$P/disasm_robust.py" "$B" 0xfffffff00a793200 0xfffffff00a7935cc

# Build identity / kernel revision
unzip -p "$HOME/Downloads/iPhone14,8_27.2_24B119_Restore.ipsw" BuildManifest.plist
ipsw kernel version "$B"
sha256sum "$B"
```
