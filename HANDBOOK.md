# AIM reconstruction handbook

This is a workflow guide. Target lists, compiler settings, machine configuration,
match results, and experiment history belong in their authoritative files and
generated reports. Adding a target or completing a reconstruction does not require
editing this handbook.

## Getting started

Run commands from the workbench directory. Install its declared dependencies and
use command help for available options:

```powershell
Set-Location aimcmp
python -m pip install -e .
python -m aimcmp --help
```

Choose a target from the manifest. These examples select its first entry; select
the entry you intend to work on instead:

```powershell
$project = '../targets/project.json'
$targetConfig = (Get-Content $project -Raw | ConvertFrom-Json).targets[0]
$target = $targetConfig.name
$projectRoot = Split-Path (Resolve-Path $project)
$ledger = Join-Path $projectRoot $targetConfig.mapping
$original = Join-Path $projectRoot $targetConfig.original
$rebuilt = Join-Path $projectRoot $targetConfig.rebuilt
$map = Join-Path $projectRoot $targetConfig.map
$report = "../targets/reports/iterations/$target/latest.json"
```

Find project state at its source:

| Information | Where to read it |
|---|---|
| Targets, source locations, artifacts, and connections | `targets/project.json` |
| Build options, inputs, and link order | The target's recipe under `build/recipes/` |
| Compiler environment and pinned tool versions | The profile selected by the recipe |
| Private machine overrides | The manifest's optional `local_config` file |
| Names, types, original identity, and evidence | The target's mapping ledger |
| Current match status and differences | Generated comparison reports |
| Prior experiments and frozen inputs | Checkpoints and variant runs |

Original binaries and generated artifacts are excluded from Git. Supply originals
at their configured locations. Remote builds require SSH/SCP access to the configured
Windows machine. Analysis requires the Binary Ninja RPyC service with access to the
binary paths; consult command help for connection options. Machine-specific settings
belong in the ignored local config.

## 1. Read comparison reports

```powershell
python -m aimcmp brief $report
python -m aimcmp brief $report --format json
python -m aimcmp brief --help
```

`brief` reads a saved report without an image or a live analysis connection.
Compare reports for the same original when investigating changes.

Read three measurements separately: normalized instruction coverage helps locate
differences; exact executable-section bytes establish a code match; whole-file
equality additionally covers resources, data, headers, and layout. A function
score alone does not establish whole-file equality. Timestamp-only classification
must account for the actual differing bytes.

## 2. Build, analyze, and compare

```powershell
python -m aimcmp iterate $project $target --require-exact
python -m aimcmp iterate --help
```

`iterate` uploads configured inputs, builds remotely, retrieves artifacts and MAP
files, analyzes both images, and writes comparisons and stage diagnostics.
`--require-exact` checks executable-section bytes; it does not require whole-file
equality. Use the report to determine the result and preserve failure diagnostics.

Recipes define build inputs and options. The workbench derives upload lists and
renders build scripts from them. Keep every compilation unit, resource, export
definition, and object ordering in the recipe. Rebuild every affected target when
changing shared source or build settings.

## 3. Record identities and evidence

```powershell
python -m aimcmp mapping show $ledger
python -m aimcmp mapping resolve $ledger $original $rebuilt --map $map
python -m aimcmp mapping --help
```

Ledgers bind original addresses to an original SHA-256. Keep permanent IDs while
refining names and types. Prefer rebuilt symbols over addresses that move between
builds; explicit rebuilt addresses must be pinned to their artifact identity.

Record evidence and distinguish hypotheses from verified observations.
Reconstructed names and source shapes remain interpretations even when the bytes
match. Annotation changes can affect normalized comparisons; raw-byte equality
is independent of those annotations.

## 4. Save and restore experiments

```powershell
python -m aimcmp checkpoint save $project $target my-attempt
python -m aimcmp checkpoint list $project $target
python -m aimcmp checkpoint --help
```

Choose a fresh checkpoint name. Saving freezes configured sources, the ledger,
recipe, profile, build artifacts, and comparison evidence. A completed mismatch
can be useful evidence; a failed build does not establish a comparison result.

Compare checkpoints before choosing one to restore. Restore checks identity and
integrity and backs up working inputs. It does not install a compiler or perform
a remote build. Run `iterate` afterward and rebuild targets that share restored
inputs.

## 5. Compile source variants

```powershell
python -m aimcmp variants --help
python -m aimcmp variants run --help
python -m aimcmp variants promote --help
```

Use a bounded set of plausible source shapes or flags. Variant specifications and
templates describe the experiment; isolated builds and reports preserve results.
Keep experiments outside canonical source until explicitly promoted.

Review raw-code equality and whole-file differences separately from normalized
scores. Promotion verifies saved evidence and backs up working inputs. Rebuild
affected targets afterward. When several ordinary source forms compile
identically, choose the simplest and record the ambiguity in the ledger or
experiment evidence.

## 6. Ask focused analysis questions

```powershell
python -m aimcmp query-target $project $target entry --fields assembly,hlil,types
python -m aimcmp query-target --help
python -m aimcmp query --help
```

Query a function or data address, symbol, or ledger identity. Select the original
or rebuilt side explicitly when needed. Ask for the assembly, decompilation,
callers, references, or types relevant to the current uncertainty. Bounded output
and visible errors make the returned evidence easier to inspect.

## Daily workflow

### Test decompiler annotations

Keep a contract's `type_confidence` separate from a function body's match status.
Verified type annotations require `type_verification` (`byte-match` or `probe`)
and specific `type_evidence`. Structured type declarations likewise carry their
own confidence and evidence. Legacy declaration strings and unclassified
signatures are excluded from verified-only analysis. Imported contracts use
`kind: import` and the exact `DLL!decorated_symbol` identity, checked against the
pinned original. For call-count studies, record `physical_parameter_count`,
including the receiver and any hidden result argument.

From `aimcmp/`, run a focused experiment with explicitly selected functions:

```powershell
python -m aimcmp annotation-study ../originals/AIM/aim.exe ../targets/mappings/aim-contracts.json --function 0x402846 --output ../.local/analysis/annotations/xprt
```

The runner freezes the metric definitions and ledger before collection, then
loads the hash-verified PE independently for baseline, verified, and hypothesis
analyses. It records BN version, settings, collector and annotation-engine hashes,
import types, HLIL, and per-function deltas. It uses no saved database or analysis
cache. Keep each experiment's output in its own ignored directory.
Check `status.json` before using a report: a failed rerun does not make an older
report current.

Read hypothesis changes separately from verified changes. Counts describe BN
output, not correctness; a simpler decompilation can still be wrong. Explicit
conversion nodes are counted because BN has no dedicated HLIL cast operation.
Result-type divergences are diagnostics, including legitimate conversions.
Existing Windows library types remain part of the baseline. Own EH observations
still supply lifetime evidence that HLIL omits. Types from rebuilt PDBs inherit
the confidence of our declarations.

For a cached annotated snapshot, use `snapshot --mapping ...
--annotation-layer verified`; `--annotation-layer all` also applies hypotheses.
Each layer has a separate content-keyed cache identity.

### Hone a function

```powershell
python -m aimcmp hone ../targets/project.json aim WinMain --cache ../.local/analysis/honing-cache --json ../.local/client-build/winmain-honing.json
```

The short view shows the first instruction divergence, its classification,
nearby call liveness and reaching definitions, late-load candidates, syntactic
zero counts, and prior attempts. Use `--full` for the complete JSON evidence.
By default it reads `.local/analysis/honing/ledger.json` under the configured
workspace root; `--ledger` selects another history. A target's optional
`honing_bindings` points to a hash-pinned COFF manifest for known reference
identities. Unresolved references remain visible separately from instruction
changes. Canonical equality is an allocation diagnostic, not an exact match.

ABI registers retain their identities. Preserved-register saves/restores are
checked separately from canonicalized body uses, and branch destinations are
compared after alignment. Liveness includes all general registers internally,
but the call view displays EBX/ESI/EDI/EBP and EBP-relative storage. Partial
writes and overlapping accesses are conservative; EBP-relative storage is not
source identity. ESP-relative slots and memory aliasing are unresolved. Calls
may modify storage through escaped pointers. Unknown control-flow paths are
flagged rather than treated as complete evidence.

Use `hone-log check` before compiling a proposed retry, and `hone-log add`
afterward. Both require the function's ledger ID, pinned original SHA-256,
compiler flags, a captured tool inventory, and actual compiler-preprocessed
source. Token hashing ignores comments, whitespace, and compiler line markers;
strings, token boundaries, and pragmas remain significant. Flags and tool hashes
are part of the duplicate key. Raw source with unexpanded directives is rejected.
Capture preprocessing with the same include paths, forced includes, macros,
language mode, and compiler used for the build; VC7.1's `/EP` produces suitable
input. Preserve preprocessing failures as failures rather than hashing partial
output. A report hash alone does not prove the source produced its artifact;
retain the build/checkpoint evidence alongside the entry.

```powershell
python -m aimcmp hone-log check ../.local/analysis/honing/ledger.json aim.function.WinMain --original-sha256 <hash> --preprocessed <compiler-output.i> --toolchain <captured-tools.json> --flags '<compiler-options>'
python -m aimcmp hone-log add --help
python -m aimcmp hone-log stop --help
```

Each attempt states a hypothesis and mutation family. Assessed attempts require
a report; build failures and untested sources never receive an assessment.
Use `baseline` to record an unchanged candidate; it does not count as a tried
mutation family when declaring a plateau.
Families include declaration/first-use order, initialization placement, named
intermediates, reload-at-use, if/else inversion, comparison operand order, and
zero-constant uses. Render alternatives through the existing variant templates;
the family names do not authorize blind rewrites of arbitrary C++ expressions.

Before stopping at a plateau, record `hone-log stop` with a concrete reason,
remaining mismatch classification, and tried families. The command rejects an
empty explanation and families without recorded attempts. This is a workflow
requirement; the tool cannot prevent an agent from ending its turn outside it.

Upstream libraries live in `vendor/` as pinned Git submodules. Initialize them
with `git submodule update --init --recursive` from the repository root.
`vendor/sources.json` records the relevant binaries, source roots, selection
evidence, and unresolved revisions. A version-based pin is not a byte-match
claim. Keep upstream edits in separate experimental checkouts or explicit patch
files; preserve the submodules as reference source.

Revision searches must fix the toolchain, flags, dependency revisions, and
comparison functions. Treat build failures as untested candidates. Exact-match
results need not be monotonic across revisions: scan releases first, then use
bisection only for a property with a demonstrated boundary. Preserve all passing
revisions rather than claiming a unique historical revision from identical code.

To stage the client executable's private resource and DLL import inputs, run
`python build/prepare-client.py originals/AIM .local/client-build` from the
repository root. This refreshes the staged source too, so repeat it after source
edits. Then run `python -m aimcmp build ../targets/project.json aim` from
`aimcmp/`. The build uses the VM selected in the local machine configuration.
Resources are extracted from the pinned original; no executable code is copied.
The build also downloads objects used by the exact contribution checks. From
`aimcmp/`, run `python -m aimcmp coff-compare ../originals/AIM/aim.exe ../targets/builds/aim ../targets/client-helpers.json`
to check those contributions with explicit relocation bindings.
Grouped source files can produce several same-named COFF sections. A comparison
record's one-based `section_index` selects its contribution; keep its internal
relocation bindings aligned with the rebuilt object's section table.

For a broad reconstruction pass, a compiled draft is a useful intermediate
result. Keep drafted, behavior checked, and byte exact status separate in the
mapping records. Unimplemented stubs do not count as drafted functions. Preserve
exact helper comparisons while larger routines remain provisional.

Read the report, investigate a specific difference, update source and ledger
evidence, and run `iterate`. Save a checkpoint before a substantial experiment.
Keep code comments focused on what the code does and surprising behavior; put
compiler experiments and reconstruction provenance in ledgers and local notes.

For a new module, add its source, recipe, mapping ledger, and manifest entry.
Keep machine-specific settings local. Preserve sealed historical evidence rather
than rewriting it to follow current paths.

Run checks appropriate to workbench changes:

```powershell
python -m unittest discover -s tests -v
```

Some tests require ignored originals and built artifacts. Test output records the
current result. Record compilation, comparison, and runtime testing as separate
facts in the relevant evidence.
