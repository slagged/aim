# AIM reconstruction handbook

This guide covers the six completed aimcmp features. Current reconstructions reproduce all executable-section bytes of idlemon (407 bytes), SendFile (494 bytes), and ShareFile (494 bytes). Whole-file differences are limited to timestamps. Candidates have been compiled and analyzed; they have not been executed.

## Setup and locations

From the repository root, run these commands in host PowerShell:

```powershell
Set-Location aimcmp
python -m aimcmp --help
```

| Repository path | Purpose |
|---|---|
| `.local/docs/` | Archived supporting notes, excluded from Git |
| `.local/scripts/` | Historical one-off utilities, excluded from Git |
| `.local/machine.json` | Optional private connection/tool overrides, excluded from Git |
| `aimcmp/aimcmp/` | Python implementation |
| `targets/project.json` | Target recipes, paths, VM builds, tool inventory |
| `build/recipes/` | Authoritative compiler/linker recipes |
| `build/profiles/` | Pinned compiler environments and tool versions |
| `src/` | Reconstruction sources, resources, and export definitions |
| `aimcmp/examples/` | Reusable workbench examples and variant templates |
| `targets/mappings/` | Persistent identities, types, confidence, evidence |
| `originals/AIM/` | Immutable local AIM binaries |
| `targets/builds/` | Active binaries and linker MAP files |
| `targets/reports/` | Full comparisons, compact reports, analysis caches |
| `targets/checkpoints/` | Experiments and automatic restore backups |
| `targets/experiments/runs/` | Source-variant run evidence |

Originals and generated artifacts are excluded from Git. The originals were copied from the previous workspace and verified byte for byte. Historical reports and sealed checkpoints retain their recorded paths as provenance. Active recipes use `../originals/AIM/`; restore keeps the current original path after checking its SHA-256.

The host needs Python with `pefile`, `capstone`, and `rpyc>=6.0.0`, plus SSH/SCP access to a configured Windows build VM. An editable install is available with `python -m pip install -e .`; commands here also work directly from the workbench directory.

The public manifest uses the SSH alias `build-vm`, neutral remote build directories, and documented default tool locations. `local_config` points to optional `../.local/machine.json`; if it is absent, those public defaults apply. This checkout already has private overrides for its working VM. For another machine, create the ignored file with settings such as:

```json
{
  "schema": 1,
  "targets": {
    "idlemon": { "ssh": "my-build-vm" },
    "SendFile": { "ssh": "my-build-vm" },
    "ShareFile": { "ssh": "my-build-vm" }
  },
  "toolchain": { "ssh": "my-build-vm" },
  "batch_archive_tool": "C:/Tools/7-Zip/7z.exe"
}
```

Target overrides are limited to `ssh`, `remote_dir`, and `timeout_seconds`. Tool inventory overrides may set `toolchain.ssh` and individual paths in `toolchain.files`. Sources, flags, mappings, and original identities remain public recipe settings. The shared compiler profile currently expects the compiler installation at `C:\VS2003`; inventory paths must correspond to the compiler actually selected by those scripts. Checkpoint restores preserve public machine defaults and normalize active ledger paths, without rewriting sealed historical evidence or the private override file.

The VM has VS .NET 2003 at `C:\VS2003`: compiler components 13.10.3077.0, linker 7.10.3077.0, cvtres 7.10.3052.4, and rc 5.2.3668.0. Generated batch scripts select the environment through `vsvars32.bat`. See [build profiles](.local/docs/aimcmp/build-profiles.md).

Binary Ninja is exposed through RPyC at `127.0.0.1:18812`, using `root.import_module('binaryninja')`, and must be able to read host binary paths. Override the endpoint with `--bn-host`/`--bn-port`. aimcmp opens and closes its own views. Cache hits still contact the service to verify its version; `--refresh` forces fresh analysis.

## 1. Read reports as text or JSON

```powershell
python -m aimcmp brief ../targets/reports/SendFile.json
python -m aimcmp brief ../targets/reports/SendFile.json --format json
python -m aimcmp brief ../targets/reports/iterations/SendFile/latest.json --baseline ../targets/reports/iterations/SendFile/previous.json --format json
```

`brief` summarizes a saved full report without an image or a Binary Ninja connection. Baselines must describe the same original. `previous.json` exists after an earlier iteration has been replaced. `--diff-limit` and `--function-limit` bound detail and expose truncation.

Read three measurements separately: normalized instruction coverage helps locate differences; exact raw executable-section bytes establish a code match; whole-file equality additionally covers resources, data, headers, and layout. Timestamp-only classification checks the actual differing bytes against parsed timestamp fields. A function score alone does not establish whole-file equality.

Compact JSON is schema 1, kind `aimcmp.iteration`; full JSON/HTML retains the detailed evidence. See [report commands and schema](.local/docs/aimcmp/iteration-report.md).

## 2. Build, analyze, and compare in one command

```powershell
python -m aimcmp iterate ../targets/project.json SendFile --cache ../targets/reports/cache --require-exact
python -m aimcmp iterate ../targets/project.json ShareFile --cache ../targets/reports/cache --require-exact
python -m aimcmp iterate ../targets/project.json idlemon --cache ../targets/reports/cache --require-exact
```

`iterate` uploads configured sources/flags, builds on the VM, retrieves artifacts/MAP files, analyzes both images, and compares with the preceding report. Use `--no-build` for current local artifacts, `--format json` for machine output, or `--baseline` for an explicit prior report.

Outputs under `targets/reports/iterations/<target>/` include `latest.json`, `latest.html`, `iteration.json`, `iteration.txt`, and the preceding `previous.json`. Logs and failure diagnostics preserve stage evidence.

Exit 0 means assessment completed; exit 1 means a build/analysis error; exit 2 means `--require-exact` found different raw executable-section payloads. Without that option, a completed mismatch can return 0. Timestamp-only differences do not fail the raw-code requirement.

Build recipes are authoritative for flags, resources, export definitions, products, and library order. The manifest selects a recipe and supplies source/output locations and connection defaults; it does not duplicate recipe flags or upload file lists. `build/profiles/vc71.json` records the shared environment and pinned tool versions. The workbench renders disposable `aimcmp-build.cmd` files, including for checkpoints and source variants. Checkpoints freeze the recipe and profile alongside source. Legacy batch-script checkpoints use the current declarative recipe with their saved flag override; their archived scripts remain historical evidence.

Both launchers share one source: rebuild both after edits. Their reproducing recipe uses `/O2 /Oi /Zl`, with linker settings and exact library order recorded in `build/recipes/launchers.json` and [launcher evidence](.local/docs/aimcmp/launcher-assessment.md).

## 3. Keep identities, types, and findings in a ledger

```powershell
python -m aimcmp mapping show ../targets/mappings/idlemon.json
python -m aimcmp mapping resolve ../targets/mappings/idlemon.json ../originals/AIM/idlemon.dll ../targets/builds/idlemon/idlemon.dll --map ../targets/builds/idlemon/idlemon.map
```

Ledgers bind original addresses to an original SHA-256. Permanent IDs survive name changes and rebuilt address movement. Rebuilt symbols resolve from MAP files or exports on each build. Prefer symbols; an explicit rebuilt address must be pinned to an artifact SHA and becomes stale after any artifact change.

For a new target, substitute its actual file, addresses, and symbols:

```powershell
python -m aimcmp mapping init ../targets/mappings/example.json ../originals/AIM/example.dll
python -m aimcmp mapping set ../targets/mappings/example.json example.function.timer --kind function --original 0x10001000 --name ReadTimer --rebuilt-symbol ReadTimer --type "unsigned long ReadTimer(void)" --confidence supported --evidence "Timer subtraction observed in original assembly"
python -m aimcmp mapping type ../targets/mappings/example.json "typedef struct AIM_POINT { long x; long y; } AIM_POINT;"
```

Use `--kind global` for data. Confidence is `hypothesis`, `supported`, or `verified`, recording our judgment. Repeated `--evidence` appends notes. Keep the ID when refining a name/type. `--unpaired` removes the explicit rebuilt selector while retaining original-side knowledge.

Analysis applies annotations to owned views. Invalid types, ambiguous symbols, duplicate pairings, and incorrect function starts fail explicitly. Annotation edits select separate cache entries and appear separately in deltas; raw-byte equality remains independent. See [ledger details](.local/docs/aimcmp/mapping-ledger.md).

## 4. Save, compare, and restore checkpoints

```powershell
python -m aimcmp checkpoint save ../targets/project.json SendFile my-next-attempt --cache ../targets/reports/cache --require-exact
python -m aimcmp checkpoint list ../targets/project.json SendFile
python -m aimcmp checkpoint compare ../targets/project.json SendFile matched-o2 o1-comparison --format json
python -m aimcmp checkpoint restore ../targets/project.json SendFile matched-o2
```

Choose fresh names: `matched-o2` and `o1-comparison` already exist and cannot be overwritten. Save freezes configured sources and the ledger before an isolated VM build, then records artifacts, reports, flags, tool versions/hashes, and a checked inventory. Completed mismatches can be saved for comparison; failed checkpoints retain diagnostics but cannot be restored or compared.

Compare verifies saved evidence offline. Restore checks integrity and original identity, makes a `before-restore-<time>-<id>` backup, then restores local files and the selected target recipe. Other target recipes and the current SHA-verified original path are retained. Restore performs no remote build; run `iterate` afterward and rebuild targets sharing the restored source.

Automatic backups preserve working edits and missing files without claiming the sources and binaries were built together. They can be restored by name. Restore attempts rollback on write failure. Tool inventory does not archive the entire SDK; restore does not install or switch compilers. See [checkpoint guide](.local/docs/aimcmp/checkpoint-guide.md).

## 5. Compile and rank source variants

```powershell
python -m aimcmp variants run ../targets/project.json SendFile examples/variants/launcher.json my-next-matrix --cache ../targets/reports/cache
python -m aimcmp variants promote ../targets/project.json SendFile launcher-matrix-final v0000 --require-exact
```

Use a fresh run name. The example combines initialization position, pointer-assignment shape, and compiler flags. Templates use markers such as `{{body}}`; axes supply named literal fragments or flag choices. The Cartesian product is rendered before upload. A flag choice replaces the entire configured flag string.

The runner freezes inputs, uploads one archive, builds variants in isolated VM directories, and retrieves one artifact archive. `batch_archive_tool` configures the VM's 7z path. Evidence under `targets/experiments/runs/<target>/<run>/` includes sources, logs, artifacts, tool inventory, and ranked `run.json`. Each variant gets a checkpoint named `<run>-v0000`, etc.

Individual compile failures retain evidence while the batch continues. Exit 1 means some compile/analysis or transport stage failed, even when other variants succeeded. A completed code mismatch alone does not fail the run. Ranking separates file equality except timestamps, raw code equality, normalized coverage, and exact function count.

Promotion is explicit. It checks inventories, report/artifact hashes, and an independent raw-code comparison, then restores with an automatic backup. `--require-exact` rejects mismatching code before changing active files. Rebuild both launchers afterward.

The final saved matrix found two ordinary-source variants with exact code (`v0000`, `v0002`). Compiled evidence cannot distinguish their source forms; we chose the simpler form. See [specification and runner details](.local/docs/aimcmp/variant-runner.md).

## 6. Ask Binary Ninja focused questions

```powershell
python -m aimcmp query-target ../targets/project.json idlemon IdleSetEvent --fields hlil,callers,types --cache ../targets/reports/cache
python -m aimcmp query-target ../targets/project.json idlemon idlemon.function.IdleSetEvent --fields assembly,references --format json
python -m aimcmp query-target ../targets/project.json idlemon last_input --kind data --format json
python -m aimcmp query-target ../targets/project.json SendFile WinMain --side rebuilt --fields assembly,types --limit 20
```

Select a virtual address, unique symbol, `entry`, or ledger ID. Function selectors must resolve to analyzed starts. Original is the default side; rebuilt queries use the configured MAP file. Function fields are `assembly`, `hlil`, `callers`, `references`, and `types`. Data queries support references/types with a bounded byte preview. `--limit` bounds each list and exposes truncation; `--output` saves the selected text/JSON.

For an unconfigured binary, use `python -m aimcmp query <binary> <selector>`, with optional `--map`/`--mapping`. Query JSON is schema 1, kind `aimcmp.query`. Partial errors are visible, return nonzero, and are not cached. Cache identity includes binary, analysis version, annotations, fields, and limits. Binary Ninja may analyze the image internally even though only focused evidence is exported. See [query details](.local/docs/aimcmp/focused-queries.md).

## Daily workflow and validation

Read the compact report, query the specific mismatch, update source and ledger evidence, and run `iterate`. Save a checkpoint before a substantial hypothesis; use variants for a bounded set of plausible shapes. Promote explicitly and rebuild related targets.

For another module, add its immutable original, sources, artifacts/MAP paths, and ledger to `targets/project.json`, with a declarative build recipe under `build/recipes/`. Paths resolve relative to the project file. The configured `workspace_root` permits checkpoint source files under the repository, including sibling `src/` directories; older checkpoints restore sources into their current configured directory. List every source/resource/definition/build file needed for upload and checkpoint reproducibility.

```powershell
python -m unittest discover -s tests -v
```

There are 75 passing tests, including project/source relocation and private configuration writeback. Some use local originals and built fixtures, which Git excludes; populate originals and build the three current targets before running them in a fresh checkout.

The six-item milestone is complete. [TODO](.local/docs/aimcmp/TODO.md) retains three deferred convenience ideas as future backlog.
