# FileSentinel

FileSentinel is the AEGIS local workspace at `/file/` for bounded file and binary triage. It starts with upload intake, hashes, a small set of header/format checks, report history and explicit coverage. It never executes, loads, imports, or installs an analyzed target.

## Current release

- Upload limit: 64 MiB per sample; one file per scan.
- SHA-256, SHA-1 and MD5 hashes; basic PE, ELF, Mach-O, ZIP, PDF and text identification.
- ZIP directory counters are bounded; member names and file strings are not sent to AI.
- Temporary raw input is deleted after analysis. SQLite retains only the display name and report metadata; use **Delete report** to remove a finished record.
- Configured Groq, OpenRouter and Gemini providers are reused through the APKTrust/RepoSentinel bridge. Automatic AI input is bounded metadata and numeric/boolean structure indicators, never raw bytes, paths, original filenames, archive names or sampled strings.
- The AI assessment is an opinion. It cannot declare a file safe and does not replace static evidence.
- A namespace-enabled Linux host uses a no-network Bubblewrap worker and reports `BWRAP`. If unprivileged namespaces are unavailable, the worker applies process limits and reports `PROCESS_LIMITED`; this fallback does not guarantee network or host-file isolation.

Detect It Easy, LIEF, pefile, dnfile, rabin2, YARA-X, capa, FLOSS, Ghidra, Speakeasy, reputation services and disposable-VM execution are not integrated yet. Reports name these coverage gaps. No missing engine is treated as a clean result.

## Local data

`FILESENTINEL_DATA` may override the default `.data/filesentinel` directory. The application stores a SQLite report history there. Incoming files are created with restrictive permissions, are never served from the web root and are removed after the worker exits. If the app crashes mid-scan, abandoned temporary files older than 24 hours are cleaned on the next start.

See [AEGIS architecture](../README.md#local-storage-and-architecture) and the supplied `FILESENTINEL_ARCHITECTURE.md` design brief for future pipeline stages.

## Planned architecture stages

1. Add pinned, isolated format parsers and richer structure analysis while recording engine versions, statuses, resource budgets and provenance.
2. Add independent static signatures and bounded derived-artifact routing; every extracted object must keep its parent hash and transform record.
3. Add optional emulation only as a separate `EMULATED_BEHAVIOR` evidence tier with its own strict budget and coverage display.
4. Keep real target execution out of the normal app. Any future dynamic analysis belongs in a separate disposable-VM provider.
