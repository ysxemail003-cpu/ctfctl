# Kali Tool Routing

Use this as the default expert routing table. Every substantive command still goes through `ctfctl run` or a structured adapter. Prefer the smallest tool that answers the next question.

## Structured adapter coverage (implemented as of v0.5.0-dev)

Rows marked `ctfctl tool X` return a stable JSON summary and are logged/hashed/budgeted by the runner. Everything else below is routing guidance executed through `ctfctl run`.

| Tool / action | Adapter | Category | Notes |
|---|---|---|---|
| `file`, `sha256sum`, `strings` | `ctfctl tool file` | misc | + ELF branch |
| `checksec`, ELF header facts | `ctfctl tool elf` | pwn/rev | |
| Ghidra headless | `ctfctl tool ghidra` | rev | cached; slow |
| HTTP request / session / redirects | `ctfctl tool http` / `http-session` | web | scope-checked, redacted |
| web inventory (root/robots/sitemap/forms/links) | `ctfctl tool web-inventory` | web | |
| `nmap` (explicit ports, XML) | `ctfctl tool nmap` | web/recon | usage-ledgered |
| archive import with provenance | `ctfctl import-files` | misc | immutable copy to `original/` |
| hash identification | `ctfctl tool hashid` | crypto | local heuristic + `hashid` |
| local hash cracking (`john`/`hashcat`) | `ctfctl tool crack` | crypto | wordlist required; local files only |
| `exiftool` metadata | `ctfctl tool exif` | forensics | read-only |
| `binwalk` scan / explicit extract | `ctfctl tool binwalk` | forensics | extract lands in `work/extracted/` |
| `7z` archive listing | `ctfctl tool archive` | forensics | read-only |
| `zsteg` stego detection | `ctfctl tool zsteg` | forensics | tool crash reported as status=error |
| `capinfos` + `tshark` pcap summary | `ctfctl tool pcap` | forensics | |
| `ffuf` fuzzing | `ctfctl tool ffuf` | web | FUZZ position required; requests budgeted before run |
| `sqlmap` read-only audit | `ctfctl tool sqlmap` | web | evidence-gated (`--evidence`/`--force`); level≤3 risk≤2 |
| `ROPgadget` | `ctfctl tool rop` | pwn/rev | filtered by `--only`; capped gadget list |
| `readelf --dyn-syms` imports | `ctfctl tool imports` | pwn/rev | UND symbols with versions |

## Universal file intake

| Situation | First tools |
|---|---|
| Any file | `ctfctl tool file` |
| Archive | `7z l`, then extract into `work/` |
| ELF | `ctfctl tool elf` |
| Unknown binary/rev | `strings`, `readelf`, `objdump`, `nm`, `ldd` |
| Image | `exiftool`, `binwalk`, `zsteg` when installed |
| PCAP | `capinfos`, `tshark` |
| Disk/memory | `file`, `binwalk`, `fls`, `volatility3` when installed |

## Web

| Question | Tool |
|---|---|
| Routes/forms/robots/sitemap | `ctfctl tool web-inventory` |
| Exact request/response | `ctfctl tool http` |
| Service/version | `ctfctl tool nmap` with explicit authorized ports |
| JavaScript/interaction | Browser/Playwright |
| Intercept/repeater workflow | Burp Suite |
| Targeted missing content | `ffuf` |
| Confirmed SQLi automation | `sqlmap`, only after manual evidence |

Do not run broad scans by default. Establish a baseline and diff minimal requests first.

## Pwn

| Stage | Tools |
|---|---|
| Binary facts | `ctfctl tool elf` |
| Static logic | Ghidra, `objdump`, `readelf`, `nm` |
| Dynamic behavior | GDB through `ctfctl tty`, `ltrace`, `strace` |
| Offset | Pwntools `cyclic`, GDB registers |
| ROP | `ROPgadget`, `ropper`, libc symbols |
| Exploit | Pwntools script in `scripts/` |
| Sandbox | `seccomp-tools`, syscall tracing |

Remote exploitation is allowed only after local reproduction and explicit target/port scope.

## Reverse

| Goal | Tools |
|---|---|
| Full decompilation | `ctfctl tool ghidra` |
| Fast disassembly | `r2`, `objdump` |
| Symbols/imports | `readelf`, `nm` |
| Dynamic calls | `ltrace`, `strace`, GDB |
| Patch/test | Copy to `work/`, use reversible patches |
| Embedded data | `strings`, `binwalk`, custom parsers |

## Forensics

| Artifact | Tools |
|---|---|
| PCAP | `tshark`, `capinfos`, `tcpdump`, `foremost` |
| Files/carving | `binwalk`, `foremost`, `7z` |
| Metadata | `exiftool` |
| Memory | `volatility3` when installed |
| Logs | `grep`, `jq`, custom parsers |

## Crypto

| Situation | Tools |
|---|---|
| Hash format | `hashid`, `hashcat --show`, documentation |
| Password hash | `john`, `hashcat` |
| RSA/math | Python/sage when available, custom scripts |
| TLS/certs | `openssl`, custom parsing |
| Classical crypto | targeted Python scripts |

Always preserve the original hash/ciphertext and record assumptions separately from facts.
