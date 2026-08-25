# Mega Drive cartridge header reference

This document is the working reference behind the `rom_info` tool. It encodes
the Sega Mega Drive / Genesis cartridge layout, the header checksum, and the
memory mapping, with the public technical documents it was derived from. The
tool itself reads the header through the M68K bus at cart offset `0x100` and
never re-implements emulator logic.

## Header layout

The cartridge ROM starts at `0x000000` in the 68K address space. The first
`0x200` bytes hold the exception vector table (`0x000-0x0FF`) and the
ID table / header (`0x100-0x1FF`). All strings are space-padded ASCII, all
multi-byte values are **big-endian**.

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0x100 | 16 | System type | `SEGA MEGA DRIVE`, `SEGA GENESIS`, `SEGA 32X`, ...; must start with `SEGA` for TMSS-era hardware |
| 0x110 | 16 | Copyright | `(C)XXXX YYYY.MMM` (company code, year, month) |
| 0x120 | 48 | Domestic title | padded |
| 0x150 | 48 | Overseas title | padded |
| 0x180 | 14 | Serial | `GM XXXXXXX-XX` (type 2 + catalog + version) |
| 0x18E | 2 | Checksum | stored Sega checksum |
| 0x190 | 16 | I/O support | one char per supported device, padded |
| 0x1A0 | 4 | ROM start address | big-endian |
| 0x1A4 | 4 | ROM end address | last byte address of the ROM (size − 1) |
| 0x1A8 | 4 | RAM start address | typically `0xFF0000` |
| 0x1AC | 4 | RAM end address | typically `0xFFFFFF` |
| 0x1B0 | 12 | Backup RAM | `"RA"` + backup flag byte + access byte + start + end (see below) |
| 0x1BC | 12 | Modem support | trimmed |
| 0x1C8 | 40 | Memo | trimmed |
| 0x1F0 | 3 | Region | country letters or a hardware code byte |

### I/O support codes

| Code | Device | Code | Device |
| --- | --- | --- | --- |
| J | Joypad (3-button) | P | Printer |
| 6 | 6-button joypad | T | Tablet |
| 4 | Team Play | B | Control ball |
| 0 | Joystick (Master System) | V | Paddle |
| K | Keyboard | F | Floppy disk drive |
| R | Serial RS232C | C | CD-ROM |
| L | Activator | M | Mega mouse |

### Backup RAM block (0x1B0)

The 12-byte block is `"RA"` (0x1B0-0x1B1), a backup flag byte (0x1B2, bit 7
set = battery-backed), an access byte (0x1B3), and the SRAM start (0x1B4) and
end (0x1B8) longs. The two low bits of the access byte encode which data-bus
bytes reach the SRAM: `00` both (word), `10` even addresses only, `11` odd
addresses only; `01` is reserved. Emulators historically disagree about this
field, so `rom_info` describes it as advisory.

### Serial, product, and region decoding

- Product type prefixes (2 chars at 0x180): `GM` = Game, `AI` = Education;
  third-party and first-party product codes follow the `T-…` / `MK-…` /
  `G-…` formats (see Sega Retro's product-code notes).
- Region letters (0x1F0): `J` Japan, `U` USA/Canada, `E` Europe. A single
  hex-digit byte is the newer hardware-code style from the *Sega Genesis
  Technical Bulletin* ID table (0 Japan NTSC, 1 Japan PAL, 2 Overseas NTSC,
  4 Overseas NTSC/US, 6 Overseas PAL, 8 Overseas PAL/EU, F common).

## Checksum

The cartridge checksum is a plain additive sum of big-endian **words** from
address `0x200` through the end of the ROM, keeping only the low 16 bits. A
trailing odd byte (for a ROM whose `0x200`-relative length is odd) is treated
as the high byte of the final word.

```text
sum = 0
for each 16-bit word w in [0x200, len(ROM)):
    sum = (sum + w) & 0xFFFF
if last byte of the range is odd:
    sum = (sum + (byte << 8)) & 0xFFFF
```

The licensed-game verification routine reads the stored value at `0x18E` and
the ROM end address from `0x1A4`; `rom_info` clamps the computed range to the
loaded ROM file size so a broken/generic header cannot extend the read.

## 68K memory mapping

Reference layout (as shipped with the Mega Drive, no add-ons):

| Start | End | Description |
| --- | --- | --- |
| 0x000000 | 0x3FFFFF | Cartridge ROM/RAM window (SRAM commonly in 0x200000+) |
| 0x400000 | 0x7FFFFF | Reserved (Mega-CD / 32X) |
| 0xA00000 | 0xA0FFFF | Z80 address space window |
| 0xA10000 | 0xA10FFF | I/O registers (controllers, version register at 0xA10001) |
| 0xA11000 | 0xA11FFF | Z80 control (bus request 0xA11100, reset 0xA11200) |
| 0xA13000 | 0xA130FF | Cartridge / TIME registers (SRAM access 0xA130F1, bank registers through 0xA130FF) |
| 0xA14000 | 0xA14003 | TMSS security register |
| 0xC00000 | 0xDFFFFF | VDP ports (data 0xC00000, control 0xC00004, HV counter 0xC00008) |
| 0xFF0000 | 0xFFFFFF | 68000 work RAM (mirrored every 0x10000) |

## Sources

- Plutiedev — Mega Drive ROM header reference: <https://plutiedev.com/rom-header>
- genesis-rom.txt (Felipe XnaK / Volker Oth): <https://github.com/franckverrot/EmulationResources/blob/master/consoles/megadrive/genesis_rom.txt>
- Sega Genesis ROM cartridge data (patpend): <https://patpend.net/technical/genesis/genrom.html>
- Wikibooks — Genesis Programming (header, checksum routine, 68K memory map): <https://en.wikibooks.org/wiki/Genesis_Programming/68000_programming_considerations>
- Sega Retro — Mega Drive memory map: <https://segaretro.org/Sega_Mega_Drive/Memory_map>
- MegaDrive development wiki — main 68K memory map: <https://wiki.megadrive.org/index.php?title=Main_68k_memory_map>
- Sega Genesis Technical Bulletin (ID table, region/hardware codes, PDF): <https://segaretro.org/images/2/27/GenesisTechnicalBulletins.pdf>
- Sega Retro — region / product-code formats: <https://segaretro.org/Region_codes>
- RetroShock — product-number decoding (MK-/T-/G- prefixes): <http://retroshock.bplaced.net/mdg.html>
- gumshoe (Rust) — Sega checksum reference incl. odd-length tails: <https://docs.rs/crate/gumshoe/latest/source/src/headerck/sega/mod.rs>
- SpritesMind — SRAM/backup-RAM header discussion: <http://gendev.spritesmind.net/forum/viewtopic.php?t=2281>

Cross-check oracle inside the repo: `vendor/exodus/Extensions/MDExtensions/MegaDriveROMLoader.cpp`
(`ReadROMModuleHeader`, `AutoDetectRegionCode`). The MCP parser stays
server-side and independent of the fork so the upstream dependency stays
clean.
