# esesätsch — logo assets

A drop-in `sshd` alternative written in Rust. The mark is a rust-orange `>_`
shell prompt on a dark badge, with a small cog (a "daemon" wink that also nods
to Rust's gear).

## Files
- `esesaetsch-icon.svg`        — color app icon, vector (source of truth)
- `esesaetsch-icon-mono.svg`   — single-color icon (uses `currentColor`; set via CSS `color:`)
- `esesaetsch-wordmark.svg`    — horizontal lockup (badge + wordmark + tagline)
- `esesaetsch-icon-512.png`    — 512px app icon
- `esesaetsch-icon-192.png`    — 192px (PWA / Android maskable-safe area)
- `esesaetsch-icon-48.png`     — 48px
- `esesaetsch-icon-16.png`     — 16px (simplified: prompt only)
- `esesaetsch-icon-mono-black-512.png` / `...-white-512.png` — flat stamps
- `favicon.ico`                — multi-size (16 / 32 / 48), gear dropped for legibility

## Palette
- Badge      `#241A16`
- Prompt     `#D26B3F`   (border `#C95E33`)
- Cursor/cog `#E89352`

Note: the wordmark SVG references a monospace font stack and a serif-free sans
stack; if you rasterize it on a machine without those fonts, install a mono
font (e.g. DejaVu Sans Mono) or convert the text to outlines first.
