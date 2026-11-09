# Branding

Jolt's identity is a folder outline charged with a lightning bolt: files that
move fast between nodes you control. The artwork lives in [`assets/`](assets);
this page says which file to use where and how the Control Tower applies it.

## Logo

| File | Use |
| --- | --- |
| `jolt-primary.svg` / `.png` | App icon, avatars. Gradient mark with glow on ink. |
| `jolt-transparent.svg` | Mark with glow on any dark surface. |
| `jolt-neon.svg` / `.png` | Mark with the folder lit up, tuned to read at icon sizes. |
| `jolt-monochrome.svg` | Mark without glow, for small sizes and print. |
| `jolt-light.svg` | Ink mark on Jolt yellow, for light contexts. |
| `jolt-horizontal.svg` / `-light.svg` | Lockup with the wordmark (README, slides). |
| `favicon*.png`, `favicon.ico` | Browser and touch icons. |

In the frontend, use `JoltMark` and `JoltLogo` from
`control/frontend/src/components/brand/JoltLogo.tsx` rather than an `<img>`:
they are inline SVG, so they stay sharp and need no extra request under the
Control Tower's `default-src 'self'` CSP. `tone="mono"` follows `currentColor`.
`glow` adds the artwork's soft halo, which only reads at hero sizes;
`glow="neon"` is the icon-size variant (≤48px) used in the sidebar, where the
folder outline itself glows and the halo may spill past the mark's box.

Keep clear space of at least the bolt's width around the mark. Do not recolor
the gradient, rotate the mark, or set the wordmark in another typeface.

## Color

| Token | Value | Role |
| --- | --- | --- |
| `--brand` | `#FACC15` Jolt yellow | Primary actions, focus ring, active navigation |
| `--brand-ember` | `#F97316` ember | Gradient end; never a standalone action color |
| `--brand-ink` | `#0B0B0B` ink | Logo backgrounds, darkest surface |
| `--brand-gradient` | yellow → ember, 135° | The mark, hero highlights, avatars |

Neutrals carry a faint warm tint (hue 85) so grays sit next to yellow without
looking blue. Status colors are semantic tokens, never raw Tailwind palette
classes:

| Token | Meaning |
| --- | --- |
| `success` | Online, enabled, completed |
| `warning` | Degraded, needs attention, overwrite/rename |
| `info` | Approval pending, informational copy |
| `destructive` | Offline, failed, conflicts, irreversible actions |

`warning` leans orange (hue 55) so it reads apart from the yellow brand. Use
them as `text-warning`, `bg-warning/10 border-warning/40` for callouts, and the
`success`/`warning` `Badge` variants. Categorical colors (file types, transfer
directions) may keep palette classes since they encode kind, not status.

Charts use `chart-1` (yellow) through `chart-5` (violet): yellow, ember, teal,
sky, violet.

## Type

- **Inter** (variable) for UI text, matching the wordmark.
- **JetBrains Mono** (variable) for eyebrow labels, IDs, sizes and other
  machine values: `font-mono text-xs uppercase tracking-widest`.

Both are bundled through `@fontsource-variable/*`, so no font is loaded from a
third-party origin.

## Icons

Lucide is the base icon set. Jolt's own icons (`assets/icon-*.svg`) are
available as React components in `components/brand/icons.tsx` and are used for
the main navigation:

| Icon | Concept |
| --- | --- |
| `NetworkIcon` | Network overview |
| `TransferIcon` | Relationships between nodes |
| `JobsIcon` | Jobs |
| `VolumesIcon` | Nodes and their volumes |
| `FilesIcon` | Files |
| `TrustIcon` | Access policy |
| `AccessIcon` | Identity (users, service accounts) |
| `MonitoringIcon` | Health and metrics |
| `SettingsIcon` | Settings |

They default to a stroke matching lucide's weight, so both sets can share a
menu.

## Surfaces

- The app is dark-first (`<html class="dark">`); light tokens exist for
  surfaces that opt out.
- The sidebar is the darkest layer; content sits on a slightly lifted inset.
- Brand moments (login, public shares, network overview hero) use the
  `bg-brand-grid` blueprint pattern with a radial mask, plus the mark at low
  opacity. Keep them to entry points; operational screens stay quiet.
- `text-brand-gradient` is reserved for one phrase per screen at most.
