# Rule: Component Theme & Color Adaptation for SIH 26153

**Core Directive:**
Always adjust **ONLY the color palette** (backgrounds, surfaces, borders, text colors, accent/highlights, glows) to match our UI palette.
**Do NOT change the rest of the component** (its structure, layout, geometry, sizing, animations, or styling) if it is already compatible.

### Target Color Palette:
- **Canvas / App Background**: `#000001` (Void Black)
- **Primary Surfaces / Cards**: `#080808`
- **Elevated / Popovers / Modals**: `#111111` or `#121214`
- **Hover / Active Surfaces**: `#181818`
- **Structural Borders**: `#27272A` (or `#262626`)
- **Active / Focused Borders**: `#3F3F46` or `#F0C808`
- **Primary Accent / Active Highlights**: `#F0C808` (Signal Gold) / Hover: `#FFE14C`
- **Primary Text**: `#FFFFFF`
- **Secondary Text**: `#C6C6C6` / `#A1A1AA`
- **Muted / Metadata Text**: `#71717A`
- **Critical / Danger**: `#FF304F` / `#EF4444`
- **Nominal / Success**: `#22C55E` / `#10B981`

Keep all animations, shapes, rounded radius, layout hierarchy, and functionality exactly as provided by the user unless an import or syntax fix is strictly required for React 19 / Vite compatibility.
