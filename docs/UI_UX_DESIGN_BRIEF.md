# UI/UX Design Brief & Accessibility Guidelines (UI_UX_DESIGN_BRIEF.md) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Visual Identity & Design Philosophy

PhishGuard is designed as an operational Security Operations Center (SOC) tool. The design system emphasizes clarity, high data density, rapid scan-ability, and zero cognitive friction during high-stress incident triage.

#### Core Aesthetic Principles:
- **Tactical Dark-Mode Palette:** High-contrast slate backgrounds (`bg-slate-950`, `bg-slate-900`) designed to minimize eye strain during extended night shifts.
- **Color-Coded Tactical Severity:** Consistent semantic severity colors:
  - **Critical:** Rose (`rose-500`, `#f43f5e`, background `rose-950/80`)
  - **High:** Orange / Amber (`amber-500`, `#f59e0b`, background `amber-950/80`)
  - **Moderate:** Yellow / Indigo (`indigo-400`, `#818cf8`, background `indigo-950/80`)
  - **Low / Clean:** Emerald (`emerald-400`, `#34d399`, background `emerald-950/80`)
- **Dual Typography Strategy:**
  - **UI Shell & Narrative:** Modern, legible sans-serif (`Inter`, `system-ui`) for descriptions, instructions, and standard copy.
  - **Technical Evidentiary Data:** Monospace (`JetBrains Mono`, `ui-monospace`) for RFC headers, IP addresses, domains, hashes, and formula calculations.

---

### 2. WCAG 2.2 AA Accessibility Compliance

PhishGuard targets full compliance with the Web Content Accessibility Guidelines (WCAG) 2.2 Level AA requirements:

1. **Color Contrast Ratios:**
   - All body text and telemetry labels achieve a minimum contrast ratio of **7.2:1** against their immediate background (exceeding the 4.5:1 requirement).
   - High-priority alert badges achieve at least **5.1:1** contrast against dark panel backdrops.
2. **Keyboard Navigation & Focus Management:**
   - All interactive controls (buttons, tabs, inputs, modal triggers) possess distinct visible focus indicators (`focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500`).
   - Modals trap focus during active inspection and can be dismissed via the `Escape` key.
3. **Semantic HTML & Screen-Reader Support:**
   - Structural elements use semantic tags (`<header>`, `<main>`, `<footer>`, `<nav>`, `<section>`, `<table>`).
   - Icon-only action buttons (e.g. copy hash, close modal) include accessible `title` attributes and `aria-label` fallbacks.
4. **Motion Minimization:**
   - Transitions and animations utilize `transition-all duration-200` with subtle opacity fades (`animate-in fade-in`), avoiding rapid blinking or disruptive motion triggers.

---

### 3. Component Design Specifications

#### 3.1 Top Navigation Bar (`Navbar.tsx`)
- Sticky header (`sticky top-0 z-40`) with 95% opacity backdrop blur (`bg-slate-950/95 backdrop-blur`).
- Live Loopback Engine Status indicator pill:
  - Green pulse with checkmark when FastAPI engine is reachable.
  - Amber warning icon with "Offline / API Standby" when backend loopback is unreachable.
- Responsive horizontal navigation tabs with active indicator highlight and subtle hover state transitions.

#### 3.2 Risk Score Gauge (`ScoreGauge.tsx`)
- Prominent radial numerical score display ($0.0 - 100.0$).
- Color shifts dynamically based on evaluated severity tier.
- Includes quick-action "How Score Was Computed" trigger opening the mathematical breakdown modal.

#### 3.3 Score Explainer Modal (`ScoreExplainerModal.tsx`)
- Renders an interactive mathematical audit of the asymptotic diminishing returns formula:
  $$S_c = \text{Cap}_c \times \left[ 1 - \prod_{r} \left( 1 - \frac{W_r \times \text{Conf}_r}{\text{Cap}_c + 15} \right) \right]$$
- Displays a tabular breakdown showing: Category Name, Rules Triggered, Raw Heuristic Sum, Category Cap, and Effective Diminishing Score Contribution.
- Emphasizes the **Corroboration Safeguard** notice explaining why isolated heuristics cannot trigger Critical scores.

#### 3.4 Chronological Hop Visualizer (`RoutingHopsVisualizer.tsx`)
- Vertical timeline displaying MTAs in sequence from Originating Relay (Hop #1) to Destination Server.
- Color-coded badges distinguishing RFC 1918 Private IPs from Public Routable IPs.
- Clock icons and latency tags highlighting transit delays and negative clock skews.

#### 3.5 Authentication Claims Badge (`AuthClaimsBadge.tsx`)
- Three-card grid for SPF, DKIM, and DMARC claims.
- Prominent warning banner: `"Unverified Header Claim — Preserved for Forensic Context Only"`.

---

### 4. Responsive Breakpoint Matrix

| Breakpoint | Target Screen | Layout Adaptations |
| :--- | :--- | :--- |
| `< 640px` (sm) | Mobile triage | Single-column stacked layouts, horizontal scrolling tables with touch support, condensed navbar brand. |
| `640px - 1024px` (md) | Tablets & laptops | Two-column grid layouts for metadata cards, sticky filter toolbars, collapsible secondary sidebars. |
| `> 1024px` (lg) | Multi-monitor SOC consoles | Full side-by-side split screens (5-col cases feed / 7-col case detail drawer; 4-col score gauge / 5-col metadata / 3-col action bar). |

