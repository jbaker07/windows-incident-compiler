# Mission Page Reality Report

**Generated:** 2026-01-27  
**BUILD_VERSION:** `2026-01-27-REALITY_REPORT-1`

This document provides the authoritative DOM structure and verification mechanism for the Mission tab layout.

---

## 1) DOM TREE MAP (as rendered)

### Hierarchy

```
<body>
├── #uiBuildBadge                          (line 755)
├── <header class="app-container">         (line 768)
├── <nav class="app-container">            (line 801)
└── <main class="app-container mission-wide">  (line 816) ← mission-wide toggled by JS
    └── #tabMission                        (line 819)
        └── .mission-inner                 (line 809) ← centered wrapper, max-width clamp
            └── .mission-grid              (line 810) ← CSS Grid: 2 columns
                ├── .card (left column)    (line 812) ← ANONYMOUS, no id/class wrapper
                │   ├── Step ① Path of Work
                │   ├── Step ② Playbook Selection
                │   ├── Run Duration
                │   └── #missionError
                │
                └── #missionDock           (line 936) ← RIGHT column (aside)
                    ├── .card (Run Plan)   (line 939)
                    │   └── #runPlanSummary
                    ├── .card (Start CTA)  (line 958)
                    │   ├── #btnStartRun
                    │   └── #btnStopRun
                    ├── #outcomePreviewCard (line 972) ← INSIDE DOCK
                    ├── #dockReadinessCard (line 1000)
                    ├── #missionReadinessWarning (line 1020)
                    ├── #dockLivePanels    (line 1033)
                    └── #missionHint       (line 1086)
```

### Exact Selectors (copy-paste ready)

| Element               | Selector                                      | Line Range |
|-----------------------|-----------------------------------------------|------------|
| **Main container**    | `main.app-container`                          | 816        |
| **Mission tab**       | `#tabMission`                                 | 819        |
| **Inner wrapper**     | `#tabMission .mission-inner`                  | 809        |
| **Grid**              | `#tabMission .mission-grid`                   | 810        |
| **Left column card**  | `#tabMission .mission-grid > .card`           | 812        |
| **Right dock**        | `#missionDock`                                | 936        |
| **Run Plan Summary**  | `#runPlanSummary`                             | 940        |
| **Start Button**      | `#btnStartRun`                                | 965        |
| **Stop Button**       | `#btnStopRun`                                 | 968        |
| **Outcome Preview**   | `#outcomePreviewCard`                         | 972        |
| **Readiness Card**    | `#dockReadinessCard`                          | 1000       |
| **Live Panels**       | `#dockLivePanels`                             | 1033       |

### Key CSS Rules (index.html)

```css
/* Line 59: Base constraint */
.app-container {
  max-width: 1140px;
  margin: 0 auto;
  padding: 0 24px;
}

/* Line 66: Mission override (toggled by JS) */
main.app-container.mission-wide {
  max-width: none !important;
  width: 100% !important;
}

/* Line 76: Inner wrapper for centered content */
#tabMission .mission-inner {
  width: min(clamp(1200px, 92vw, 1600px), calc(100vw - 48px));
  margin: 0 auto;
}

/* Line 810 (inline style): Grid definition */
.mission-grid {
  display: grid;
  grid-template-columns: 1fr clamp(280px, 26vw, 360px);
  gap: 20px;
  align-items: start;
}
```

---

## 2) VISUAL LAYOUT MAP (Computed Styles)

These are the **runtime** values when Mission tab is active. Run `debugMissionSnapshot()` to verify.

### Expected Values at 1920px viewport

| Element          | display | position | width       | max-width | grid-column | rect.x  | rect.y |
|------------------|---------|----------|-------------|-----------|-------------|---------|--------|
| main             | block   | static   | 1920px      | none      | N/A         | 0       | ~100   |
| #tabMission      | block   | static   | 1824px      | none      | N/A         | 24      | ~100   |
| .mission-inner   | block   | static   | 1600px      | none      | N/A         | ~160    | ~100   |
| .mission-grid    | grid    | static   | 1600px      | none      | N/A         | ~160    | ~100   |
| left .card       | block   | static   | ~1200px     | none      | auto        | ~160    | ~100   |
| #missionDock     | flex    | sticky   | ~360px      | none      | auto        | **~1240** | ~100 |
| #outcomePreviewCard | block | static  | 100%        | none      | N/A         | **~1240** | ~300 |

### Layout Verification Bullets

1. **Two-column layout works IF:** `.mission-grid` has `display: grid` AND `grid-template-columns` is applied.
2. **Dock is in right column IF:** `#missionDock.rect.x > leftCard.rect.x` (dock is positioned to the right).
3. **Stacking happens IF:** viewport < ~600px OR `grid-template-columns` is overridden/not applied.
4. **Zero-width dock IF:** dock is `display: none`, has `width: 0`, or is cut off by overflow.
5. **Outcome Preview appears "below Start" IF:** it's inside `#missionDock` in DOM but dock itself is stacked below left column.

---

## 3) DEBUG SNAPSHOT FUNCTION

This function is now available globally. Run in DevTools console:

```js
debugMissionSnapshot()
```

### What it does:

1. Logs BUILD_VERSION
2. Creates a table with computed styles + bounding rects for all key elements
3. Runs 5 assertions:
   - ✅ Outcome Preview is descendant of #missionDock
   - ✅ Dock is visually to the right of left column (rect.x comparison)
   - ✅ mission-grid has display: grid
   - ✅ main.app-container has .mission-wide class
   - ✅ Dock has non-zero width
4. Returns structured data for programmatic use

### Sample Output:

```
=== MISSION PAGE REALITY REPORT ===
[BUILD] 2026-01-27-REALITY_REPORT-1

┌────────────┬────────────────────────┬─────────┬──────────┬────────┬──────────┬────────────┐
│  (index)   │       selector         │ display │ position │ width  │ maxWidth │   rect     │
├────────────┼────────────────────────┼─────────┼──────────┼────────┼──────────┼────────────┤
│    main    │ '.app-container'       │ 'block' │ 'static' │'1920px'│  'none'  │ {x:0,...}  │
│    tab     │ '#tabMission'          │ 'block' │ 'static' │'1824px'│  'none'  │ {x:24,...} │
│   inner    │ '.mission-inner'       │ 'block' │ 'static' │'1600px'│  'none'  │ {x:160,...}│
│    grid    │ '.mission-grid'        │ 'grid'  │ 'static' │'1600px'│  'none'  │ {x:160,...}│
│  leftCard  │ '.card'                │ 'block' │ 'static' │'1200px'│  'none'  │ {x:160,...}│
│    dock    │ '#missionDock'         │ 'flex'  │ 'sticky' │'360px' │  'none'  │ {x:1380,...}│
│  outcome   │ '#outcomePreviewCard'  │ 'block' │ 'static' │'332px' │  'none'  │ {x:1394,...}│
└────────────┴────────────────────────┴─────────┴──────────┴────────┴──────────┴────────────┘

=== ASSERTIONS ===
✅ Outcome Preview is descendant of #missionDock: PASS
✅ Dock is visually to the right of left column: PASS: dock.x=1380, left.x=160
✅ mission-grid has display: grid: PASS
✅ main.app-container has .mission-wide class: PASS
✅ Dock has non-zero width: PASS: width=360px

🎉 ALL ASSERTIONS PASSED
```

---

## 4) ROOT CAUSE DIAGNOSIS TREE

If visual appearance doesn't match "DOM is correct", use this flowchart:

### Problem: Outcome Preview appears in LEFT column / below left content

```
Q1: Does debugMissionSnapshot() show `outcome.parent = #missionDock`?
    ├── NO → DOM structure is wrong. Check index.html line 972.
    └── YES → Continue to Q2

Q2: Does assertion "Dock is visually to the right" PASS?
    ├── YES → Layout IS correct. You're misreading the screen. Check x-coords.
    └── NO → Grid is not working. Continue to Q3.

Q3: What is `grid.display`?
    ├── "grid" → Continue to Q4
    └── NOT "grid" → CSS not applied. Check:
        - Is .mission-grid selector correct?
        - Is display overridden by another rule? (DevTools Elements → Computed)

Q4: Does main have .mission-wide class?
    ├── YES → Continue to Q5
    └── NO → switchTab('mission') didn't run or JS error. Check:
        - Console for errors
        - Is this tab actually Mission? (check #tabMission visibility)

Q5: Is viewport width very narrow (<700px)?
    ├── YES → Grid may be stacking due to clamp() not leaving space.
        - Widen window or check grid-template-columns responsive behavior.
    └── NO → Continue to Q6

Q6: Is dock.rect.w > 0?
    ├── YES → Check dock.rect.x vs leftCard.rect.x
        - If dock.x > left.x → IT IS on the right. Trust the numbers.
        - If dock.x ≈ left.x → Columns are overlapping. Z-index or position issue.
    └── NO → Dock is zero-width. Check:
        - overflow: hidden on parent cutting it off
        - width: 0 or display: none on #missionDock
        - flex-shrink causing collapse

Q7: Is there a DUPLICATE outcome preview?
    - Run: document.querySelectorAll('[id="outcomePreviewCard"]').length
    - If > 1 → Duplicate IDs. Find and remove extra.
```

### Common Failure Modes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Dock below left column | Grid stacking at narrow width | Widen viewport or adjust `grid-template-columns` |
| Outcome in wrong place visually | You're looking at wrong card OR old cache | Run `debugMissionSnapshot()` and check `outcome.parent` |
| Everything constrained to 1140px | `.mission-wide` class not applied | Check switchTab() JS, ensure Mission tab is active |
| Dock exists but 0 width | `overflow: hidden` or `flex-shrink` | Check computed styles on dock and parents |

---

## 5) HARD RULE GOING FORWARD

### Rule 1: Verify with debugMissionSnapshot()

Every Mission layout change MUST be validated by:

```js
// In DevTools console after change:
debugMissionSnapshot()
```

**Acceptable result:** All 5 assertions pass.

### Rule 2: Build badge is single source of truth

- **JS constant:** `BUILD_VERSION` at [app.js line 62](app.js#L62)
- **HTML badge:** `#uiBuildBadge` at [index.html line 755](index.html#L755)

Both MUST match. Console logs BUILD_VERSION at boot. If badge doesn't match console → cache issue.

### Rule 3: Trust computed rects, not visual inspection

When in doubt:
```js
const result = debugMissionSnapshot();
console.log('Dock X:', result.elements.dock.rect.x);
console.log('Left X:', result.elements.leftCard.rect.x);
console.log('Dock is right of left?', result.elements.dock.rect.x > result.elements.leftCard.rect.x);
```

If `dock.x > left.x`, the dock IS on the right regardless of what you think you see.

### Rule 4: Never accept "hard refresh" as root cause

Cache issues are diagnosed by:
1. Check `#uiBuildBadge` text vs console `[UI BUILD]` log
2. If they don't match → cache issue
3. If they DO match and assertions still fail → actual code bug

---

## File Reference

| File | Purpose | Key Lines |
|------|---------|-----------|
| [index.html](../target/release/ui/index.html) | DOM structure + CSS | 755 (badge), 66-76 (layout CSS), 810 (grid), 936 (#missionDock), 972 (#outcomePreviewCard) |
| [app.js](../target/release/ui/app.js) | JS logic + debug function | 62-63 (BUILD_VERSION), 19669-19766 (debugMissionSnapshot), 19776 (switchTab) |

---

## Quick Reference: Run This Now

```js
// Step 1: Check build
// Look at visible badge on page. It should say: 2026-01-27-REALITY_REPORT-1
// Console should have logged: [UI BUILD] 2026-01-27-REALITY_REPORT-1

// Step 2: Run snapshot
debugMissionSnapshot()

// Step 3: Check assertions
// All 5 should be ✅

// Step 4: If failures, use Q1-Q7 diagnosis tree above
```
