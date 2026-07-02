# Frontend EXP Data

This directory contains static data used by the desktop GUI.

## `lpeExpCatalog.ts`

Linux local privilege escalation knowledge-base catalog for GUI browsing and future scan-result matching.

The catalog stores reviewed source URLs, affected-environment notes, verification commands, build/run hints, cleanup notes, and matching keywords. It intentionally does not vendor full external PoC repositories into the frontend bundle, and the desktop GUI should not generate local EXP bundles from this data.

When a public project documents a target-side online one-liner, store it under `usage.officialOnline`. Otherwise, leave `usage` empty and let the GUI point the operator to the confirmed GitHub link and compile/run notes.

Future scan integration should match KubeTrail LPE finding titles or `lpe.*` fact evidence against each card's `cves` and `detectionHints`.
