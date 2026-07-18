# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Audit analysis

### Observation

A neutral, mode-agnostic detection produced by the shared detection engine from a device configuration, carrying a severity, a confidence label, a reachability tag, and evidence pointing at the originating config element. Observations are the single source of truth for detection: both audit modes are presentation lenses over the same observations, so the two modes can never disagree about an underlying fact.

### Reachability

Where a configuration element can be reached from: WAN-reachable (the public internet), LAN-only (internal networks), or local (nowhere on any network — a disabled interface, or a port-forward with no matching enabled pass rule). Reachability is computed once per observation and is the shared spine both modes consume — the defensive mode uses it to order and prioritize findings, and the adversarial mode uses it as its primary exposure filter. A service or rule is WAN-reachable only when a live WAN rule actually permits it, never on the element merely existing; ambiguous cases bias toward reporting exposure rather than hiding it.

### Confidence

A three-level label (high / medium / low) on an Observation describing how certain the detection is. Confidence is presentation metadata only — it never gates whether an observation is surfaced. Every match is reported with its label; nothing is dropped by a confidence threshold.

### Blue mode

The defensive audit lens. Renders Observations as framework-free hygiene findings plus recommendations synthesized from the compliance plugins it runs, ordered by severity then reachability. *Avoid:* defensive mode, blue team mode.

### Red mode

The adversarial audit lens over the same Observations, reframed for a reader thinking like an attacker and prioritized by reachability — WAN-reachable exposures lead; LAN-only and local items are excluded from the exposure findings. Red mode runs no compliance plugins; it is a framing lens, not a separate analysis. *Avoid:* attacker mode, red team mode.

### Hygiene finding

A framework-free configuration smell that no compliance plugin owns at per-element granularity — insecure management protocols, weak crypto defaults, any-to-any rules, disabled logging. Detected once in the shared engine; blue mode renders hygiene findings de-duplicated against fired compliance controls, and red mode reframes the WAN-reachable ones as exposure.

### ExploitNotes

The impact-and-context framing attached to a red-mode exposure finding: why an exposure matters to a defender or an attacker, never how to exploit it. ExploitNotes carry no weaponized or step-by-step instructions — this boundary is enforced mechanically by a denylist run over the generated notes, not by authoring discipline. A sharper-tone variant adjusts tone only and never changes the safety property.

## Device model

### Named-object reference layer

An additive registry (`NamedObjects`) and reference concept (`ObjectRef`) on `CommonDevice` that lets a device parser preserve object-oriented config as named object definitions plus rule-level references to them, alongside the existing resolved-inline-value fields. Resolved values are always populated so existing pf-family checks keep firing unmodified; the reference is optional and stays empty for devices (OPNsense, pfSense) that have no named-object concept. Unlocks reference-integrity checks like dangling-object detection without a schema rewrite.

### DeviceBundle

The planned container for a config file that yields more than one `CommonDevice` from a single parse — the deferred FortiGate VDOM case, where each VDOM (plus the global scope) becomes its own device rather than being merged into one. Not yet implemented: today's parsers are single-`CommonDevice`-per-file only, and a VDOM-bearing FortiGate config is detected and warned rather than expanded into a DeviceBundle.
