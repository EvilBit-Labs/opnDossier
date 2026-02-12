# Configuration Diff

**Old File:** `prod-config-v1.xml`
**New File:** `prod-config-v2.xml`
**Compared At:** 2026-01-15 10:30:00
**Tool Version:** 1.0.0

## Summary

| Type | Count |
|------|-------|
| Added | 2 |
| Removed | 1 |
| Modified | 2 |
| **Total** | **5** |

## Firewall

| Change | Description | Security |
|--------|-------------|----------|
| **+** | Added rule: Allow HTTP | 🔴 HIGH |
| **-** | Removed rule: Legacy FTP | 🟡 MEDIUM |
| **~** | Modified rule: SSH access restricted | 🟢 LOW |

<details>
<summary>Show details</summary>

### **+** Added rule: Allow HTTP

- **Path:** `filter.rule[uuid=abc-123]`
- **Type:** added
- **Security Impact:** 🔴 HIGH
- **New Value:** `type=pass, src=any, dst=any:80`

### **-** Removed rule: Legacy FTP

- **Path:** `filter.rule[uuid=def-456]`
- **Type:** removed
- **Security Impact:** 🟡 MEDIUM
- **Old Value:** `type=pass, proto=tcp, dst=any:21`

### **~** Modified rule: SSH access restricted

- **Path:** `filter.rule[uuid=ghi-789]`
- **Type:** modified
- **Security Impact:** 🟢 LOW
- **Old Value:** `src=any`
- **New Value:** `src=10.0.0.0/8`

</details>

## Interfaces

| Change | Description | Security |
|--------|-------------|----------|
| **+** | Added interface: opt1 (DMZ) |  |

<details>
<summary>Show details</summary>

### **+** Added interface: opt1 (DMZ)

- **Path:** `interfaces.opt1`
- **Type:** added
- **New Value:** `enable=1, if=igb2, descr=DMZ`

</details>

## System

| Change | Description | Security |
|--------|-------------|----------|
| **~** | Hostname changed |  |

<details>
<summary>Show details</summary>

### **~** Hostname changed

- **Path:** `system.hostname`
- **Type:** modified
- **Old Value:** `fw-old`
- **New Value:** `fw-new`

</details>

