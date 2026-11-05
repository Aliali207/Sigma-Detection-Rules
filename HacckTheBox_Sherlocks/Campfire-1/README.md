# Campfire-1: Kerberoasting Detection with Sigma

Detection engineering write-up based on the Hack The Box Sherlock **Campfire-1**.
A Sigma rule was written to detect Kerberoasting from Windows Security Event ID 4769
and was validated against the Domain Controller logs provided with the Sherlock,
using [Chainsaw](https://github.com/WithSecureLabs/chainsaw).

## Overview

Kerberoasting (MITRE ATT&CK [T1558.003](https://attack.mitre.org/techniques/T1558/003/))
lets an authenticated domain user request Kerberos service tickets (TGS) for accounts
with an SPN, then crack them offline to recover the service account password.
Attackers usually request tickets encrypted with **RC4 (0x17)** because they are
much faster to crack than AES.

## Detection Logic

The rule alerts on any Kerberos service ticket request (Event ID 4769) whose
ticket encryption type is RC4 (`0x17`).

| Field | Value |
|---|---|
| Log source | Windows Security |
| Event ID | 4769 |
| Condition | `TicketEncryptionType = 0x17` |
| Level | Low |

Rule file: [`kerberoasting-rule.yml`](kerberoasting-rule.yml)

## Data Source

- Sherlock: Hack The Box **Campfire-1**
- Log file: `Domain Controller\SECURITY-DC.evtx` 

## Validation

The rule was run directly against the `.evtx` file with Chainsaw, using the
Sigma event logs mapping:

```powershell
.\chainsaw.exe hunt "C:\...\campfire-1\Domain Controller\SECURITY-DC.evtx" `
  -s C:\...\sigma\kerberoasting-rule.yml `
  --mapping .\mappings\sigma-event-logs-all.yml
```
