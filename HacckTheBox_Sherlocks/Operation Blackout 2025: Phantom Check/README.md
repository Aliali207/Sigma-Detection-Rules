## Lab Overview

This Sherlock provides several investigative pivots that reveal how the attacker attempted to identify the underlying virtualization environment before proceeding with further malicious activity.

The attacker leveraged **Windows Management Instrumentation (WMI)** to retrieve system information, including the computer manufacturer, using commands such as:

```powershell
Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer
```

The investigation also revealed the use of a **Nashang script** designed to identify common virtualization platforms by examining multiple system artifacts, including registry keys, running processes, BIOS information, and ACPI-related identifiers.

The script checked for artifacts associated with the following virtualization platforms:

- Hyper-V
- VMware
- Virtual PC
- VirtualBox
- Xen
- QEMU

Using the script's behavior and the provided Windows event logs as investigative references, I developed a **Sigma detection rule** designed to identify PowerShell script blocks exhibiting similar virtualization-fingerprinting behavior.

The goal of this rule is to help detect potential virtualization and sandbox discovery activity that may be used by attackers to assess their execution environment.
