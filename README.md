Thanks for the clarification!

Here's an updated `README.md` tailored for a **Threat Detection repository based on Sigma rules**. This version clarifies that the rules are written in [Sigma](https://sigmahq.io/), the generic and open signature format for log-based detections.

---

# Threat Detection (Sigma Rules)

A curated collection of **Sigma rules** to detect malicious behavior, adversary techniques, and indicators of compromise across different threat categories — including Remote Access Trojans (RATs), Advanced Persistent Threats (APTs), and Active Directory abuse.

## 📌 About

**Sigma** is a generic rule format for log events that enables the sharing of detection logic across different SIEM and log analysis platforms. This repository provides Sigma-based threat detection rules that can be converted into queries for popular tools like:

* Splunk
* Elastic (Kibana)
* Sentinel
* Graylog
* QRadar

## 📁 Repository Structure

```
threat-detection/
├── APT/                # Sigma rules related to APT actor behavior and TTPs
├── Active Directory/   # Sigma rules for AD attacks like DCShadow, Kerberoasting, etc.
├── RAT/                # Sigma rules for detecting RATs such as Adwind, DarkMe, etc.
```

## 🔍 Detection Coverage

| Category             | Example Rules                                          |
| -------------------- | ------------------------------------------------------ |
| **RAT**              | Adwind initial execution, DarkMe RAT execution         |
| **APT**              | Specific TTPs used by known APT groups                 |
| **Active Directory** | Privilege abuse, persistence, lateral movement tactics |

Each rule is mapped (when possible) to **MITRE ATT\&CK** tactics and techniques.

## 🚀 Getting Started

1. Clone this repository:

   ```bash
   git clone https://github.com/rodanmaharjan/threat-detection.git
   cd threat-detection
   ```

2. Browse by category:

   ```bash
   cd RAT/
   ```

3. Convert Sigma rules to your SIEM format using [sigmac](https://github.com/SigmaHQ/sigma):

   ```bash
   sigmac -t splunk -c config/splunk-windows.yml rule.yml
   ```

## ✅ Rule Format Example

```yaml
title: Adwind RAT Initial Execution
id: a1b2c3d4-5678-90ab-cdef-1234567890ab
description: Detects Java-based Adwind RAT execution via suspicious command-line usage.
status: experimental
author: rodanmaharjan
date: 2025/01/12
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "javaw.exe"
      - "-jar"
      - "adwind"
  condition: selection
fields:
  - CommandLine
  - ParentImage
  - Image
level: high
tags:
  - attack.execution
  - attack.t1059
  - rat.adwind
```

## 👥 Contributions

Contributions are welcome! If you'd like to submit a rule, ensure:

* It's in valid Sigma YAML format
* Includes appropriate metadata (e.g., MITRE mappings, tags)
* Tested or peer-reviewed before PR

## 📚 Resources

* [Sigma HQ Documentation](https://github.com/SigmaHQ/sigma)
* [MITRE ATT\&CK Framework](https://attack.mitre.org/)
* [SIGMAC (Sigma Converter)](https://github.com/SigmaHQ/sigmac)

## 📜 License

This project is licensed under the MIT License.

---

