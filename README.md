# Splunk-Sysmon-SOC-Lab
A hybrid SIEM environment engineering high-fidelity Windows endpoint logging (Sysmon), real-time SPL detection rules, and a live SOC incident response dashboard.
# Hybrid SIEM Infrastructure & Endpoint Threat Detection Pipeline

## 📌 Project Overview
This project details the engineering, deployment, and validation of a robust, multi-tier Security Information and Event Management (SIEM) environment designed for localized endpoint monitoring and active threat detection. 

Operating on a hybrid virtualization architecture, the project establishes a resilient logging pipeline that streams high-fidelity operating system and process telemetry into a central analytical engine. Instead of relying on passive signature monitoring, this pipeline implements programmatic, case-insensitive logic capable of detecting real-world adversary behavior. Over the course of the project, multiple core infrastructure blocks—ranging from virtualization driver architecture conflicts to service account access tokens and execution throttling—were encountered, diagnosed, and systematically remediated.

## 🏗️ Architecture & Data Flow Hierarchy
The deployment isolates a server-tier analytics collector from a virtualized target node. Telemetry ingestion bypasses fragile file-monitoring models, interfacing directly with Windows event APIs.

[Image of a security operations center dashboard layout]

* **Analytics Node (Host):** macOS ARM64 running **Splunk Enterprise** (Listening on TCP port `9997`).
* **Target Node (Virtual Guest):** Windows 11 ARM64 running inside **UTM**, monitored via **Sysmon64a** and shipping data through the **Splunk Universal Forwarder**.

### 🔄 Ingestion Architecture Data Path:
1. **Kernel-Level Capture:** System activity triggers Windows security auditing and Sysmon drivers.
2. **API Subscription Hook:** The Splunk Universal Forwarder hooks directly into the Windows Event Log API channels via a declarative config file (`inputs.conf`).
3. **Encapsulated Network Transport:** Telemetry is forwarded over a virtual bridge network link straight to the Splunk Host receiver.
4. **Parsing & Normalization:** Splunk parses the unstructured text, mapping fields for Search Processing Language (SPL) ingestion.

---

## 🛠️ Infrastructure Provisioning & Troubleshooting Ledger (RCA)

Building this environment required overcoming several critical system boundaries. Below is the engineering Root Cause Analysis (RCA) log:

### ⚡ Incident 1: Subsystem Driver Blocked from Kernel Space
* **Symptom:** Utility installation failed with `StartService failed for SysmonDrv: This driver has been blocked from loading`.
* **Root Cause Analysis:** Windows 11 enforces strict kernel driver signature verification. Because the guest VM runs an ARM64-based architecture, deploying standard x64 binaries (`Sysmon64.exe`) resulted in an irreversible instruction-set mismatch at the driver layer, forcing the kernel to block execution.
* **Remediation:** Purged the unlinked service block and explicitly deployed the ARM64-native binary wrapper:
    ```powershell
    sc.exe delete Sysmon64
    .\Sysmon64a.exe -accepteula -i sysmonconfig-export.xml
    ```
    This loaded an instruction-set compliant, digitally signed ARM64 kernel driver, restoring immediate functionality.

### ⚡ Incident 2: Telemetry Ingestion Silence on Sysmon Channel Space
* **Symptom:** Windows Security logs migrated successfully, but high-fidelity Sysmon operational channels returned `0` records.
* **Root Cause Analysis:** By default, the Splunk Forwarder service was provisioned utilizing a low-privilege virtual service account profile (`NT SERVICE\SplunkForwarder`). Unlike standard security log readers, the Sysmon operational channel enforces strict access control descriptors that denied authorization to this virtualized token, raising a silent `errorCode=5 (Access Denied)` exception.
* **Remediation:** Altered the operational token structure of the forwarder service, re-allocating the execution context to high-privilege system space:
    ```powershell
    sc.exe config SplunkForwarder obj= "LocalSystem"
    Restart-Service SplunkForwarder
    ```
    The `LocalSystem` identity bypassed DACL restrictions, immediately flushing all Sysmon telemetry objects into the SIEM layer.

### ⚡ Incident 3: Windows Event Collapsing & Loop Optimization Failure
* **Symptom:** Automated credential attack loops designed to populate Event Code 4625 failed to return alerts or logs inside the SIEM console.
* **Root Cause Analysis:** Programmatic execution via `Start-Process` was trapped inside PowerShell's error handling space, failing to hit the local security authority. When switched to standard local loops, Windows network throttling and loopback optimizations grouped or dropped the rapid failures internally to conserve processing overhead, starving the logging pipeline.
* **Remediation:** Directed the attack traffic to hit the local Inter-Process Communication administrative share link via an explicit target wrapper:
    ```powershell
    net use \\localhost\IPC$ /user:fakeuser123 WrongPassword999
    ```
    By routing through the local `\\localhost\IPC$` channel, loopback optimizations were bypassed, forcing the OS to explicitly evaluate the transaction and log separate, un-grouped Event ID 4625 logs.

---

## 🎯 MITRE ATT&CK Matrix Alignment & Custom SPL Logic

The engineered detection suite targets foundational adversarial tactics. To counter sophisticated defensive evasion tactics (such as character case-mixing), the queries programmatically normalize inputs to lowercase schemas using the `lower()` evaluator.

### 🛡️ T1110 - Credential Access (Brute Force)
* **Attack Vector:** Attempting to iterate authentication locks to compromise accounts.
* **Detection Strategy:** Isolates authentication failure boundaries (Event ID 4625) across short, concurrent windows.
* **SPL Query Logic:**
    ```splunk
    index=* sourcetype="WinEventLog:Security" EventCode=4625
    | stats count as failed_attempts values(TargetUserName) as targeted_users dc(TargetUserName) as unique_users_targeted by SourceNetworkAddress
    | where failed_attempts >= 5
    ```

### 🛡️ T1059.001 - Execution / T1027 - Defense Evasion (PowerShell Subversion)
* **Attack Vector:** Attackers executing obfuscated scripts, bypassing local execution policies, or hosting fileless staging scripts.
* **Detection Strategy:** Monitors process creation (Sysmon Event ID 1) strings for signature evasion flags (`-enc`, `Bypass`, `IEX`, `DownloadString`).
* **SPL Query Logic:**
    ```splunk
    index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*powershell.exe" OR Image="*pwsh.exe")
    | eval CommandLine_Lower=lower(CommandLine)
    | search CommandLine_Lower="*-encodedcommand*" OR CommandLine_Lower="*-enc*" OR CommandLine_Lower="*-e *" OR CommandLine_Lower="*bypass*" OR CommandLine_Lower="*iex*" OR CommandLine_Lower="*downloadstring*"
    | timechart count by host
    ```

### 🛡️ T1053.005 - Persistence (Scheduled Tasks)
* **Attack Vector:** Registering non-volatile execution hooks to maintain access through system reboots.
* **Detection Strategy:** Flags the structural creation payload argument (`/create`) targeting `schtasks.exe`.
* **SPL Query Logic:**
    ```splunk
    index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*schtasks.exe" AND CommandLine="*/create*"
    | timechart count by host
    ```

---

## 📊 Live Incident Response SOC Dashboard
To optimize incident triage, the analytical engine was decoupled from legacy background cron scheduling (which suffered drops under virtualization) and migrated into low-latency **Real-Time Streaming Pipelines**.

The interface is structured into an active threat tracking grid:
1. **PowerShell Evasion Trends:** Visualized as a column chart monitoring frequency spikes.
2. **Active Endpoint Threat Ledger:** A live, tabular forensic view surfacing the executing identity, machine asset, dynamic threat category classification, and exact command string payload.
3. **Persistence Mechanism Detections:** Dedicated graph isolating execution anomalies seeking environmental longevity.

![SOC Dashboard Mockup]([Insert Your Final Saved Dashboard Image Link Here])

---

## 🧠 Key Cyber Engineering Takeaways
1. **Telemetry Fidelity over Legacy Logs:** Standard OS auditing easily hides execution arguments. Incorporating Sysmon provides absolute clarity into process parameters (`CommandLine`, `ParentImage`).
2. **Programmatic Resilience:** Relying on basic text matching fails against obfuscation. Defenses must leverage normalization functions (e.g., lowercase cast layers) to withstand simple string manipulations.
3. **Infrastructure Visibility:** Technical troubleshooting should always progress systematically outward-to-inward: validating network interface bindings, testing log visibility locally, inspecting access controls (ACLs), and analyzing runtime account permissions.
