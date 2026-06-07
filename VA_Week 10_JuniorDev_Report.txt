# VULNERABILITY ASSESSMENT AND EXPLOITATION IN A SIMULATED ENVIRONMENT

**Target:** JuniorDev Active Directory Environment  
**IKB21403 Vulnerability Analysis**  
**Date:** 31 May 2026

---

## 1. EXECUTIVE SUMMARY

### 1.1 Overall Risk Level

## Critical Risk

### 1.2 Total Vulnerabilities Found

A total of 6 vulnerabilities were identified across the JuniorDev Active Directory target system:

| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 3     |

### 1.3 Biggest Concern

The assessment of the JuniorDev Linux environment revealed a chain of critical vulnerabilities enabling complete system compromise. The Jenkins instance exposed on port 30609 was protected only by weak default credentials (`admin:matrix`) and lacked account lockout or rate limiting, allowing a successful brute‑force attack via Hydra. Administrative access to Jenkins led to remote code execution through the Script Console, granting an initial reverse shell as the `jenkins` user. From there, a world‑readable SSH private key belonging to the `juniordev` user was stolen, enabling lateral movement to a standard user account. Finally, an unpatched Linux kernel (4.19.0-8) and a command injection vulnerability in an internal web application on port 8080 provided a reliable path to root privilege escalation. A single crafted POST request to the vulnerable application returned a reverse shell with full root access. These findings demonstrate critical failures in credential management, file permissions, system patching, and secure coding practices within the Linux environment.

### 1.4 Network Diagram

![Network Diagram](network_diagram_placeholder.png)

---

## 2. SCOPE AND METHODOLOGY

### 2.1 Scan type

- **Unauthenticated** – All reconnaissance and the initial brute‑force attack against Jenkins were performed without any prior authentication.
- **Authenticated** – After successfully compromising the Jenkins admin account, the tester gained an authenticated foothold. This phase included internal enumeration as the `jenkins` user, discovery of world‑readable SSH keys, lateral movement to `juniordev`, and finally privilege escalation to root via command injection.

### 2.2 Tools used

- Nmap
- Nuclei
- Hydra
- Jenkins web interface
- Netcat
- Python
- wget
- linpeas.sh
- SSH

### 2.3 Target IP / Host

`10.150.150.38` (hostname: `dev1`)

### 2.4 Date and duration

May 4 – May 31, 2026

---

## 3. SEVERITY RATING

| Severity      | CVSS V4 Score Range | Definition                                                                                  |
|---------------|---------------------|---------------------------------------------------------------------------------------------|
| Critical      | 9.0 – 10.0          | Exploitation leads to a complete system compromise. Requires immediate remediation.        |
| High          | 7.0 – 8.9           | Likely to severely impact confidentiality, integrity, or availability.                     |
| Moderate      | 4.0 – 6.9           | Exploitation is possible but limited in scope or impact.                                   |
| Low           | 0.1 – 3.9           | Minimal impact or requires highly unlikely/privileged conditions.                          |
| Informational | N/A                 | No direct security impact; best-practice findings or observations.                         |

---

## 4. VULNERABILITY SUMMARY

| ID          | Vulnerability                                                                 | CVE        | CVSS Severity | Service       | Port  |
|-------------|-------------------------------------------------------------------------------|------------|---------------|---------------|-------|
| Vuln‑01     | Jenkins Default / Weak Credentials (`admin:matrix`) Enabling Unauthenticated Admin Access | N/A        | 9.2 Critical   | HTTP (Jenkins)| 30609 |
| Vuln‑02     | Jenkins Script Console Exposed to Authenticated Users – Remote Code Execution | N/A        | 9.0 Critical   | HTTP (Jenkins)| 30609 |
| Vuln‑03     | World‑Readable SSH Private Key (`/home/juniordev/.ssh/id_rsa`) Allowing Lateral Movement | N/A        | 7.5 High       | SSH           | 22    |
| Vuln‑04     | Unpatched Linux Kernel 4.19.0-8 – Local Privilege Escalation                 | CVE‑2022‑0847 | 7.8 High       | OS Kernel     | –     |
| Vuln‑05     | Command Injection in Web Application on Port 8080 (`op1` Parameter → `system()` Call) | N/A        | 9.8 Critical   | Custom Web App| 8080  |
| Vuln‑06     | No Account Lockout / Rate Limiting on Jenkins Login (Hydra Brute‑Force Possible) | N/A        | 7.4 High       | HTTP (Jenkins)| 30609 |

---

## 5. DETAILED FINDINGS

### Finding Vuln‑01: Jenkins Default / Weak Credentials (Critical)

| **Severity**   | Critical                                                                                                 |
|----------------|----------------------------------------------------------------------------------------------------------|
| **Description**| The Jenkins instance on port 30609 was protected only by default/weak credentials (`admin:matrix`). An attacker could brute‑force the login using `rockyou.txt` and gain administrative access to Jenkins. No account lockout or rate limiting was present. |
| **Risk**       | **Likelihood:** High – the password `matrix` is present in common wordlists, and no brute‑force protection exists. <br> **Impact:** Very High – Admin access to Jenkins allows arbitrary Groovy script execution, leading to remote code execution on the host as the `jenkins` user. |
| **Systems**    | `dev1 (10.150.150.38)` – Debian Linux kernel 4.19.0-8                                                    |
| **Tools Used** | Nmap, Hydra, `rockyou.txt`                                                                               |
| **False Positive** | No. The credentials `admin:matrix` were verified by successfully logging into the Jenkins web interface and gaining administrative access. |

#### Evidence

![Jenkins login evidence](jenkins_login_placeholder.png)

#### Remediation

| **Patch and Config fix** | Change default admin password immediately. Enforce a strong password policy (minimum 14 characters, complexity). Disable the default admin account and create individual named accounts. |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Compensating controls**| Implement a web application firewall (WAF) rule to block brute‑force patterns. Place Jenkins behind a VPN or IP whitelist. |
| **Priority**             | **Immediate** – Weak credentials are the top entry point for attackers.                                                  |

---

### Finding Vuln‑02: Jenkins Script Console – Remote Code Execution (Critical)

| **Severity**   | Critical                                                                                                 |
|----------------|----------------------------------------------------------------------------------------------------------|
| **Description**| After authenticating with the weak admin credentials, the Jenkins Script Console was accessible. This console permits execution of arbitrary Groovy and Java code, which was used to run a reverse shell command (`nc -e /bin/bash`). |
| **Risk**       | **Likelihood:** High – Any authenticated admin can access the Script Console by default. <br> **Impact:** Very High – Immediate shell access on the target server as the `jenkins` user, leading to further lateral movement and privilege escalation. |
| **Systems**    | `dev1 (10.150.150.38)` – Debian Linux kernel 4.19.0-8                                                    |
| **Tools Used** | Jenkins web interface, Netcat, Python                                                                     |
| **False Positive** | No. The Script Console was used to execute `nc -e /bin/bash`, which returned a reverse shell to the attacker’s listener, confirming remote code execution. |

#### Evidence

![Script Console RCE 1](script_console_rce1_placeholder.png)
![Script Console RCE 2](script_console_rce2_placeholder.png)

#### Remediation

| **Patch and Config fix** | Restrict access to the Script Console by assigning the `Overall/RunScripts` permission only to highly trusted users (e.g., admin). |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Compensating controls**| Log all Script Console usage (Jenkins audit logs). Integrate with a SIEM to alert on suspicious Groovy commands.         |
| **Priority**             | **Short‑term** – Requires valid admin credentials first, but once fixed should be hardened within 1‑2 weeks.             |

---

### Finding Vuln‑03: World‑Readable SSH Private Key (High)

| **Severity**   | High                                                                                                    |
|----------------|----------------------------------------------------------------------------------------------------------|
| **Description**| The SSH private key for user `juniordev` was stored with world‑readable permissions (`/home/juniordev/.ssh/id_rsa`). The `jenkins` user could read the key and use it to authenticate as `juniordev` without a passphrase. |
| **Risk**       | **Likelihood:** Medium – Requires prior local access, which is realistic after initial compromise. <br> **Impact:** High – Lateral movement from a low‑privileged service account to a regular user account, expanding the attack surface. |
| **Systems**    | `dev1 (10.150.150.38)` – Debian Linux kernel 4.19.0-8                                                    |
| **Tools Used** | `cat`, SSH client                                                                                        |
| **False Positive** | No. The private key at `/home/juniordev/.ssh/id_rsa` was successfully used to authenticate as `juniordev` via SSH without a passphrase. |

#### Evidence

*(No image provided in original PDF)*

#### Remediation

| **Patch and Config fix** | Set strict permissions on SSH private keys: `chmod 600 /home/juniordev/.ssh/id_rsa` and ensure the `.ssh` directory has `chmod 700`. |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Compensating controls**| Use a configuration management tool like Ansible or Puppet to enforce correct file permissions across all user home directories. Regularly scan for world‑readable private keys using automated scripts. |
| **Priority**             | **Immediate** – An attacker with any local access can steal the key and move laterally.                                   |

---

### Finding Vuln‑04: Unpatched Linux Kernel (4.19.0-8) – Local Privilege Escalation (High)

| **Severity**   | High                                                                                                    |
|----------------|----------------------------------------------------------------------------------------------------------|
| **Description**| The target ran an outdated Linux kernel (4.19.0-8) known to be vulnerable to multiple local privilege escalation exploits. Automated enumeration with `linpeas.sh` flagged the kernel as a high‑confidence vector. |
| **Risk**       | **Likelihood:** Medium – An attacker with local user access can run a public exploit to gain root. <br> **Impact:** Very High – Full root compromise of the host. |
| **Systems**    | `dev1 (10.150.150.38)` – Debian Linux kernel 4.19.0-8                                                    |
| **Tools Used** | `linpeas.sh`, `wget`                                                                                     |
| **False Positive** | No. The kernel version was confirmed via `uname -r`, and `linpeas.sh` flagged it as vulnerable to multiple public exploits (e.g., Dirty Pipe). The command injection on port 8080 later provided root access, demonstrating the kernel’s exposure. |

#### Evidence


#### Remediation

| **Patch and Config fix** | Upgrade the Linux kernel to a patched version. If a full upgrade is not possible, apply distribution‑provided backported security patches. |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Compensating controls**| Restrict local shell access to trusted users only. Deploy kernel hardening modules like AppArmor or SELinux to limit exploit capabilities. Use eBPF‑based runtime detection for known exploit patterns. |
| **Priority**             | **Short‑term** – Requires local user access first, but kernel exploits are reliable; patch within 30 days.               |

---

### Finding Vuln‑05: Command Injection in Web Application on Port 8080 (Critical)

| **Severity**   | Critical                                                                                                |
|----------------|----------------------------------------------------------------------------------------------------------|
| **Description**| A web application listening on `127.0.0.1:8080` accepted a POST parameter named `op1`. The application unsafely passed the value to Python’s `system()`, allowing arbitrary command injection. An attacker could send a crafted POST request to obtain a reverse shell as `root`. |
| **Risk**       | **Likelihood:** High – The vulnerable endpoint required no authentication and was reachable from the local machine; an attacker already on the host (e.g., as `juniordev`) could exploit it directly. <br> **Impact:** Very High – Complete root compromise. |
| **Systems**    | `dev1 (10.150.150.38)` – Debian Linux kernel 4.19.0-8                                                    |
| **Tools Used** | `curl` or `wget`, Netcat                                                                                 |
| **False Positive** | No. A crafted POST request returned a root reverse shell. |

#### Evidence


![Command injection evidence](cmd_injection_placeholder.png)

#### Remediation

| **Patch and Config fix** | Replace unsafe functions (`system()`, `eval()`, `os.system()`) with parameterised APIs or a safe command parser. Validate and sanitize all user input against an allowlist. |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Compensating controls**| Run the web application with the lowest possible privileges (non‑root). Use a reverse proxy with input filtering to block suspicious characters. |
| **Priority**             | **Immediate** – This allowed an unauthenticated root shell; fix or disable the application immediately.                  |

---

### Finding Vuln‑06: Missing Account Lockout and No Rate Limiting on Jenkins Login (High)

| **Severity**   | High                                                                                                    |
|----------------|----------------------------------------------------------------------------------------------------------|
| **Description**| The Jenkins login page did not implement account lockout after failed attempts, nor did it have rate limiting. This allowed Hydra to brute‑force the admin password by testing over 8.5 million passwords from `rockyou.txt` in a short time. |
| **Risk**       | **Likelihood:** Medium – Requires network access to port 30609 and a username (`admin`). <br> **Impact:** High – Successful brute‑force leads to full Jenkins admin access, then remote code execution. |
| **Systems**    | `dev1 (10.150.150.38)` – Debian Linux kernel 4.19.0-8                                                    |
| **Tools Used** | Hydra, `rockyou.txt`                                                                                     |
| **False Positive** | No. Hydra successfully tested over 8.5 million passwords against the Jenkins login page without any lockout or delay, and the correct password (`matrix`) was discovered within minutes. |

#### Evidence

*(No image provided in original PDF)*

#### Remediation

| **Patch and Config fix** | Enable the Jenkins “Lockout Failed Logins” feature (via plugin or native settings). Configure a lockout threshold and lockout duration. |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Compensating controls**| Place Jenkins behind a reverse proxy that implements rate limiting. Enforce multi‑factor authentication (MFA) for all Jenkins users. |
| **Priority**             | **Short‑term** – Should be implemented alongside strong password policies.                                               |

---

*End of report*
