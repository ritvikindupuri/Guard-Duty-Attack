# AWS Threat Detection & Vulnerability Analysis: GuardDuty vs. OWASP Juice Shop

## Executive Summary
This project demonstrates a complete cloud security assessment, simulating an attack lifecycle that pivots from a compromised web application to the underlying cloud infrastructure. Acting as both the Red Team (Attacker) and Blue Team (Defender), I deployed a vulnerable application (OWASP Juice Shop) on AWS, executed a credential theft attack via the EC2 Instance Metadata Service (IMDS), and detected the breach using **Amazon GuardDuty**.

The primary objective was to validate GuardDuty's ability to detect high-fidelity threats—specifically the unauthorized cross-account use of stolen IAM credentials—and to implement hardening strategies to prevent recurrence.

## Architecture & Tech Stack
* **Compute:** Amazon EC2 (Hosting OWASP Juice Shop via Docker)
* **Infrastructure as Code:** AWS CloudFormation
* **Storage:** Amazon S3 (Private target for data exfiltration)
* **Security:** Amazon GuardDuty (Malware Protection & Behavioral Analysis)
* **Attack Tools:** SQL Injection, Command Injection (RCE), AWS CloudShell

<p align="center">
  <img src=".assets/Architecture Diagram.png" alt="Architecture Diagram" width="800"/>
  <br>
  <b>Figure 1: Attack Path & Detection Architecture</b>
</p>

The diagram above illustrates the five-stage "Kill Chain" executed in this project:

1.  **Initial Access:** An external attacker exploits public web vulnerabilities (SQLi, RCE) to gain control of the web server.
2.  **Credential Access:** The attacker forces the compromised EC2 instance to query the Instance Metadata Service (169.254.169.254) to steal temporary IAM role credentials.
3.  **Lateral Movement:** The attacker pivots to an external environment (simulated via AWS CloudShell), authenticating as the compromised role from a new IP address.
4.  **Exfiltration:** Using the stolen permissions, the attacker accesses and downloads private S3 resources (`secret-information.txt`).
5.  **Detection:** Amazon GuardDuty ingests CloudTrail logs, identifying the anomaly of EC2 credentials being used from a non-EC2 IP address and flagging the behavior.

## MITRE ATT&CK Mapping
| Tactic | ID | Technique | Project Implementation |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application | SQL Injection on Login Portal |
| **Execution** | T1059 | Command and Scripting Interpreter | RCE via Node.js `child_process.exec` |
| **Credential Access** | T1552 | Unsecured Credentials | Extracting IAM keys via EC2 IMDSv1 |
| **Exfiltration** | T1567 | Exfiltration Over Web Service | Downloading S3 files via AWS CLI |

## Lab Setup (Infrastructure as Code)
The lab environment was provisioned using a custom CloudFormation template to ensure a consistent, isolated baseline.

<p align="center">
  <img src=".assets/Infrastructure Deployment.png" alt="Infrastructure Deployment" width="800"/>
  <br>
  <b>Figure 2: Automated Deployment</b>
</p>

The CloudFormation stack `GuardDuty-Lab` shown above successfully provisioned the VPC, Security Groups, EC2 Instance, and the target S3 Bucket.

## The Attack Lifecycle (Red Team)

### Phase 1: Authentication Bypass
I exploited an unsanitized email input field to bypass authentication constraints.
* **Payload:** `' or 1=1;--` (Forces boolean TRUE on password check)

<p align="center">
  <img src=".assets/SQL Injection.png" alt="SQL Injection" width="600"/>
  <br>
  <b>Figure 3: SQL Injection Execution</b>
</p>

As shown in Figure 3, injecting the SQL payload into the login portal manipulates the backend query, granting Administrative access without a valid password.

### Phase 2: Credential Theft (IMDS Abuse)
Using a Command Injection vulnerability in the User Profile, I forced the server to query the AWS internal metadata service.
* **Objective:** Retrieve `AccessKeyId`, `SecretAccessKey`, and `Token` for the attached IAM Role.

<p align="center">
  <img src=".assets/Command Injection.png" alt="Command Injection" width="600"/>
  <br>
  <b>Figure 4: RCE Payload Retrieving IAM Credentials</b>
</p>

The screenshot above demonstrates the `curl` command executed via the application layer. It targets `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, causing the server to return its own temporary IAM keys.

### Phase 3: Cross-Account Data Exfiltration
I moved to **AWS CloudShell** to simulate an external attacker. By configuring the AWS CLI with the stolen session token, I successfully accessed the private S3 bucket.

<p align="center">
  <img src=".assets/Cloudshell S3 Data Exfiltration.png" alt="Data Exfiltration" width="800"/>
  <br>
  <b>Figure 5: Exfiltration via CloudShell</b>
</p>

Figure 5 shows the successful download of `secret-information.txt`. This confirms that the attacker has successfully pivoted from the web application to the cloud storage layer using the compromised IAM role.

## Defense & Detection (Blue Team)

### Analysis of GuardDuty Findings
GuardDuty generated high-fidelity alerts based on the anomalous behavior observed in CloudTrail data events.

**Finding 1: Instance Credential Exfiltration**
* **Type:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`
* **Severity:** High
* **Root Cause:** GuardDuty detected that credentials issued solely for an EC2 instance were being used to sign API requests from an external IP address (CloudShell). This confirms key compromise.

<p align="center">
  <img src=".assets/Instance Credential Exfiltration Alert.png" alt="Credential Exfiltration Alert" width="800"/>
  <br>
  <b>Figure 6: GuardDuty Credential Alert</b>
</p>

**Finding 2: Malicious Object Detected**
* **Type:** `Object:S3/MaliciousFile`
* **Root Cause:** S3 Malware Protection scanned a newly uploaded file and identified the EICAR signature string.

<p align="center">
  <img src=".assets/S3 Eicar test File Upload.png" alt="EICAR Upload" width="800"/>
  <br>
  <b>Figure 7: Uploading the EICAR Test File</b>
</p>

<p align="center">
  <img src=".assets/S3 Malware Scan Alert.png" alt="Malware Scan Alert" width="800"/>
  <br>
  <b>Figure 8: S3 Malware Finding</b>
</p>

## Remediation & Hardening
Detecting the threat is only half the battle. To prevent this attack in a production environment, the following controls are required:

1.  **Enforce IMDSv2:**
    * **Fix:** Configure EC2 instances to require IMDSv2 (Session Tokens). This mitigates SSRF and simple Command Injection attacks by requiring a `PUT` request header that typical web exploits cannot easily generate.
    * *Command:* `aws ec2 modify-instance-metadata-options --http-tokens required`
2.  **Least Privilege IAM:**
    * **Fix:** The EC2 role had broad `s3:ListBucket` permissions. Scoping this down to specific resources and prefixes limits the blast radius of any potential exfiltration.
3.  **Input Validation (WAF):**
    * **Fix:** Deploy AWS WAF with the "SQL Database" and "Linux Operating System" managed rule sets to block the initial SQLi and RCE vectors at the network edge.

## Conclusion
This project highlights a critical cloud security concept: **Identity is the new perimeter.** While the initial entry point was a web application vulnerability, the actual damage (data exfiltration) was enabled by over-permissive IAM roles and the lack of IMDS protection. By using GuardDuty, I validated that behavioral detection is essential for identifying credential abuse that traditional signature-based tools often miss.
