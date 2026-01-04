# AWS Threat Detection & Vulnerability Analysis: GuardDuty vs. OWASP Juice Shop

## Executive Summary
This project demonstrates a full-cycle cloud security assessment simulating a critical data breach scenario. Acting as both the Red Team (Attacker) and Blue Team (Defender), I deployed a vulnerable web application (OWASP Juice Shop) on AWS to execute a "Kill Chain" that escalated from application-layer compromise to cloud-layer credential theft.

The primary objective was to validate **Amazon GuardDuty's** efficacy in detecting lateral movement and data exfiltration, specifically focusing on the abuse of EC2 Instance Metadata Service (IMDS) credentials. This project highlights the critical need for behavioral analytics in identifying threats that bypass traditional perimeter defenses.

## Architecture & Tech Stack
* **Compute:** Amazon EC2 (Hosting OWASP Juice Shop via Docker)
* **Infrastructure as Code:** AWS CloudFormation
* **Storage:** Amazon S3 (Private target for exfiltration & malware staging)
* **Security:** Amazon GuardDuty (Malware Protection & CloudTrail Analysis)
* **Attack Tools:** SQL Injection, Command Injection (RCE), AWS CloudShell

<p align="center">
  <img src=".assets/Architecture Diagram.png" alt="Architecture Diagram" width="800"/>
  <br>
  <b>Figure 1: Attack Path & Detection Architecture</b>
</p>

The architecture above visualizes the five-stage attack lifecycle executed in this lab:

1.  **Initial Access:** External exploitation of public web vulnerabilities (SQLi, RCE).
2.  **Credential Access:** Abuse of the EC2 Instance Metadata Service (IMDSv1) to scrape temporary IAM role credentials (`AccessKeyId`, `SecretAccessKey`, `Token`).
3.  **Lateral Movement:** Pivoting to an external environment (simulated via AWS CloudShell) and authenticating as the compromised instance role.
4.  **Exfiltration:** illicitly accessing and downloading sensitive objects from a private S3 bucket.
5.  **Detection:** GuardDuty correlates CloudTrail management events to identify the anomaly of EC2 credentials being used from an external IP address.

## MITRE ATT&CK Mapping
| Tactic | ID | Technique | Data Source (Detection) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application | Web Application Firewall (WAF) Logs |
| **Execution** | T1059 | Command and Scripting Interpreter | Process Execution Logs (EDR) |
| **Credential Access** | T1552 | Unsecured Credentials | **CloudTrail (Non-API Event)** |
| **Exfiltration** | T1567 | Exfiltration Over Web Service | **S3 Data Events** |

## Lab Setup (Infrastructure as Code)
The environment was provisioned using a custom CloudFormation template to ensure a consistent, secure-by-design baseline (excluding the intentional application vulnerabilities).

<p align="center">
  <img src=".assets/Infrastructure Deployment.png" alt="Infrastructure Deployment" width="800"/>
  <br>
  <b>Figure 2: Automated Deployment</b>
</p>

The CloudFormation stack `GuardDuty-Lab` successfully provisioned the isolated VPC, Security Groups, EC2 Instance Profile, and the target S3 Bucket.

## The Attack Lifecycle (Red Team)

### Phase 1: Authentication Bypass
I exploited an unsanitized email input field on the login portal to bypass authentication mechanisms.
* **Payload:** `' or 1=1;--` (Forces boolean TRUE on the backend SQL query).

<p align="center">
  <img src=".assets/SQL Injection.png" alt="SQL Injection" width="600"/>
  <br>
  <b>Figure 3: SQL Injection Execution</b>
</p>

As shown in Figure 3, the payload successfully logged the attacker in as the administrator without requiring a valid password.

### Phase 2: Credential Theft (IMDS Abuse)
Leveraging a Command Injection vulnerability in the User Profile, I forced the server to query the AWS internal metadata service (169.254.169.254).
* **Objective:** Retrieve the temporary IAM credentials assigned to the EC2 Instance Profile.

<p align="center">
  <img src=".assets/Command Injection.png" alt="Command Injection" width="600"/>
  <br>
  <b>Figure 4: RCE Payload Retrieving IAM Credentials</b>
</p>

Figure 4 demonstrates the `curl` command executed via the application layer. The server response leaks the `AccessKeyId`, `SecretAccessKey`, and `Token`, which were then saved to a public file (`credentials.json`).

### Phase 3: Cross-Account Data Exfiltration
I pivoted to **AWS CloudShell** to simulate an attacker operating from an external network. By configuring the AWS CLI with the stolen session token, I successfully bypassed network restrictions to access the private S3 bucket.

<p align="center">
  <img src=".assets/Cloudshell S3 Data Exfiltration.png" alt="Data Exfiltration" width="800"/>
  <br>
  <b>Figure 5: Exfiltration via CloudShell</b>
</p>

The terminal output above confirms the successful download of `secret-information.txt`, validating that the IAM role permissions were successfully hijacked.

## Defense & Detection (Blue Team)

### Analysis of GuardDuty Findings
GuardDuty successfully generated high-fidelity alerts by analyzing CloudTrail and S3 Data events.

**Finding 1: Instance Credential Exfiltration**
* **Type:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`
* **Severity:** **High**
* **Analysis:** GuardDuty's behavioral engine detected that credentials issued *exclusively* for an EC2 instance were used to sign API requests from a different IP address (CloudShell). This is a deterministic indicator of key compromise.

<p align="center">
  <img src=".assets/Instance Credential Exfiltration Alert.png" alt="Credential Exfiltration Alert" width="800"/>
  <br>
  <b>Figure 6: GuardDuty Credential Alert</b>
</p>

**Finding 2: Malicious Object Detected**
* **Type:** `Object:S3/MaliciousFile`
* **Analysis:** Upon uploading a test file, GuardDuty Malware Protection for S3 automatically initiated a scan and identified the EICAR signature string.

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

## Remediation & Hardening Strategies
To prevent this attack vector in a production environment, the following controls must be implemented:

1.  **Enforce IMDSv2:**
    * **Risk:** IMDSv1 allows simple GET requests to retrieve credentials.
    * **Fix:** Require IMDSv2 on all EC2 instances. This mandates a session token via a `PUT` request, which effectively neutralizes most SSRF and Command Injection attempts.
    * *Command:* `aws ec2 modify-instance-metadata-options --http-tokens required`
2.  **Least Privilege IAM Policies:**
    * **Risk:** The EC2 role had broad `s3:ListBucket` permissions on the entire account.
    * **Fix:** Scope permissions down to specific bucket ARNs and prefixes required for the application's function.
3.  **Network Defense (WAF):**
    * **Fix:** Deploy AWS WAF with Managed Rules for SQL database and POSIX OS exploits to block the initial injection vectors at the edge.

## Conclusion
This project reinforces that **Identity is the new perimeter**. While the initial breach leveraged application vulnerabilities, the critical impact (data exfiltration) was enabled by the lack of protections on the EC2 Instance Metadata Service. By leveraging GuardDuty, organizations can detect when valid credentials are used in anomalous contexts, providing a last line of defense against sophisticated credential theft.
