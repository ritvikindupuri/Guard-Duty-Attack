# AWS Threat Detection & Vulnerability Analysis: GuardDuty vs. OWASP Juice Shop

## Project Overview
This project simulates a full-cycle security event—acting as both the Red Team (Attacker) and Blue Team (Defender). I deployed a deliberately vulnerable web application (OWASP Juice Shop) on AWS and executed a multi-stage attack to compromise the server, exfiltrate temporary IAM credentials via the EC2 Instance Metadata Service (IMDS), and access sensitive S3 data.

Finally, I utilized **Amazon GuardDuty** to detect the intrusion, analyze the findings, and validated defenses using S3 Malware Protection.

## Architecture & Tech Stack
* **Compute:** Amazon EC2 (Hosting OWASP Juice Shop)
* **Infrastructure as Code:** AWS CloudFormation
* **Storage:** Amazon S3 (Target for data exfiltration & malware testing)
* **Security:** Amazon GuardDuty (Threat Detection & Malware Protection)
* **Attack Tools:** SQL Injection, Command Injection (RCE), AWS CloudShell

<p align="center">
  <img src=".assets/Architecture Diagram.png" alt="Architecture Diagram" width="800"/>
  <br>
  <b>Figure 1: Project Architecture & Attack Path</b>
</p>

The infrastructure was deployed securely using AWS CloudFormation to ensure a consistent and isolated lab environment.

<p align="center">
  <img src=".assets/Infrastructure Deployment.png" alt="Infrastructure Deployment" width="800"/>
  <br>
  <b>Figure 2: CloudFormation Stack Deployment</b>
</p>

## The Attack Lifecycle (Red Team)

### 1. Initial Access: SQL Injection
Bypassed the administrative login portal by exploiting an unsanitized email input field.
* **Vulnerability:** SQL Injection (SQLi)
* **Payload:** `' or 1=1;--`
* **Result:** Gained administrative access to the web application without a password.

<p align="center">
  <img src=".assets/SQL Injection.png" alt="SQL Injection" width="600"/>
  <br>
  <b>Figure 3: Exploiting SQL Injection to Bypass Authentication</b>
</p>

### 2. Privilege Escalation: Command Injection & IMDS Abuse
Exploited a Remote Code Execution (RCE) vulnerability in the User Profile "Username" field to interact with the underlying OS.
* **Vulnerability:** Node.js Command Injection via `child_process.exec`
* **Technique:** Abused the EC2 Instance Metadata Service (IMDS) to request temporary IAM credentials.
* **Result:** The application fetched the `AccessKeyId`, `SecretAccessKey`, and `Token` and wrote them to a publicly accessible JSON file (`credentials.json`).

<p align="center">
  <img src=".assets/Command Injection.png" alt="Command Injection" width="600"/>
  <br>
  <b>Figure 4: RCE Payload Retrieving IAM Credentials</b>
</p>

### 3. Data Exfiltration
Using **AWS CloudShell** to simulate an external attacker environment, I configured the AWS CLI with the stolen credentials.
* **Target:** Private S3 Bucket containing `secret-information.txt`.
* **Action:** Successfully downloaded sensitive data to the attacker's environment.

<p align="center">
  <img src=".assets/Cloudshell S3 Data Exfiltration.png" alt="Data Exfiltration" width="800"/>
  <br>
  <b>Figure 5: Exfiltrating S3 Data via CloudShell</b>
</p>

## Defense & Analysis (Blue Team)

### GuardDuty Findings
Upon completion of the attack, AWS GuardDuty successfully generated high-severity findings:

1.  **Finding:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`
    * **Analysis:** GuardDuty detected that credentials created exclusively for the EC2 instance were used from a different IP address (the CloudShell session) to perform API calls. This confirmed the credential theft.

<p align="center">
  <img src=".assets/Instance Credential Exfiltration Alert.png" alt="Credential Exfiltration Alert" width="800"/>
  <br>
  <b>Figure 6: GuardDuty Detection of Credential Misuse</b>
</p>

2.  **Finding:** `Object:S3/MaliciousFile`
    * **Analysis:** After enabling Malware Protection for S3, I uploaded an EICAR test file. GuardDuty automatically scanned the object and flagged it as malware.

<p align="center">
  <img src=".assets/S3 Eicar test File Upload.png" alt="EICAR Upload" width="800"/>
  <br>
  <b>Figure 7: Uploading Malicious Test File</b>
</p>

<p align="center">
  <img src=".assets/S3 Malware Scan Alert.png" alt="Malware Scan Alert" width="800"/>
  <br>
  <b>Figure 8: GuardDuty S3 Malware Finding</b>
</p>

## Key Learnings
* **Input Sanitization:** The attack was possible due to lack of input validation in the web app (SQLi and RCE).
* **IMDS Protection:** Restricting access to the Instance Metadata Service (IMDSv2) and using minimal IAM roles is critical to preventing credential theft.
* **Continuous Monitoring:** GuardDuty provides necessary visibility into behavioral anomalies, specifically when valid credentials are used in unauthorized contexts.
