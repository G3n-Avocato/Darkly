
## Breach type:

According to OWASP, improper file type handling is a common vulnerability and could fall under the following categories:

* OWASP Top 10 2017: A5 - Security Misconfiguration (Unvalidated Redirects and Forwards).
* OWASP Top 10 2021: A8 - Security of APIs and Services (Injection).

## Risks:

* If the server accepts and processes the uploaded file `coucou.php` as an image `image/jpeg`, it enables an attacker to execute malicious code on the server.
* Remote Code Execution (RCE) allows attackers to run arbitrary commands on the server. They can steal sensitive data, modify files, or exploit other vulnerabilities to escalate privileges.

## How to avoid:

* Validate the actual MIME type of the uploaded file rather than relying solely on the file extension.
* Limit allowed file types to only those necessary for the application.
* Rename uploaded files randomly and not rely on the file extension.

## Sources:
* 
* https://chocapikk.com/posts/2023/faille_upload/