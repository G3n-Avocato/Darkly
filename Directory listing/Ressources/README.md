# Directory listing

Web servers can be configured to automatically list the contents of directories that do not have an index page present. This can aid an attacker by enabling them to quickly identify the resources at a given path, and proceed directly to analyzing and attacking those resources. It particularly increases the exposure of sensitive files within the directory that are not intended to be accessible to users, such as temporary files and crash dumps.

## Breach type

* A01:2021 - Broken Access Control  
  
    Information Disclosure:
    * CWE-548: Exposure of Information Through Directory Listing
    * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    * CWE-285: Improper Authorization -- (the client user should not have the permissions to access hidden files and sensitive files)
    * CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory: The product places sensitive information into files or directories that are accessible to actors who are allowed to have access to the files, but not to the sensitive information. 
  
    Directory Traversal:
    * CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## How to find the flag

* Discover the existence of the file `robots.txt` at the url `192.168.56.101/robots.txt`. This file is commonly used to inform search engines that they need to ignore specific files or directories, and to give the adress of a sitemap.xml file.
* In `robots.txt` we find two URL path corresponding to two ignored directories of the website : 
    * `Disallow: /whatever`
    * `Disallow: /.hidden`
* The first one is used for another security breach so we'll focus on the second one : `./hidden`
* Inside, we find around 15000 directories, each containing one README.md file. The flag is obviously in one of the README files but we obvioulsy won`t check them manually.

## Risks

* Information disclosure:
    * Information disclosure often serves as a stepping stone for chaining with other vulnerabilities, leading to more severe attacks like SQL injection, command injection, or remote code execution.
    * If paths or sensitive data are present, they can be exploited to allow other attacks on your site, such as data recovery (backup files or old versions of the application that might still contain sensitive data, which can be recovered and exploited) or an unauthorized connection on the administrator page for example.

## How to avoid

* Do not include paths to sensitive or restricted resources in the robots.txt file, this file is publicly accessible, its function is not to prevent access to the resources it contains.
* Protect access to sensitive resources like hidden file, and do not store password files on the site.
* Avoid storing sensitive information (e.g., passwords, API keys, personal data) in files or directories that can be accessed externally.
* Ensure sensitive information is stored in secure, non-public locations such as environment variables, secure databases, or encrypted files.
* Validate and sanitize all inputs that might determine file paths or names to prevent unauthorized access or file placement.
* Limit the access of information to only those who need it (minimum privilege required).
* Implement proper session management to prevent unauthorized access, including the use of secure tokens and session expiration.

## Sources
* [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
* [CWE-285](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-538](https://cwe.mitre.org/data/definitions/538.html)
* [CWE-548](https://cwe.mitre.org/data/definitions/548.html)
* [Explanation robots.txt file](https://robots-txt.com/)