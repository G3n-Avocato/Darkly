# Path Traversal

A path traversal attack (directory traversal) aims to access files and directories that are stored outside the web root folder. By mainipulating variables that reference files with "dot-dot-slash (../)" sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system.

## Breach type:

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
CWE-23: Relative Path Traversal
CWE-36: Absolute Path Traversal

## How to find the flag:

* Use this URL : http://192.168.56.101/index.php?page=../../../../../../../../etc/passwd

## Risks:

Every time a ressource or file is included by the application, there is a risk that an attacker may be able to include a file or remote resource you didn't authorize.
* Integrity: The attacker may be able to create or overwrite critical files that are used to execute code, such as programs or libraries.
* The attacker may be able to create files, such ad programs, librairies or important data, an attacker can bypass authentication with it.
* Expose sensitive data.
* corrupt unexpected critical files such as programs or important data, it has the potential to lock out product users. 

## How to avoid:

* Input Validation:
    * Use an "accept known good" input validation strategy, with list of acceptable inputs, reject any input that does not strictly conform to specifications, or transform it into something taht does.
    * Consider all potentially relevant properties, use allowlist that limit the character set to be used, only allow a single '.' character to avoid CWE-23, exclude directory separators such as '/' or '\', to avoid CWE-36 
    * Use a list of allowable file extensions to avoid CWE-434: Unrestricted Upload of File with Dangerous Type.
* Avoid User Input in File System Calls: Minimize the use of user input for file operations.
* Use Indexes: Instead of actual filenames, use indexes or predefined values.
* Restrict Path Construction: Surround user input with predefined path code to restrict path traversal.
* Use chrooted jails or similar sandbox, restrict users' access to their personal directory by creating a "virtual prison" where each user will be isolated in their own cell
* Store librairy, include and utility files outside of the web document root. Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers to access it.
* Use Firewall that can detect attacks against this weakness. 

## Sources:
* https://cwe.mitre.org/data/definitions/22.html
* https://book.hacktricks.xyz/pentesting-web/file-inclusion
* https://owasp.org/www-community/attacks/Path_Traversal
* https://github.com/JahTheTrueGod/Directory-Traversal-Cheat-Sheet