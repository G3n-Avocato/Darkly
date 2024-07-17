# Path Traversal
A path traversal attack (directory traversal) aims to access files and directories that are stored outside the web root folder. By mainipulating variables that reference files with "dot-dot-slash (../)" sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system.

## Breach type:

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## How to find the flag:
* Use this URL : http://192.168.56.101/index.php?page=../../../../../../../../etc/passwd

## Risks:
Every time a ressource or file is included by the application, there is a risk that an attacker may be able to include a file or remote resource you didn't authorize.


## How to avoid:
* Avoid User Input in File System Calls: Minimize the use of user input for file operations.
* Use Indexes: Instead of actual filenames, use indexes or predefined values.
* Restrict Path Construction: Surround user input with predefined path code to restrict path traversal.
* 

## Sources:
* https://cwe.mitre.org/data/definitions/22.html
* https://book.hacktricks.xyz/pentesting-web/file-inclusion
* https://owasp.org/www-community/attacks/Path_Traversal
* https://github.com/JahTheTrueGod/Directory-Traversal-Cheat-Sheet
* https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md