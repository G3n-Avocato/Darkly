# Buffer overflow


## Breach type:
* CWE 788 Access of Memory Location After End of Buffer.
    * Buffer overflow is considered a critical security vulnerability. It occurs when a program attempts to put more data in a buffer than it can hold. 
    * Writing outside the bounds of an allocated memory block can corrupt data, crash the program, or execute malicious code.

## How to find the flag:

* Go to the `survey` page
* Choose and inspect a survey grade field with the console `<select name="valeur" onchange="javascript:this.form.submit();">`
    * Here we understand that the value is submitted to the form on change
* Modify the html to cause an overflow of the grade input `<option value="1">99999999999999999999999</option>`
    * Select the grade "1" and it's done!

## Risks:

* Allows an attacker to execute malicious code or manipulate data. Overflow is used for: SQL injection, data corruption, exec malicious code.
* Out-of-bounds read give access to sensitive information like system details, buffers position in memory.
This knowledge can be used for futher attacks with more consequences.
* Corrupt data can cause denial of service or other operational problems and make the site unavailable.

## How to avoid:

* Validate and clean up all users input before using it in code.
* Use libraries, frameworks or languages that automatically manage certain overflow protections.
* Environment Hardening, Run or Compil the software using features or extensions that randomly arrange the positions of a program's executable and librairies in memory.
* Perform security tests regularly to identify and correct potential vulnerabilities with updates.

## Sources:
* https://owasp.org/www-community/vulnerabilities/Buffer_Overflow
* https://cwe.mitre.org/data/definitions/788.html
* https://cwe.mitre.org/data/definitions/119.html