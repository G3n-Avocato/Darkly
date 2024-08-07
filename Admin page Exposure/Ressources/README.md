# Admin page Exposure

The administrator page is a page present on all web applications, it is the configuration page of a website, only certain users must have the necessary privileges to access it.  

A robots.txt file tells a search engine's crawlers which URLs it can access on your site. This file controls how search engine robots crawl your site.

## Breach type

* A01:2021 - Broken Access Control   
    Information Disclosure :
    * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    * CWE-285: Improper Authorization -- (the client user should not have the permissions to access hidden files and sensitive files)

    Directory Traversal :
    * CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

* A07:2021 - Identification and Authentication Failures
    Broken Authentication :
    * CWE-287: Improper Authentication

## How to find the flag

* Find the admin page `http://192.168.56.101/admin/`

* Find the robots.txt file `http://192.168.56.101/robots.txt`

* On page robots.txt, they are two URL Path : `/whatever` and `/.hidden`

* Go the page `http://192.168.56.101/whatever/`

* Download the file `htpasswd`

* In this file they are : `root:437394baff5aa33daa618be47b75cb49`

* root is the username for admin page, the password is encrypt with MD5, to decrypt we use `https://md5decrypt.net/`, we obtain `qwerty123@`

* Return to the admin page, enter credentials

* Get your flag and profit !

## Risks

* Admin page exposure : 
    - an attacker can try to brute-force credentials, or exploit poorly secured resources.
    - Access to the administrator page generally gives full access to the website system, database information, all files and codes that make up the site, an attacker can modify the settings and configuration of the application (implant malware).

* Information disclosure :
    - robots.txt is a public file, the paths contained in the robots.txt will be checked by potential attackers, if paths or sensitive data are present, they can be exploited to allow other attacks on your site, such as data recovery or an unauthorized connection on the administrator page for example.

## How to avoid

* Admin page exposure : 
    - strengthen the password system, requiring a strong password policy, adding 2FA.
    - hide the url of the admin page. By making the URL of the administration page dynamic so that it changes regularly, a system must also be put in place so that real administrators have access without problem. It's also possible to limit access to this page to only certain IP addresses.  

* Information disclosure :
    - do not include paths to sensitive or restricted resources in the robots.txt file, this file is publicly accessible, its function is not to prevent access to the resources it contains.
    - protect access to sensitive resources like hidden file, and do not store password files on the site.

## Sources
* [Owasp Security Risk A01 - A07](https://owasp.org/www-project-top-ten/)
* [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
* [CWE-285](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-287](https://cwe.mitre.org/data/definitions/287.html)
* [Explanation robots.txt file](https://robots-txt.com/)
* [Admin page exposure](https://beaglesecurity.com/blog/vulnerability/administration-page-exposure.html)
* [Dynamic Url](https://www.larksuite.com/en_us/topics/cybersecurity-glossary/dynamic-url)