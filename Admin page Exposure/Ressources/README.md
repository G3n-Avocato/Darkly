# Admin page Exposure

## Breach type

* A01:2021 - Broken Access Control
    * CWE-200 - Information Exposure
    * CWE-601 - 
    * CWE-602 - Client-Side Enforcement of Server-Side Security

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


## How to avoid


## Sources
* https://robots-txt.com/
