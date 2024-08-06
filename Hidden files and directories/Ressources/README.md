# Hidden files and directories

## Breach type

* Exposure of Information Through Directory Listing (CWE-548): This vulnerability occurs when a web server discloses the existence of files and directories that are not intended to be publicly accessible. This can be achieved through blind guessing attacks or by exploiting server misconfigurations that enable directory listings 5.

## How to find the flag

* Discover the existence of the file `robots.txt` at the url `192.168.56.101/robots.txt`. This file is commonly used to inform search engines that they need to ignore specific files or directories, and to give the adress of a sitemap.xml file.
* In `robots.txt` we find two URL path corresponding to two ignored directories of the website : 
    * `Disallow: /whatever`
    * `Disallow: /.hidden`
* The first one is used for another security breach so we'll focus on the second one : `./hidden`
* Inside, we find around 15000 directories, each containing one README.md file. The flag is obviously in one of the README files but we obvioulsy won`t check them manually.

## Risks


## How to avoid


## Sources