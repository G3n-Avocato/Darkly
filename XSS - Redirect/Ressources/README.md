# XSS (Cross-site Scripting) Redirect social network

## Breach type:
A7: Cross-Site Scripting (XSS)". This category highlights the prevalence and risk associated with XSS vulnerabilities in web applications.
    * CWE-601: URL Redirection to Untrusted Site ('Open Redirect'). It refers to the security weakness where an application redirects users to a location specified by an attacker-controlled URL. 

## How to find the flag:
* Go to the homepage `http://192.168.56.101/index.php`
* Press `F12` to open the inspector then click on one of the three social media icons at the bottom of the page.
* You'll find an external href redirection `<a href="index.php?page=redirect&amp;site=instagram" class="icon fa-instagram"></a>`
* Modify the redirection by putting the address of your choice in the `site` field value, ie `site=www.google.com`
* Get your flag and profit !

## Risks:
* Phishing attacks: Redirecting users to a malicious site that mimics a legitimate one to steal credentials or sensitive information.
* Malware delivery: Redirecting users to a site that hosts malware compromising their system and data.
* XSS attacks: If the redirect URL is not properly validated and sanitized, it can lead to XSS vulnerabilities, allowing attackers to execute arbitrary scripts in the context of other users' sessions (more details at `XSS - Feedback` section)

## How to avoid:
* Use a Safe Redirect Mechanism: Implement a safe redirect mechanism that checks the validity of the URL before performing the redirect. 
    * Whitelist URLs: Only allow redirects to URLs that are explicitly trusted.
    * Use Regular Expressions: Validate the URL format using regular expressions.
* Avoid Direct User Input in Redirects: Do not use user input directly in redirect URLs! Instead, use server-side logic to determine the target URL. The construction of the URLs server-side is the best way to avoid manipulation by the user!

## Sources:
* https://www.vaadata.com/blog/fr/failles-xss-principes-types-dattaques-exploitations-et-bonnes-pratiques-securite/
* https://en.wikipedia.org/wiki/Cross-site_scripting
* https://owasp.org/www-community/attacks/xss/