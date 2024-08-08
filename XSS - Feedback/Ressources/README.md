# XSS (Cross-site Scripting) Feadback page

XSS is a code injection vulnerability like SQL injections, in which malicious scripts are injected into websites, generally in the form of a browser-side script, to a different end user.

* There are three primary types of XSS: Stored XSS, Reflected XSS, and DOM-Based XSS.
    * Stored XSS (Persistent or Type II): The malicious script is permanently stored on the target server, such as in a database, comment field, or forum post. The script is executed whenever the stored data is retrieved and viewed by users.
    * Reflected XSS (Non-persistent or Type I): The malicious script is reflected off a web server, typically via a URL or form submission. The script is executed immediately and returned to the user as part of the response.
    * DOM-Based XSS: The vulnerability exists in the client-side code rather than the server-side. The malicious script is executed as a result of modifying the DOM environment in the victim's browser, typically using client-side JavaScript.

## Breach type

* A03:2021 - Injection
    * CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting).  
    The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.
    * CWE-20: Improper Input Validation

## How to find the flag

* Go the the feedback page : `http://192.168.56.101/index.php?page=feedback`
* After trying to inject complex scripts in the form, we realized that you just need to type the word `script` (or one of its letters) in the `name` or in the `message` field
* You can also type a basic script in the message field, ie `<script>alert</script>`. The script will not execute itself but you'll get your flag !

## Risks

* Data Theft: XSS attacks can be used to steal sensitive information, such as cookies, session tokens, and other private data, allowing attackers to impersonate users and gain unauthorized access to accounts.
* Malware Distribution: Attackers can use XSS to inject malicious scripts that can download and install malware on the victim’s device, compromising their system and data.
* Defacement: XSS can be used to modify the content of a website, leading to misinformation, reputation damage, and loss of user trust. This is particularly damaging for websites that rely on user-generated content.
* Phishing Attacks: XSS can be exploited to create fake login forms or other misleading interfaces, tricking users into providing their credentials or other sensitive information directly to the attacker.

## How to avoid

* Escape User Input: Use modern web framework (templating, auto-escaping) but you need also to know how you framework prevents XSS and where it has gaps.
* Input Validation and Sanitization: Validate and sanitize all user inputs on both client and server sides to ensure they do not contain malicious scripts. This can be done using libraries and frameworks that provide built-in functions for cleaning input.
* Content Security Policy (CSP): Implement a robust Content Security Policy that restricts the sources from which scripts can be loaded. This helps to mitigate the risk of executing unauthorized scripts on your site.
* Security review of the code to search for all places where input from an HTTP request could possibly make its way into the HTML output.

## Sources
* [vaadata XSS attacks](https://www.vaadata.com/blog/fr/failles-xss-principes-types-dattaques-exploitations-et-bonnes-pratiques-securite/)
* [Wikipedia Cross Site Scripting](https://en.wikipedia.org/wiki/Cross-site_scripting)
* [OWASP Types of Cross Site Scripting](https://owasp.org/www-community/Types_of_Cross-Site_Scripting)
* [OWASP A03:2021](https://owasp.org/Top10/A03_2021-Injection/)
* [CWE-79](https://cwe.mitre.org/data/definitions/79.html)