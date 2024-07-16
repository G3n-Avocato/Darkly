# XSS (Cross-site Scripting) Feadback page

## Breach type:
* XSS is a code injection vulnerability like SQL injections, in which malicious scripts are injected into websites, generally in the form of a browser side script, to a different end user.
* They are two primary types of XSS : Stored XSS and Reflected XSS, + DOM Based XSS. 
    * Stored XSS (Persistent or Type II)
    * 

## How to find the flag:

* 
* 

## Risks:
* access any cookies, session tokens, or other sensitive information retained by the browser and used with that site
* declosure of end user files,
* redirecting the user to some other page or site
* modifying presentation of content 


## How to avoid:

* Use modern web framework (templating, auto-escaping) but you need also to know how you framework prevents XSS and where it has gaps.

* Correct :
    * perform a security review of the code and search for all places where input from an HTTP request could possibly make its way into the HTML output.

## Sources:
https://www.vaadata.com/blog/fr/failles-xss-principes-types-dattaques-exploitations-et-bonnes-pratiques-securite/

https://owasp.org/www-community/attacks/xss/#:~:text=XSS%20attacks%20can%20generally%20be,that%20is%20discussed%20separately%20here.

https://owasp.org/www-community/Types_of_Cross-Site_Scripting