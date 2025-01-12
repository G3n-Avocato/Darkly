# IP Spoofing

IP spoofing allows you to pose as a reliable source to another machine, site, server, network. By using tools that allow you to modify the sender's source address in IP packets. This action only occurs at the network level.

## Breach type
* A07:2021 - Identification and Authentication Failures
    * CWE-290: Authentication Bypass by Spoofing
    * CWE-291: Reliance on IP Address for Authentication
    * CWE-348: Use of Less Trusted Source

## How to find the flag

* Launch the inspector on the homepage
* Click on the href link hidden in the footer : `<a href="?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f"><li>&copy; BornToSec</li></a>`
* Discover a hidden page with informations about the Albatros and an image and a hidden text in the `<div class="container">` saying : 
    `You must come from : "https://www.nsa.gov/"." (...) "Let's use this browser : "ft_bornToSec". It will help you a lot !`

* Use curl to impersonate the browser ft_bornToSec coming from https://www.nsa.gov: 

    `curl -A "ft_bornToSec" -e "https://www.nsa.gov/" -L "http://192.168.56.101/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f" | grep flag`

* How it works :

    `-A "ft_bornToSec"`: This option sets the User-Agent header of the HTTP request. The User-Agent is a header that identifies the client (in this case, cURL) to the server. Here, it is set as "ft_bornToSec".

    `-e "https://www.nsa.gov/"`: The -e or --referer option specifies the Referer header. This header indicates which URL the browser accessed before accessing the current URL. In this example, it is set to "https://www.nsa.gov/", which means cURL simulates coming from the site www.nsa.gov.

    `-L`: This option instructs CURL to follow redirects automatically. If the server responds with a status code indicating a redirection (e.g., 301 or 302), cURL will follow the redirection and request the new URL.

## Risks
* DDOS attacks using many different IPs, to overwhelm computer servers with packets of data, it slows down or crash a website/network.
* IP spoofing allows you to hide the infiltration of a network by botnets.
* Can allows you to bypass authentication, access user sessions, access sensitive or private data, allows unauthorized execution of code or commands.
* Man in the middle attacks

## How to avoid

It's necessary to use these methods together in order to be truly protected against it:

* Detect IP spoofing/Deploying packet filtering:
    * It's difficult to detect IP spoofing because this doesn'leave external sign. But we can use network monitoring tools to analyze traffic at endpoints.

* Two packet filtering systems:
    * Ingress filtering looks at incoming packets, checks source IP header to verify it matches with an authorized ip source.
    * Egress filtering looks at outgoing packets, checks source IP addresses that don't match with those on the organization's network for prevent insiders from launching IP spoofing attacks.

* Use Packet Filtering with firewalls and IDS : 
    * The firewall is used to filter traffic, blocking access from unauthorized sources and spoofed IP addresses. Firewalls can inspect IP packet headers to ensure they are legitimate.
    * The IDS is designed to detect and alert on potential malicious activities or policy violations within a network. It does not block traffic but monitors and analyzes it for suspicious behavior.

* Using robust verification methods, even among networked computers, can prevent the development of a botnetwork in the case where a computer in a network is infected.

* Migrate sites to IPv6, it makes Ip IP spoofing harder by including encryption and authentication steps. High proportion of the world's internet traffic still uses IPv4.

## Sources
* [IP Spoofing via HTTP Headers](https://owasp.org/www-community/pages/attacks/ip_spoofing_via_http_headers)
* [Test CMD curl](https://www.baeldung.com/linux/curl-test-ip-spoofing)
* [IP Spoofing Wikipedia](https://en.wikipedia.org/wiki/IP_address_spoofing#:~:text=In%20computer%20networking%2C%20IP%20address,of%20impersonating%20another%20computing%20system)
* [IP Spoofing def](https://usa.kaspersky.com/resource-center/threats/ip-spoofing)
* [CWE-290](https://cwe.mitre.org/data/definitions/290.html)
