# JavaScript

Learn more about using JavaScript with Nuclei v3

## **Introduction**

Nuclei and the ProjectDiscovery community thrive on the ability to write exploits/checks in a fast and simple YAML format. We work consistently to improve our **Nuclei templates** to encourage those as the standard for writing security checks. We understand the limitations and are always working to address those, while we work on expanding our capabilities.

Nuclei currently supports writing templates for complex HTTP, DNS, SSL protocol exploits/checks through a powerful and easy to use DSL in the Nuclei engine. However, we understand the current support may not be enough for addressing vulnerabilities across all protocols and in non-remote domains of security like local privilege escalation checks, kernel etc.

To address this, Nuclei v3 includes an embedded runtime for JavaScript that is tailored for **Nuclei** with the help of [**Goja**](https://github.com/dop251/goja).

## **Features**

**Support for provider or driver-specific exploits**

Some vulnerabilities are specific to software or a driver. For example, a Redis buffer overflow exploit, an exploit of specific VPN software, or exploits that are not part of the Internet Engineering Task Force (IETF) standard protocols.

Since these are not standard protocols they are not typically added to Nuclei. Detection for these types of exploits cannot be written using a ‘network’ protocol. They are often very complex to write and detection for these exploits can be written by exposing the required library in Nuclei (if not already present). We now provide support for writing detection of these types of exploits with JavaScript.

**Non-network checks**

Security is not limited to network exploits. Nuclei provides support for security beyond network issues like:

- Local privilege escalation checks
- Kernel exploits
- Account misconfigurations
- System misconfigurations

**Complex network protocol exploits**

Some network exploits are very complex to write due to nature of the protocol or exploit itself. For example [**CVE-2020-0796**](https://nvd.nist.gov/vuln/detail/cve-2020-0796) requires you to manually construct a packet. Detection for these exploits is usually written in Python but now can be written in JavaScript.

**Multi-step exploits**

LDAP or Kerberos exploits usually involve a multi-step process of authentication and are difficult to write in YAML-based DSL. JavaScript support makes this easier.

**Scalable and maintainable exploits**

One off exploit detection written in code are not scalable and maintainable due to nature of language, boilerplate code, and other factors. Our goal is to provide the tools to allow you to write the **minimum** code required to run detection of the exploit and let Nuclei do the rest.

**Leveraging Turing complete language**

While YAML-based DSL is powerful and easy to use it is not Turing complete and has its own limitations. Javascript is Turing complete thus users who are already familiar with JavaScript can write network and other detection of exploits without learning new DSL or hacking around existing DSL.

## **Requirements**

- A basic knowledge of JavaScript (loops, functions, arrays) is required to write a JavaScript protocol template
- Nuclei v3.0.0 or above

# **JavaScript Protocol**

Review examples of JavaScript with Nuclei v3

The JavaScript protocol was added to Nuclei v3 to allow you to write checks and detections for exploits in JavaScript and to bridge the gap between network protocols.

- Internally any content written using the JavaScript protocol is executed in Golang.
- The JavaScript protocol is **not** intended to fit into or be imported with any existing JavaScript libraries or frameworks outside of the Nuclei ecosystem.
- Nuclei provides a set of functions, libraries that are tailor-made for writing exploits and checks and only adds required/necessary functionality to complement existing YAML-based DSL.
- The JavaScript protocol is **not** intended to be used as a general purpose JavaScript runtime and does not replace matchers, extractors, or any existing functionality of Nuclei.
- Nuclei v3.0.0 ships with **15+ libraries (ssh, ftp, RDP, Kerberos, and Redis)** tailored for writing exploits and checks in JavaScript and will be continuously expanded in the future.

## **Simple Example**

Here is a basic example of a JavaScript protocol template:

```yaml
id: ssh-server-fingerprint
info:  
  name: Fingerprint SSH Server Software  
  author: Ice3man543,tarunKoyalwar  
  severity: info  
  javascript:  
  - code: |      
      var m = require("nuclei/ssh");      
      var c = m.SSHClient();      
      var response = c.ConnectSSHInfoMode(Host, Port);      
      to_json(response);    
    args:      
      Host: "{{Host}}"      
      Port: "22"    
    extractors:      
      - type: json        
        json:          
          - '.ServerID.Raw'
```

In the Nuclei template example above, we are fingerprinting SSH server software by connecting in non-auth mode and extracting the server banner. Let's break down the template.

### **Code Section**

The **`code:`** contains actual JavaScript code that is executed by Nuclei at runtime. In the above template, we are:

- Importing **`nuclei/ssh`** module/library
- Creating a new instance of **`SSHClient`** object
- Connecting to SSH server in **`Info`** mode
- Converting response to json

### **Args Section**

The **`args:`** section can be simply understood as variables in JavaScript that are passed at runtime and support DSL usage.

### **Output Section**

The value of the last expression is returned as the output of JavaScript protocol template and can be used in matchers and extractors. If the server returns an error instead, then the **`error`** variable is exposed in the matcher or extractor with an error message.

## **SSH Bruteforce Example**

**SSH Password Bruteforce Template**

```yaml
id: ssh-brute
info:  
  name: SSH Credential Stuffing  
  author: tarunKoyalwar  
  severity: critical  
  javascript:  
  - pre-condition: |      
      var m = require("nuclei/ssh");      
      var c = m.SSHClient();      
      var response = c.ConnectSSHInfoMode(Host, Port);      
      // only bruteforce if ssh server allows password based authentication      
      response["UserAuth"].includes("password")    
    code: |      
      var m = require("nuclei/ssh");      
      var c = m.SSHClient();      
      c.Connect(Host,Port,Username,Password);    
    args:      
      Host: "{{Host}}"      
      Port: "22"      
      Username: "{{usernames}}"      
      Password: "{{passwords}}"    
    threads: 10    
    attack: clusterbomb    
    payloads:      
      usernames: helpers/wordlists/wp-users.txt      
      passwords: helpers/wordlists/wp-passwords.txt    
    stop-at-first-match: true    
    matchers:      
      - type: dsl        
        dsl:          
          - "response == true"          
          - "success == true"        
        condition: and
```

In the example template above, we are bruteforcing ssh server with a list of usernames and passwords. We can tell that this might not have been possible to achieve with the network template. Let's break down the template.

### **Pre-Condition**

**`pre-condition`** is an optional section of JavaScript code that is executed before running "code" and acts as a pre-condition to exploit. In the above template, before attempting brute force, we check if:

- The address is actually an SSH server.
- The ssh server is configured to allow password-based authentication.

**Further explanation**

- If pre-condition returns **`true`** only then **`code`** is executed; otherwise, it is skipped.
- In the code section, we import **`nuclei/ssh`** module and create a new instance of **`SSHClient`** object.
- Then we attempt to connect to the ssh server with a username and password. This template uses [**payloads**](https://docs.projectdiscovery.io/templates/protocols/http/http-payloads) to launch a clusterbomb attack with 10 threads and exits on the first match.

Looking at this template now, we can tell that JavaScript templates are powerful for writing multistep and protocol/vendor-specific exploits, which is a primary goal of the JavaScript protocol.

## **Init**

**`init`** is an optional JavaScript section that can be used to initialize the template, and it is executed just after compiling the template and before running it on any target. Although it is rarely needed, it can be used to load and preprocess data before running a template on any target.

For example, in the below code block, we are loading all ssh private keys from **`nuclei-templates/helpers`** directory and storing them as a variable in payloads with the name **`keys`**. If we were loading private keys from the "pre-condition" code block, then it would have been loaded for every target, which is not ideal.

```yaml
variables:  
  keysDir: "helpers/"  # load all private keys from this directory
javascript:    
  # init field can be used to make any preperations before the actual exploit    
  # here we are reading all private keys from helpers folder and storing them in a list  
  - init: |      
      let m = require('nuclei/fs');      
      let privatekeys = m.ReadFilesFromDir(keysDir)      
      updatePayload('keys',privatekeys)    
    payloads:      
      # 'keys' will be updated by actual private keys after init is executed      
      keys:         
        - key1        
        - key2
```

Two special functions that are available in the **`init`** block are

| **Function** | **Description** |
| --- | --- |
| **`updatePayload(key,value)`** | updates payload with given key and value |
| **`set(key,value)`** | sets a variable with given key and value |

# Modules

### **Bytes**

# **Namespace: bytes**

## **Table of contents**

### **Classes**

- [**Buffer**](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/bytes.Buffer)

### **Fs**

# **Namespace: fs**

## **Table of contents**

### **Functions**

- [**ListDir**](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#listdir)
- [**ReadFile**](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#readfile)
- [**ReadFileAsString**](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#readfileasstring)
- [**ReadFilesFromDir**](https://docs.projectdiscovery.io/templates/protocols/javascript/modules/fs#readfilesfromdir)

## **Functions**

### **ListDir**

▸ **ListDir**(**`path`**, **`itemType`**): **`string`**[] | **`null`**

ListDir lists itemType values within a directory depending on the itemType provided itemType can be any one of ['file','dir',"]

### **Parameters**

| **Name** | **Type** |
| --- | --- |
| **`path`** | **`string`** |
| **`itemType`** | **`string`** |

### **Returns**

**`string`**[] | **`null`**

**`Example`**

```jsx
const fs = require('nuclei/fs');// this will only return files in /tmp directoryconst files = fs.ListDir('/tmp', 'file');
```

**`Example`**

```jsx
const fs = require('nuclei/fs');// this will only return directories in /tmp directoryconst dirs = fs.ListDir('/tmp', 'dir');
```

**`Example`**

```jsx
const fs = require('nuclei/fs');// when no itemType is provided, it will return both files and directoriesconst items = fs.ListDir('/tmp');
```

### **Defined in**

fs.ts:26

---

### **ReadFile**

▸ **ReadFile**(**`path`**): **`Uint8Array`** | **`null`**

ReadFile reads file contents within permitted paths and returns content as byte array

### **Parameters**

| **Name** | **Type** |
| --- | --- |
| **`path`** | **`string`** |

### **Returns**

**`Uint8Array`** | **`null`**

**`Example`**

```jsx
const fs = require('nuclei/fs');// here permitted directories are $HOME/nuclei-templates/*const content = fs.ReadFile('helpers/usernames.txt');
```

### **Defined in**

fs.ts:42

---

### **ReadFileAsString**

▸ **ReadFileAsString**(**`path`**): **`string`** | **`null`**

ReadFileAsString reads file contents within permitted paths and returns content as string

### **Parameters**

| **Name** | **Type** |
| --- | --- |
| **`path`** | **`string`** |

### **Returns**

**`string`** | **`null`**

**`Example`**

```jsx
const fs = require('nuclei/fs');// here permitted directories are $HOME/nuclei-templates/*const content = fs.ReadFileAsString('helpers/usernames.txt');
```

### **Defined in**

fs.ts:58

---

### **ReadFilesFromDir**

▸ **ReadFilesFromDir**(**`dir`**): **`string`**[] | **`null`**

ReadFilesFromDir reads all files from a directory and returns a string array with file contents of all files

### **Parameters**

| **Name** | **Type** |
| --- | --- |
| **`dir`** | **`string`** |

### **Returns**

**`string`**[] | **`null`**

**`Example`**

```jsx
const fs = require('nuclei/fs');// here permitted directories are $HOME/nuclei-templates/*const contents = fs.ReadFilesFromDir('helpers/ssh-keys');log(contents);
```