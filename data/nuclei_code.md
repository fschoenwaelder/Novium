# Code

Learn about using external code with Nuclei

Nuclei enables the execution of external code on the host operating system. This feature allows security researchers, pentesters, and developers to extend the capabilities of Nuclei and perform complex actions beyond the scope of regular supported protocol-based testing.

By leveraging this capability, Nuclei can interact with the underlying operating system and execute custom scripts or commands, opening up a wide range of possibilities. It enables users to perform tasks such as system-level configurations, file operations, network interactions, and more. This level of control and flexibility empowers users to tailor their security testing workflows according to their specific requirements.

To write code template, a code block is used to indicate the start of the requests for the template. This block marks the beginning of the code-related instructions.

```yaml
# Start the requests for the template right here
code:
```

## **Engine**

To execute the code, a list of language interpreters, which are installed or available on the system environment, is specified. These interpreters can be and not limited to **`bash`** **`sh`** **`py`** **`python3`**, **`go`**, **`ps`**, among others, and they are searched sequentially until a suitable one is found. The identifiers for these interpreters should correspond to their respective names or identifiers recognized by the system environment.

```yaml
engine:
  - py
  - python3
```

The code to be executed can be provided either as an external file or as a code snippet directly within the template.

For an external file:

```yaml
source: helpers/code/pyfile.py
```

For a code snippet:

```yaml
source: |
  import sys
  print("hello from " + sys.stdin.read())
```

The target is passed to the template via stdin, and the output of the executed code is available for further processing in matchers and extractors. In the case of the Code protocol, the response part represents all data printed to stdout during the execution of the code.

## **Parts**

Valid **`part`** values supported by **Code** protocol for Matchers / Extractor are -

| **Value** | **Description** |
| --- | --- |
| response | execution output (trailing whitespaces are filtered) |
| stderr | Raw Stderr Output(if any) |

The provided example demonstrates the execution of a bash and python code snippet within the template. The specified engines are searched in the given order, and the code snippet is executed accordingly. Additionally, dynamic template variables are used in the code snippet, which are replaced with their respective values during the execution of the template which shows the flexibility and customization that can be achieved using this protocol.

```yaml
id: code-template

info:
  name: example code template
  author: pdteam
  severity: info

variables:
  OAST: "{{interactsh-url}}"

code:
  - engine:
      - sh
      - bash
    source: |
      echo "$OAST" | base64

  - engine:
      - py
      - python3
    source: |
      import base64
      import os
      
      text = os.getenv('OAST')
      text_bytes = text.encode('utf-8')
      base64_bytes = base64.b64encode(text_bytes)
      base64_text = base64_bytes.decode('utf-8')
      
      print(base64_text)

http:
  - method: GET
    path:
      - "{{BaseURL}}/?x={{code_1_response}}"
      - "{{BaseURL}}/?x={{code_2_response}}"

# digest: 4a0a0047304502202ce8fe9f5992782da6ba59da4e8ebfde9f19a12e247adc507040e9f1f1124b4e022100cf0bc7a44a557a6655f79a2b4789e103f5099f0f81a8d1bc4ad8aabe7829b1c5:8eeeebe39b11b16384b45bc7e9163000
```

Apart from required fields mentioned above, Code protocol also supports following optional fields to further customize the execution of code.

## **Args**

Args are arguments that are sent to engine while executing the code. For example if we want to bypass execution policy in powershell for specific template this can be done by adding following args to the template.

```yaml
- engine:
    - powershell
    - powershell.exe
  args:
    - -ExecutionPolicy
    - Bypass
    - -File
```

## **Pattern**

Pattern field can be used to customize name / extension of temporary file while executing a code snippet in a template

```yaml
 pattern: "*.ps1"
```

adding **`pattern: "*.ps1"`** will make sure that name of temporary file given pattern.

## **Examples**

This code example shows a basic response based on DSL.

```yaml
id: code-template

info:
  name: example code template
  author: pdteam
  severity: info

self-contained: true

code:
  - engine:
      - py
      - python3
    source: |
      print("Hello World")
    extractors:
      - type: dsl
        dsl:
          - response

# digest: 4a0a0047304502204576db451ff35ea9a13c107b07a6d74f99fd9a78f5c2316cc3dece411e7d5a2b022100a36db96f2a56492147ca3e7de3c4d36b8e1361076a70924061790003958c4ef3:c40a3a04977cdbf9dca31c1002ea8279
```

Below is a example code template where we are executing a powershell script while customizing behaviour of execution policy and setting pattern to **`*.ps1`**

```yaml
id: ps1-code-snippet

info:
  name: ps1-code-snippet
  author: pdteam
  severity: info
  description: |
    ps1-code-snippet
  tags:
    - code

code:
  - engine:
      - powershell
      - powershell.exe
    args:
      - -ExecutionPolicy
      - Bypass
      - -File
    pattern: "*.ps1"
    source: |
      $stdin = [Console]::In
      $line = $stdin.ReadLine()
      Write-Host "hello from $line"
    
    matchers:
      - type: word
        words:
          - "hello from input"

# digest: 4a0a00473045022100eb01da6b97893e7868c584f330a0cd52df9bddac005860bb8595ba5b8aed58c9022050043feac68d69045cf320cba9298a2eb2e792ea4720d045d01e803de1943e7d:4a3eb6b4988d95847d4203be25ed1d46
```

## **Running Code Templates**

By default Nuclei will not execute code templates. To enable code protocol execution, **`-code`** flag needs to be explicitly passed to nuclei.

```yaml
nuclei -t code-template.yaml -code
```