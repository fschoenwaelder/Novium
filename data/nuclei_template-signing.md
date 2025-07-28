# Template Signing

Review details on template signing for Nuclei

Template signing via the private-public key mechanism is a crucial aspect of ensuring the integrity, authenticity, and security of templates. This mechanism involves the use of asymmetric cryptography, specifically the Elliptic Curve Digital Signature Algorithm (ECDSA), to create a secure and verifiable signature.

In this process, a template author generates a private key that remains confidential and securely stored. The corresponding public key is then shared with the template consumers. When a template is created or modified, the author signs it using their private key, generating a unique signature that is attached to the template.

Template consumers can verify the authenticity and integrity of a signed template by using the author’s public key. By applying the appropriate cryptographic algorithm (ECDSA), they can validate the signature and ensure that the template has not been tampered with since it was signed. This provides a level of trust, as any modifications or unauthorized changes to the template would result in a failed verification process.

By employing the private-public key mechanism, template signing adds an additional layer of security and trust to the template ecosystem. It helps establish the identity of the template author and ensures that the templates used in various systems are genuine and have not been altered maliciously.

**What does signing a template mean?**

Template signing is a mechanism to ensure the integrity and authenticity of templates. The primary goal is to provide template writers and consumers a way to trust crowdsourced or custom templates ensuring that they are not tampered with.

All [**official Nuclei templates**](https://github.com/projectdiscovery/nuclei-templates) include a digital signature and are verified by Nuclei while loading templates using ProjectDiscovery’s public key (shipped with the Nuclei binary).

Individuals or organizations running Nuclei in their work environment can generate their own key-pair with **`nuclei`** and sign their custom templates with their private key, thus ensuring that only authorized templates are being used in their environment.

This also allows entities to fully utilize the power of new protocols like **`code`** without worrying about malicious custom templates being used in their environment.

**NOTE:**

- **Template signing is optional for all protocols except `code`**.
- **Unsigned code templates are disabled and can not be executed using Nuclei**.
- **Only signed code templates by the author (yourself) or ProjectDiscovery can be executed.**
- **Template signing is primarily introduced to ensure security of template to run code on host machine.**
- Code file references (for example: **`source: protocols/code/pyfile.py`**) are allowed and content of these files is included in the template digest.
- Payload file references (for example: **`payloads: protocols/http/params.txt`**) are not included in the template digest as it is treated as a payload/helper and not actual code that is being executed.
- Template signing is deterministic while both signing and verifying a template i.e. if a code file is referenced in a template that is present outside of templates directory with **`lfa`** flag then verification will fail if same template is used without **`lfa`** flag. (Note this only applies to **`lfa`** i.e. local file access flag only)

### **Signing Custom Template**

The simplest and recommended way to generate key-pair and signing/verfifying templates is to use **`nuclei`** itself.

When signing a template if key-pair does not exist then Nuclei will prompt user to generate a new key-pair with options.

```bash
$ ./nuclei -t templates.yaml -sign
[INF] Generating new key-pair for signing templates
[*] Enter User/Organization Name (exit to abort) : acme
[*] Enter passphrase (exit to abort): 
[*] Enter same passphrase again: 
[INF] Successfully generated new key-pair for signing templates
```

> Note: Passphrase is optional and can be left blank when used private key is encrypted with passphrase using PEMCipherAES256 Algo
> 

Once a key-pair is generated, you can sign any custom template using **`-sign`** flag as shown below.

```bash
$ ./nuclei -t templates.yaml -sign
[INF] All templates signatures were elaborated success=1 failed=0
```

> Note: Every time you make any change in your code template, you need to re-sign it to run with Nuclei.
> 

### **Template Digest and Signing Keys**

When a template is signed, a digest is generated and added to the template. This digest is a hash of the template content and is used to verify the integrity of the template. If the template is modified after signing, the digest will change, and the signature verification will fail during template loading.

```
# digest: 4a0a00473045022100eb01da6b97893e7868c584f330a0cd52df9bddac005860bb8595ba5b8aed58c9022050043feac68d69045cf320cba9298a2eb2e792ea4720d045d01e803de1943e7d:4a3eb6b4988d95847d4203be25ed1d46
```

The digest is in the format of **`signature:fragment`**, where the signature is the digital signature of the template used to verify its integrity, and the fragment is metadata generated by MD5 hashing the public key to disable re-signing of code templates not written by you.

The key-pair generated by Nuclei is stored in two files in the **`$CONFIG/nuclei/keys directory`**, where **`$CONFIG`** is the system-specific config directory. The private key is stored in nuclei-user-private-key.pem, which is encrypted with a passphrase if provided. The public key is stored in nuclei-user.crt, which includes the public key and identifier (e.g., user/org name) in a self-signed certificate.

```bash
$ la ~/.config/nuclei/keys total 16
-rw-------  1 tarun  staff   251B Oct  4 21:45 nuclei-user-private-key.pem # encrypted private key with passphrase
-rw-------  1 tarun  staff   572B Oct  4 21:45 nuclei-user.crt # self signed certificate which includes public key and identifier (i.e user/org name)
```

To use the public key for verification, you can either copy it to the **`$CONFIG/nuclei/keys`** directory on another user's machine, or set the **`NUCLEI_USER_CERTIFICATE`** environment variable to the path or content of the public key.

To use the private key, you can copy it to the **`$CONFIG/nuclei/keys`** directory on another user's machine, or set the **`NUCLEI_USER_PRIVATE_KEY`** environment variable to the path or content of the private key.

```bash
$ export NUCLEI_USER_CERTIFICATE=$(cat path/to/nuclei-user.crt)
$ export NUCLEI_USER_PRIVATE_KEY=$(cat path/to/nuclei-user-private-key.pem)
```

It's important to note that you are responsible for securing and managing the private key, and Nuclei has no accountability for any loss of the private key.

By default, Nuclei loads the user certificate (public key) from the default locations mentioned above and uses it to verify templates. When running Nuclei, it will execute signed templates and warn about executing unsigned custom templates and block unsigned code templates. You can disable this warning by setting the **`HIDE_TEMPLATE_SIG_WARNING`** environment variable to **`true`**.

## **FAQ**

**Found X unsigned or tampered code template?**

```bash
./nuclei -u scanme.sh -t simple-code.yaml                      
__     _   ____  __  _______/ /__  (_)  
/ __ \/ / / / ___/ / _ \/ / 
/ / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.0.0-dev		projectdiscovery.io

[WRN] Found 1 unsigned or tampered code template (carefully examine before using it & use -sign flag to sign them)
[INF] Current nuclei version: v3.0.0-dev (development)
[INF] Current nuclei-templates version: v9.6.4 (latest)
[WRN] Executing 1 unsigned templates. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] No results found. Better luck next time!
[FTL] Could not run nuclei: no templates provided for scan
```

Here **`simple-code.yaml`** is a code protocol template which is not signed or content of template has been modified after signing which indicates loss of integrity of template. If you are template writer then you can go ahead and sign the template using **`-sign`** flag and if you are template consumer then you should carefully examine the template before signing it.

**Re-signing code templates are not allowed for security reasons?**

```bash
nuclei -u scanme.sh -t simple-code.yaml -sign
[ERR] could not sign 'simple-code.yaml': [signer:RUNTIME] re-signing code templates are not allowed for security reasons.
[INF] All templates signatures were elaborated success=0 failed=1
```

The error message **`re-signing code templates are not allowed for security reasons`** comes from the Nuclei engine. This error indicates that a code template initially signed by another user and someone is trying to re-sign it.

This measure was implemented to prevent running untrusted templates unknowingly, which might lead to potential security issues. When you encounter this error, it suggests that you’re dealing with a template that has been signed by another user Likely, the original signer is not you or the team from projectdiscovery.

By default, Nuclei disallows executing code templates that are signed by anyone other than you or from the public templates provided by projectdiscovery/nuclei-templates.

This is done to prevent potential security abuse using code templates.

To resolve this error:

1. Open and thoroughly examine the code template for any modifications.
2. Manually remove the existing digest signature from the template.
3. Sign the template again.

This way, you can ensure that only templates verified and trusted by you (or projectdiscovery) are run, thus maintaining a secure environment.