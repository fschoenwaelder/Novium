# File

Learn about using Nuclei to work with the local file system

## **Overview**

Nuclei allows modelling templates that can match/extract on the local file system.

```yaml
# Start of file template block
file:
```

## **Extensions**

To match on all extensions (except the ones in default denylist), use the following -

```yaml
extensions:
  - all
```

You can also provide a list of custom extensions that should be matched upon.

```yaml
extensions:
  - py
  - go
```

A denylist of extensions can also be provided. Files with these extensions will not be processed by nuclei.

```yaml
extensions:
  - all
denylist:
  - go
  - py
  - txt
```

By default, certain extensions are excluded in nuclei file module. A list of these is provided below-

```
3g2,3gp,7z,apk,arj,avi,axd,bmp,css,csv,deb,dll,doc,drv,eot,exe,flv,gif,gifv,gz,h264,ico,iso,jar,jpeg,jpg,lock,m4a,m4v,map,mkv,mov,mp3,mp4,mpeg,mpg,msi,ogg,ogm,ogv,otf,pdf,pkg,png,ppt,psd,rar,rm,rpm,svg,swf,sys,tar,tar.gz,tif,tiff,ttf,txt,vob,wav,webm,wmv,woff,woff2,xcf,xls,xlsx,zip
```

## **More Options**

**max-size** parameter can be provided which limits the maximum size (in bytes) of files read by nuclei engine.

As default the **`max-size`** value is 5 MB (5242880), Files larger than the **`max-size`** will not be processed.

---

**no-recursive** option disables recursive walking of directories / globs while input is being processed for file module of nuclei.

## **Matchers / Extractors**

**File** protocol supports 2 types of Matchers -

| **Matcher Type** | **Part Matched** |
| --- | --- |
| word | all |
| regex | all |

| **Extractors Type** | **Part Matched** |
| --- | --- |
| word | all |
| regex | all |

## **Example File Template**

The final example template file for a Private Key detection is provided below.

```yaml
id: google-api-key
info:
  name: Google API Key
  author: pdteam
  severity: info
file:
  - extensions:
      - all
      - txt
    extractors:
      - type: regex
        name: google-api-key
        regex:
          - "AIza[0-9A-Za-z\\-_]{35}"
```

```bash
# Running file template on http-response/ directory
nuclei -t file.yaml -file -target http-response/
# Running file template on output.txt
nuclei -t file.yaml -file -target output.txt
```

# **File Protocol Examples**

Examples of the File Protocol Nuclei Templates

## **Basic File Template**

This template checks for a pattern in provided files.

```yaml
id: ssh-public-key
info:  
  name: SSH Public Key Detect  
  author: pd-team  
  severity: low
file:  
  - extensions:      
      - pub    
    max-size: 1024 # read very small chunks    
    matchers:      
      - type: word        
        words:          
          - "ssh-rsa"
```

## **Extension Denylist with No-Recursive**

The below template is same as last one, but it makes use of an extension denylist along with the no-recursive option.

```yaml
id: ssh-private-key
info:  
  name: SSH Private Key Detect  
  author: pd-team  
  severity: high
file:  
  - extensions:      
      - all    
    denylist:      
      - pub    
    no-recursive: true    
    max-size: 1024 # read very small chunks    
    matchers:      
      - type: word        
        words:          
          - "BEGIN OPENSSH PRIVATE KEY"          
          - "BEGIN PRIVATE KEY"          
          - "BEGIN RSA PRIVATE KEY"          
          - "BEGIN DSA PRIVATE KEY"          
          - "BEGIN EC PRIVATE KEY"          
          - "BEGIN PGP PRIVATE KEY BLOCK"          
          - "ssh-rsa"
```