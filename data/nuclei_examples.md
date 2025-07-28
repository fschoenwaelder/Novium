# Here is a corrected and properly annotated template that accomplishes the goal of finding an exposed OpenAPI specification.
```yaml
id: swagger-openapi-exposure

info:
  name: Swagger OpenAPI Specification Exposure
  author: pdteam (corrected by Gemini)
  severity: medium
  description: Detects publicly exposed OpenAPI/Swagger specification files.
  reference:
    - https://github.com/swagger-api/swagger-spec/issues/1359
  tags: swagger,openapi,exposure,api

# 'http' is a list of requests. All the following lines indented under the '-'
# belong to this single request definition.
http:
  - method: GET

    # The 'batteringram' attack type tries each payload against the base URL.
    attack: batteringram

    # Payloads are defined within the request that will use them.
    # These are common paths for OpenAPI spec files.
    payloads:
      paths:
        - /openapi.json
        - /swagger.json
        - /v2/api-docs
        - /api/v1/openapi.json
        - /openapi
        - /api/openapi.json

    # The path is constructed using the variable from the payloads section.
    path:
      - "{{BaseURL}}{{paths}}"

    # This ensures the template stops after the first successful find for a host.
    stop-at-first-match: true

    # Matchers are defined inside the request to check the response of that request.
    # 'and' means both matchers must be true for a successful finding.
    matchers-condition: and
    matchers:
      # Matcher 1: The HTTP status code must be 200 (OK).
      - type: status
        status:
          - 200

      # Matcher 2: The response body must contain specific keywords.
      # The 'or' condition means any of these words can trigger the match.
      - type: word
        part: body
        words:
          - '"openapi":'
          - '"swagger":'
          - '"info":'
        condition: or
```

# Check for CSP & Default Components
```yaml
id: misconfiguration-csp-and-default-components

info:
  name: Missing CSP Header and Exposed Default Components
  author: Gemini
  severity: medium # Severity is medium as it combines a low (missing CSP) and potentially high (exposed admin panel) finding.
  description: >
    This template checks for two common security misconfigurations:
    1. A missing Content-Security-Policy (CSP) header, which can make sites more vulnerable to XSS.
    2. Exposure of common default files, directories, or welcome pages which can reveal server information or provide unauthorized access.
  tags: misconfiguration,generic,csp,default-files,apache,nginx,tomcat,wordpress

http:
  # === Request 1: Check for missing Content-Security-Policy header ===
  # This request targets the base URL and checks its response headers.
  - method: GET
    path:
      - "{{BaseURL}}"

    # The matcher triggers if the "Content-Security-Policy" header is NOT found.
    matchers:
      - type: word
        part: header
        words:
          - "Content-Security-Policy"
        negative: true # This makes it a "missing" check.
    
    # This block is for extracting information, not for matching.
    # It will show the matched part in the output if found.
    extractors:
      - type: kval
        part: header
        kval:
          - "server" # Extracts the server software if the header is present

  # === Request 2: Check for exposed default pages and components ===
  # This request uses a list of payloads to check for common default paths.
  - method: GET
    # The 'batteringram' attack type tries each path payload individually.
    attack: batteringram
    
    payloads:
      # A list of common default paths for various servers and applications.
      paths:
        - "/"
        - "/index.html"
        - "/default.html"
        - "/dashboard"
        - "/icons/README"
        - "/manual/"
        - "/examples/"
        - "/manager/html"
        - "/phpmyadmin/"
        - "/wp-login.php"
        - "/wp-admin/"
        - "/web.config"

    # The path for the request is built from the payload list.
    path:
      - "{{BaseURL}}{{paths}}"

    # Stops after the first successful match for a given host to avoid excessive requests.
    stop-at-first-match: true

    # 'and' condition: BOTH status must be 200 AND body must contain a keyword.
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        part: body
        # 'or' condition: Any of these keywords will cause a match.
        condition: or
        words:
          - "Welcome to nginx!"
          - "It works!" # Common Apache default on Debian/Ubuntu
          - "Index of /" # Generic directory listing
          - "Apache Tomcat"
          - "phpMyAdmin"
          - "Powered by WordPress"
          - "<title>IIS Windows Server</title>"
```

# Search for Sensitive File Exposure
```yaml
id: sensitive-file-exposure

info:
  name: Exposed Sensitive Files (.git, .env)
  author: Gemini
  severity: high # Exposure of source code or credentials is a high severity finding.
  description: >
    This template checks for the exposure of sensitive files and directories.
    1. Detects publicly accessible .git/config file, which implies the entire source code repository may be exposed.
    2. Probes for common environment files (.env) that can contain credentials, API keys, and other secrets.
  tags: exposure,security,git,env,secrets,config

http:
  # === Request 1: Check for exposed .git repository config ===
  # A publicly accessible .git/config file is a reliable indicator of an exposed repository.
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"

    # Stop after the first match on a host. If .git/config is found, no need to check further.
    stop-at-first-match: true

    # 'and' condition: The response must have a 200 status and contain git config content.
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        # This string is characteristic of a git config file.
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and

  # === Request 2: Check for exposed environment files ===
  - method: GET
    # The 'batteringram' attack type tries each path payload individually.
    attack: batteringram

    payloads:
      # A list of common environment file names.
      filenames:
        - ".env"
        - ".env.local"
        - ".env.dev"
        - ".env.development"
        - ".env.prod"
        - ".env.production"
        - ".env.example"
        - ".env.sample"
        - "env.js"

    # The path for the request is built from the payload list.
    path:
      - "{{BaseURL}}/{{filenames}}"

    # Stops after the first successful match for a given host.
    stop-at-first-match: true

    # 'and' condition: BOTH status must be 200 AND body must contain a keyword.
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      # Check for common patterns in .env files. Using regex for better matching.
      - type: regex
        part: body
        # Looks for patterns like 'KEY=VALUE' (without quotes).
        regex:
          - '(?i)^[A-Z_]+='
          - 'APP_KEY='
          - 'DB_PASSWORD='
          - 'SECRET_KEY='
        condition: or
```

# Search for Technology-Specific Exposures
```yaml
id: technology-specific-exposures

info:
  name: Detection of Exposed Server Status Pages and Admin Panels
  author: Gemini
  severity: medium
  description: >
    This template detects various technology-specific pages that should not be publicly exposed.
    These can include server status pages, which leak operational data, or login panels for administrative tools.
  tags: exposure,devops,jenkins,grafana,apache,nginx,status

http:
  # === Request 1: Check for Apache mod_status page ===
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Apache Server Status"
          - "Server Uptime"
        condition: and

  # === Request 2: Check for Nginx stub_status page ===
  - method: GET
    path:
      - "{{BaseURL}}/stub_status"
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Active connections"
          - "Reading: "
        condition: and
        
  # === Request 3: Check for Jenkins Login Panel ===
  - method: GET
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/jenkins/login"
    attack: batteringram # Try both paths
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "<title>Jenkins</title>"
          - "Welcome to Jenkins!"
        condition: or

  # === Request 4: Check for Grafana Login Panel ===
  - method: GET
    path:
      - "{{BaseURL}}/login"
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Welcome to Grafana"
          - "grafana-app"
        condition: or

  # === Request 5: Check for exposed PHP-FPM status page ===
  - method: GET
    path:
      - "{{BaseURL}}/status" # Common path for php-fpm status
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "pool:"
          - "process manager:"
          - "active processes:"
        condition: and
```

# Check for Exposed API Documentation (Swagger UI / Redoc)
```yaml
id: api-documentation-exposure

info:
  name: Exposed API Documentation (Swagger UI / Redoc)
  author: Gemini
  severity: low # Generally low risk, but can provide attackers a roadmap of the API.
  description: >
    Detects exposed API documentation interfaces like Swagger UI and Redoc.
    While often intentional, these can give attackers a complete and interactive map of an application's API endpoints.
  tags: exposure,api,swagger,redoc,docs,openapi

http:
  # === Request 1: Check for Swagger UI Interface ===
  - method: GET
    attack: batteringram
    path:
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/swagger/index.html"
      - "{{BaseURL}}/swagger-ui/"
      - "{{BaseURL}}/api-docs"
      - "{{BaseURL}}/docs/"
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "<title>Swagger UI</title>"
          - "swagger-ui-container"
        condition: or

  # === Request 2: Check for Redoc Interface ===
  - method: GET
    attack: batteringram
    path:
      - "{{BaseURL}}/redoc"
      - "{{BaseURL}}/docs"
      - "{{BaseURL}}/api/docs"
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "<title>ReDoc</title>"
          - "<redoc" # This is the HTML tag Redoc uses
        condition: or

  # === Request 3: Check for OpenAPI/Swagger JSON Spec File ===
  - method: GET
    attack: batteringram
    path:
      - "{{BaseURL}}/openapi.json"
      - "{{BaseURL}}/swagger.json"
      - "{{BaseURL}}/v2/api-docs"
      - "{{BaseURL}}/v3/api-docs"
    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: header
        words:
          - "application/json"
      - type: word
        part: body
        words:
          - '"swagger":'
          - '"openapi":'
        condition: or
```