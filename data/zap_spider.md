# Spider

The Spider is a tool that is used to automatically discover new resources (URLs) on a particular Site. It begins with a list of URLs to visit, called the seeds, which depends on how the Spider is started. The Spider then visits these URLs, it identifies all the hyperlinks in the page and adds them to the list of URLs to visit and the process continues recursively as long as new resources are found.

The Spider can be configured and started using the [Spider dialogue](https://www.zaproxy.org/docs/desktop/addons/spider/dialog/).

During the processing of an URL, the Spider makes a request to fetch the resource and then parses the response, identifying hyperlinks. It currently has the following behavior when processing types of responses:

### HTML

Processes the specific tags, identifying links to new resources:

- Base - Proper handling
- A, Link, Area, Base - ‘href’ attribute
- Applet, Audio, Embed, Frame, IFrame, Input, Script, Img, Video - ‘src’ attribute
- Blockquote - ‘cite’ attribute
- Meta - ‘http-equiv’ for ’location’, ‘refresh’ and ‘Content-Security-Policy’, ’name’ for ‘msapplication-config’
- Applet - ‘codebase’, ‘archive’ attributes
- Img - ’longdesc’, ’lowsrc’, ‘dynsrc’, ‘srcset’ attributes
- Isindex - ‘action’ attribute
- Object - ‘codebase’, ‘data’ attributes
- Param - ‘value’ attribute
- Svg - ‘href’ and ‘xlink:href’ attributes of ‘image’ and ‘script’ elements
- Table - ‘background’ attribute
- Video - ‘poster’ attribute
- Form - proper handling of Forms with both GET and POST method. The fields values are generated validly, including [HTML 5.0 input types](http://www.w3schools.com/html5/html5_form_input_types.asp) ‘form’, ‘formaction’, ‘formmethod’ attributes of buttons are also respected.
- Comments - Valid tags found in comments are also analyzed, if specified in the [Options Spider screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/)
- Import - ‘implementation’ attribute
- Inline string - ‘p’, ’title’, ’li’, ‘h1’, ‘h2’, ‘h3’, ‘h4’, ‘h5’, ‘h6’, and ‘blockquote’ tags

### Robots.txt file

If set in the [Options Spider screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/), it also analyzes the ‘Robots.txt’ file and tries to identify new resources using the specified rules. It has to be mentioned that the Spider does not follow the rules specified in the ‘Robots.txt’ file.

### sitemap.xml file

If set in the [Options Spider screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/), the Spider also analyzes the ‘sitemap.xml’ file and tries to identify new resources.

### SVN metadata files

If set in the [Options Spider screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/), the Spider should also parse SVN metadata files and tries to identify new resources.

### Git metadata files

If set in the [Options Spider screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/), the Spider should also parse Git metadata files and tries to identify new resources.

### .DS_Store files

If set in the [Options Spider screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/), the Spider should also parse .DS_Store files and tries to identify new resources.

### OData Atom Format

OData content using the Atom format is currently supported. All included links (relative or absolute) are processed.

### SVG Files

SVG image files are parsed to identify HREF attributes and extract/resolve any contained links.

### Non-HTML Text Response

Text responses are parsed scanning for the URL pattern

### Non-Text Response

Currently, the Spider does not process this type of resources.

## Other Aspects

- When checking if an URL was already visited, the behaviour regarding how parameters are handled can be configured on the Spider Options screen.
- When checking if an URL was already visited, there are a few common parameters which are ignored: jsessionid, phpsessid, aspsessionid, utm_*
- The Spider’s behaviour regarding cookies depends on how the Spider is started and which options are enabled. For more details refer to the Spider Options screen.

The spider is configured using the [Spider Options screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/).

# Spider Automation Framework Support

This add-on supports the Automation Framework.

## Job: spider

The Spider job runs the Traditional Spider. This is fast but does not handle modern applications as effectively.

It is covered in the video: [ZAP Chat 10 Automation Framework Part 4 - Spidering](https://youtu.be/WivoyVerBCo).

By default this job will spider the first context defined in the environment and so none of the parameters are mandatory.

This job supports monitor tests.

## YAML

```yaml
  - type: spider                       # The traditional spider - fast but doesnt handle modern apps so well
    parameters:
      context:                         # String: Name of the context to spider, default: first context
      user:                            # String: An optional user to use for authentication, must be defined in the env
      url:                             # String: Url to start spidering from, default: first context URL
      maxDuration:                     # Int: The max time in minutes the spider will be allowed to run for, default: 0 unlimited
      maxDepth:                        # Int: The maximum tree depth to explore, default 5
      maxChildren:                     # Int: The maximum number of children to add to each node in the tree
      acceptCookies:                   # Bool: Whether the spider will accept cookies, default: true
      handleODataParametersVisited:    # Bool: Whether the spider will handle OData responses, default: false
      handleParameters:                # Enum [ignore_completely, ignore_value, use_all]: How query string parameters are used when checking if a URI has already been visited, default: use_all
      maxParseSizeBytes:               # Int: The max size of a response that will be parsed, default: 2621440 - 2.5 Mb
      parseComments:                   # Bool: Whether the spider will parse HTML comments in order to find URLs, default: true
      parseGit:                        # Bool: Whether the spider will parse Git metadata in order to find URLs, default: false
      parseDsStore:                    # Bool: Whether the spider will parse .DS_Store files in order to find URLs, default: false
      parseRobotsTxt:                  # Bool: Whether the spider will parse 'robots.txt' files in order to find URLs, default: true
      parseSitemapXml:                 # Bool: Whether the spider will parse 'sitemap.xml' files in order to find URLs, default: true
      parseSVNEntries:                 # Bool: Whether the spider will parse SVN metadata in order to find URLs, default: false
      postForm:                        # Bool: Whether the spider will submit POST forms, default: true
      processForm:                     # Bool: Whether the spider will process forms, default: true
      sendRefererHeader:               # Bool: Whether the spider will send the referer header, default: true
      threadCount:                     # Int: The number of spider threads, default: 2 * Number of available processor cores
      userAgent:                       # String: The user agent to use in requests, default: '' - use the default ZAP one
    tests:
      - name: 'At least 100 URLs found'                 # String: Name of the test, default: statistic + operator + value
        type: 'stats'                                   # String: Type of test, only 'stats' is supported for now
        statistic: 'automation.spider.urls.added'       # String: Name of an integer / long statistic, currently supported: 'automation.spider.urls.added'
        operator: '>='                                  # String ['==', '!=', '>=', '>', '<', '<=']: Operator used for testing
        value: 100                                      # Int: Change this to the number of URLs you expect to find
        onFail: 'info'                                  # String: One of 'warn', 'error', 'info', mandatory
```

# Spider dialog

This dialog launches the [Spider](https://www.zaproxy.org/docs/desktop/addons/spider/).

## Scope

The first tab allows you to select or change the starting point.

If the starting point is in one or more Contexts then you will be able to choose one of them.

If that context has any Users defined then you will be able to select one of them.

If you select one of the users then the spider will be performed as that user, with ZAP (re)authenticating as that user whenever necessary.

If you select ‘Recurse’ then all of the nodes underneath the one selected will also be used to seed the Spider.

If you select ‘Spider Subtree Only’ the Spider will only access resources that are under the starting point (URI). When evaluating if a resource is found within the specified subtree, the Spider considers only the scheme, host, port, and path components of the URI.

If you select ‘Show Advanced Options’ then the following tab will be shown which provides fine grain control over the spider process.

Clicking on the ‘Reset’ button will reset all of the options to their default values.

## Advanced

The parameters on this tab correspond to the same parameters on the [Options Spider screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/).

## Accessed via

| [Spider tab](https://www.zaproxy.org/docs/desktop/addons/spider/tab/) | ‘New Scan’ button |
| --- | --- |
| Sites tab | ‘Attack / Spider…’ right click menu item |
| History tab | ‘Attack / Spider…’ right click menu item |

# Options Spider screen

This screen allows you to configure the [Spider](https://www.zaproxy.org/docs/desktop/addons/spider/) options.

It should be noted that modifying most of these options also affects the running Spider.

### Maximum depth to crawl

The parameter defines the maximum depth in the crawling process where a page must be found in order for it to be processed. Resources found deeper than this level are not fetched and parsed by the spider. The value zero means unlimited depth.

The depth is calculated starting from the seeds, so, if a Spider scan starts with only a single URL (eg. URL manually specified), the depth is calculated from this one. However, if the scan starts with multiple seeds (eg. recurse and Sites tree node with children), a resource is processed if it’s depth relative to *any* of the seeds is less than the defined one.

### Number of threads used

The Spider is multi-threaded and this is the number that defines the maximum number of worker threads used in the crawling process. Changing this parameter does not have any effect on any crawling that is in progress.

### Maximum duration

The maximum length of time that the Spider should run for, measured in minutes. Zero (the default) means that the Spider will run until it has found all of the links that it is able to.

### Maximum children to crawl

This parameter limits the number of children that will be crawled at every node in the tree.

This is useful for data driven applications that have large numbers of ‘pages’ that are in fact exactly the same code but containing different data, for example from a database.

By default this is set to zero which means there are no limits applied to the number of child nodes crawled.

### Maximum parse size

Defines the maximum size, in bytes, that a response might have to be parsed. This allows the Spider to skip big responses/files. Zero means unlimited size.

### Domains Always in Scope

Allows to manage the domains, string literals or regular expressions, that are in the Spider’s scope. The normal behavior of the Spider is to only follow links to resources found on the same domain as the page where the scan started. However, this option allows you to define additional domains that are considered “in scope” during the crawling process. Pages on these domains are processed during the scan.

### Query parameters handling

When crawling, the Spider has an internal mechanism that marks which pages were already visited, so they are not processed again. When this check is made, the way the URIs parameters are handled is set using this option. There are three available options:

- **Ignore parameters completely** - if [www.example.org/?bar=456](http://www.example.org/?bar=456) is visited, then [www.example.org/?foo=123](http://www.example.org/?foo=123) will not be visited
- **Consider only parameter’s name** (ignore parameter’s value) - if [www.example.org/?foo=123](http://www.example.org/?foo=123) is visited, then [www.example.org/?foo=456](http://www.example.org/?foo=456) will not be visited, but [www.example.org/?bar=789](http://www.example.org/?bar=789) or [www.example.org/?foo=456](http://www.example.org/?foo=456)&bar=123 will be visited
- **Consider both parameter’s name and value** - if [www.example.org/?123](http://www.example.org/?123) is visited, any other uri that is different (including, for example, [www.example.org/?foo=456](http://www.example.org/?foo=456) or [www.example.org/?bar=abc](http://www.example.org/?bar=abc)) will be visited

### Send “Referer” header

If the Spider requests should be sent with the “Referer” header.

### Accept Cookies

If the Spider scans should accept cookies while Spidering. If enabled the Spider will properly handle any cookies received from the server and will send them back accordingly. If the option is disabled, the Spider will not send any cookies in its requests. For example, this might control whether or not the Spider uses the same session throughout a spidering scan.

When accepting cookies the cookies are not shared between Spider scans, each scan has its own cookie jar.

This option has low priority, the Spider will respect other (global) options related to the HTTP state. This option is ignored if, for example, the option Use Global HTTP State is selected, when spidering as a User or when a HTTP Session is active.

### Process forms

During the crawling process, the behaviour of the Spider when it encounters HTML forms is defined by this option. If disabled, the HTML forms will not be processed at all. If enabled, the HTML forms with the method defined as HTTP GET will be submitted with some generated values. The behaviour when encountering forms with the method defined as HTTP POST is configured by the next option.

### POST forms

As briefly described in the previous paragraph (Process Forms), this option configures the behaviour of the Spider when *Process Forms* is enabled and when encountering HTML forms that have to be POSTed.

### Parse HTML Comments

This option defines whether the Spider should also consider HTML comments when searching for links to resources. Only the resources found in commented valid HTML tags will be processed.

### Parse ‘robots.txt’ files

This option defines whether the Spider should also spider the robots.txt files found on websites, searching for links to resources. This option does not define whether the Spider should follow the rules imposed by the robots.txt file.

### Parse ‘sitemap.xml’ files

This option controls whether the Spider should also consider ‘sitemap.xml’ file and try to identify new resources.

### Parse SVN metadata files

This option controls whether the Spider should also parse SVN metadata files and try to identify new resources.

### Parse Git metadata files

This option controls whether the Spider should also parse Git metadata files and try to identify new resources.

### Parse .DS_Store files

This option controls whether the Spider should also parse .DS_Store files and try to identify new resources.

### Handle OData-specific parameters

This options defines whether the Spider should try to detect OData-specific parameters (i.e. resources identifiers) in order to properly process them according to the rule defined by the “Query parameters handling” option.

### Irrelevant Parameters

Allows to manage the parameters that should be removed when canonicalising the URLs found.

The session names defined in the HTTP Sessions options are taken into account and removed.

# Spider tab

The Spider tab shows you the set of unique URIs found by the [Spider](https://www.zaproxy.org/docs/desktop/addons/spider/) during the scans.

The ‘New Scan’ button launches the [Spider dialog](https://www.zaproxy.org/docs/desktop/addons/spider/dialog/) which allows you to specify exactly what should be scanned.

The Spider can be run on multiple Sites in parallel and the results for each scan are shown by selecting the scan via the ‘Progress’ pull-down.

The toolbar shows information about a scan and allows to control it. It provides a set of buttons which allows to:

- Pause (and  resume) the selected Spider scan;
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/pause.png)
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/play.png)
    
- Stop the selected Spider scan;
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/stop.png)
    
- Clean completed scans;
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/broom.png)
    
- Open the [Spider Options screen](https://www.zaproxy.org/docs/desktop/addons/spider/options/).
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/gear.png)
    

The progress bar shows how far the selected Spider scan has progressed. It is also shown the number of active Spider scans and the number of URIs found for the selected scan.

For each URI found you can see:

- Processed - Whether the URI was processed by the Spider or was skipped from fetching because of a rule (e.g. it was out of scope)
- Method - The HTTP method, e.g. GET or POST, through which the resource should be accessed
- URI - the resource found
- Flags - any information about the URI (e.g. if it’s a seed or why was it not processed)

For each Spider message, shown under the Messages tab, you can see details of the request sent and response received. The `Processed` column, indicates whether:

- Successfully - the response was successfully received and parsed
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/green_dot.png)
    
- Empty Message - the response was not parsed because it was empty
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/red_dot.png)
    
- I/O Error - an input/output error occurred while fetching the response
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/red_dot.png)
    
- Max Children - the response was not parsed because the corresponding parent Sites node already has more child nodes than the maximum allowed
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/red_dot.png)
    
- Max Depth - the response was not parsed because it passed the maximum depth allowed
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/red_dot.png)
    
- Max Size - the response was not parsed because its size is not under the maximum allowed
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/red_dot.png)
    
- Not Text - the response was not parsed because it’s not text, for example, an image
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/red_dot.png)
    
- Spider Stopped - the response was not fetched or parsed because the Spider was already stopped
    
    ![](https://www.zaproxy.org/docs/desktop/addons/spider/images/red_dot.png)