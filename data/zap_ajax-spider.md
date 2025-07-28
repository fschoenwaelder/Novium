# Ajax Spider

The AJAX Spider add-on integrates in ZAP a crawler of AJAX rich sites called Crawljax. You can use it to identify the pages of the targeted site. You can combine it with the (normal) spider for better results.

The spider is configured using the [Options AJAX Spider screen](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/options/).

This add-on supports the [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/automation/).

## Accessed via

| [AJAX Spider tab](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/tab/) |  |
| --- | --- |
| History tab | ‘Attack/AJAX Spider…’ right click menu item |
| Sites tab | ‘Attack/AJAX Spider…’ right click menu item |

# Ajax Spider Automation Framework Support

This add-on supports the Automation Framework.

## Job: spiderAjax

The spiderAjax job allows you to run the Ajax Spider - it is slower than the traditional spider but handles modern web applications well.

It is covered in the video: [ZAP Chat 10 Automation Framework Part 4 - Spidering](https://youtu.be/WivoyVerBCo).

This job supports monitor tests.

```yaml
  - type: spiderAjax                   # The ajax spider - slower than the spider but handles modern apps well
    parameters:
      context:                         # String: Name of the context to spider, default: first context
      user:                            # String: An optional user to use for authentication, must be defined in the env
      url:                             # String: Url to start spidering from, default: first context URL
      maxDuration:                     # Int: The max time in minutes the ajax spider will be allowed to run for, default: 0 unlimited
      maxCrawlDepth:                   # Int: The max depth that the crawler can reach, default: 10, 0 is unlimited
      numberOfBrowsers:                # Int: The number of browsers the spider will use, more will be faster but will use up more memory, default: number of cores
      runOnlyIfModern:                 # Boolean: If true then the spider will only run if a "modern app" alert is raised, default: false
      inScopeOnly:                     # Boolean: If true then any URLs requested which are out of scope will be ignored, default: true
      browserId:                       # String: Browser Id to use, default: firefox-headless
      clickDefaultElems:               # Bool: When enabled only click the default element: 'a', 'button' and 'input', default: true
      clickElemsOnce:                  # Bool: When enabled only click each element once, default: true
      eventWait:                       # Int: The time in milliseconds to wait after a client side event is fired, default: 1000
      maxCrawlStates:                  # Int: The maximum number of crawl states the crawler should crawl, default: 0 unlimited
      randomInputs:                    # Bool: When enabled random values will be entered into input element, default: true
      reloadWait:                      # Int: The time in milliseconds to wait after the URL is loaded, default: 1000
      elements:                        # A list of HTML elements to click - will be ignored unless clickDefaultElems is false
      - "a"
      - "button"
      - "input"
      excludedElements:                 # A list of HTML elements to exclude from click.
        - description: "Logout Button"  # String: Description of the exclusion.
          element: "button"             # String: Name of the element.
          xpath:                        # String: XPath of the element, optional.
          text:                         # String: Text of the element (exact match and case sensitive), optional.
          attributeName: "aria-label"   # String: Name of the attribute, optional unless the value is provided.
          attributeValue: "Logout"      # String: Value of the attribute, optional unless the name is provided.

    tests:
      - name: 'At least 100 URLs found'      # String: Name of the test, default: statistic + operator + value
        type: 'stats'                        # String: Type of test, only 'stats' is supported for now
        statistic: 'spiderAjax.urls.added'   # String: Name of an integer / long statistic, currently supported: 'spiderAjax.urls.added'
        operator: '>='                       # String ['==', '!=', '>=', '>', '<', '<=']: Operator used for testing
        value: 100                           # Int: Change this to the number of URLs you expect to find
        onFail: 'info'                       # String [warn, error, info]: Change this to 'warn' or 'error' for the test to take effect

```

If the ‘runOnlyIfModern’ is set to ‘True’ then the [passiveScan-wait](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-pscanwait/) job MUST be run before this one (as well as after it) and the [Modern Web Application](https://www.zaproxy.org/docs/alerts/10109/) rule installed and enabled. If either of those things are not done then the ajax spider will always run and a warning output. If they are both done and no “Modern Web Application” alert is raised then the assumption is made that this is a tradition app and therefore the ajax spider is not needed.

# AJAX Spider Context

This screen allows you to manage Context data for the AJAX Spider.

## Excluded Elements

Allows to configure the elements that should be excluded from the crawling.

An excluded element needs the Description, the Element (i.e. tag name), and one of: XPath, Text (of the element, exact match and case sensitive), and Attribute (both its name and value).

# Options AJAX Spider screen

This screen allows you to configure the [AJAX Spider](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/) options. The AJAX Spider is an add-on for a crawler called Crawljax. The add-on sets up a local proxy in ZAP to talk to Crawljax. The AJAX Spider allows you to crawl web applications written in AJAX in far more depth than the native Spider. Use the AJAX Spider if you may have web applications written in AJAX. You should also use the native Spider as well for complete coverage of a web application (e.g., to cover HTML comments).

## Configuration Options

| Field | Details | Default |
| --- | --- | --- |
| Browser | AJAX Spider relies on an external browser to crawl the targeted site. You can specify which one you want to use. For more details on supported browsers refer to “Selenium” add-on help pages. | Firefox Headless |
| Number of Browser Windows to Open | You can configure the number of windows to be used by AJAX Spider. The more windows, the faster the process will be. | Num cores |
| Maximum Crawl Depth | The maximum depth that the crawler can reach. Zero means unlimited depth. | 10 |
| Maximum Crawl States | The maximum number of states that the crawler should crawl. Zero means unlimited crawl states. | 0 (unlimited) |
| Maximum Duration | The maximum time that the crawler is allowed to run. Zero means unlimited running time. | 60 minutes |
| Event Wait Time | The time to wait after a client side event is fired. | 1000 ms |
| Reload Wait Time | The time to wait after URL is loaded. | 1000 ms |
| Enable Browser Extensions | When enabled, any browser extensions added by other add-ons will be enabled in the browsers used for crawling. | False |
| Click Elements Once | When enabled, the crawler attempts to interact with each element (e.g., by clicking) only once. If this is not set, the crawler will attempt to click multiple times. Unsetting this option is more rigorous but may take considerably more time. | True |
| Use Random Values in Form Fields | When enabled, inserts random values into form fields. Otherwise, it uses empty values. | True |
| Click Default Elements Only | When enabled, only elements “a”, “button” and “input” will be clicked during crawl. Otherwise, it uses the table below to determine which elements will be clicked. For more in depth analysis, disable this and configure the clickable elements in the table. | True |
| Select elements to click during crawl (table) | The list of elements to crawl. This table only applies when “click default elements only” is not enabled. Use “enable all” for a more in depth analysis, though it may take somewhat longer. | All enabled |
| Allowed Resources (table) | The list of allowed resources. The allowed resources are always fetched even if out of scope, allowing to include necessary resources (e.g. scripts) from 3rd-parties. |  |

# AJAX Spider dialog

This dialog launches the AJAX Spider.

## Scope

The first tab allows you to change key features like:

### Starting Point

The URL which the AJAX spider will start crawling from, or a context (in which case it will be used one of the URLs that are in context as starting point).

### Context

Allows to select the Context to be spidered.

### User

Allows to select one of the users available from the selected context, to perform the spider scan as a user (ZAP will (re)authenticate as that user whenever necessary).

### Just In Scope

If set then any URLs which are out of scope will be ignored.

**Note:** The option `Just In Scope` is mutually exclusive with `Context` option, if one is used the other is ignored.

### Spider Subtree Only

If set then the spider will only access resources that are under the starting point (URI). When evaluating if a resource is found within the specified subtree, the spider considers only the scheme, host, port, and path components of the URI.

### Browser

The type of browser to use.

Browsers will only be shown if ZAP has sufficient configuration to run them.

They may still fail to run if the browsers cannot be found or if the configuration information is incorrect.

### Show Advanced Options

If selected then the Options tab will be shown.

## Options

This tab allows you to change options including:

### Number of Browser Windows to Open

You can configure the number of windows to be used by AJAX Spider.

The more windows, the faster the process will be.

### Maximum Crawl Depth

The maximum depth that the crawler can reach. Zero means unlimited depth.

### Maximum Crawl States

The maximum number of states that the crawler should crawl. Zero means unlimited crawl states.

### Maximum Duration

The maximum time that the crawler is allowed to run. Zero means unlimited running time.

### Event Wait Time

The time to wait after a client side event is fired.

### Reload Wait Time

The time to wait after URL is loaded.

### Allowed Resources

The list of allowed resources. The allowed resources are always fetched even if out of scope, allowing to include necessary resources (e.g. scripts) from 3rd-parties.

# AJAX Spider tab

The AJAX Spider tab shows you the set of unique URIs found by [AJAX Spider](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/).

For each request you can see:

| The request index - each request is numbered, starting at 1 |
| --- |
| The request timestamp |
| The HTML method, e.g. GET or POST |
| The URL requested |
| The HTTP response status code |
| A short summary of what the HTTP response code means |
| The length of time the whole request took |
| The size of the response header |
| The size of the response body |
| Any *Alerts* on the request |
| Any *Notes* you have added to request |
| Any *Tags* you have added to request |

Selecting a requests will display it in the *Request tab* and *Response tab* above.

## Right click menu

Right clicking on a node will bring up a menu which will allow you to:

### Attack

The Attack menu has the following submenus:

### Active Scan Site

This will initiate an *Active Scan* of the whole of the site containing the selected node.

The *Active Scan tab* will be display and will show the progress of the scan.

### Active Scan Node

This will initiate an *Active Scan* of just the node selected.

The *Active Scan tab* will be display and will show the progress of the scan.

### Spider Site

This will initiate a *spider* of the whole of the site containing the selected node.

The *Spider tab* will be display and will show the progress of the scan.

### Forced Browse Site

This will initiate a *forced browse* of the whole of the site containing the selected node.

The *Forced Browse tab* will be display and will show the progress of the scan.

### Forced Browse Directory

This will initiate a *forced browse* on the selected directory.

The *Forced Browse tab* will be displayed and will show the progress of the scan.

### Forced Browse Directory (and children)

This will initiate a *forced browse* on the selected directory and all children found.

The *Forced Browse tab* will be displayed and will show the progress of the scan.

### Exclude from

This menu has the following submenus:

### Proxy

This will exclude the selected nodes from the proxy. They will still be proxied via ZAP but will not be shown in any of the tabs.

This can be used to ignore URLs that you know are not relevant to the system you are currently testing.

The nodes can be included again via the *Session Properties* dialog

### Scanner

This will prevent the selected nodes from being actively scanned.

The nodes can be included again via the *Session Properties* dialog

### Spider

This will prevent the selected nodes from being spidered.

The nodes can be included again via the *Session Properties* dialog

### Run application

This menu allows you to *invoke applications* that you have configured via the *Options Applications screen* which is also accessible via the ‘Configure applications…’ submenu.

### Manage Tags…

This will bring up the *Manage Tags dialog* which allows you to change the *tags* associated with the request.

### Note…

This will bring up the *Add Note dialog* which allows you to record *notes* related to the request.

### Break…

This will bring up the *Add Break Point dialog* which allows you to set a break point on that URL.

### Alerts for this node

If the URL selected has *alerts* associated with it then they will be listed under this menu.

Selecting one of the alerts will cause it to be displayed.

### Resend…

This will bring up the *Resend dialog* which allows you to resend the request after making any changes to it that you want to.

### New Alert…

This will bring up the *Add Alert dialog* which allows you to manually record a new *Alert* against this request.

### Open URL in Browser

This will open the URL of the selected node in your default browser.