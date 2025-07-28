# Script Console

The Script Console add-on allows you to run scripts that can be embedded within ZAP and can access internal ZAP data structures.

It supports any scripting language that supports JSR 223 ([http://www.jcp.org/en/jsr/detail?id=223](http://www.jcp.org/en/jsr/detail?id=223)) , including:

- ECMAScript / JavaScript (using [Nashorn engine](https://docs.oracle.com/javase/8/docs/technotes/guides/scripting/nashorn/), included by default)
- Zest [https://developer.mozilla.org/en-US/docs/zest](https://developer.mozilla.org/en-US/docs/zest) (included by default)
- Groovy [http://groovy-lang.org/](http://groovy-lang.org/)
- Python [http://www.jython.org](http://www.jython.org/)
- Ruby - [http://jruby.org/](http://jruby.org/)
- and many more…

**WARNING - scripts run with the same permissions as ZAP, so do not run any scripts that you do not trust!**

## Script Types

Different types of scripts are supported:

- Stand Alone - scripts that are self contained and are only run when your start them manually
- Active Rules - these run as part of the Active Scanner and can be individually enabled
- Passive Rules - these run as part of the Passive Scanner and can be individually enabled
- Proxy - these run ‘inline’, can change every request and response and can be individually enabled. They can also trigger break points
- HTTP Sender - scripts that run against every request/response sent/received by ZAP. This includes the proxied messages, messages sent during active scanner, fuzzer, …
- Targeted - scripts that are invoked with a target URL and are only run when your start them manually
- Authentication - scripts that are invoked when authentication is performed for a Context. To be used, they need to be selected when configuring the Script-Based Authentication Method for a Context.
- Script Input Vector - scripts for defining exactly what ZAP should attack
- Extender - scripts which can add new functionality, including graphical elements and new API end points

**Note:** Add-ons can add additional types of scripts, which should be described in the help of the corresponding add-on.

All scripts that are run automatically are initially ‘disabled’ - you must enable them via the [The Scripts ’tree’ tab](https://www.zaproxy.org/docs/desktop/addons/script-console/tree/) before they will run.

If an error occurs when they run then they will be disabled.

When you select the script then the last error will be shown in the [Script Console tab](https://www.zaproxy.org/docs/desktop/addons/script-console/console/).

Targeted scripts can be invoked by right clicking on a record in the Sites or History tabs and selecting the ‘Invoke with script…’ menu item.

All scripting languages can be used for all script types, but only those languages that have been downloaded from the ZAP Marketplace will typically have templates. However you may well be able to adapt a template for another language.

If your favourite language is not available on the Marketplace then please raise a new issue via the “Online/Report an issue” menu item.

## Global Variables

Variables can be shared between all scripts via the class org.zaproxy.zap.extension.script.ScriptVars.

For example in JavaScript you can use this class as follows:

```jsx
org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("var.name","value")

org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("var.name")
```

## Script Variables

Variables can be shared between separate invocations of the same script via the same org.zaproxy.zap.extension.script.ScriptVars class.

For example in JavaScript you can use this class as follows:

```jsx
org.zaproxy.zap.extension.script.ScriptVars.setScriptVar(this.context, "var.name","value")

org.zaproxy.zap.extension.script.ScriptVars.getScriptVar(this.context, "var.name")
```

Note that these methods are only usable from scripting languages that provide access to the ScriptContext (like JavaScript). For other scripting languages (in ZAP versions after 2.7.0) the variables can be accessed/set by manually specifying the name of the script:

```jsx
org.zaproxy.zap.extension.script.ScriptVars.setScriptVar("ScriptName", "var.name","value")

org.zaproxy.zap.extension.script.ScriptVars.getScriptVar("ScriptName", "var.name")
```

## Custom Global/Script Variables

Newer versions of ZAP (after 2.8.0) allow to set custom global/script variables, which can be of any type not just strings, for example, lists, maps.

In JavaScript they are accessed/set as follows:

```jsx
var ScriptVars = Java.type(“org.zaproxy.zap.extension.script.ScriptVars”)

ScriptVars.setScriptCustomVar(this.context, “var.name”, {x: 1, y: 3}) print(ScriptVars.getScriptCustomVar(this.context, “var.name”).y) // Prints 3

ScriptVars.setGlobalCustomVar(“var.name”, [“A”, “B”, “C”, “D”]) print(ScriptVars.getGlobalCustomVar(“var.name”)[2]) // Prints C
```

# Scripts Automation Framework Support

This add-on supports the Automation Framework.

## Job: script

The script job allows you to execute various actions with scripts:

## Action: add

Adds the specified script to ZAP. Scripts are enabled but not configured to be loaded when ZAP restarts.

By default the default script engine for the file extension (if any) will be used - this may be overridden using the ’engine’ parameter.

- type: mandatory, can be any of the script types supported by ZAP
- engine: optional, can be used to override the default engine for the file extension
- name: optional, defaults to the file name, can be used to specify the script in another job
- source: mandatory, the path to the file (absolute or relative to the plan), must be a readable text file

The `source` parameter was previously called `file`, both will work.

## Action: remove

Removes the specified script from ZAP.

- name: mandatory, the name of the script in ZAP

## Action: run

Runs the specified script to ZAP. The script must already be available in ZAP, for example added using the ‘add’ action.

- type: mandatory, can be ‘standalone’ or ’targeted’
- name: mandatory, the name of the script in ZAP
- engine: optional, can be used to override the default engine for the file extension
- target: mandatory, if type is ’targeted’, the target URL to be invoked for ’targeted’ script

## Action: loaddir

Loads all of the scripts in the subdirectories under the specified source path to ZAP. Scripts are enabled but not configured to be loaded when ZAP restarts.

The scripts must be in subdirectories named after the relevant script type (such as ‘active’, ‘passive’, ‘proxy’ etc) and must have an appropriate extension for the script language used.

- source: mandatory, the path to the directory (absolute or relative to the plan).

## Action: enable

Enables the specified script. The script must already be available in ZAP, for example added using the ‘add’ action.

- name: mandatory, the name of the script in ZAP

## Action: disable

Disables the specified script. The script must already be available in ZAP, for example added using the ‘add’ action.

- name: mandatory, the name of the script in ZAP

## YAML definition

Not all of the parameters are valid for all of the actions, see above for details.

```yaml
  - type: script
    parameters:
      action:                    # String: The executed action - available actions: add, remove, run, enable, disable
      type:                      # String: The type of the script
      engine:                    # String: The script engine to use - can be used to override the default engine for the file extension
      name:                      # String: The name of the script, defaults to the file name
      source:                    # String: The full or relative file path, must be readable
      inline:                    # String: The full script (may be multi-line) - supply this or 'file' not both
      target:                    # String: The URL to be invoked for "targeted" script type

```

The `source` parameter was previously called `file`, both will work.

## Inline Scripts

Inline scripts are where the script contents are in the YAML plan rather that a separate file. An example of adding and running a simple standalone inline script is:

```yaml
  - type: script
      parameters:
        action: "add"
        type: "standalone"
        engine: "ECMAScript : Graal.js"
        name: "inline-test"
        inline: |
          print("This is a simple example")
          print("Of a multi-line script")
  - type: script
      parameters:
        action: "run"
        type: "standalone"
        name: "inline-test"
```

## Interacting with plans

Scripts can interact with running plans using code like:

```jsx
var extAF = control.getExtensionLoader().getExtension("ExtensionAutomation");

var plans = extAF.getRunningPlans();

if (plans.size() >  0) {
  plans.get(0).getProgress().info("An info message added by a script");
} else {
  print('No running plans');
}
```

# Script Console Tab

The Scripts Console allows you to write scripts which run within ZAP.

It is made up of:

- A toolbar
- A text area (top) in which you can write your scripts
- An output text area (bottom) for debug and error messages, with “print” statements.

To create a new script or to load or switch scripts see the [The Scripts ’tree’ tab](https://www.zaproxy.org/docs/desktop/addons/script-console/tree/).

Right-click in the script area for display and editing options.

In ZAP versions after 2.7.0 if the script currently displayed in the console is changed by another program then you will be given the option to keep the script in the console or replace it with the changed script.

If a script is changed by another program when it is not being displayed and has not previously been changed in the script console then that script will be loaded and the new contents will be used when the script is run.

Templates can be viewed in the console but cannot be edited.

## Toolbar Buttons

### Save Script

This button allows you to save the script currently displayed in the console to a file.

The shortcut `ctrl+S` (or `cmd+S` on macOS) may also be used for this purpose.

### Enable / Disable Script

This button may be used to enable or disable the script currently displayed in the console.

### Run and Stop Buttons

You can run ‘Stand Alone’ scripts using the ‘Run’ button on the tab toolbar.

All other types of scripts will be run when enabled or if explicitly invoked.

### Auto-complete

The console supports a limited form of auto-complete, controlled by a button on the toolbar.

When enabled a popup will be shown when you type the name of one of the defined parameters followed by a dot - this will show you all of the methods available for you to call. Selecting one of them will insert the method and parameters into your script. If you type another dot immediately after the method call then you will be shown another prompt for the methods available to the return type, if any. You will be able to keep expanding the types returned until you start typing something else.

# Script Console Options

## When the Script in the Console Changes on Disk

This setting allows you to configure the default behaviour when a script open in the Script Console changes on disk, for example if it was updated in another code editor. There are three options to choose from:

- **Ask Each Time**: This will prompt you each time the script is changed on disk, allowing you to choose whether to keep the script in the console or replace it with the changed script.
- **Keep Script**: This will always keep the script in the console, even if it is changed on disk.
- **Replace Script**: This will always replace the script in the console with the changed script.

Note that if there are unsaved changes to the script, you will always be prompted to choose which version to keep.

## Font

### Font Name

Set the name of the font used in the script console. A monospaced font is used by default.

### Font Size

Set the size of the font used in the script console. The default font size is 12.

## Code Style

### Tab Size

Set the width by which the code should be indented when you press Tab. The unit is the width of one space character. The default tab size is 4.

### Use Tab Character

Use tab characters (`\t`) instead of spaces for indentation. The size of one tab character is determined by the **Tab Size**setting. The default is to use spaces.

# Script Scan Rules

Active and Passive Scripts that implement the `getMetadata` function are treated as first-class scan rules by ZAP. Example implementation of this function in a script would look like:

```jsx
function getMetadata() {
	return ScanRuleMetadata.fromYaml(`
id: 12345
name: Active Vulnerability Title
description: Full description
solution: The solution
references:
  - Reference 1
  - Reference 2
category: INJECTION  # info_gather, browser, server, misc, injection
risk: INFO  # info, low, medium, high
confidence: LOW  # false_positive, low, medium, high, user_confirmed
cweId: 0
wascId: 0
alertTags:
  name1: value1
  name2: value2
otherInfo: Any other Info
status: alpha
`);
}

```

The `category` field is only used for Active Scan Scripts. Any additional fields in the metadata are ignored. The metadata function is evaluated upon saving the script, which is exposed as a scan rule if the metadata is valid.

# Scripts tree tab

The Scripts tree tab shows you all of the scripts you currently have loaded organized by type.

It also shows you which templates you have available - these cannot be run directly, you use them to create new scripts.

It also allows you to add new scripts, load, save and remove them.

The tab includes a toolbar which allows you to:

- Create a new script
- Load a script from filestore

Scripts that are run within ZAP components, such as the Active Scanner, can be enabled and disabled via right click menu option.

All scripts can be removed from the UI via a right click ‘Remove Script’ menu option.