# SOAP Support

This add-on imports and scans WSDL files containing SOAP endpoints.

It also supports the [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/soap-support/automation/).

## Importing

The add-on will automatically detect any SOAP definitions and spider them as long as they are in scope.

A menu item is added to the Import menu:

- Import a WSDL File

Operations to import a WSDL file from the local filesystem or from a URL are also available via the API.

**NOTE:** As of version 6 of this add-on, only encoded URLs are supported.

### Form Handler Add-on Support

The SOAP add-on supports overriding default parameter values based on field names via the Form Handler add-on. For example,

![](https://www.zaproxy.org/docs/desktop/addons/soap-support/images/formHandlerExample.png)

Latest code:

[SOAP Support](https://github.com/zaproxy/zap-extensions/tree/main/addOns/soap)

## Statistics

This add-on maintains the following statistics:

- soap.urls.added: The total number of URLs (or SOAP Actions) added from imported WSDL files.

# SOAP Alerts

The following alerts are raised by the SOAP add-on. {#id-90026}{#id-90029}{#id-90030}

| Alert Reference | Name | Description | Latest Code |
| --- | --- | --- | --- |
| [90026](https://www.zaproxy.org/docs/alerts/90026/) | Action Spoofing | SOAP requests contain some sort of operation that is later executed by the web application. This operation can be found in the first child element of the SOAP Body. However, if HTTP is used to transport the SOAP message the SOAP standard allows the use of an additional HTTP header element called SOAPAction. This header element contains the name of the executed operation. It is supposed to inform the receiving web service of what operation is contained in the SOAP Body, without having to do any XML parsing. This optimization can be used by an attacker to mount an attack, since certain web service frameworks determine the operation to be executed solely on the information contained in the SOAPAction header field. | [SOAPActionSpoofingActiveScanRule.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/SOAPActionSpoofingActiveScanRule.java) |
| [90029](https://www.zaproxy.org/docs/alerts/90029/) | SOAP XML Injection | During an “XML Injection” an attacker tries to add or manipulate various XML Tags in the SOAP message aiming to manipulate the XML structure. Usually a successful XML injection results in the execution of a restricted or unintended operation. Depending on the executed operation various security or business controls might be violated. | [SOAPXMLInjectionActiveScanRule.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/SOAPXMLInjectionActiveScanRule.java) |
| [90030](https://www.zaproxy.org/docs/alerts/90030/) | WSDL File Detection | This alert is raised when the passive scanner detects a WSDL file. | [WSDLFilePassiveScanRule.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/WSDLFilePassiveScanRule.java) |

# SOAP Automation Framework Support

This add-on supports the Automation Framework.

The add-on will import WSDL files containing SOAP endpoints if they are found while spidering but adding them explicitly via a URL or local file is recommended if they are available.

## Job: soap

The soap job allows you to import WSDL files locally or from a URL.

It is covered in the video: [ZAP Chat 11 Automation Framework Part 5 - APIs](https://youtu.be/xuP00Ri460k).

```yaml
  - type: soap                         # SOAP WSDL import
    parameters:
      wsdlFile:                        # String: Local file path of the WSDL, default: null, no definition will be imported
      wsdlUrl:                         # String: URL pointing to the WSDL, default: null, no definition will be imported
```