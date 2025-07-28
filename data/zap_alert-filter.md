# Alert Filter

Alert Filters allow you to automatically override the risk levels of any alerts raised by the active and passive scan.

There are 2 different types of Alert Filter:

- [Context Alert Filters](https://www.zaproxy.org/docs/desktop/addons/alert-filters/contextalertfilter/)
- [Global Alert Filters](https://www.zaproxy.org/docs/desktop/addons/alert-filters/globalalertfilter/)

Alert Filters can also be defined in the [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/alert-filters/automation/).

The easiest way to create Alert Filters is to right click an alert and select the ‘Create Alert Filter…’ option. This will display the [Alert Filter Dialog](https://www.zaproxy.org/docs/desktop/addons/alert-filters/alertfilterdialog/).

You can also create Alert Filter manually. By default Alert Filters only apply to new alerts, but you can both test and apply the Alert Filters to existing alerts.

# Alert Filter Dialog

This dialog is shown when you add or modify a [Context Alert Filter](https://www.zaproxy.org/docs/desktop/addons/alert-filters/contextalertfilter/) or a [Global Alert Filter](https://www.zaproxy.org/docs/desktop/addons/alert-filters/globalalertfilter/)

It has the following fields:

### Scope

This can either be ‘Global’ for a Global Alert Filter or the name of an existing context. It is only editable when you create an Alert Filter from an existing Alert.

### Alert Type

The first pull down lists all of the active and passive alert rules currently installed along with their (known) alert references. The second pull down lists all known IDs (scan rules and alert references). It also allows to manually specify one, if not listed (e.g. custom rule or not yet installed).

### New Risk Level

The new risk level to be assigned to any alerts raised that match the criteria defined by the rule.

### URL

An optional URL.

If specified then this rule will be applied if the URL matches the URL of a raised alert.

### URL is Regex?

If set and a URL is specified then the URL will be treated as a regex expression when compared with the URL of the alert.

If it is not set then any specified URL must exactly match the URL of the alert.

### Parameter

An optional parameter.

If specified then this rule will be applied if the parameter exactly matches the parameter of a raised alert.

### Parameter is Regex?

If set and a parameter is specified then the parameter will be treated as a regex expression when compared with the parameter of the alert.

If it is not set then any specified parameter must exactly match the parameter of the alert.

### Attack

An optional attack.

If specified then this rule will be applied if the attack exactly matches the attack of a raised alert.

### Attack is Regex?

If set and a attack is specified then the attack will be treated as a regex expression when compared with the attack of the alert.

If it is not set then any specified attack must exactly match the attack of the alert.

### Evidence

An optional evidence.

If specified then this rule will be applied if the evidence exactly matches the evidence of a raised alert.

### Evidence is Regex?

If set and a evidence is specified then the evidence will be treated as a regex expression when compared with the evidence of the alert.

If it is not set then any specified evidence must exactly match the evidence of the alert.

### Method

An optional method.

If specified then this rule will be applied if the method matches (case insensitive) the method of a raised alert.

### Enabled

If set then this rule will be applied to all alerts raise against the given context.

### Test Filter

The ‘Test’ button will show a count of how many existing alerts the filter will apply to. It is disabled if the filter is disabled.

### Apply Filter

The ‘Apply’ button will actually apply the filter to all of the existing alerts that it applies to. It will then show a count of the number of alerts iit changed. It is disabled if the filter is disabled.

# Alert Filter Automation Framework Support

This add-on supports the Automation Framework.

## Job: alertFilter

The alertFilter job allows you to define global and context specific alert filters.

It is covered in the video: [ZAP Chat 08 Automation Framework Part 2 - Environment](https://youtu.be/1fcpU54N-mA).

```yaml
  - type: alertFilter                  # Used to change the risk levels of alerts
    parameters:
      deleteGlobalAlerts: true         # Boolean, if true then will delete all existing global alerts, default false
    alertFilters:                      # A list of alertFilters to be applied
      - ruleId:                        # Int: Mandatory, the scan rule ID or the alert reference
        newRisk:                       # String: Mandatory new risk level, one of 'False Positive', 'Info', 'Low', 'Medium', 'High'
        context:                       # String: Optional context name, if empty then a global alert filter will be created
        url:                           # String: Optional string to match against the alert, supports environment vars
        urlRegex:                      # Boolean: Optional, if true then the url is a regex
        parameter:                     # String: Optional string to match against the alert parameter field
        parameterRegex:                # Boolean: Optional, if true then the parameter is a regex, supports environment vars
        attack:                        # String: Optional string to match against the alert attack field
        attackRegex:                   # Boolean: Optional, if true then the attack is a regex
        evidence:                      # String: Optional string to match against the alert evidence field
        evidenceRegex:                 # Boolean: Optional, if true then the evidence is a regex
```

# Context Alert Filters

Context [Alert Filters](https://www.zaproxy.org/docs/desktop/addons/alert-filters/) allow you to automatically override the risk levels of any alerts raised by the active and passive scan rules within a context. The Alert Filters will be exported and imported with the context - they will not persist over ZAP sessions unless the context is imported again.

This add-on adds an ‘Alert Filters’ panel to the contexts dialog.

The panel shows a list of all of the Alert Filters along with buttons for adding, removing, and deleting them. Adding or modifying an Alert Filter will display the [Alert Filter Dialog](https://www.zaproxy.org/docs/desktop/addons/alert-filters/alertfilterdialog/).

# Options Global Alert Filters

This Options screen allows you to configure Global [Alert Filters](https://www.zaproxy.org/docs/desktop/addons/alert-filters/) which allow you to automatically override the risk levels of any alerts raised by the active and passive scan rules. Unlike [Context Alert Filters](https://www.zaproxy.org/docs/desktop/addons/alert-filters/contextalertfilter/) they apply to all alerts raised, not just those raised in a specific context.

They will also be persisted across ZAP sessions.

The screen shows a list of all of the Global Alert Filters along with buttons for adding, removing, and deleting them.

Adding or modifying an Alert Filter will display the [Alert Filter Dialog](https://www.zaproxy.org/docs/desktop/addons/alert-filters/alertfilterdialog/).