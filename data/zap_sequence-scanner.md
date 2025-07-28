# Sequence Scanner

This add-on facilitates the recording and scanning sequences of requests. In some web applications it is necessary for particular events or pages to be accessed or completed in a certain order. By recording a sequence and then scanning it, it is possible to ensure such flows happen in an expected manner.

The sequence active scanner will replay the sequence it is attacking. If a sequence is selected in the “Scripts” tab then the result of running the script will be shown in the “Zest Results” tab. If the sequence includes Zest assertions then these should give you a good indication of whether or not the sequence is running in the same way as when it was recorded.

The active scanner will be run on each step of sequence, and each scan will complete before the next step is performed. If you are using the desktop then you will be able to see the scans for each step in the “Active Scan” tab - they will be labelled as “<sequence name>/Step <id>”.

Replaying each step, and attacking it before progressing to the next step, significantly increases the chances of the active scan successfully attacking the sequence. However you should check that the sequence did complete successfully and that the active scan requests were not automatically rejected. The reports that support sequences will include information that can help you determine this.

This add-on supports the [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/sequence-scanner/automation/).

## Creating Sequences

One sequence script should be created for each multi-step operation in the application/site being tested. There are several options for creating sequences:

1. Use the Automation Framework [sequence-import](https://www.zaproxy.org/docs/desktop/addons/sequence-scanner/automation/) job.
2. Use the Import menu item Import HAR as Sequence.
3. In either the Sites tree or History tab select the requests you wish to have included, right click, and use “Add To Zest Script” (either choosing to create a new script or adding to an existing Sequence script).
4. From the main tool bar, use the “Record a New Zest Script…” button, selecting “Sequence” as the type.

### Assertions

When importing the sequences it is possible to choose to create assertions for each HTTP message of the sequence:

- Assert Status Code - asserts that the replayed HTTP message has the same status code.
- Assert Length - asserts that the replayed HTTP message has the same response body length, within the margin (percentage) specified.

## Scanning

You can active scan sequences via:

- The “Sequence Active Scan” dialog.
- The context menu “Active Scan Sequence” option on the top node of a Sequence script.
- The Automation Framework [sequence-activeScan](https://www.zaproxy.org/docs/desktop/addons/sequence-scanner/automation/) job.

## Sequence Active Scan dialog

This dialog is accessible via the “Tools” menu, and allows you to actively scan sequences.

### Scan Policy

The name of the scan policy to use for active scanning. The “Sequence” policy included with this add-on is the recommented one to use.

### Sequences

The sequences to active scan. You must select at least one sequence. Selected sequences will be actively scanned in order.

## Reporting

The following reports can include sequence scanning results:

- [Traditional JSON Report](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/).
- [Traditional JSON Report with Requests and Responses](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/).

# Automation Framework Support

This add-on supports the Automation Framework.

## Job: sequence-import

The `sequence-import` job allows you to create a Sequence from an HAR file.

```yaml
  - type: sequence-import      # Imports a sequence from a HAR file.
    parameters:
      name:                    # The name by which the seq will be known in ZAP.
      path:                    # The full/relative path to the HAR file to import.
      assertCode:              # Boolean, if true add status code assertion.
      assertLength:            # Integer, if supplied then add approx len assertion (value between 0 and 100).

```

This job will automatically detect any HTTP Form parameters that are used in future requests and add Zest assignments to handle them.

## Job: sequence-activeScan

The `sequence-activeScan` job allows you to active scan sequences.

```yaml
  - type: sequence-activeScan                  # Active scans one or all sequences.
    parameters:
      sequence:                                # String: The name of the sequence, or empty to active scan all sequences.
      context:                                 # String: Context to use when active scanning, default: first context.
      user:                                    # String: An optional user to use for authentication, must be defined in the env.
      policy:                                  # String: Name of the scan policy to be used, default: Sequence.
    policyDefinition:                          # The policy definition - only used if the 'policy' is not set
      defaultStrength:                         # String: The default Attack Strength for all rules, one of Low, Medium, High, Insane (not recommended), default: Medium
      defaultThreshold:                        # String: The default Alert Threshold for all rules, one of Off, Low, Medium, High, default: Medium
      rules:                                   # A list of one or more active scan rules and associated settings which override the defaults
      - id:                                    # Int: The rule id as per https://www.zaproxy.org/docs/alerts/
        name:                                  # Comment: The name of the rule for documentation purposes - this is not required or actually used
        strength:                              # String: The Attack Strength for this rule, one of Low, Medium, High, Insane, default: Medium
        threshold:                             # String: The Alert Threshold for this rule, one of Off, Low, Medium, High, default: Medium
    tests:
      - name: 'test one'                       # Name of the test, optional
        type: alert                            # Specifies that the test is of type 'alert'
        action: passIfPresent/passIfAbsent     # String: The condition (presence/absence) of the alert, default: passIfAbsent
        scanRuleId:                            # Integer: The id of the scanRule which generates the alert, mandatory
        alertName:                             # String: The name of the alert generated, optional
        url: http://www.example.com/path       # String: The url of the request corresponding to the alert generated, optional
        method:                                # String: The method of the request corresponding to the alert generated, optional
        attack:                                # String: The actual attack which generated the alert, optional
        param:                                 # String: The parameter which was modified to generate the alert, optional
        evidence:                              # String: The evidence corresponding to the alert generated, optional
        confidence:                            # String: The confidence of the alert, one of 'False Positive', 'Low', 'Medium', 'High', 'Confirmed', optional
        risk:                                  # String: The risk of the alert, one of 'Informational', 'Low', 'Medium', 'High', optional
        otherInfo:                             # String: Addional information corresponding to the alert, optional
        onFail: 'info'                         # String: One of 'warn', 'error', 'info', mandatory

```

**Note** : Unless the `defaultThreshold` of the `policyDefinition` is `OFF` all rules will be enabled to start with.