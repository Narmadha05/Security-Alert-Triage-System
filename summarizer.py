def format_triage_report(triage_result):
    """
    Formats an individual alert triage result into a human-readable report.
    """
    return (
        f"\n--- SECURITY ALERT TRIAGE REPORT ---\n"
        f"Severity          : {triage_result['severity']}\n"
        f"Summary           : {triage_result['summary']}\n"
        f"Likely Cause      : {triage_result['likely_cause']}\n"
        f"Recommended Action: {triage_result['recommended_action']}\n"
        f"-----------------------------------\n"
    )


def format_incident_report(incident):
    """
    Formats a correlated security incident into a human-readable report.
    """
    return (
        f"\n=== CORRELATED SECURITY INCIDENT ===\n"
        f"Source IP         : {incident['source_ip']}\n"
        f"Alerts Observed   : {incident['alerts_observed']}\n"
        f"Incident Severity : {incident['incident_severity']}\n"
        f"Confidence        : {incident['confidence']}\n"
        f"Interpretation    : {incident['interpretation']}\n"
        f"Recommended Action: {incident['recommended_action']}\n"
        f"===================================\n"
    )
