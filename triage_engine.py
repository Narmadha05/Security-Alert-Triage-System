# Severity levels used for alert triage
SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH"]

def triage_alert(alert):
    """
    Takes a security alert as input and returns a triage decision.
    """

    if alert.get("alert_type") == "AUTH_FAILURE":
        count = alert.get("count", 0)

        # LOW: single failure
        if count == 1:
            return {
                "severity": "LOW",
                "summary": "Single failed login attempt detected",
                "likely_cause": "User input error",
                "recommended_action": "Monitor"
            }

        # MEDIUM: repeated failures
        elif 2 <= count <= 4:
            return {
                "severity": "MEDIUM",
                "summary": "Multiple failed login attempts detected",
                "likely_cause": "Suspicious login behavior",
                "recommended_action": "Investigate user activity"
            }

        # HIGH: aggressive failures
        elif count >= 5:
            return {
                "severity": "HIGH",
                "summary": "High number of failed login attempts detected",
                "likely_cause": "Potential brute-force attack",
                "recommended_action": "Escalate and investigate source IP"
            }


        # Rule for unauthorized access attempts
    if alert.get("alert_type") == "UNAUTHORIZED_ACCESS":
        return {
            "severity": "HIGH",
            "summary": "Unauthorized access attempt detected",
            "likely_cause": "Access control violation",
            "recommended_action": "Escalate immediately and investigate affected resource"
        }
     


# Default handling for unknown alert types
    return {
        "severity": "MEDIUM",
        "summary": "Unknown alert type received",
        "likely_cause": "Unrecognized or new alert pattern",
        "recommended_action": "Review alert details and update triage rules if necessary"
    }

def format_triage_report(triage_result):
    """
    Formats the triage result into a human-readable report.
    """
    return (
        f"\n--- SECURITY ALERT TRIAGE REPORT ---\n"
        f"Severity          : {triage_result['severity']}\n"
        f"Summary           : {triage_result['summary']}\n"
        f"Likely Cause      : {triage_result['likely_cause']}\n"
        f"Recommended Action: {triage_result['recommended_action']}\n"
        f"-----------------------------------\n"
    )



if __name__ == "__main__":
    alerts = [
        {
            "alert_type": "AUTH_FAILURE",
            "count": 1,
            "source": "192.168.1.10"
        },
        {
            "alert_type": "AUTH_FAILURE",
            "count": 4,
            "source": "192.168.1.15"
        },
        {
            "alert_type": "AUTH_FAILURE",
            "count": 7,
            "source": "192.168.1.22"
        },
        {
            "alert_type": "UNAUTHORIZED_ACCESS",
            "user": "admin@example.com",
            "resource": "admin_panel"
        },
        {
            "alert_type": "UNKNOWN_EVENT",
            "details": "Unexpected system behavior"
        }
    ]

    for alert in alerts:
        triage_result = triage_alert(alert)
        report = format_triage_report(triage_result)
        print(report)

