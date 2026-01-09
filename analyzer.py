def triage_alert(alert):
    """
    Takes a security alert as input and returns a triage decision.
    """

    alert_type = alert.get("alert_type")

    # Authentication failures
    if alert_type == "AUTH_FAILURE":
        count = alert.get("count", 0)

        if count == 1:
            return {
                "severity": "LOW",
                "summary": "Single failed login attempt detected",
                "likely_cause": "User input error",
                "recommended_action": "Monitor"
            }

        elif 2 <= count <= 4:
            return {
                "severity": "MEDIUM",
                "summary": "Multiple failed login attempts detected",
                "likely_cause": "Suspicious login behavior",
                "recommended_action": "Investigate user activity"
            }

        elif count >= 5:
            return {
                "severity": "HIGH",
                "summary": "High number of failed login attempts detected",
                "likely_cause": "Potential brute-force attack",
                "recommended_action": "Escalate and investigate source IP"
            }

    # Unauthorized access attempts
    if alert_type == "UNAUTHORIZED_ACCESS":
        return {
            "severity": "HIGH",
            "summary": "Unauthorized access attempt detected",
            "likely_cause": "Access control violation",
            "recommended_action": "Escalate immediately and investigate affected resource"
        }

    # Safe default for unknown alerts
    return {
        "severity": "MEDIUM",
        "summary": "Unknown alert type received",
        "likely_cause": "Unrecognized or new alert pattern",
        "recommended_action": "Review alert details and update triage rules if necessary"
    }
