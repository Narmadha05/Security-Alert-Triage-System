from collections import defaultdict

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}

def determine_confidence(alert_count, highest_severity):
    if alert_count >= 5 and highest_severity == "HIGH":
        return "HIGH"
    elif alert_count >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def correlate_by_ip(triaged_alerts, threshold=3):
    """
    Groups triaged alerts by source IP and identifies correlated activity.

    Args:
        triaged_alerts (list): List of dicts with alert data + triage result
        threshold (int): Minimum alerts from same IP to consider correlation

    Returns:
        list: Correlated incident summaries
    """

    ip_groups = defaultdict(list)

    # Group alerts by source IP
    for alert in triaged_alerts:
        source_ip = alert.get("source_ip")
        if source_ip:
            ip_groups[source_ip].append(alert)

    correlated_incidents = []

    for ip, alerts in ip_groups.items():
        if len(alerts) >= threshold:
            highest_severity = max(
                alerts,
                key=lambda a: SEVERITY_ORDER[a["severity"]]
            )["severity"]

            confidence = determine_confidence(len(alerts), highest_severity)
            correlated_incidents.append({
                "source_ip": ip,
                "alerts_observed": len(alerts),
                "incident_severity": highest_severity,
                "confidence": confidence,
                "interpretation": "Repeated suspicious activity from same source",
                "recommended_action": "Investigate and consider blocking source IP"
                })


    return correlated_incidents
