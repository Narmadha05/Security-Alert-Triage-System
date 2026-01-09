import json
from analyzer import triage_alert
from correlator import correlate_by_ip
from summarizer import format_triage_report, format_incident_report


def load_alerts():
    with open("alerts/sample_alerts.json") as f:
        return json.load(f)


if __name__ == "__main__":
    alerts = load_alerts()

    print("\n--- INDIVIDUAL ALERT TRIAGE ---")

    triaged_alerts = []

    for alert in alerts:
        triage_result = triage_alert(alert)

        enriched_alert = alert.copy()
        enriched_alert.update(triage_result)

        triaged_alerts.append(enriched_alert)

        print(format_triage_report(triage_result))

    print("\n--- CORRELATED INCIDENTS ---")

    incidents = correlate_by_ip(triaged_alerts)

    if not incidents:
        print("No correlated incidents detected.\n")
    else:
        for incident in incidents:
            print(format_incident_report(incident))
