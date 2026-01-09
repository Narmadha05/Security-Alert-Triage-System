# Security Alert Traige and Correlation Engine
A rule-based security system that analyzes raw security alerts, assigns severity, correlates related events by source IP, and generates incident-level summaries to support security triage and prioritization.
The project focuses on security decision-making, not alert generation or exploitation.

# Core Components
- analyzer.py : Applies triage rules to classify alerts as Low, Medium or High
- correlator.py : Correlates alerts by source IP and generates incidents with confidence scoring
- summarizer.py : Formats alerts and incidents into human-readable reports
- alerts/sample_alerts.json : Simulated security alert input
- app.py : Integrates the full pipeline
