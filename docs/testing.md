# Testing

The project was tested using:

- Normal alert records
- Duplicate alert records
- Missing timestamp records
- Multiple alert types
- Benign alerts
- DDoS alerts
- Multiple source IP addresses
- CSV upload testing
- Dashboard display testing

Expected result:

- Duplicate alerts should be removed.
- Missing timestamps should be handled safely.
- Related alerts should be grouped.
- MITRE techniques should be displayed.
- Threat scores and threat levels should be generated.
