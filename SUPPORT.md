# Commercial support

`mosquitto_cert_rego` is open source (EPL-2.0 OR BSD-3-Clause — see [LICENSE](LICENSE)). Anyone may run it, fork it, modify it, and ship it in their own products, commercial or otherwise, free of charge.

Running it in a production MQTT broker is also a fine moment to have a phone number to call when something goes wrong. **Nordic Trust Services** offers paid support and services on top of this project.

## What's on offer

- **Installation and integration.** Help wiring the plugin into an existing mosquitto deployment, PKI design review, Rego policy authoring alongside your security team, SIEM / audit-log pipeline setup.
- **Incident response.** Triage + root-cause analysis of auth / ACL / audit-log anomalies, with a defined response SLA.
- **Custom features.** Additional host functions (your own identity store, bespoke revocation source, SIEM format, …), custom cert-parsing extensions, additional audit sinks. Deliverable as either open-source patches upstreamed to this repo or as a private plugin that loads alongside this one.
- **Hardening review.** External review of your policies, audit configuration, and deployment topology against our cybersec test battery (see [e2e/README.md](e2e/README.md)) and your own threat model.
- **Training.** Rego-for-MQTT workshops for your engineering team, covering the input-document shape, fail-closed idioms, and the example patterns in [examples/](examples/).

## What's **not** on offer

- Changing the license of the open-source code published in this repository. EPL-2.0 OR BSD-3-Clause is final for everything already here — commercial support doesn't take that away from anyone.
- Indemnification beyond what the chosen open-source license provides, unless explicitly written into a signed services agreement.

## Getting in touch

- Project issues / bug reports / open-source discussion: GitHub issues on this repository.
- Commercial inquiries: contact Nordic Trust Services via the channel listed on our site (fill in once published — email, form, whatever).

## Trademark notice

"Nordic Trust Services" is a trademark of Nordic Trust Services. Forks, packages, and derivative works may freely use the code under the applicable open-source license, but may not use the Nordic Trust Services name or logo in a way that implies endorsement or affiliation without prior written permission.

The name of this project (`mosquitto_cert_rego`) is not a Nordic Trust Services trademark and may be used in fork names, packages, etc. subject to the open-source license terms.
