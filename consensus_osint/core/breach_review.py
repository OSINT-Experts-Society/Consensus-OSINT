"""Explain recorded breach coverage without querying providers or loading adapters."""
from .models import Status, redact_options


def breach_review(summary):
    findings = [f for f in summary.findings if f.category == "breach"]
    options = summary.options or {}
    rows = []
    labels = {
        Status.FOUND: ("Exposure reported", "This provider reported breach or infostealer exposure; verify the returned evidence."),
        Status.NOT_FOUND: ("No exposure reported", "No match in this provider's available data. Other breaches may exist."),
        Status.UNKNOWN: ("Inconclusive", "The response did not establish whether exposure exists."),
        Status.BLOCKED: ("Access blocked", "The provider blocked the check or requires authorised access."),
        Status.RATE_LIMITED: ("Rate limited", "The provider limited requests; this is not a negative result."),
        Status.ERROR: ("Check failed", "The check could not complete; this is not a negative result."),
        Status.SKIPPED: ("Not run", "This check was skipped; no exposure verdict is available."),
    }
    for finding in findings:
        label, reason = labels.get(finding.status, labels[Status.UNKNOWN])
        from .presentation import split_fields
        from .reports import display_fields

        details, diagnostics = split_fields(finding.to_dict().get("extra", {}))
        if diagnostics.get("message"):
            details = {"Provider message": diagnostics["message"], **details}
        def flatten(value, path=""):
            if isinstance(value, dict):
                for key, item in value.items():
                    yield from flatten(item, f"{path}.{key}" if path else str(key))
            elif isinstance(value, list):
                for index, item in enumerate(value, 1):
                    yield from flatten(item, f"{path} [{index}]")
            elif value is not None and value != "":
                yield path, value

        evidence = [{"name": field.key, "label": field.key.replace("_", " ").replace("].", "] / ").capitalize(), "value": field.value}
                    for field in display_fields(dict(flatten(details)), limit=0, include_images=True)]
        if finding.status is Status.FOUND and not evidence:
            reason = "The provider reported exposure, but no supporting fields were returned or saved. This report cannot substantiate the signal."
        if finding.error:
            reason += " " + str(redact_options({"error": finding.error})["error"])
        elif finding.http_status and finding.status not in (Status.FOUND, Status.NOT_FOUND):
            reason += f" HTTP {finding.http_status}."
        rows.append({"query": finding.query, "site": finding.site, "outcome": label,
                     "explanation": reason, "evidence": evidence})
    if findings:
        explanation = "Breach lookups cover individual datasets. A failed or inconclusive check does not mean no breach exists."
    elif options.get("no_breach"):
        explanation = "Breach lookups were excluded for this search. No breach assessment was made."
    elif options.get("no_modules"):
        explanation = "Code integrations, including breach lookups, were excluded for this search."
    else:
        explanation = "No breach lookup outcome was recorded. This does not establish that the identifiers are absent from breaches."
    held = []
    plans = options.get("breach_plan", {})
    if isinstance(plans, dict):
        for plan in plans.values():
            if isinstance(plan, dict) and isinstance(plan.get("held"), list):
                held.extend(row for row in plan["held"] if isinstance(row, dict)
                            and isinstance(row.get("site"), str) and isinstance(row.get("reason"), str))
    return {"explanation": explanation, "rows": rows, "held": held}
