"""Evidence-status rules shared by the Streamlit UI and automated tests."""


def nvd_status(cve_id: str | None, nvd_available: bool, nvd_error: str | None) -> tuple[str, str]:
    """Return a user-facing NVD label and explanation without overclaiming."""
    if not cve_id:
        return "Not requested", "Enter a CVE ID to retrieve an official NVD CVE record."
    if nvd_error:
        return "Unavailable", "NVD could not be reached; any local CISA result is still shown below."
    if nvd_available:
        return "Record found", "Official NVD CVE record retrieved."
    return "No record found", f"NVD did not return a record for {cve_id}."


def cisa_status(cve_id: str | None, cisa_match_count: int) -> tuple[str, str]:
    """Return a cautious CISA KEV status statement."""
    if not cve_id:
        return "Semantic search", "Results are relevant CISA KEV records, not an exact CVE match."
    if cisa_match_count:
        return "Listed in KEV", "CISA has a matching record in its Known Exploited Vulnerabilities catalog."
    return (
        "Not listed in KEV",
        "No CISA KEV match was found. This does not prove the vulnerability is safe or unexploited.",
    )
