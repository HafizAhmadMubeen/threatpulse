"""A small hand-built STIX bundle, so most RAG tests need no download.

It has the shapes that matter in the real file: a sub-technique, a revocation chain, a
deprecated technique, and detection text that sits in separate objects.
"""


def technique(stix_id: str, external_id: str | None, name: str, **fields) -> dict:
    references = [{"source_name": "mitre-attack", "external_id": external_id}] if external_id else []
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": fields.pop("description", f"{name} description."),
        "external_references": references,
        "kill_chain_phases": [{"phase_name": fields.pop("tactic", "credential-access")}],
        "x_mitre_platforms": fields.pop("platforms", ["Windows"]),
        **fields,
    }


def relationship(kind: str, source: str, target: str) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{kind}-{source}-{target}",
        "relationship_type": kind,
        "source_ref": source,
        "target_ref": target,
    }


def analytic(stix_id: str, text: str, platform: str = "Windows", **fields) -> dict:
    return {
        "type": "x-mitre-analytic",
        "id": stix_id,
        "description": text,
        "x_mitre_platforms": [platform],
        **fields,
    }


def strategy(stix_id: str, name: str, analytics: list[str], **fields) -> dict:
    return {
        "type": "x-mitre-detection-strategy",
        "id": stix_id,
        "name": name,
        "x_mitre_analytic_refs": analytics,
        **fields,
    }


def fixture_objects() -> list[dict]:
    return [
        technique("ap--parent", "T1003", "OS Credential Dumping"),
        technique(
            "ap--lsass",
            "T1003.001",
            "LSASS Memory",
            description=(
                "Adversaries read <code>lsass.exe</code> memory.(Citation: Some Report) "
                "See [the docs](https://example.com/page) for more."
            ),
        ),
        technique("ap--linux", "T1111", "Linux Only", platforms=["Linux"], tactic="discovery"),
        technique("ap--final", "T1685", "Disable or Modify Tools", tactic="defense-impairment"),
        technique("ap--old", "T1562.001", "Disable or Modify Tools", revoked=True),
        # A chain: T1150 -> T1547.011 -> T1003
        technique("ap--chain1", "T1150", "Old One", revoked=True),
        technique("ap--chain2", "T1547.011", "Old Two", revoked=True),
        technique("ap--deprecated", "T1064", "Scripting", x_mitre_deprecated=True),
        # A revocation whose replacement is deprecated, so nothing active remains.
        technique("ap--dead", "T1999", "Dead End", revoked=True),
        technique("ap--noid", None, "No External ID"),
        relationship("revoked-by", "ap--old", "ap--final"),
        relationship("revoked-by", "ap--chain1", "ap--chain2"),
        relationship("revoked-by", "ap--chain2", "ap--parent"),
        relationship("revoked-by", "ap--dead", "ap--deprecated"),
        analytic("an--linux", "Linux analytic text.", platform="Linux"),
        analytic("an--windows", "Process opens lsass.exe with vm_read.(Citation: X)"),
        analytic("an--retired", "Retired analytic.", x_mitre_deprecated=True),
        strategy(
            "det--lsass",
            "Detection of LSASS access",
            ["an--linux", "an--windows", "an--retired", "an--missing"],
        ),
        strategy("det--retired", "Retired strategy", [], x_mitre_deprecated=True),
        relationship("detects", "det--lsass", "ap--lsass"),
        relationship("detects", "det--retired", "ap--parent"),
    ]
