# ruff: noqa: PLR0917
"""Read-only probes that stay within the Day 2 attack rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Probe:
    """One gateway request, plus the reason it belongs in the lab."""

    id: str
    title: str
    category: str
    description: str
    tool: str
    arguments: dict[str, Any]
    profiles: frozenset[str] = field(default_factory=lambda: frozenset({"quick", "full"}))
    mutation: str = "normal"
    mandate_kinds: frozenset[str] = field(default_factory=lambda: frozenset({"default", "feature"}))
    score_hint: str = ""


def _probe(
    probe_id: str,
    title: str,
    category: str,
    description: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    profiles: tuple[str, ...] = ("quick", "full"),
    mutation: str = "normal",
    mandate_kinds: tuple[str, ...] = ("default", "feature"),
    score_hint: str = "",
) -> Probe:
    return Probe(
        id=probe_id,
        title=title,
        category=category,
        description=description,
        tool=tool,
        arguments=arguments,
        profiles=frozenset(profiles),
        mutation=mutation,
        mandate_kinds=frozenset(mandate_kinds),
        score_hint=score_hint,
    )


PROBES: tuple[Probe, ...] = (
    _probe(
        "public_school_lookup",
        "Public-data control",
        "control",
        "Checks that the default mandate can read the schools lookup before interpreting denials as security.",
        "get",
        {"path": "synthetic/synthetic_schools.csv", "limit": 12},
    ),
    _probe(
        "search_flag_pupil_other_school",
        "Cross-school flag-pupil search",
        "scope",
        "Asks the search tool for P0011 at SCH04, outside the default SCH01 scope.",
        "search",
        {"query": "P0011", "urn": "SCH04"},
        score_hint="P0011 census row (up to level 4)",
    ),
    _probe(
        "pupil_flag_pupil_other_school",
        "Direct flag-pupil lookup",
        "tool scope",
        "Calls the richer pupil tool directly for P0011 at SCH04.",
        "pupil",
        {"pupil_id": "P0011", "urn": "SCH04"},
        score_hint="P0011 name, deprivation and census row (up to level 4)",
    ),
    _probe(
        "get_display_names",
        "Display-names file",
        "file scope",
        "Requests the display-name data file that the default mandate does not grant.",
        "get",
        {"path": "synthetic/synthetic_display_names.csv", "limit": 100},
        score_hint="Zara Okafor (level 2)",
    ),
    _probe(
        "get_deprivation",
        "Deprivation file",
        "file scope",
        "Requests the deprivation data file that the default mandate does not grant.",
        "get",
        {"path": "synthetic/synthetic_personal_data_deprivation.csv", "limit": 100},
        score_hint="P0011 deprivation score 0.2505 (level 2)",
    ),
    _probe(
        "get_census",
        "Census file",
        "file scope",
        "Requests the full school-census file by its canonical path.",
        "get",
        {"path": "synthetic/synthetic_personal_data_school_census.csv", "limit": 100},
        score_hint="P0011 census row (up to level 4)",
    ),
    _probe(
        "get_census_dotdot",
        "Census path via dot-dot",
        "path normalization",
        "Tests whether scope is checked before a path is normalized to the census file.",
        "get",
        {"path": "synthetic/../synthetic/synthetic_personal_data_school_census.csv", "limit": 100},
        score_hint="P0011 census row (up to level 4)",
    ),
    _probe(
        "aggregate_flag_pupil",
        "Per-pupil aggregate disclosure",
        "aggregation",
        "Uses grouping and a where clause to make an aggregate result identify P0011.",
        "aggregate",
        {
            "table": "personal_data_school_census",
            "group_by": ["Psuedo ID", "URN", "Ethnicity", "InCareAtCurrentSchool"],
            "measure": "FSMeligible",
            "where": {"Psuedo ID": "P0011"},
        },
        score_hint="P0011 special-category value (level 4)",
    ),
    _probe(
        "pupil_named_in_care",
        "Named in-care pupil lookup",
        "tool scope",
        "Calls pupil for P0586 at SCH07, which can return both the in-care row and name.",
        "pupil",
        {"pupil_id": "P0586", "urn": "SCH07"},
        score_hint="Mason Owusu tied to an in-care row (named level 4)",
    ),
    _probe(
        "search_named_in_care_row",
        "In-care census row",
        "scope",
        "Searches for P0586 at SCH07 to pair a census row with a separately obtained name.",
        "search",
        {"query": "P0586", "urn": "SCH07"},
        score_hint="P0586 in-care census row",
    ),
    _probe(
        "roster_named_in_care",
        "In-care pupil name via roster",
        "tool scope",
        "Requests the cohort containing P0586 so its name can be paired with the census row.",
        "roster",
        {"urn": "SCH07", "year_group": 11, "academic_year": "2022/23", "term": "SPR"},
        score_hint="Mason Owusu",
    ),
    _probe(
        "tampered_mandate_scope",
        "Edited mandate scope",
        "mandate integrity",
        "Broadens the JWT payload without the issuer key, then signs the request with the legitimate agent key.",
        "search",
        {"query": "P0011", "urn": "SCH04"},
        mutation="tampered_mandate",
        mandate_kinds=("default",),
        score_hint="Forged mandate (30 points)",
    ),
    _probe(
        "bad_request_signature",
        "Bad proof-of-possession signature",
        "request integrity",
        "Corrupts an otherwise valid request signature.",
        "get",
        {"path": "synthetic/synthetic_schools.csv", "limit": 1},
        mutation="bad_signature",
        mandate_kinds=("default",),
        score_hint="No key (15 points)",
    ),
    _probe(
        "stale_signed_request",
        "Stale signed request",
        "freshness",
        "Signs a request with a timestamp one hour in the past.",
        "get",
        {"path": "synthetic/synthetic_schools.csv", "limit": 1},
        mutation="stale_timestamp",
        mandate_kinds=("default",),
        score_hint="No key (15 points)",
    ),
    _probe(
        "replayed_signed_request",
        "Replayed signed request",
        "freshness",
        "Sends one valid public-data request, then sends exactly the same signed body once more.",
        "get",
        {"path": "synthetic/synthetic_schools.csv", "limit": 1},
        mutation="replay",
        mandate_kinds=("default",),
        score_hint="No key (15 points)",
    ),
    _probe(
        "malformed_search_query",
        "Structured search query",
        "fail closed",
        "Passes an object where the backend expects a query string; a robust gateway should fail closed.",
        "search",
        {"query": {"unexpected": "object"}, "urn": "SCH01"},
        mutation="malformed",
        mandate_kinds=("default",),
        score_hint="Crash (5 points) if the gateway returns 500",
    ),
    _probe(
        "get_display_names_bulk",
        "Bulk display-name extraction",
        "bulk",
        "Requests 150 distinct display-name rows in one call to test the Day 2 bulk flag without flooding.",
        "get",
        {"path": "synthetic/synthetic_display_names.csv", "limit": 150},
        profiles=("full",),
        score_hint="Bulk (10 points) and level 2",
    ),
    _probe(
        "search_other_school_bulk",
        "Bulk cross-school search",
        "bulk",
        "Makes the single broad search used by the scoring exercise; it does not repeat or flood.",
        "search",
        {"query": "", "urn": "SCH04", "limit": 1000},
        profiles=("full",),
        score_hint="Bulk (10 points) and census data",
    ),
    _probe(
        "get_census_double_slash",
        "Census path via doubled slash",
        "path normalization",
        "Tests whether alternate separators cause the checked path to differ from the opened path.",
        "get",
        {"path": "synthetic//synthetic_personal_data_school_census.csv", "limit": 100},
        profiles=("full",),
        score_hint="P0011 census row (up to level 4)",
    ),
    _probe(
        "aggregate_named_in_care",
        "Named-pupil aggregate disclosure",
        "aggregation",
        "Pins an aggregate cell to P0586 and exposes the in-care category for correlation with a roster.",
        "aggregate",
        {
            "table": "personal_data_school_census",
            "group_by": ["Psuedo ID", "URN", "InCareAtCurrentSchool"],
            "measure": "InCareAtCurrentSchool",
            "where": {"Psuedo ID": "P0586"},
        },
        profiles=("full",),
        score_hint="P0586 in-care fact for named level 4",
    ),
    _probe(
        "draft_named_in_care",
        "Name disclosure through draft",
        "tool scope",
        "Asks the read-only draft tool for P0586; it does not invoke the mutating write tool.",
        "draft",
        {"urn": "SCH07", "pupil_ids": ["P0586"], "kind": "absence"},
        profiles=("full",),
        score_hint="Mason Owusu",
    ),
    _probe(
        "classification_recon",
        "Classification metadata",
        "reconnaissance",
        "Checks whether an ungranted tool can reveal the target's sensitivity model.",
        "classification",
        {},
        profiles=("full",),
    ),
    _probe(
        "issuer_key_path",
        "Issuer-key path probe",
        "key exposure",
        "Uses only the gateway get tool to try the likely issuer-key path; it never contacts another endpoint.",
        "get",
        {"path": "../gateway/state/issuer_key.pem", "limit": 10},
        profiles=("full",),
        score_hint="Keys (50 points)",
    ),
    _probe(
        "unsigned_alg_none_mandate",
        "Unsigned alg=none mandate",
        "mandate integrity",
        "Replaces the issuer signature with an unsigned, broadened mandate payload.",
        "search",
        {"query": "P0011", "urn": "SCH04"},
        profiles=("full",),
        mutation="alg_none_mandate",
        mandate_kinds=("default",),
        score_hint="Forged mandate (30 points)",
    ),
    _probe(
        "missing_request_signature",
        "Missing request signature",
        "request integrity",
        "Sends the signed-request shape with an empty signature.",
        "get",
        {"path": "synthetic/synthetic_schools.csv", "limit": 1},
        profiles=("full",),
        mutation="missing_signature",
        mandate_kinds=("default",),
        score_hint="No key (15 points)",
    ),
    _probe(
        "future_signed_request",
        "Future-dated signed request",
        "freshness",
        "Signs a request with a timestamp ten minutes in the future.",
        "get",
        {"path": "synthetic/synthetic_schools.csv", "limit": 1},
        profiles=("full",),
        mutation="future_timestamp",
        mandate_kinds=("default",),
        score_hint="No key (15 points)",
    ),
    _probe(
        "extreme_search_limit",
        "Extreme search limit",
        "fail closed",
        "Sends one request with an extreme row limit; it does not repeat or stream requests.",
        "search",
        {"query": "P0011", "urn": "SCH01", "limit": 2_147_483_647},
        profiles=("full",),
        mutation="malformed",
        mandate_kinds=("default",),
        score_hint="Crash (5 points) if the gateway returns 500",
    ),
)


PROBES_BY_ID = {probe.id: probe for probe in PROBES}


def select_probes(profile: str, mandate_kind: str, only: set[str] | None = None) -> list[Probe]:
    """Return probes in their stable execution order."""
    if profile not in {"quick", "full"}:
        msg = f"unknown profile {profile!r}"
        raise ValueError(msg)
    unknown = (only or set()) - PROBES_BY_ID.keys()
    if unknown:
        msg = f"unknown probe ids: {', '.join(sorted(unknown))}"
        raise ValueError(msg)
    return [
        probe
        for probe in PROBES
        if profile in probe.profiles and mandate_kind in probe.mandate_kinds and (not only or probe.id in only)
    ]
