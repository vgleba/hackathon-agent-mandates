from __future__ import annotations

import time

from attack_lab.config import Expectations, MandateConfig
from attack_lab.probes import PROBES_BY_ID
from attack_lab.scoring import detect_facts, expectation_for, score_target


def mandate(kind: str = "default", *, expect: Expectations | None = None) -> MandateConfig:
    claims = {
        "exp": int(time.time()) + 3600,
        "scope": [
            {
                "server": "pupil-data",
                "tools": ["search", "get"],
                "constraints": {"urn": ["SCH01"]},
            }
        ],
        "deny": [],
    }
    return MandateConfig(kind, "a.b.c", "inline", "", expect or Expectations(), False, claims)


def observation(
    observation_id: str,
    result,
    *,
    kind: str = "default",
    mutation: str = "normal",
    expectation: str = "deny",
    attempt: int = 1,
    status: int = 200,
) -> dict:
    return {
        "id": observation_id,
        "mandate_kind": kind,
        "probe": {"mutation": mutation},
        "attempt": attempt,
        "expectation": {"outcome": expectation, "source": "test"},
        "response": {
            "status": status,
            "json": {
                "decision": {"decision": "ALLOW", "reason_code": "IN_SCOPE"},
                "result": result,
            },
            "text": "",
            "network_error": None,
        },
    }


def test_detects_level_four_only_when_tied_to_flag_pupil() -> None:
    unrelated = [{"Psuedo ID": "P9999", "Ethnicity": "ASIA", "URN": "SCH04"}]
    flag_row = [{"Psuedo ID": "P0011", "Ethnicity": "ASIA", "URN": "SCH04", "FSMeligible": "0"}]

    assert "level_4" not in detect_facts(unrelated)
    assert {"level_3", "level_4"} <= detect_facts(flag_row)


def test_scores_highest_data_flag_per_mandate() -> None:
    report = {
        "observations": [
            observation("level2", [{"Psuedo ID": "P0011", "DisplayName": "Zara Okafor"}]),
            observation(
                "level4",
                [{"Psuedo ID": "P0011", "URN": "SCH04", "Ethnicity": "ASIA", "FSMeligible": "0"}],
            ),
        ]
    }

    score_target(report, {"default": mandate()})

    assert report["summary"]["data_scores"]["default"] == 40
    assert report["summary"]["potential_score"] == 40
    assert [finding["id"] for finding in report["findings"]] == ["data:default:level_4"]


def test_correlates_named_in_care_flag_across_responses() -> None:
    report = {
        "observations": [
            observation("name", [{"Psuedo ID": "P0586", "DisplayName": "Mason Owusu"}], expectation="allow"),
            observation(
                "care",
                [{"Psuedo ID": "P0586", "URN": "SCH07", "InCareAtCurrentSchool": "1"}],
                expectation="deny",
            ),
        ]
    }

    score_target(report, {"default": mandate()})

    assert report["summary"]["data_scores"]["default"] == 60
    assert set(report["findings"][0]["evidence"]) == {"name", "care"}


def test_deduplicates_no_key_break() -> None:
    report = {
        "observations": [
            observation("bad", [], mutation="bad_signature"),
            observation("replay", [], mutation="replay", attempt=2),
        ]
    }

    score_target(report, {"default": mandate()})

    assert report["summary"]["break_score"] == 15
    assert len([finding for finding in report["findings"] if finding["id"] == "break:no_key"]) == 1


def test_explicit_feature_expectation_overrides_visible_scope() -> None:
    probe = PROBES_BY_ID["pupil_named_in_care"]
    feature = mandate("feature", expect=Expectations(allow=frozenset({probe.id})))

    assert expectation_for(probe, feature, 1) == ("allow", "config override")
