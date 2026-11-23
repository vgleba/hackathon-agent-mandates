"""Desk end to end: the real page API, gateway, data server and assistant processes."""

import re
import subprocess
import sys
import threading
import time

import httpx
import pytest

from desk import server, words
from lab import launch

BASE = f"http://127.0.0.1:{server.PORTS['page']}"
ORIGIN = {"origin": BASE}
DUNMORE = {"school": "SCH04", "year": 11}
OK, REFUSED, SIGNED_OUT, MISSING = 200, 403, 401, 404


class Person(httpx.Client):
    def __init__(self, link: str):
        super().__init__(base_url=BASE, headers=ORIGIN, timeout=60, follow_redirects=True)
        self.get(link)

    def check(self, job, **choice):
        return self.post("/api/check", json={"job": job, "choice": choice}).json()

    def start(self, job, **choice):
        r = self.post("/api/start", json={"draft": self.check(job, **choice)["draft"]})
        assert r.status_code == OK, r.text
        return r.json()["id"]

    def job(self, job_id):
        return next(j for j in self.get("/api/work").json()["jobs"] if j["id"] == job_id)

    def waiting(self, at_least=0):
        for _ in range(80):
            found = self.get("/api/waiting").json()["waiting"]
            if len(found) >= at_least:
                return found
            time.sleep(0.25)
        raise AssertionError

    def finish(self, job_id, answer=None):
        done = set()
        for _ in range(160):
            job = self.job(job_id)
            if not job["running"]:
                return job
            for w in self.waiting() if answer else []:
                if w["id"] not in done:
                    done.add(w["id"])
                    self.post(f"/api/waiting/{w['id']}", json={"answer": answer})
            time.sleep(0.25)
        raise AssertionError(job)

    def run(self, job, answer=None, **choice):
        return self.finish(self.start(job, **choice), answer)

    def ids(self, **where):
        return list(self.post("/api/class", json={**DUNMORE, **where}).json()["pupils"])


@pytest.fixture(scope="module")
def links():
    try:
        launch.require_free_ports(server.PORTS, "Desk")
    except SystemExit:
        pytest.skip("Desk is already running")
    child = subprocess.Popen(
        [sys.executable, "-u", "-m", "desk"],
        cwd=server.ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    found = []
    try:
        for line in child.stdout:
            found += re.findall(r"http://\S+/signin\?t=\S+", line)
            if len(found) == 2:
                break
        # keep reading, or a full pipe would stop everything that Desk started; and nothing here should log an error
        logged = []
        threading.Thread(target=lambda: logged.extend(child.stdout), daemon=True).start()
        for _ in range(100):
            try:
                httpx.get(BASE)
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        yield found
    finally:
        child.kill()
        child.wait()
    assert not [line for line in logged if "Traceback" in line], "".join(logged)


@pytest.fixture(scope="module")
def jsmith(links):
    return Person(links[0])


@pytest.fixture(scope="module")
def priya(links):
    return Person(links[1])


# ------------------------------------------------------------ signing in


def test_a_link_signs_one_person_in_once(links, jsmith, priya):
    assert jsmith.get("/api/me").json()["name"] == "J Smith"
    assert list(priya.get("/api/me").json()["schools"]) == ["SCH04", "SCH05"]
    assert Person(links[0]).get("/api/me").status_code == SIGNED_OUT


@pytest.mark.parametrize("path", ["me", "work", "waiting", "activity", "handover"])
def test_nothing_without_signing_in(links, path):  # noqa: ARG001
    assert httpx.get(f"{BASE}/api/{path}").status_code == SIGNED_OUT
    assert httpx.get(f"{BASE}/api/{path}", cookies={"desk": "made-up"}).status_code == SIGNED_OUT


def test_another_site_cannot_drive_the_page(jsmith):
    ask = {"json": {}, "cookies": dict(jsmith.cookies)}
    assert httpx.post(f"{BASE}/api/stop-everything", **ask).status_code == REFUSED
    evil = {"origin": "https://evil.example"}
    assert httpx.post(f"{BASE}/api/stop-everything", headers=evil, **ask).status_code == REFUSED
    assert httpx.get(BASE, headers={"host": "evil.example"}).status_code == 400


# ------------------------------------------------------------ every job


def test_find_a_pupil(jsmith):
    one = jsmith.ids()[:1]
    basic = jsmith.run("find_pupil", **DUNMORE, pupils=one, detail="basic")
    assert basic["state"] == "done"
    assert "Free school meals" not in basic["result"]["columns"]
    meals = jsmith.run("find_pupil", **DUNMORE, pupils=one, detail="meals")
    assert "Free school meals" in meals["result"]["columns"]
    assert "Ethnic group" not in meals["result"]["columns"]


def test_counts(jsmith):
    meals = jsmith.run("count", what="meals", split="school", school="all", when="term")
    assert ["Dunmore Community College", "About 15", "About 40"] in meals["result"]["rows"]
    care = jsmith.run("count", what="care", split="school", school="all", when="term")
    assert all(r[1] == words.TOO_FEW for r in care["result"]["rows"])


def test_a_year_group_one_pupil_at_a_time(jsmith):
    job = jsmith.run("meals_check", school="SCH05", year=11, pupils=jsmith.ids(school="SCH05"))
    assert job["result"]["note"].startswith("12 of 38")


def test_letters_approved_and_refused(jsmith):
    three = jsmith.ids()[:3]
    yes = jsmith.run("letters", "approve", **DUNMORE, kind="absence", pupils=three, helper=False)
    assert len(yes["result"]["letters"]) == 3
    no = jsmith.run("letters", "refuse", **DUNMORE, kind="absence", pupils=three, helper=False)
    assert (no["state"], no["result"]) == ("stopped", None)


def test_letters_shared_with_a_helper(jsmith):
    job = jsmith.run("letters", "approve", **DUNMORE, kind="absence", pupils=jsmith.ids()[:4], helper=True)
    assert len(job["result"]["letters"]) == 4
    assert "wrote 2" in job["helper"]


def test_a_correction_shows_now_and_new(jsmith):
    fix = {"field": "Language", "value": "2_OTH", "reason": "test"}
    job_id = jsmith.start("correct", **DUNMORE, pupils=jsmith.ids()[:1], **fix)
    (item,) = jsmith.waiting(1)
    assert item["change"]["new"] == "Another language"
    assert item["change"]["now"]
    assert jsmith.finish(job_id, "refuse")["state"] == "stopped"


def test_safeguarding_and_what_it_saw(jsmith):
    job = jsmith.run("safeguarding", **DUNMORE, pupils=jsmith.ids()[:2], confirm=True)
    seen = jsmith.get(f"/api/work/{job['id']}/seen").json()
    assert (len(seen["pupils"]), seen["special"], seen["complete"]) == (2, ["Ethnic group", "In care"], True)


def test_the_newsletter_sees_nobody(jsmith):
    job = jsmith.run("newsletter")
    assert jsmith.get(f"/api/work/{job['id']}/seen").json()["pupils"] == []


# ------------------------------------------------------------ control


def test_two_people_are_kept_apart_and_access_can_be_taken_back(jsmith, priya):
    two = {**DUNMORE, "kind": "absence", "pupils": jsmith.ids()[:2], "helper": True}
    draft = jsmith.check("letters", **two)["draft"]
    assert priya.post("/api/start", json={"draft": draft}).status_code == MISSING
    job_id = jsmith.post("/api/start", json={"draft": draft}).json()["id"]
    assert jsmith.post("/api/start", json={"draft": draft}).status_code == MISSING
    held = jsmith.waiting(2)
    assert priya.get("/api/waiting").json()["waiting"] == []
    for path in (f"/api/work/{job_id}/take-back", f"/api/work/{job_id}/stop-helper"):
        assert priya.post(path, json={}).status_code == MISSING
    assert priya.get(f"/api/work/{job_id}/seen").status_code == MISSING
    assert priya.post(f"/api/waiting/{held[0]['id']}", json={"answer": "approve"}).status_code == REFUSED
    assert jsmith.post(f"/api/work/{job_id}/take-back", json={}).status_code == OK
    assert jsmith.job(job_id)["state"] == "taken back"
    assert jsmith.post(f"/api/waiting/{held[0]['id']}", json={"answer": "approve"}).status_code == REFUSED


def test_stop_everything_stops_everything(jsmith):
    one = {**DUNMORE, "kind": "absence", "pupils": jsmith.ids()[:1], "helper": False}
    started = [jsmith.start("letters", **one) for _ in range(2)]
    jsmith.waiting(2)
    jsmith.post("/api/stop-everything", json={})
    assert {jsmith.job(j)["state"] for j in started} == {"taken back"}


def test_the_browser_cannot_supply_names_pupils_or_access(jsmith, priya):
    base = {**DUNMORE, "detail": "basic"}
    for pupils in ({"P0011": "Nobody"}, ["P0011"], ["P0001"], "P0011", None):
        assert jsmith.check("find_pupil", **base, pupils=pupils)["ask"]["field"] == "pupils"
    assert "ask" in jsmith.check("newsletter", scope=[])
    assert priya.post("/api/class", json={"school": "SCH01", "year": 11}).status_code == REFUSED


def test_no_key_or_mandate_reaches_the_browser(jsmith):
    paths = ("/api/me", "/api/work", "/api/waiting", "/api/activity", "/", "/app.js")
    text = "".join(jsmith.get(p).text for p in paths)
    assert not re.search(r"PRIVATE KEY|eyJ[A-Za-z0-9_-]{20}|\"jwk\"|\"sig\"", text)


def test_activity_is_in_plain_words(jsmith):
    found = jsmith.get("/api/activity").json()
    assert found["complete"]
    assert found["lines"]
    assert not any(re.search(r"[A-Z]{3,}_[A-Z]", x["text"]) for x in found["lines"])
