"""Expert-grade assessment records: derive whether the multi-agent gates were met.

The `expert` object in a schema-version-2 findings file records the spend
consent, preflights, every spawned worker, redundant recon and discovery,
variant analysis, refutation panels, severity calibration and ratings, the
omission challenge, simulated reception and the non-participant QA audit
(`reference/expert-mode.md`). This module recomputes the gates from those
records; supplied summaries and statuses are never trusted. It checks declared
records and their consistency, not that a worker really ran or judged well.
"""
import re

from three_pass import derive_three_pass

VERSION = 1
DISCOVERY_ANGLES = ("entry-first", "sink-first", "control-first")
SKEPTIC_ANGLES = ("defense-exists", "unreachable", "precondition-unrealistic", "impact-overstated",
                  "not-shipped")
PERSONAS = ("executive", "engineer", "auditor")
ROLES = ("recon", "discovery", "variant", "conditions", "falsification", "skeptic", "rater", "omission",
         "persona", "qa")
SEVERITY_ORDER = ("High", "Medium", "Low", "Info")
EXCLUDED = ("FalsePositive", "NotApplicable")
CWE = re.compile(r"^CWE-\d{1,5}$")
CODE_ID = re.compile(r"^F-\d{3}$")

# Calibration key for reference/expert-mode.md §Calibration anchors. Raters receive
# only the anchor text; the orchestrator compares their scores with this key.
ANCHOR_KEY = {"A1": "High", "A2": "Medium", "A3": "Medium", "A4": "Low", "A5": "High",
              "A6": "Low", "A7": "Low", "A8": "High", "A9": "Info"}


def enabled(data):
    return isinstance(data, dict) and "expert" in data


def _list(value, where, error_type):
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise error_type(f"{where}: must be a list of objects")
    return value


def _text(record, key, where, error_type, required=True):
    value = record.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise error_type(f"{where}.{key}: must be a nonblank string")
    return value


def _strings(record, key, where, error_type):
    value = record.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise error_type(f"{where}.{key}: must be a list of nonblank strings")
    return value


def _count(record, key, where, error_type):
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise error_type(f"{where}.{key}: must be a non-negative integer")
    return value


def calibrated(scores):
    """A rater is calibrated when every anchor is scored, at most one differs, and none by two levels."""
    if not isinstance(scores, dict) or set(scores) != set(ANCHOR_KEY):
        return False
    misses = 0
    for anchor, expected in ANCHOR_KEY.items():
        got = scores.get(anchor)
        if got not in SEVERITY_ORDER:
            return False
        distance = abs(SEVERITY_ORDER.index(got) - SEVERITY_ORDER.index(expected))
        if distance >= 2:
            return False
        misses += distance > 0
    return misses <= 1


def derive_expert(data, error_type=ValueError, integrity=None):
    """Return {opted_in, status, mode, gaps, counts}; gaps name each unmet gate."""
    if not enabled(data):
        return {"opted_in": False}
    record = data["expert"]
    if not isinstance(record, dict):
        raise error_type("expert: must be an object")
    if record.get("version") != VERSION:
        raise error_type(f"expert.version: must be {VERSION}")
    gaps = []
    gap = gaps.append

    mode = record.get("mode")
    if mode not in ("full", "single-agent"):
        raise error_type("expert.mode: full or single-agent")
    host = _text(record, "host", "expert", error_type)
    consent = record.get("consent")
    if not isinstance(consent, dict):
        raise error_type("expert.consent: must be an object")
    ceiling = _count(consent, "ceiling", "expert.consent", error_type)
    approved = _strings(consent, "engines", "expert.consent", error_type)
    _text(consent, "data_boundary", "expert.consent", error_type)
    _text(consent, "record", "expert.consent", error_type)
    if host not in approved:
        gap("consent_missing_host")

    preflight = _list(record.get("preflight", []), "expert.preflight", error_type)
    reachable = []
    for i, item in enumerate(preflight):
        engine = _text(item, "engine", f"expert.preflight[{i}]", error_type)
        _text(item, "record", f"expert.preflight[{i}]", error_type)
        exit_code = item.get("exit")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise error_type(f"expert.preflight[{i}].exit: must be an integer")
        if exit_code == 0 and engine in approved and engine not in reachable:
            reachable.append(engine)
    if host not in reachable and mode == "full":
        gap("mode_without_host_preflight")
    engines = [e for e in approved if e in reachable]
    cross_engine = len(engines) >= 2

    spawns = _list(record.get("spawns", []), "expert.spawns", error_type)
    actors = {}
    spawn_ids = set()
    for i, item in enumerate(spawns):
        where = f"expert.spawns[{i}]"
        sid = _text(item, "id", where, error_type)
        actor = _text(item, "actor", where, error_type)
        role = _text(item, "role", where, error_type)
        engine = _text(item, "engine", where, error_type)
        _text(item, "prompt", where, error_type)
        _text(item, "return", where, error_type)
        if role not in ROLES:
            raise error_type(f"{where}.role: one of {ROLES}")
        if sid in spawn_ids:
            raise error_type(f"{where}.id: duplicate {sid}")
        spawn_ids.add(sid)
        if engine not in engines:
            gap(f"spawn_on_unapproved_engine:{sid}")
        if actor in actors and actors[actor] != (role, engine):
            gap(f"actor_reused_across_roles:{actor}")
        actors.setdefault(actor, (role, engine))
    if len(spawns) > ceiling:
        gap("spawns_over_ceiling")

    def spawned(actor, role):
        return actors.get(actor, (None,))[0] == role

    def engine_of(actor):
        return actors.get(actor, (None, None))[1]

    findings = {f.get("id"): f for f in data.get("findings", []) if isinstance(f, dict)}
    code = {fid: f for fid, f in findings.items() if isinstance(fid, str) and CODE_ID.match(fid)}
    active = {fid: f for fid, f in code.items()
              if (f.get("validation") or {}).get("verdict") not in EXCLUDED}
    serious = [fid for fid, f in active.items() if f.get("severity") in ("High", "Medium")]

    # Recon twice, reconciled.
    recon = _list(record.get("recon", []), "expert.recon", error_type)
    recon_actors = {_text(r, "actor", f"expert.recon[{i}]", error_type) for i, r in enumerate(recon)}
    for i, r in enumerate(recon):
        _count(r, "routes", f"expert.recon[{i}]", error_type)
        if not spawned(r["actor"], "recon"):
            gap(f"recon_actor_not_spawned:{r['actor']}")
    if len(recon_actors) < 2:
        gap("recon_not_redundant")
    reconcile = record.get("reconciliation")
    if not isinstance(reconcile, dict):
        gap("recon_not_reconciled")
        routes = disagreements = 0
    else:
        routes = _count(reconcile, "routes", "expert.reconciliation", error_type)
        disagreements = _count(reconcile, "disagreements", "expert.reconciliation", error_type)
        if _count(reconcile, "resolved", "expert.reconciliation", error_type) != disagreements:
            gap("recon_disagreements_open")

    # Discovery: every planned cell read by two actors from two angles.
    profile = data.get("three_pass") if isinstance(data.get("three_pass"), dict) else {}
    cells = [c.get("id") for c in profile.get("coverage", []) if isinstance(c, dict)]
    if not cells:
        gap("three_pass_missing")
    discovery = _list(record.get("discovery", []), "expert.discovery", error_type)
    by_cell = {cell: [] for cell in cells}
    discoverers = {}
    raw = 0
    for i, d in enumerate(discovery):
        where = f"expert.discovery[{i}]"
        actor = _text(d, "actor", where, error_type)
        angle = _text(d, "angle", where, error_type)
        if angle not in DISCOVERY_ANGLES:
            raise error_type(f"{where}.angle: one of {DISCOVERY_ANGLES}")
        raw += _count(d, "raw_candidates", where, error_type)
        if not spawned(actor, "discovery"):
            gap(f"discovery_actor_not_spawned:{actor}")
        for cell in _strings(d, "cells", where, error_type):
            if cell not in by_cell:
                gap(f"discovery_unknown_cell:{cell}")
            else:
                by_cell[cell].append((actor, angle, engine_of(actor)))
        for fid in _strings(d, "candidates", where, error_type):
            if fid not in code:
                gap(f"discovery_unknown_finding:{fid}")
            discoverers.setdefault(fid, set()).add(actor)
    thin = [c for c, passes in by_cell.items()
            if len({a for a, _, _ in passes}) < 2 or len({g for _, g, _ in passes}) < 2
            or (cross_engine and len({e for _, _, e in passes}) < 2)]
    for cell in thin:
        gap(f"cell_not_redundant:{cell}")

    # Variant analysis for every serious finding.
    variants = _list(record.get("variants", []), "expert.variants", error_type)
    varied, hits, new_from_variants = set(), 0, set()
    for i, v in enumerate(variants):
        where = f"expert.variants[{i}]"
        actor = _text(v, "actor", where, error_type)
        _text(v, "pattern", where, error_type)
        _text(v, "search", where, error_type)
        count = _count(v, "hits", where, error_type)
        hits += count
        if not spawned(actor, "variant"):
            gap(f"variant_actor_not_spawned:{actor}")
        seeds = _strings(v, "findings", where, error_type)
        varied.update(seeds)
        dispositions = _list(v.get("dispositions", []), f"{where}.dispositions", error_type)
        if len(dispositions) != count:
            gap(f"variant_hits_unaccounted:{i}")
        for j, item in enumerate(dispositions):
            _text(item, "location", f"{where}.dispositions[{j}]", error_type)
            result = _text(item, "result", f"{where}.dispositions[{j}]", error_type)
            _text(item, "reason", f"{where}.dispositions[{j}]", error_type)
            target = result.split(":", 1)[1] if ":" in result else ""
            if result.split(":", 1)[0] not in ("finding", "same", "safe"):
                raise error_type(f"{where}.dispositions[{j}].result: finding:F-NNN, same:F-NNN or safe")
            if result.startswith(("finding:", "same:")) and target not in code:
                gap(f"variant_unknown_finding:{target or result}")
            if result.startswith("finding:") and target in code:
                new_from_variants.add(target)
                discoverers.setdefault(target, set()).add(actor)
    for fid in serious:
        if fid not in varied:
            gap(f"variant_missing:{fid}")

    # Omission challenge over the whole assessment.
    omission = _list(record.get("omission", []), "expert.omission", error_type)
    every_discoverer = {a for passes in by_cell.values() for a, _, _ in passes}
    for i, o in enumerate(omission):
        actor = _text(o, "actor", f"expert.omission[{i}]", error_type)
        _text(o, "reason", f"expert.omission[{i}]", error_type)
        if not spawned(actor, "omission") or actor in every_discoverer:
            gap(f"omission_actor_not_independent:{actor}")
        for fid in _strings(o, "added", f"expert.omission[{i}]", error_type):
            if fid not in code:
                gap(f"omission_unknown_finding:{fid}")
            discoverers.setdefault(fid, set()).add(actor)
    if not omission:
        gap("omission_missing")

    for fid in code:
        if fid not in discoverers:
            gap(f"finding_without_discovery:{fid}")

    # Independence of verification from discovery.
    verifiers = {}
    for fid, f in code.items():
        proof = f.get("verification") if isinstance(f.get("verification"), dict) else {}
        verifier = proof.get("reviewer")
        verifiers[fid] = verifier
        if not isinstance(verifier, str) or not spawned(verifier, "conditions"):
            gap(f"verifier_not_spawned:{fid}")
        elif verifier in discoverers.get(fid, set()):
            gap(f"verifier_is_discoverer:{fid}")
        for review in proof.get("reviews", []) if isinstance(proof.get("reviews"), list) else []:
            reviewer = review.get("reviewer") if isinstance(review, dict) else None
            if reviewer in discoverers.get(fid, set()) or reviewer == verifier:
                gap(f"reviewer_not_independent:{fid}")

    # Refutation panels for serious findings.
    panels = _list(record.get("panels", []), "expert.panels", error_type)
    panel_counts = {"refuted": 0, "survived": 0, "unproven": 0}
    paneled = set()
    for i, p in enumerate(panels):
        where = f"expert.panels[{i}]"
        fid = _text(p, "finding", where, error_type)
        paneled.add(fid)
        skeptics = _list(p.get("skeptics", []), f"{where}.skeptics", error_type)
        results = []
        for j, s in enumerate(skeptics):
            w = f"{where}.skeptics[{j}]"
            actor = _text(s, "actor", w, error_type)
            angle = _text(s, "angle", w, error_type)
            result = _text(s, "result", w, error_type)
            _text(s, "reason", w, error_type)
            _strings(s, "evidence_ids", w, error_type)
            if angle not in SKEPTIC_ANGLES:
                raise error_type(f"{w}.angle: one of {SKEPTIC_ANGLES}")
            if result not in panel_counts:
                raise error_type(f"{w}.result: refuted, survived or unproven")
            panel_counts[result] += 1
            results.append(result)
            if not spawned(actor, "skeptic") or actor in discoverers.get(fid, set()) or actor == verifiers.get(fid):
                gap(f"skeptic_not_independent:{fid}:{actor}")
        if len({s["actor"] for s in skeptics}) < 2 or len({s["angle"] for s in skeptics}) < 2:
            gap(f"panel_too_small:{fid}")
        if cross_engine and len({engine_of(s["actor"]) for s in skeptics}) < 2:
            gap(f"panel_monoculture:{fid}")
        refuted = results.count("refuted")
        verdict = (code.get(fid, {}).get("validation") or {}).get("verdict")
        if refuted * 2 > len(results) and verdict not in EXCLUDED and not _text(p, "resolution", where, error_type, False).strip():
            gap(f"panel_refutation_unresolved:{fid}")
    for fid in serious:
        if fid not in paneled:
            gap(f"panel_missing:{fid}")

    # Severity: calibrated, independent, double-rated.
    raters = {}
    for i, c in enumerate(_list(record.get("calibration", []), "expert.calibration", error_type)):
        rater = _text(c, "rater", f"expert.calibration[{i}]", error_type)
        if not spawned(rater, "rater"):
            gap(f"rater_not_spawned:{rater}")
        raters[rater] = calibrated(c.get("scores"))
    ratings = {}
    for i, r in enumerate(_list(record.get("ratings", []), "expert.ratings", error_type)):
        where = f"expert.ratings[{i}]"
        fid = _text(r, "finding", where, error_type)
        rater = _text(r, "rater", where, error_type)
        severity = _text(r, "severity", where, error_type)
        _text(r, "reason", where, error_type)
        if severity not in SEVERITY_ORDER:
            raise error_type(f"{where}.severity: one of {SEVERITY_ORDER}")
        if not raters.get(rater):
            gap(f"rater_not_calibrated:{rater}")
        elif rater in discoverers.get(fid, set()) or rater == verifiers.get(fid):
            gap(f"rater_not_independent:{fid}:{rater}")
        else:
            ratings.setdefault(fid, {})[rater] = severity
    resolutions = {_text(r, "finding", f"expert.severity_resolutions[{i}]", error_type)
                   for i, r in enumerate(_list(record.get("severity_resolutions", []),
                                               "expert.severity_resolutions", error_type))
                   if _text(r, "reason", f"expert.severity_resolutions[{i}]", error_type)}
    agreed = 0
    for fid, f in active.items():
        given = ratings.get(fid, {})
        if len(given) < 2:
            gap(f"severity_not_double_rated:{fid}")
        elif set(given.values()) == {f.get("severity")}:
            agreed += 1
        elif fid not in resolutions:
            gap(f"severity_disagreement_unresolved:{fid}")
        if not isinstance(f.get("cwe"), str) or not CWE.match(f["cwe"]):
            gap(f"cwe_missing:{fid}")

    # Simulated reception by three distinct recipients.
    reception = _list(record.get("reception", []), "expert.reception", error_type)
    seen_personas = set()
    for i, r in enumerate(reception):
        where = f"expert.reception[{i}]"
        persona = _text(r, "persona", where, error_type)
        actor = _text(r, "actor", where, error_type)
        _text(r, "stop_span", where, error_type)
        _text(r, "disposition", where, error_type)
        if persona not in PERSONAS:
            raise error_type(f"{where}.persona: one of {PERSONAS}")
        if not spawned(actor, "persona"):
            gap(f"persona_not_spawned:{actor}")
        seen_personas.add(persona)
    for persona in PERSONAS:
        if persona not in seen_personas:
            gap(f"reception_missing:{persona}")

    # Non-participant QA.
    qa = record.get("qa")
    if not isinstance(qa, dict):
        gap("qa_missing")
        qa_result = "missing"
    else:
        qa_actor = _text(qa, "actor", "expert.qa", error_type)
        qa_result = _text(qa, "result", "expert.qa", error_type)
        if qa_result not in ("pass", "imbalance"):
            raise error_type("expert.qa.result: pass or imbalance")
        if not spawned(qa_actor, "qa"):
            gap("qa_not_independent")
        if qa_result != "pass":
            gap("qa_imbalance")

    three = derive_three_pass(data, error_type, integrity=integrity)
    if three.get("opted_in") and three.get("status") != "complete":
        gap("three_pass_incomplete")

    status = "degraded" if mode == "single-agent" else ("held" if gaps else "complete")
    return {
        "opted_in": True, "status": status, "mode": mode,
        "engines": engines, "cross_engine": cross_engine, "gaps": list(dict.fromkeys(gaps)),
        "counts": {
            "spawns": len(spawns), "ceiling": ceiling, "recon_actors": len(recon_actors), "routes": routes,
            "recon_disagreements": disagreements, "cells": len(cells),
            "redundant_cells": len(cells) - len(thin), "discovery_passes": len(discovery),
            "raw_candidates": raw, "findings": len(code), "variant_hits": hits,
            "variant_findings": len(new_from_variants), "panels": len(paneled & set(code)),
            **{f"skeptic_{k}": v for k, v in panel_counts.items()},
            "raters": len(raters), "raters_calibrated": sum(raters.values()),
            "rated": len([fid for fid in active if len(ratings.get(fid, {})) >= 2]),
            "severity_agreed": agreed, "active": len(active),
            "personas": len(seen_personas), "omission_passes": len(omission), "qa": qa_result,
        },
    }
