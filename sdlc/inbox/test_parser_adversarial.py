import pytest
"""
Adversarial tests for aivis.parser.parse_tool_list.

Every test below asserts a specific field value against the behaviour of
src/aivis/parser.py as pasted on 2026-08-17 (177 lines). TARGET line numbers
refer to that file.

HOW THESE PREDICTIONS WERE CHECKED
----------------------------------
The pasted source was reconstructed byte-for-byte into a scratch package with
a dataclass stand-in for ToolEntry(rank, name_raw, name_norm, why,
citation_domains) and this file was executed against it: 14 passed, 1 failed,
matching every PREDICTION line below. That reconstruction is NOT your repo --
if your real models.ToolEntry validates or coerces any of those five fields,
that is the one place these results could diverge. Run the file for real.

PREDICTIONS CHANGED DURING THE LINE-BY-LINE RE-READ PASS
--------------------------------------------------------
None. No prediction flipped between drafting and re-derivation.

Two things did change, neither a prediction:
  C1. test_pe02_* originally used the input "1. - Great for sprint planning".
      Re-reading line 128 killed it: the fallback split is r"\s+-\s+", which
      requires whitespace BEFORE the hyphen, and a line-leading "- " has none.
      That input yields name_raw="- Great for sprint planning" and PE-03, not
      PE-02. Replaced with an empty bold pair, which does reach line 137.
  C2. test_pe04_* asserted ["asana", "asana"] and failed on first execution --
      my error, not the parser's: the middle entry is still in the list.
      Corrected to ["asana", "notion", "asana"]. Prediction was and stayed PASS.

STANDING NOTES FOUND WHILE DERIVING THESE TESTS (not bugs the tests assert,
but facts the reader needs):

  N1. PE-06 and OCV-01 are inseparable. Both early-return branches (lines
      76-83 and 93-101) emit PE-06 *and* OCV-01 together. There is no input
      that produces one without the other, so the two codes carry exactly
      one bit of information between them, not two.

  N2. parse_success (line 169) ignores parse_errors entirely. A list where
      every entry is missing its why-text returns parse_success=True with
      parse_errors=["PE-03"]. "Success" here means "shaped like a list",
      not "valid".

  N3. Duplicates are recorded, never removed (lines 142-145 then 153). The
      returned tool_list still contains both copies, so any downstream
      count of len(tool_list) is inflated by the duplicate.

  N4. The task asked for 7 error-code tests. Six error codes exist: PE-02,
      PE-03, PE-04, PE-06, OCV-01, OCV-02. The source emits no other code
      string, and PE-01 and PE-05 appear nowhere in it. There are 6 tests in
      that section, not 7. A seventh would have had to be invented.

  N5. There is no test here for PE-06 on empty input (lines 76-83) because it
      is not a realistic model response -- a model that returns "" is a
      transport failure, not a parse failure, and the test would assert the
      same three fields as the clarifying-question test.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aivis.parser import parse_tool_list  # noqa: E402


# ---------------------------------------------------------------------------
# 1. One test per error code (6 exist, not 7 -- see N4)
# ---------------------------------------------------------------------------

# TARGET: lines 120-123, 133-137. PREDICTION: PASS. REASON: "** **" matches the
# bold regex with group(1)=" ", which strips to "", so the entry is dropped at
# line 137 and only the two well-formed entries survive.
def test_pe02_empty_bold_name_is_dropped_not_kept_as_blank():
    raw = (
        "1. **Asana** - Best for cross-team task tracking\n"
        "2. **Trello** - Kanban boards for small teams\n"
        "3. ** ** - (name pending)\n"
    )
    tools, meta = parse_tool_list(raw)
    assert meta["parse_errors"] == ["PE-02"]
    assert [t.name_raw for t in tools] == ["Asana", "Trello"]


# TARGET: lines 138-139, 169. PREDICTION: PASS. REASON: the bare name yields
# why="" so PE-03 fires, but parse_success only checks rank and name_raw, so it
# still reports True.
def test_pe03_missing_why_still_reports_parse_success_true():
    raw = (
        "1. Asana - Best for cross-team task tracking\n"
        "2. Trello\n"
        "3. Jira Software - Issue tracking for engineering teams\n"
    )
    tools, meta = parse_tool_list(raw)
    assert meta["parse_errors"] == ["PE-03"]
    assert tools[1].why == ""
    assert meta["parse_success"] is True


# TARGET: lines 142-145. PREDICTION: PASS. REASON: both entries normalise to
# "asana"; the second sets has_dup and appends PE-04 but is still appended to
# tool_list at line 153.
def test_pe04_duplicate_is_flagged_but_still_returned():
    raw = (
        "1. Asana - Task tracking across teams\n"
        "2. Notion - Docs and wikis in one place\n"
        "3. Asana - Also strong for project timelines\n"
    )
    tools, meta = parse_tool_list(raw)
    assert meta["parse_errors"] == ["PE-04"]
    assert meta["has_duplicates"] is True
    assert [t.name_norm for t in tools] == ["asana", "notion", "asana"]


# TARGET: lines 93-101. PREDICTION: PASS. REASON: a clarifying-question reply
# has no line matching the item regex at line 90, so the no-item branch returns
# PE-06 with parse_mode "unknown".
def test_pe06_clarifying_question_response_is_unparseable():
    raw = (
        "Happy to help with that. Before I recommend anything, could you tell me "
        "how many people are on the team and whether you need time tracking? "
        "The right answer is very different for a team of 5 versus 500."
    )
    tools, meta = parse_tool_list(raw)
    assert meta["parse_errors"] == ["PE-06"]
    assert meta["parse_mode"] == "unknown"
    assert tools == []


# TARGET: lines 93-94. PREDICTION: PASS. REASON: prose naming tools inline never
# matches the item regex, so OCV-01 is appended and nothing is extracted, even
# though three real tool names are present in the text.
def test_ocv01_prose_naming_tools_yields_no_entries():
    raw = (
        "For most software teams the usual shortlist is Asana, Trello, and Jira, "
        "with Notion showing up when documentation matters more than ticketing."
    )
    tools, meta = parse_tool_list(raw)
    assert meta["violations"] == ["OCV-01"]
    assert tools == []


# TARGET: lines 163-166. PREDICTION: PASS. REASON: 11 parsed entries trip the
# length check, OCV-02 is recorded and the list is truncated to the first 10.
def test_ocv02_eleven_items_truncates_to_ten():
    names = [
        "Asana", "Trello", "Jira", "Notion", "Basecamp", "Smartsheet",
        "Wrike", "Teamwork", "Podio", "Zoho Projects", "Airtable",
    ]
    raw = "".join(f"{i}. {n} - Solid choice for teams\n" for i, n in enumerate(names, 1))
    tools, meta = parse_tool_list(raw)
    assert meta["violations"] == ["OCV-02"]
    assert len(tools) == 10
    assert [t.name_raw for t in tools][-1] == "Zoho Projects"


# ---------------------------------------------------------------------------
# 2. Rank sequence with a gap
# ---------------------------------------------------------------------------

# TARGET: lines 110-113. PREDICTION: PASS. REASON: rank is read from the literal
# digit in the line, not from position, so the third entry inherits the model's
# skipped numbering and gets rank 4.
def test_rank_gap_third_entry_gets_rank_four_not_three():
    raw = (
        "1. Asana - Task tracking across teams\n"
        "2. Trello - Kanban boards for small teams\n"
        "4. Jira - Issue tracking for engineering teams\n"
    )
    tools, meta = parse_tool_list(raw)
    assert [t.rank for t in tools] == [1, 2, 4]


# ---------------------------------------------------------------------------
# 3. Bold name with three separator characters
# ---------------------------------------------------------------------------

# TARGET: line 120. PREDICTION: PASS. REASON: the en-dash is inside the
# character class [:–—-], so the bold branch splits name from why.
def test_bold_name_en_dash_separator():
    tools, meta = parse_tool_list("1. **Asana** – Best for cross-team task tracking\n")
    assert tools[0].name_raw == "Asana"
    assert tools[0].why == "Best for cross-team task tracking"


# TARGET: line 120. PREDICTION: PASS. REASON: the em-dash is also inside the
# same character class.
def test_bold_name_em_dash_separator():
    tools, meta = parse_tool_list("1. **Asana** — Best for cross-team task tracking\n")
    assert tools[0].name_raw == "Asana"
    assert tools[0].why == "Best for cross-team task tracking"


# TARGET: line 120. PREDICTION: PASS. REASON: the trailing "-" in [:–—-] is a
# literal hyphen, and \s* on both sides absorbs the surrounding spaces.
def test_bold_name_plain_hyphen_separator():
    tools, meta = parse_tool_list("1. **Asana** - Best for cross-team task tracking\n")
    assert tools[0].name_raw == "Asana"
    assert tools[0].why == "Best for cross-team task tracking"


# ---------------------------------------------------------------------------
# 4. "no citation" mid-sentence alongside a real domain
# ---------------------------------------------------------------------------

# TARGET: lines 148-151. PREDICTION: FAIL. REASON: the guard scans the whole
# line for "no citation" and, on a match, discards every domain including the
# real one, so asana.com is thrown away — this assertion documents the defect.
@pytest.mark.xfail(strict=True, reason="BUG: parse_tool_list drops a real citation_domain when the sentence contains a citation-absence phrase")
def test_no_citation_phrase_should_not_discard_a_real_domain():
    raw = (
        "1. Asana - Widely used across marketing teams, see asana.com, though I "
        "have no citation for the 2024 market-share figure.\n"
    )
    tools, meta = parse_tool_list(raw)
    assert tools[0].citation_domains == ["asana.com"]


# ---------------------------------------------------------------------------
# 5. ALIAS_TABLE hit that requires suffix stripping first
# ---------------------------------------------------------------------------

# TARGET: lines 33-36 then 49-50. PREDICTION: PASS. REASON: " software" is
# stripped first, producing "wrike project management", which is the literal
# alias key on line 17; the raw string with the suffix is not a key.
def test_alias_reached_only_after_suffix_strip():
    raw = "1. Wrike Project Management software - Best for enterprise workflows\n"
    tools, meta = parse_tool_list(raw)
    assert tools[0].name_norm == "wrike"
    assert tools[0].name_raw == "Wrike Project Management software"


# ---------------------------------------------------------------------------
# 6. Collision created by normalization
# ---------------------------------------------------------------------------

# TARGET: lines 42-43, 49-50, 142-145. PREDICTION: PASS. REASON: "Monday" is
# rewritten to "monday.com" by the alias table while "Monday.com" is preserved
# by the keep-list, so two visually distinct names land on one key.
def test_monday_and_monday_dot_com_collide_after_normalization():
    raw = (
        "1. Monday - Visual project boards for non-technical teams\n"
        "2. Notion - Docs and wikis in one place\n"
        "3. Monday.com - Automations and dashboards\n"
    )
    tools, meta = parse_tool_list(raw)
    assert [t.name_norm for t in tools] == ["monday.com", "notion", "monday.com"]
    assert meta["has_duplicates"] is True


# ---------------------------------------------------------------------------
# 7. Domain mentioned inside why-text
# ---------------------------------------------------------------------------

# TARGET: line 151 via lines 54-63. PREDICTION: PASS. REASON: extract_domains
# runs over the whole line, so a named integration partner is recorded as a
# citation domain with no evidential link to the claim.
def test_integration_mention_becomes_a_citation_domain():
    raw = "1. Trello - Kanban boards that integrate with slack.com for notifications\n"
    tools, meta = parse_tool_list(raw)
    assert tools[0].citation_domains == ["slack.com"]


# ---------------------------------------------------------------------------
# 8. Ordering of truncation versus duplicate detection
# ---------------------------------------------------------------------------

# TARGET: lines 142-145 versus 163-166. PREDICTION: PASS. REASON: duplicate
# detection runs inside the per-item loop and truncation runs after it, so the
# 11th item is flagged as a duplicate and then deleted, leaving PE-04 and
# has_duplicates=True describing an entry no longer in the returned list.
def test_item_eleven_is_dropped_after_duplicate_detection_not_before():
    names = [
        "Asana", "Trello", "Jira", "Notion", "Basecamp", "Smartsheet",
        "Wrike", "Teamwork", "Podio", "Zoho Projects", "Asana",
    ]
    raw = "".join(f"{i}. {n} - Solid choice for teams\n" for i, n in enumerate(names, 1))
    tools, meta = parse_tool_list(raw)
    assert len(tools) == 10
    assert meta["has_duplicates"] is True
    assert "PE-04" in meta["parse_errors"]
    assert [t.name_norm for t in tools].count("asana") == 1
