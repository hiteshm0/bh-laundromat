"""Test-only model transport. Installed on child PYTHONPATH by test_push_graph."""

import io
import json
import os
import re
import urllib.request

if os.getenv("LAUNDROMAT_MODEL") == "mocked-push-test":
    from laundromat import provider

    if os.getenv("MOCK_GROQ_GPT_OSS"):
        os.environ["LAUNDROMAT_MODEL"] = "openai/gpt-oss-120b"

    original_role = provider.role

    def mocked_role(name, artifact, trace, **kwargs):
        try:
            return original_role(name, artifact, trace, **kwargs)
        finally:
            if trace:
                trace[-1]["origin"] = "mocked"

    provider.role = mocked_role

    def respond(req, **kwargs):
        body = json.loads(req.data)
        groq = os.getenv("LAUNDROMAT_PROVIDER") == "groq"
        if groq:
            assert req.full_url == "https://api.groq.com/openai/v1/chat/completions"
            assert req.get_header("Authorization") == "Bearer " + os.environ["GROQ_API_KEY"]
            assert [m["role"] for m in body["messages"]] == ["system", "user"]
            artifact = json.loads(body["messages"][1]["content"])
            if "changes" in artifact:
                assert body["max_completion_tokens"] == provider.REVIEW_OUTPUT_TOKENS
                if os.getenv("MOCK_GROQ_GPT_OSS"):
                    assert body["response_format"]["type"] == "json_schema"
                    contract = body["response_format"]["json_schema"]
                    assert contract["strict"] is True
                    anchors = contract["schema"]["$defs"]["Advisory"]["properties"]["anchor"]["enum"]
                    labels = [
                        label for change in artifact["changes"]
                        for label in re.findall(r"^[+-] \[(A\d+)\]", change["diff"], re.MULTILINE)
                    ]
                    assert anchors == labels
                else:
                    assert body["response_format"] == {"type": "json_object"}
            else:
                assert body["response_format"] == {"type": "json_object"}
                assert body["max_completion_tokens"] == 700
        else:
            assert req.full_url == "https://api.openai.com/v1/responses"
            artifact = json.loads(body["input"])
        if "changes" in artifact:
            assert kwargs["timeout"] == 12
            assert "UNCOMMITTED_REVIEW_MARKER" not in json.dumps(artifact)
            assert "LMTEST_" not in json.dumps(artifact)
            if os.getenv("MOCK_REVIEW_TIMEOUT"):
                raise TimeoutError("Mock advisory provider timed out")
            if os.getenv("MOCK_REVIEW_ERROR"):
                raise RuntimeError("Mock advisory provider failed unexpectedly")
            output = {"findings": []}
            if os.getenv("MOCK_REVIEW_FINDING"):
                change = next(change for change in artifact["changes"] if change["path"] == "review.js")
                anchor = re.search(r"^\+ \[(A\d+)\] export function listStock", change["diff"], re.MULTILINE)[1]
                assert "inventory/stock.cjs" in {code["path"] for code in artifact["related_code"]}
                if os.getenv("MOCK_REVIEW_BAD_LOCATION"):
                    anchor = "A999"
                output["findings"].append(dict(
                    anchor=anchor,
                    title="Missing access check",
                    explanation="The inventory handler has no access check.",
                    recommendation="Require an authorized session before reading inventory.",
                ))
        elif "policy" in artifact:
            output = dict(
                path=artifact["path"],
                line=artifact["line"],
                reasoning="Aisle changes the statement",
                property="parameter binding",
                route="runtime",
            )
        elif "fixture" in artifact:
            fixture = artifact["fixture"]
            assert artifact["case_fields"] == ["term"]
            filter_by = fixture["filter_by"]
            terms = [row[filter_by] for row in fixture["rows"] if row[filter_by] is not None]
            if fixture["match"] == "contains":
                terms = [term.partition(" ")[0] for term in terms]
            cases = [dict(term=term) for term in list(dict.fromkeys(terms))[:2]]
            output = dict(
                entry_point=artifact["entry_point"],
                assertions=artifact["required_assertions"],
                cases=cases,
            )
        elif "seed" in artifact:
            output = dict(
                entry_point=artifact["entry_point"],
                assertions=artifact["required_assertions"],
                cases=[dict(term=k, expected_skus=artifact["seed"][k]) for k in ("north", "south")],
            )
        else:
            line = artifact["source"].splitlines()[artifact["line"] - 1]
            bound = '  return db.prepare("SELECT sku FROM stock WHERE aisle = ? ORDER BY sku").all(aisle);'
            if "const pattern =" in artifact["source"]:
                bound = '  return db.prepare("SELECT * FROM products WHERE name LIKE ? ORDER BY id").all(pattern);'
            if os.getenv("MOCK_BAD_PATCH"):
                bound = bound.replace(".all(aisle)", ".all()")
            output = dict(
                path=artifact["path"],
                old_line=line,
                new_line=bound,
                rationale="Bind the aisle at execution",
            )
        if os.getenv("MOCK_MALFORMED"):
            output = {"unrecognized": True}
        envelope = dict(model="mocked-push-test", usage={"total_tokens": 0})
        truncated = "changes" in artifact and os.getenv("MOCK_REVIEW_TRUNCATED")
        if groq:
            envelope["choices"] = [
                {"finish_reason": "length" if truncated else "stop",
                 "message": {"content": json.dumps(output)}}
            ]
        else:
            envelope.update(
                status="completed",
                output=[{"content": [{"type": "output_text", "text": json.dumps(output)}]}],
            )
        return io.BytesIO(json.dumps(envelope).encode())

    urllib.request.urlopen = respond
