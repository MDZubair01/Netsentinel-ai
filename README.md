# NetSentinel AI - proof of concept (stdlib Python)

Run: `python3 run_tests.py` (writes test_results.json)

Files
- netsentinel_poc.py : Dual-Ring cache logic, stage-1 injection pre-filter, MCP tool-call firebreak
- run_tests.py       : our own test sets (28 injections incl. 8 paraphrased, 30 benign, 30 tool calls) + cache-poisoning test
- test_results.json  : output of the last run

Honest limits
- Test sets were written by us and are small. They are baselines, not a public benchmark.
- The keyword pre-filter caught 0 of 8 paraphrased injections -> the Gemma stage is required (not built here).
- One legitimate SQL call was wrongly blocked (keyword inside a string) -> replace regex checks with a real SQL parser.
- Not yet built: FastAPI service, Redis/Memorystore, Vertex AI context caching, Gemma classifier.
