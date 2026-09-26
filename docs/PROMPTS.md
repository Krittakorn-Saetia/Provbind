# Prompts for Claude Code, in order

Start Claude Code in the repo root. Send one prompt at a time, and move on only when the task's tests pass. Commit after each green task.

## 0. Orientation (no code)
> Read CLAUDE.md, docs/ROLE2-HANDOFF.md and contracts/envelope.schema.json. Don't write code yet. Summarise tasks T1–T12 in your own words, list the files you will create, and point out anything in the handoff that looks inconsistent or underspecified.

## 1. Pipeline (T1, T2)
> Do T1 and T2 from docs/ROLE2-HANDOFF.md. pipeline/build-and-attest.sh and pipeline/gen_provenance.py already exist and are tested; don't rewrite them unless something fails. I have already created the key pair and exported COSIGN_PASSWORD. Run the build on testbed/standin-app and report the ref@digest and the number of SBOM dependency entries. If a command fails, show me the error and propose the smallest fix.

## 2. Layer union (T5)
> Do T5. Implement compiler/layers.py with the two-pass algorithm in Section 7.1, exactly. Write every row of the T5 test table as a pytest case using synthetic tars built in the test (gzip, zstd and plain). Run the tests and show me the results.

## 3. Paths (T6)
> Do T6: compiler/paths.py with realpath from Section 7.2, and key canonicalisation after the union. Write every row of the T6 table as a test. Run all unit tests.

## 4. Image fetch (T4)
> Do T4: compiler/oci.py using crane manifest, crane blob and the blob cache. Check v_M and v_C, handle an image index as described, and add the unit tests plus one integration test against the stand-in image.

## 5. Evidence (T3)
> Do T3: compiler/evidence.py. Parse cosign output defensively: accept both a DSSE envelope and a bare statement per line, and find the Rekor log index by recursive key search. Raise EvidenceError on any binding failure. Add unit tests with canned outputs and one integration test.

## 6. SBOM, owners, closure, caps (T8, T9, T7, T10)
> Do T8, then T9, then T7, then T10, each with the tests listed in the handoff. For T7, use pyelftools and the library search order in the T7 section. Run the whole test suite at the end.

## 7. Envelope and CLI (T11)
> Do T11: compiler/compile.py with the CLI, exit codes, schema validation and atomic write. Add a golden-file test on a small synthetic image, and a test that the schema rejects a missing field.

## 8. Integration (T12)
> Run the full pipeline on testbed/standin-app: build and attest, then compile. Check every item of the "done when" list in Section 1 (use requests in place of the test package) and report the result of each check, plus the timings. Then update the status table in Section 14.

## 9. The real demo image (when Role 1 delivers testbed/demo-app/)
> Build, attest and compile testbed/demo-app. Check the Section 1 "done when" list exactly, including that /tmp/.x9 is absent and that the requestz-helper files are owned by its pypi purl. Print the ref@digest and the envelope path for the team.

## Tips
- If Claude Code wants to change anything in `contracts/`, stop and bring it to the team first.
- Ask for the diff and a short explanation before accepting large changes.
- If a test is hard to write, have it write the failing test first and show you, then fix the code.
