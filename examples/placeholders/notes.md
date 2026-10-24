# Documentation snippets from tests/false_positive_test.j2.

AWS access key ids start with AKIA followed by 16 characters.
Example prefix only: AKIAIOSFODNN7EXAMPL
GitHub docs mention ghp_example tokens; that body is too short.
Do not commit live keys.

Findings never store the full secret: only a length-preserving mask.
