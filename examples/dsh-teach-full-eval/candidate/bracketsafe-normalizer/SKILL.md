---
name: bracketsafe-normalizer
description: Apply the named BracketSafe text normalization contract when a user explicitly asks to normalize an input; do not trigger for questions that only discuss or explain the name.
license: MIT
---

# Apply the BracketSafe contract

Use this contract only when the user explicitly asks to apply or run the BracketSafe normalizer on an input.

1. Remove leading and trailing Unicode whitespace.
2. If nothing remains, return exactly `BRACKETSAFE_EMPTY`.
3. Replace each remaining run of Unicode whitespace with one underscore.
4. Lowercase ASCII letters `A` through `Z`; preserve all other characters.
5. Wrap the result in `[[` and `]]`.
6. Return only the normalized result. Do not call tools, read files, or access the network.

Do not apply the transformation when the user merely asks what “BracketSafe” might mean or explicitly says not to transform text.
