# Entropy threshold notes

Threshold: ENTROPY_MIN = 4.5 bits/char (extension/detect.js).
Method: every candidate token (32+ chars of [A-Za-z0-9+/=_-] for the catch-all, 40 chars of [A-Za-z0-9/+=] for the AWS shape) was taken from the benign corpus and from the source files of express, flask and terraform-aws-vpc. The structural filter (URLs, paths, word slugs, hashes, UUIDs) runs first, as in the engine. The AWS shape needs mixed case to reach the gate.

## True-positive fixtures (the AWS and catch-all samples)

| rule | bits/char | mixed | length |
|---|---|---|---|
| AWS Secret Access Key | 4.972 | yes | 40 |
| AWS Secret Access Key | 4.972 | yes | 40 |
| AWS Secret Access Key | 4.972 | yes | 40 |
| High-entropy token | 4.958 | yes | 46 |
| High-entropy token | 5.000 | yes | 32 |
| High-entropy token | 5.031 | yes | 64 |

## Benign tokens that reach the gate

Candidates seen: 3081. Reaching the gate: 26.

| bits/char | rule | mixed | source | token (first 40 chars) |
|---|---|---|---|---|
| 4.973 | he | yes | express/test/res.cookie.js:290 | xJjV2iZ6EI7C8E5kzwbfA9PVLl1ZR07UTnuTgQQ4 |
| 4.629 | he | yes | express/test/res.cookie.js:257 | 2BPb1rsD95o5Jm5SqWs1KteqdnynnB7jkTE |
| 4.423 | he | yes | flask/docs/config.rst:618 | FLASK_MYAPI__credentials__username=user1 |
| 4.234 | he | no | flask/CHANGES.rst:1147 | JSONIFY_PRETTYPRINT_REGULAR=False |
| 4.193 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:17 | args=--only=terraform_documented_variabl |
| 4.128 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:19 | args=--only=terraform_module_pinned_sour |
| 4.119 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:18 | args=--only=terraform_typed_variables |
| 4.084 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:16 | args=--only=terraform_documented_outputs |
| 4.074 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:14 | args=--only=terraform_unused_declaration |
| 4.071 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:13 | args=--only=terraform_deprecated_index |
| 4.053 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:22 | args=--only=terraform_required_providers |
| 4.027 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:21 | args=--only=terraform_required_version |
| 4.005 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:12 | args=--only=terraform_deprecated_interpo |
| 3.978 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:24 | args=--only=terraform_workspace_remote |
| 3.976 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:23 | args=--only=terraform_standard_module_st |
| 3.954 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:15 | args=--only=terraform_comment_syntax |
| 3.945 | he | no | terraform-aws-vpc/.pre-commit-config.yaml:20 | args=--only=terraform_naming_convention |
| 3.875 | he | no | terraform-aws-vpc/examples/ipam/README.md:14 | target=aws_vpc_ipam_preview_next_cidr |
| 3.804 | he | no | flask/src/flask/app.py:327 | subdomain_matching=subdomain_matching |
| 3.804 | he | no | flask/tests/test_basic.py:1537 | subdomain_matching=subdomain_matching |
| 3.770 | he | no | flask/src/flask/sansio/blueprints.py:438 | provide_automatic_options=provide_automa |
| 3.726 | he | no | flask/src/flask/app.py:330 | instance_relative_config=instance_relati |
| 3.665 | he | no | flask/src/flask/cli.py:991 | exclude_patterns=exclude_patterns |
| 3.590 | he | no | flask/src/flask/testing.py:238 | follow_redirects=follow_redirects |
| 3.309 | he | no | flask/src/flask/app.py:495 | get_flashed_messages=get_flashed_message |
| 3.040 | he | no | terraform-aws-vpc/modules/flow-log/README.md:35 | example-20250602150510701600000001 |

## Decision

- Every true-positive fixture is at or above 4.958 bits/char.
- At 4.5, two benign tokens still pass: the express cookie signatures at 4.973 and 4.629. They are random-looking HMAC values in test assertions, the same range as the fixtures, so entropy cannot separate them. They are a documented, accepted false positive.
- At 4.3 the flask config value (4.423) would also pass. At 4.5 it is removed, and all 24 other benign tokens (3.0 to 4.234) fall below it.
- 4.5 sits in the gap between the highest benign value that is not a signature (4.423) and the lowest true positive (4.958), so both sides keep a margin.
- Limitation: all true-positive fixtures are generated from a 36-character alphabet and run high. Real key distributions have not been sampled here.
