# The scanner as one image for any CI: Python 3.11, ripgrep, git and aws-arch-agent at the
# version of this checkout. The entrypoint is the CLI, so arguments go straight to it:
#
#   docker run --rm -v "$PWD":/repo IMAGE --repo /repo --no-llm --no-synth
#
# Two targets. `default` has no Node. `v2` adds Node (npx, for `cdk synth`) and the v2 extra.
# Built and pushed by .github/workflows/release.yml on a v* tag.

FROM python:3.11-slim-bookworm AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ripgrep git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

FROM runtime AS default
RUN pip install . && rm -rf /src
WORKDIR /repo
ENTRYPOINT ["aws-arch-agent"]

FROM node:22-bookworm-slim AS node

FROM runtime AS v2
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && pip install ".[v2]" && rm -rf /src
WORKDIR /repo
ENTRYPOINT ["aws-arch-agent"]
