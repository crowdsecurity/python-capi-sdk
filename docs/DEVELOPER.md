![CrowdSec Logo](images/logo_crowdsec.png)
# CrowdSec CAPI Python SDK

## Developer guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Local installation](#local-installation)
  - [Virtual environment](#virtual-environment)
  - [Install dependencies](#install-dependencies)
  - [Unit tests](#unit-tests)
- [Release process](#release-process)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Local installation

### Virtual environment

```bash
python -m venv venv
source venv/bin/activate
```

### Install dependencies

```bash
pip install --upgrade pip
python install -r requirements.txt
pip install -r requirements-dev.txt
```

### Unit tests

```bash
python -m pytest
```

## Release process

We use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) approach to determine the next version number of the SDK.

Once you are ready to release a new version (e.g when all your changes are on the `main` branch), you should:

- Determine the next version number based on the changes made since the last release: `MAJOR.MINOR.PATCH`
- Update the [CHANGELOG.md](../CHANGELOG.md) file with the new version number and the changes made since the last release.
  - Each release description must respect the same format as the previous ones.
- Commit the changes with a message like `docs(changelog:) Prepare for release MAJOR.MINOR.PATCH`.
- Browse to the [GitHub `Create and publish release` action](https://github.com/crowdsecurity/python-capi-sdk/actions/workflows/release.yml)
    - Click on `Run workflow` and fill the `Tag name` input with the new version number prefixed by a `v`: `vMAJOR.MINOR.PATCH`.
    - Tick the `Publish to PyPI` checkbox.
    - Click on `Run workflow` to trigger the release process.

 
