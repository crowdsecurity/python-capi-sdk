![CrowdSec Logo](images/logo_crowdsec.png)

# CrowdSec CAPI Python SDK

## User Guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description

This SDK allows you to interact with the CrowdSec Central API (CAPI).

## Features

- Handle multiple security engines
  - Automatic management of credentials (password, machine_id and login token)
- Create signals
- CrowdSec CAPI available endpoints:
  - Push signals
  - Retrieve decisions stream list
  - Enroll a machine

## Quick start

### Installation

First, install CrowdSec CAPI SDK via the [pip](https://pypi.org/project/pip/) package installer for Python:
```bash
pip install cscapi
```

Please see the [Installation Guide](./INSTALLATION_GUIDE.md) for mor details.

### CAPI Client instantiation

To instantiate a CAPI client, you have to:

- Pass an implementation of the provided `StorageInterface` in the first parameter. For this quick start, we will 
  use a basic `SQLStorage` implementation, but we advise you to develop a more secured class as we are storing sensitive data.


- Pass a `CAPIClientConfig` object as a second parameter. You will find below [the list of available 
  settings](#capi-client-configurations) for the `CAPIClientConfig` instantiation.

```python
from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.sql_storage import SQLStorage

client = CAPIClient(
    storage=SQLStorage(),
    config=CAPIClientConfig(
        scenarios=["acme/http-bf", "crowdsec/ssh-bf"]
    ),
)
```

#### CAPI calls

Once your client is instantiated, you can perform the following calls:

##### Push signals

In order to quickly create a well formatted signal, we provide a helper method: `create_signal`:

```python
from cscapi.utils import create_signal, generate_machine_id_from_key

signals = [
    create_signal(
        attacker_ip="81.81.81.81",
        scenario="crowdsec/ssh-bf",
        created_at="2024-02-19 12:12:21 +0000",
        machine_id=generate_machine_id_from_key("myMachineKeyIdentifier"),
        context=[{"key": "scenario-version", "value": "1.0.0"}],
        message="test message",
    )
]
```

Once you have your signals, you can store it in the database and send it to the CAPI:

```python
# This stores the signals in the database
client.add_signals(signals)
# You can program this call to send signals periodically.
client.send_signals()
```

##### Get Decisions stream list

To retrieve the list of top decisions, you can do the following call:

```python
decisions = client.get_decisions()
```

##### Enroll security engines

To enroll machines you have to specify:

- The list of machine ids you want to enroll
- The `name` that will be display in the console for machines
- An `attachment_key` that is generated in your CrowdSec backoffice account (a.k.a. `enrollement key`)
- A `tags` array to apply on the console for the instance
- An `overwrite` boolean to force enroll the instance or not (if already enrolled)


```python
from cscapi.utils import generate_machine_id_from_key

client.enroll_machines(
    [
        generate_machine_id_from_key("myMachine1"),
        generate_machine_id_from_key("myMachine2"),
    ],
    "basicName",
    "myenrollkeyigotonconsole",
    ["some_tag", "another_tag"],
    True,
)
```

## CAPI Client Configurations

The `CAPIClientConfig` object allows you to configure the behavior of the `CAPIClient`. Below is the list of available settings:

---

- `scenarios` (`List[str]`, **required**)

You have to pass an array of CrowdSec scenarios that will be used to log in your watcher. 

You should find a list of available scenarios on the [CrowdSec hub collections page](https://hub.crowdsec.net/browse/).

Each scenario must match the regular expression `#^[A-Za-z0-9]{0,16}\/[A-Za-z0-9_-]{0,64}$#`.

If you want to use custom scenarios, please contact the CrowdSec team to get them registered.

---

- `prod` (`bool`)

If set to `True`, the client will use the production CAPI endpoint. If set to `False`, the client will use the development CAPI endpoint. 

Default to `False`.

---

- `user_agent_prefix` (`str`)

The user agent prefix to use for the requests.

This is useful to identify your client in the CrowdSec logs and console.

Final value will be: `{config.user_agent_prefix}-capi-py-sdk/{__version__}` where `__version__` is the current version of this package.

Default to empty string.

---

- `max_retries` (`int`)

If there is an issue while sending signals, we will retry up to `max_reties` times. If the number of attempts reaches this value, the machine will be flagged as `is_failing=True`

Default to 3.

---

- `latency_offset` (`int`)

Used as a buffer to ensure that the token is not just valid at the current moment, but will remain valid for at least `latency_offset` seconds in the future.

Default to 10.

---

- `retry_delay`(`int`)

Specifies the amount of time (in seconds) that the client should wait before retrying a failed operation.

Default to 5

___

- `logger` (`logging.Logger`)

The logger to use for the client.



