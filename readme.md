# stix2reporter

Reporting module for Cuckoo, which outputs STIX2 Observables (`observed-data`-objects).

## Installation
- install python packages from requirements.txt
- integrate the directory `STIX2reporter/reporting` into the 'reporting' directory from Cuckoo (`venv/lib/python2.7/site-packages/cuckoo/reporting`).
- insert the following into 'reporting' (`~/.cuckoo/conf/reporting.conf`), adjust parameters to your liking:

```py
[stix2reporter]
enabled = yes
username = DemoUser
use_env_variables = yes
include_src_addr = no
blacklist = /path/to/blacklist.yml
discard_terminated_processes = yes
include_all_artifacts = no
```
- in Cuckoos config.py (`venv/lib/python2.7/site-packages/cuckoo/common/config.py`) insert the following:

```py
class Config(object):
    configuration = {
        reporting: {
----------- INSERT ONLY THE LINES BELOW ----------------------
            "stix2reporter": {
                "enabled": Boolean(True),
                "username": String("cuckoo"),
                "use_env_variables": Boolean(True),
                "include_src_addr": Boolean(False),
                "blacklist": Path(),
                "discard_terminated_processes": Boolean(True),
                "include_all_artifacts": Boolean(False),
            },
--------------------------------------------------------------
```

## Parameter
- `username`: Username used within the Windows VM, where the sample is executed in. If `use_env_variables` is set to `yes/True`, the username will be replaced with `%USERNAME%` in the resulting STIX objects.
- `use_env_variables`: If set to `yes/True`, replace common paths with Windows env variables, e.g. `%TEMP%`, `%APPDATA%`, etc.
- `include_src_addr`: If set to `no/False`, source address information are excluded for network observables.
- `blacklist`: Specifies the path to a blacklist.
- `discard_terminated_processes`: If set to `yes/True`, processes which are not running at the end of analysis, as well as Mutexes attached to such processes, will be excluded.
- `include_all_artifacts`: From the analysis it is not clear if a write operation appends to or overwrites a specific file. If set to `yes/True`, every write operation on one file will be included within a resulting `file`-observable as an `artifact`-object. If set to `no/False`, only **one** `artifact`-object will be included if possible -- in the case of multiple write operations, **no** `artifact`-object will be included for this file.
