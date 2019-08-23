# this can be used to directly convert existing .json reports from cuckoo to stix2 observables.

import json
import sys
import os
from cuckoo.reporting import stix2reporter
import logging
logging.basicConfig()

class TestFramework:
    def main(self):
        if len(sys.argv) != 2 and len(sys.argv) != 3:
            print('Usage: TestFramework.py path/to/report [output/directory]')
            return 1

        with open(sys.argv[1]) as json_data:
            report = json.load(json_data)

        s2r = stix2reporter()
        if len(sys.argv) == 2:
            s2r.reports_path = os.path.dirname(sys.argv[1])
        else:
            s2r.reports_path = sys.argv[2]
        s2r.set_options({"enabled": True,
                         "username": "Administrator",
                         "use_env_variables": True ,
                         "include_src_addr": False,
                         "include_all_artifacts": False,
                         "discard_terminated_processes": True,
                         "whitelist": '/home/c/git/FKIE/reporting2stix/stix2reporter/whitelist.yml'})
        s2r.run(report)

if __name__ == "__main__":
    testFramework = TestFramework()
    testFramework.main()
