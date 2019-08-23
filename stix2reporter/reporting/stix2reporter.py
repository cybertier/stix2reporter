# General
import os
import sys
import re
import itertools
import ntpath
import datetime
import pytz
import logging
import shlex
import base64
import traceback
import yaml
import stix2
log = logging.getLogger(__name__)

# Cuckoo
from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError, CuckooDependencyError
from cuckoo.misc import cwd

now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class stix2reporter(Report):
    """ Save analysis in STIX 2.0 """

    def run(self, results):
        # Save Cuckoo Sandbox results dictionary for processing
        self.results = results
        self.observables = []
        self.processes = []
        self.files = []
        self.directories = []
        self.deleted_files = []
        self.deleted_directories = []
        self.mutexes = []
        self.reg_keys = []
        self.reg_values = {}
        self.deleted_reg_keys = []
        self.deleted_reg_values = {}
        self.connections = []
        self.http_connections = []
        self.domains = []
        self.terminated_pids = []

        self.load_blacklist()
        try:
            self.target_name = self.results["target"]["file"]['name']
        except KeyError:
            self.target_name = None

        # add dropped files
        if "dropped" in self.results and len(self.results["dropped"]) > 0:
            for file in self.results["dropped"]:
                if 'filepath' not in file:
                    continue
                if not file['pids']:
                    continue
                obj = file
                obj['label'] = 'Dropped File'
                self.files.append(obj)

        # get terminated processes
        if self.options.get('discard_terminated_processes'):
            self.get_terminated_pids(self.results['debug'])

        # analyse and create observables
        self.behaviour(self.results['behavior'])
        self.network(self.results['network'])
        self.remove_observables()

        self.write_output()

    def write_output(self):
        # build STIX objects
        for file in self.files:
            obs = self.create_file_obs(file, file['label'])
            self.observables.append(obs) if obs else None
        for process in self.processes:
            obs = self.create_process_obs(process)
            self.observables.append(obs) if obs else None
        for directory in self.directories:
            obs = self.create_directory_obs(directory)
            self.observables.append(obs) if obs else None
        for mutex in self.mutexes:
            obs = self.create_mutex_obs(mutex)
            self.observables.append(obs) if obs else None
        for regkey in self.reg_keys:
            obs = self.create_regkey_obs(regkey, self.reg_values.get(regkey['key'], None))
            self.observables.append(obs) if obs else None
        for connection in self.connections:
            obs = self.create_connection_obs(connection)
            self.observables.append(obs) if obs else None
        for http in self.http_connections:
            obs = self.create_http_connection_obs(http)
            self.observables.append(obs) if obs else None
        for domain in self.domains:
            obs = self.create_domain_obs(domain)
            self.observables.append(obs) if obs else None

        if not self.observables:
            raise CuckooReportError("Failed to generate STIX2 report: No Observables to report.")

        # write report
        try:
            bundle = stix2.Bundle(objects=self.observables).serialize(sort_keys=False, indent=4)
            try:
                os.makedirs(self.reports_path)
            except OSError:
                pass
            with open(os.path.join(self.reports_path, 'stix2.json'), 'w') as report:
                report.write(bundle)
        except Exception as e:
            raise CuckooReportError("Failed to generate STIX2 report: %s" % e)

    # network
    def network(self, data):
        for connection in data.get('tcp', []):
            con = self.connection(connection, 'tcp')
            self.connections.append(con) if con else None
        for connection in data.get('udp', []):
            con = self.connection(connection, 'udp')
            self.connections.append(con) if con else None
        for http_con in data.get('http_ex', []):
            con = self.http_connection(http_con, data['http'])
            self.http_connections.append(con) if con else None
        for dns_req in data.get('dns', []):
            query = self.dns_query(dns_req)
            self.domains.append(query) if query else None

    def http_connection(self, http_con, http_legacy):
        dest_addr = {'value': http_con['dst']}
        if is_valid_ipv6(http_con['dst']):
            dest_addr['type'] = 'ipv6-addr'
        elif is_valid_ipv4(http_con['dst']):
            dest_addr['type'] = 'ipv4-addr'
        else:
            log.error("Type of network address ({0}) not known!", http_con['dst'])
            return None

        header = {}
        for http_legacy in http_legacy:
            if http_con['uri'] == http_legacy['path'] and http_con['host'] == http_legacy['host'] and http_con[
                    'method'] == http_legacy['method'] and http_con['dport'] == http_legacy['port']:
                if 'user-agent' in http_legacy:
                    header['user-agent'] = http_legacy['user-agent']
                if 'version' in http_legacy:
                    header['version'] = http_legacy['version']
        http = {
            'request_method': http_con['method'],
            'request_value': http_con['uri'],
            'request_version': header.get('version', None),
            'request_header': {
                'User-Agent': header.get('user-agent', None),
                'Host': http_con['host']
            }
        }

        # Future ToDo -- not yet in STIX 2.0:
        # http_con['status']
        # http_con['response']

        obj = {
            'type': 'network-traffic',
            'dst_ref': '1',
            'dst_port': http_con['dport'],
            'protocols': ['tcp', 'http'],
            'extensions': {
                'http-request-ext': http
            }
        }
        observable = {'0': obj, '1': dest_addr}
        return observable

    def connection(self, data, protocol):
        src_addr = None
        if self.options.get("include_src_addr"):
            src_addr = {'value': data['src']}
            if is_valid_ipv6(data['src']):
                src_addr['type'] = 'ipv6-addr'
            elif is_valid_ipv4(data['src']):
                src_addr['type'] = 'ipv4-addr'
            else:
                log.error("Type of network address ({0}) not known!", data['src'])
                return None

        dest_addr = {'value': data['dst']}
        if is_valid_ipv6(data['dst']):
            dest_addr['type'] = 'ipv6-addr'
        elif is_valid_ipv4(data['dst']):
            dest_addr['type'] = 'ipv4-addr'
        else:
            log.error("Type of network address ({0}) not known!", data['dst'])
            return None

        obj = {'type': 'network-traffic', 'dst_port': data['dport'], 'protocols': [protocol]}

        observable = {}
        counter = 0
        observable[str(counter)] = obj
        counter += 1
        observable[str(counter)] = dest_addr
        obj['dst_ref'] = str(counter)
        counter += 1
        if src_addr:
            obj['dst_port'] = data['sport']
            observable[str(counter)] = src_addr
            obj['src_ref'] = str(counter)
        return observable

    def dns_query(self, data):
        domain = {'type': 'domain-name', 'value': data['request']}
        answers = []

        for answer in data['answers']:
            ip = answer['data']
            if is_valid_ipv4(ip):
                ans = {'type': 'ipv4-addr', 'value': ip}
                answers.append(ans)
            elif is_valid_ipv6(ip):
                ans = {'type': 'ipv6-addr', 'value': ip}
                answers.append(ans)

        obj = {'0': domain}
        counter = 1
        for answer in answers:
            obj[str(counter)] = answer
            counter += 1

        if counter > 1:
            obj['0']['resolves_to_refs'] = range(1, counter)

        return obj

    # host
    def behaviour(self, data):
        summary = data.get('summary', {})
        files_created = summary.get('file_created', [])
        files_deleted = summary.get('file_deleted', [])
        directories_created = summary.get('directory_created', [])
        # directories_deleted = summary.get('directory_removed', [])
        # registry_written = summary.get('regkey_written', [])
        # registry_deleted = summary.get('regkey_deleted', [])

        # analyse process calls
        for process in data['processes']:
            for call in process['calls']:
                self.process_call(call)

        self.process_processes(data['processes'])
        self.process_mutexes(data)
        self.process_files(files_created, files_deleted, directories_created)

    def process_processes(self, data):
        for process in data:
            obj = {
                'type': 'process',
                'time': self.get_time(process['first_seen']),
                'name': process['process_name'],
                'process_path': process['process_path']
            }

            if 'pid' in process:
                obj['pid'] = process['pid']

            if (process['process_path'].lower() != process['command_line'].lower()
                    and not (process['command_line'][0] == '"' and
                             (process['command_line'][-1] == '"' or process['command_line'][-2:] == '" ')
                             and process['command_line'][1:].index('"') >= len(process['command_line']) - 3)):
                # process has arguments; the above if-clause checks for things like:
                # [c:\bad.exe], ["c:\bad.exe"] and ["c:\bad.exe" ](<--mind the trailing witespace!),
                # which all do not feature any arguments but look different!
                # All those examples have been observed running real world malware samples.
                obj['command_line'] = process['command_line']
                try:
                    arguments = shlex.split(obj['command_line'], posix=False)[1:]
                    if arguments:
                        obj['arguments'] = arguments
                except Exception as e:
                    if str(e) == 'No closing quotation':
                        try:
                            arguments = shlex.split(obj['command_line'] + '"', posix=False)[1:]
                            if arguments:
                                obj['arguments'] = arguments
                        except:
                            pass
            self.processes.append(obj)

    def process_files(self, files_created, files_deleted, directories_created):
        # files
        known_files = []
        for known_file in self.files:
            if 'filepath' in known_file:
                known_files.append(known_file['filepath'])
        deleted_files = [] + files_deleted
        for deleted_file in self.deleted_files:
            deleted_files.append(deleted_file['filepath'])
        deleted_directories = []
        for deleted_directory in self.deleted_directories:
            deleted_directories.append(deleted_directory['dirpath'])

        for file in files_created:
            if file not in known_files and file not in deleted_files and ntpath.dirname(
                    file) + r'\\' not in deleted_directories and ntpath.dirname(file) not in directories_created:
                obj = {'label': 'File Created', 'type': 'file', 'name': ntpath.basename(file), 'filepath': file}
                self.files.append(obj)

    def get_mutexes(self, behaviour):
        mutexes = []
        for process in behaviour.get('generic'):
            pid = process.get('pid')
            if self.options.get('discard_terminated_processes') and pid in self.terminated_pids:
                continue
            if 'summary' in process and 'mutex' in process['summary']:
                mutexes.extend(process['summary']['mutex'])
        return mutexes

    def process_mutexes(self, data):
        mutexes = self.get_mutexes(data)
        for mutex in mutexes:
            known = False
            for known_mutex in self.mutexes:
                if known_mutex['name'] == mutex:
                    known = True
                    break
            if known:
                continue
            obj = {'type': 'mutex', 'name': mutex}
            self.mutexes.append(obj)

    def process_call(self, call):
        # api calls regarding files
        if call['category'] == 'file':
            switcher = {
                'CreateFile2': lambda: self.api_create_file(call),
                'CreateFileA': lambda: self.api_create_file(call),
                'CreateFileW': lambda: self.api_create_file(call),
                'NtCreateFile': lambda: self.api_create_file(call),
                'WriteFile': lambda: self.api_write_file(call),
                'WriteFileEx': lambda: self.api_write_file(call),
                'NtWriteFile': lambda: self.api_write_file(call),
                'DeleteFile': lambda: self.api_delete_file(call),
                'DeleteFileA': lambda: self.api_delete_file(call),
                'DeleteFileW': lambda: self.api_delete_file(call),
                'ZwDeleteFile': lambda: self.api_delete_file(call),
                'RemoveDirectoryA': lambda: self.api_delete_directory(call),
                'RemoveDirectoryW': lambda: self.api_delete_directory(call),
            }
            observable = switcher.get(call['api'], lambda: None)()
            if not observable:
                return None

            known = False
            for index, file in enumerate(self.files):
                if 'filepath' in file and 'filepath' in observable and file['filepath'] == observable['filepath']:
                    # file already known; do not include it again, but update data
                    known = True

                    # update timestamps
                    obs = self.update_timestamps(file, observable)
                    if obs:
                        self.files[index] = obs

                    # update artifacts
                    obs = self.files[index]
                    if 'artifacts' in observable:
                        if 'artifacts' in file:
                            obs['artifacts'] += observable['artifacts']
                        else:
                            obs['artifacts'] = observable['artifacts']
                    self.files[index] = obs
                    break
            if not known:
                observable['first_observed'] = observable['time']
                observable['last_observed'] = observable['time']
                observable.pop('time', None)
                self.files.append(observable)

        # api calls regarding registry
        if call['category'] == 'registry':
            switcher = {
                'RegSetValueExA': lambda: self.api_set_regkey(call),
                'RegSetValueExW': lambda: self.api_set_regkey(call),
                #'RegCreateKeyExA': lambda: self.api_create_regkey(call),
                #'RegCreateKeyExW': lambda: self.api_create_regkey(call),
                'RegDeleteValueA': lambda: self.api_delete_regvalue(call),
                'RegDeleteValueW': lambda: self.api_delete_regvalue(call),
                'RegDeleteKeyA': lambda: self.api_delete_regkey(call),
                'RegDeleteKeyW': lambda: self.api_delete_regkey(call),
                'RegDeleteKeyExA': lambda: self.api_delete_regkey(call),
                'RegDeleteKeyExW': lambda: self.api_delete_regkey(call),
            }
            observable = switcher.get(call['api'], lambda: None)()
            if not observable:
                return None

            if 'value' in observable:
                value = {'data': observable['data'], 'datatype': observable['datatype'], 'time': observable['time']}
                values = self.reg_values.get(observable['key'], {})
                if observable['value'] in values:
                    for index, data in enumerate(values[observable['value']]):
                        if observable['data'] != data['data']:
                            if datetime.datetime.strptime(data['time'],
                                                          '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                                                              observable['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                                data['data'] = observable['data']
                                data['datatype'] = observable['datatype']
                                data['time'] = observable['time']
                                values[observable['value']][index] = data
                        else:
                            data['time'] = observable['time']
                            values[observable['value']][index] = data
                else:
                    values[observable['value']] = [value]
                self.reg_values[observable['key']] = values
            observable.pop('value', None)
            observable.pop('data', None)
            observable.pop('datatype', None)

            known = False
            for index, regkey in enumerate(self.reg_keys):
                if regkey['key'] == observable['key']:
                    # regkey already known; do not include it again, but update data
                    known = True

                    # update timestamps
                    obs = self.update_timestamps(regkey, observable)
                    if obs:
                        self.reg_keys[index] = obs
            if not known:
                observable['first_observed'] = observable['time']
                observable['last_observed'] = observable['time']
                observable.pop('time', None)
                self.reg_keys.append(observable)

    def api_create_mutant(self, data):
        # [TODO] This may be only for NtCreateMutant!
        if data['return_value'] != 0:
            return None
        obj = {'label': 'Mutex Created', 'name': data['arguments']['mutant_name']}
        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        return obj

    def api_create_file(self, data):
        # [TODO] This may be only for NtCreateFile!
        if data['flags']['status_info'] != 'FILE_CREATED':
            return None
        obj = {
            'label': 'File Created',
            'name': ntpath.basename(data['arguments']['filepath']),
            'filepath': data['arguments']['filepath']
        }
        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        return obj

    def api_write_file(self, data):
        if data['return_value'] != 0:
            return None
        # [TODO] This may be only for NtWriteFile!
        obj = {
            'label': 'File Written',
            'name': ntpath.basename(data['arguments']['filepath']),
            'filepath': data['arguments']['filepath'],
            'artifacts': [data['arguments']['buffer']]
        }
        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        return obj

    def api_delete_file(self, data):
        # not an observable object, but remove observables affected by this
        if data['return_value'] == 0:
            # yes, zero is fail, non-zero success: https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-deletefilea
            return None
        obj = {'label': 'File Deleted', 'filepath': data['arguments']['filepath']}
        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        self.deleted_files.append(obj)
        return None

    def api_delete_regkey(self, data):
        # not an observable object, but remove observables affected by this
        if data['return_value'] != 0:
            return None
        obj = {'label': 'Registry Key Deleted', 'key': data['arguments']['regkey']}
        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        self.deleted_reg_keys.append(obj)
        return None

    def api_delete_regvalue(self, data):
        # not an observable object, but remove observables affected by this
        if data['return_value'] != 0:
            return None
        key = ntpath.dirname(data['arguments']['regkey'])
        obj = {'label': 'Registry Value Deleted', 'value': ntpath.basename(data['arguments']['regkey'])}
        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        deleted = self.deleted_reg_values.get(key, [])
        deleted.append(obj)
        self.deleted_reg_values[key] = deleted
        return None

    def api_set_regkey(self, data):
        if data['return_value'] != 0:
            return None
        # [TODO] This may be only for RegSetValueExW!
        key = ntpath.dirname(data['arguments']['regkey'])
        value = ntpath.basename(data['arguments']['regkey'])
        obj = {
            'label': 'Registry Key Written',
            'key': key,
            'value': value,
            'data': data['arguments']['value'],
            'datatype': data['flags']['reg_type']
        }

        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        return obj

    def api_create_regkey(self, data):
        if data['return_value'] != 0:
            return None
        # [TODO] This may be only for RegCreateKeyExW!
        key = ntpath.dirname(data['arguments']['regkey'])
        obj = {'label': 'Registry Key Created or Read', 'key': key}

        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        return obj

    def api_delete_directory(self, data):
        # not an observable object, but remove observables affected by this
        if data['return_value'] == 0:
            return None
        obj = {'label': 'Directory Deleted', 'dirpath': data['arguments']['dirpath']}
        time = self.get_time(data['time'])
        if time:
            obj['time'] = time
        self.deleted_directories.append(obj)
        return None

    ###### Create STIX2 Observables ######
    def create_process_obs(self, data):

        if self.options.get('discard_terminated_processes') and data['pid'] in self.terminated_pids:
            return {}

        first_observed = data['time']
        last_observed = data['time']
        del data['time']

        obj = {'0': data}
        del data['process_path']

        # do not include the process of the target file itself!
        # account for cuckoo running .dll files
        if 'command_line' in data and re.match(
                r'\"C:\\Windows\\System32\\rundll32\.exe\" C:\\Users\\.*\\AppData\\Local\\Temp\\' + self.target_name +
                r'\.dll,DllMain', data['command_line']):
            return {}
        # account for cuckoo appending the .exe file extension, if it does not exists already
        if ('command_line' in data and 'C:\\Users\\' + self.options.get("username") + '\\AppData\\Local\\Temp\\' +
                self.target_name == data['command_line'] or len(data) == 2 and 'name' in data and
            (self.target_name == data['name'] or self.target_name == '.exe'.join(data['name'].split('.exe')[:-1]))):
            return {}

        if self.is_blacklisted(obj):
            return {}

        if self.options.get('use_env_variables'):
            if 'command_line' in obj['0']:
                obj['0']['command_line'] = self.replace_env_variables(obj['0']['command_line'])
            if 'arguments' in obj['0']:
                for i, arg in enumerate(obj['0']['arguments']):
                    obj['0']['arguments'][i] = self.replace_env_variables(obj['0']['arguments'][i])

        try:
            observed_data = stix2.ObservedData(first_observed=first_observed,
                                               last_observed=last_observed,
                                               number_observed=1,
                                               objects=obj,
                                               labels='Process Created')
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create Process Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create Process Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    def create_file_obs(self, data, labels=None):
        if 'time' in data:
            first_observed = data['time']
            last_observed = data['time']
        else:
            first_observed = now
            last_observed = now
        if 'first_observed' in data:
            first_observed = data['first_observed']
        if 'last_observed' in data:
            last_observed = data['last_observed']

        counter = 1
        obj = {}
        file = {'type': 'file'}

        # Add Hashes
        hashes = self.get_hashes(data)
        if hashes:
            file['hashes'] = hashes

        # Add other fields
        if 'size' in data and data['size']:
            file['size'] = data['size']
        if 'name' in data and data['name']:
            file['name'] = data['name']
        if 'filepath' in data and data['filepath']:
            directory = {'type': 'directory'}
            directory['path'] = ntpath.dirname(data['filepath'])
            obj[str(counter)] = directory
            file['parent_directory_ref'] = str(counter)
            file['name'] = ntpath.basename(data['filepath'])
            counter += 1

        obj['0'] = file

        if 'artifacts' in data and data['artifacts']:
            if self.options.get("include_all_artifacts"):
                for artifact in data['artifacts']:
                    art = {'type': 'artifact', 'payload_bin': base64.b64encode(artifact.encode('utf-8'))}
                    obj[str(counter)] = art
                    contains_refs = obj['0'].get('contains_refs', [])
                    contains_refs.append(str(counter))
                    obj['0']['contains_refs'] = contains_refs
                    counter += 1
            elif len(data['artifacts']) == 1:
                artifact = data['artifacts'][0]
                art = {'type': 'artifact', 'payload_bin': base64.b64encode(artifact.encode('utf-8'))}
                obj[str(counter)] = art
                contains_refs = obj['0'].get('contains_refs', [])
                contains_refs.append(str(counter))
                obj['0']['contains_refs'] = contains_refs
                counter += 1

        # run blacklist with original filepaths
        if self.is_blacklisted(obj):
            return {}

        # run blacklist with modified filepaths
        if not self.options.get('use_env_variables'):
            name_bak = obj['0']['name']
            path_bak = obj['1']['path']
        if 'name' in obj['0']:
            obj['0']['name'] = self.replace_env_variables(obj['0']['name'])
        if '1' in obj:
            obj['1']['path'] = self.replace_env_variables(obj['1']['path'])
        if self.is_blacklisted(obj):
            return {}
        if not self.options.get('use_env_variables'):
            obj['0']['name'] = name_bak
            obj['1']['path'] = path_bak

        try:
            observed_data = stix2.ObservedData(first_observed=first_observed,
                                               last_observed=last_observed,
                                               number_observed=1,
                                               objects=obj,
                                               labels=labels)
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create File Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create File Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    def create_directory_obs(self, data):
        obj = {}
        obj['0'] = data
        obj['0']['path'] = obj['0']['path']
        if self.is_blacklisted(obj):
            return {}
        obj['0']['path'] = self.replace_env_variables(obj['0']['path'])
        if self.is_blacklisted(obj):
            return {}
        try:
            observed_data = stix2.ObservedData(first_observed=now,
                                               last_observed=now,
                                               number_observed=1,
                                               objects=obj,
                                               labels='Directory Created or Read')
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create Directory Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create Directory Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    def create_mutex_obs(self, data):
        if not data['name']:
            return {}
        if 'time' in data:
            first_observed = data['time']
            last_observed = data['time']
        else:
            first_observed = now
            last_observed = now
        if 'first_observed' in data:
            first_observed = data['first_observed']
        if 'last_observed' in data:
            last_observed = data['last_observed']
        obj = {0: {'type': 'mutex', 'name': data['name']}}
        if self.is_blacklisted(obj[0]):
            return {}
        try:
            observed_data = stix2.ObservedData(first_observed=first_observed,
                                               last_observed=last_observed,
                                               number_observed=1,
                                               objects=obj,
                                               labels='Mutex Created')
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create Mutex Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create Mutex Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    def create_regkey_obs(self, regkey, values):
        if 'time' in regkey:
            first_observed = regkey['time']
            last_observed = regkey['time']
        else:
            first_observed = now
            last_observed = now
        if 'first_observed' in regkey:
            first_observed = regkey['first_observed']
        if 'last_observed' in regkey:
            last_observed = regkey['last_observed']

        values = []
        obj = {
            'type': 'windows-registry-key',
            'key': regkey['key'],
        }

        values = []
        for key, value in self.reg_values.items():
            if key == regkey['key']:
                for val, data in value.items():
                    for d in data:
                        value_data = base64.b64encode(
                            d['data'].encode('utf-8')) if d['datatype'] == 'REG_BINARY' else d['data']
                        v = {'name': val, 'data': value_data, 'data_type': d['datatype']}
                        values.append(v)
        if values:
            obj['values'] = values

        if self.is_blacklisted(obj):
            return {}

        try:
            observed_data = stix2.ObservedData(first_observed=first_observed,
                                               last_observed=last_observed,
                                               number_observed=1,
                                               objects={0: obj},
                                               labels=regkey['label'])
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create RegistryKey Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create RegistryKey Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    def create_connection_obs(self, data):
        if self.is_blacklisted(data):
            return {}
        if 'time' in data:
            first_observed = data['time']
            last_observed = data['time']
        else:
            first_observed = now
            last_observed = now
        if 'first_observed' in data:
            first_observed = data['first_observed']
        if 'last_observed' in data:
            last_observed = data['last_observed']
        try:
            observed_data = stix2.ObservedData(first_observed=first_observed,
                                               last_observed=last_observed,
                                               number_observed=1,
                                               objects=data,
                                               labels='Network Connection')
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create Network Connection Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create Network Connection Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    def create_http_connection_obs(self, data):
        if self.is_blacklisted(data):
            return {}
        if 'time' in data:
            first_observed = data['time']
            last_observed = data['time']
        else:
            first_observed = now
            last_observed = now
        if 'first_observed' in data:
            first_observed = data['first_observed']
        if 'last_observed' in data:
            last_observed = data['last_observed']
        try:
            observed_data = stix2.ObservedData(first_observed=first_observed,
                                               last_observed=last_observed,
                                               number_observed=1,
                                               objects=data,
                                               labels='HTTP Connection')
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create HTTP Connection Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create HTTP Connection Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    def create_domain_obs(self, data):
        if self.is_blacklisted(data['0']):
            return {}
        try:
            observed_data = stix2.ObservedData(first_observed=now,
                                               last_observed=now,
                                               number_observed=1,
                                               objects=data,
                                               labels='Domain')
            return observed_data
        except Exception as e:
            if hasattr(e, 'message'):
                log.error("Unable to create Domain Observable: {0} {1}".format(e, e.message))
                traceback.print_exc(file=sys.stdout)
            else:
                log.error("Unable to create Domain Observable: {0}".format(e))
                traceback.print_exc(file=sys.stdout)
            return {}

    ###### helper functions #######
    def get_time(self, time):
        if not time:
            return None
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except AttributeError:
            None
        try:
            return datetime.datetime.fromtimestamp(time, tz=pytz.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except TypeError:
            None
        return None

    def update_timestamps(self, obj, obs):
        if not 'first_observed' in obj:
            obj['first_observed'] = obs['time']
            obj['last_observed'] = obs['time']
            return obj
        elif datetime.datetime.strptime(obj['first_observed'], '%Y-%m-%dT%H:%M:%S.%fZ') > datetime.datetime.strptime(
                obs['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
            obj['last_observed'] = obj['first_observed']
            obj['first_observed'] = obs['time']
            return obj
        elif datetime.datetime.strptime(obj['last_observed'], '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                obs['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
            obj['last_observed'] = obs['time']
            return obj
        return None

    def get_hashes(self, data):
        hashes = {}
        if 'md5' in data and data['md5']:
            hashes['MD5'] = data['md5']
        if 'sha1' in data and data['sha1']:
            hashes['SHA-1'] = data['sha1']
        if 'sha256' in data and data['sha256']:
            hashes['SHA-256'] = data['sha256']
        if 'sha512' in data and data['sha512']:
            hashes['SHA-512'] = data['sha512']
        if 'ssdeep' in data and data['ssdeep'] is not None:
            ssdeephash = Hash()
            ssdeephash.fuzzy_hash_value = data['ssdeep']
            ssdeephash.type_ = 'SSDEEP'
            hashes['SSDEEP'] = ssdeephash
        return hashes

    def replace_env_variables(self, path):
        if not self.options.get("use_env_variables"):
            return path

        username = self.options.get("username")
        new_path = path
        if re.search(r'C:\\Users\\' + username + r'\\AppData\\Roaming\\', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Users\\' + username + r'\\AppData\\Roaming\\',
                              '%APPDATA%\\\\',
                              new_path,
                              flags=re.IGNORECASE)
        if re.search(r'C:\\Users\\' + username + r'\\AppData\\Roaming$', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Users\\' + username + r'\\AppData\\Roaming',
                              '%APPDATA%',
                              new_path,
                              flags=re.IGNORECASE)
        if re.search(r'C:\\Users\\' + username + r'\\AppData\\Local\\', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Users\\' + username + r'\\AppData\\Local\\',
                              '%LOCALAPPDATA%\\\\',
                              new_path,
                              flags=re.IGNORECASE)
        if re.search(r'C:\\Users\\' + username + r'\\AppData\\Local$', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Users\\' + username + r'\\AppData\\Local',
                              '%LOCALAPPDATA%',
                              new_path,
                              flags=re.IGNORECASE)
        if re.search(r'C:\\Users\\' + username + r'\\AppData\\Temp\\', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Users\\' + username + r'\\AppData\\Temp\\',
                              '%TEMP%\\\\',
                              new_path,
                              flags=re.IGNORECASE)
        if re.search(r'C:\\Users\\' + username + r'\\AppData\\Temp$', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Users\\' + username + r'\\AppData\\Temp', '%TEMP%', new_path, flags=re.IGNORECASE)
        if re.search(r'C:\\Users\\' + username, new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Users\\' + username, '%USERPROFILE%', new_path, flags=re.IGNORECASE)
        if re.search(username, new_path, flags=re.IGNORECASE):
            new_path = re.sub(username, '%USERNAME%', new_path, flags=re.IGNORECASE)
        if re.search(r'C:\\Program Files\\', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Program Files\\', '%PROGRAMFILES%\\\\', new_path, flags=re.IGNORECASE)
        if re.search(r'C:\\Program Files$', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Program Files$', '%PROGRAMFILES%', new_path, flags=re.IGNORECASE)
        if re.search(r'C:\\Program Files \(x86\)\\', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Program Files \(x86\)\\', '%PROGRAMFILES(X86)%\\\\', new_path, flags=re.IGNORECASE)
        if re.search(r'C:\\Program Files \(x86\)$', new_path, flags=re.IGNORECASE):
            new_path = re.sub(r'C:\\Program Files \(x86\)$', '%PROGRAMFILES(X86)%', new_path, flags=re.IGNORECASE)
        if re.search(username.upper()[:6] + r'~\d', new_path):
            new_path = re.sub(username.upper()[:6] + r'~\d', username, new_path)
            new_path = self.replace_env_variables(new_path)
        if re.search(re.escape(self.target_name), new_path):
            new_path = re.sub(self.target_name, '%TARGETFILE%', new_path)
        return new_path

    def remove_observables(self):
        ###### files
        # remove directories marked as file observables
        for files in itertools.combinations(self.files, 2):
            try:
                if 'filepath' in files[0] and 'filepath' in files[1] and re.match(re.escape(
                        files[0]['filepath']), files[1]['filepath']) and files[0] in self.files:
                    self.files.remove(files[0])
                    #print("Removed folder:", files[0]['filepath'])
                elif 'filepath' in files[0] and 'filepath' in files[1] and re.match(re.escape(
                        files[1]['filepath']), files[0]['filepath']) and files[1] in self.files:
                    self.files.remove(files[1])
                    #print("Removed folder:", files[1]['filepath'])
            except ValueError:
                None

        marked_for_removal = []
        for file in self.files:
            for deleted in self.deleted_files:
                if 'filepath' in file and file['filepath'] == deleted['filepath']:
                    if 'last_observed' in file and datetime.datetime.strptime(
                            file['last_observed'], '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                                deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        marked_for_removal.append(
                            (file, datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    elif 'time' in file and datetime.datetime.strptime(
                            file['time'], '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                                deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        marked_for_removal.append(
                            (file, datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    elif 'time' not in file and 'last_observed' not in file:
                        # TODO: unsure if file should be removed; no timestamps to compare - make it switchable with parameter?
                        marked_for_removal.append(
                            (file, datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
            for deleted in self.deleted_directories:
                if 'filepath' in file and ntpath.dirname(file['filepath']) == ntpath.dirname(deleted['dirpath']):
                    if 'last_observed' in file and datetime.datetime.strptime(
                            file['last_observed'], '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                                deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        marked_for_removal.append(
                            (file, datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    elif 'time' in file and datetime.datetime.strptime(
                            file['time'], '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                                deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        marked_for_removal.append(
                            (file, datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    elif 'time' not in file and 'last_observed' not in file:
                        # TODO: unsure if file should be removed; no timestamps to compare - make it switchable with parameter?
                        marked_for_removal.append(
                            (file, datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))

        # check if marked files are seen again after their removal; if they are, keep the observable!
        for index, marked in enumerate(marked_for_removal):
            #print("Marked for removal:", marked[0]['filepath'])
            for file in self.files:
                if 'filepath' in file and 'filepath' in marked[0] and marked[0]['filepath'] == file['filepath']:
                    if 'last_observed' in file and datetime.datetime.strptime(
                            file['last_observed'],
                            '%Y-%m-%dT%H:%M:%S.%fZ') > marked[1] and marked in marked_for_removal:
                        marked_for_removal.remove(marked)
                        #print("NOT removed:", file['filepath'])
                    elif 'time' in file and datetime.datetime.strptime(
                            file['time'], '%Y-%m-%dT%H:%M:%S.%fZ') > marked[1] and marked in marked_for_removal:
                        marked_for_removal.remove(marked)
                        #print("NOT removed:", file['filepath'])

        # remove marked observables
        for file in self.files[:]:
            for marked in marked_for_removal:
                if file in self.files and 'filepath' in file and 'filepath' in marked[0] and marked[0][
                        'filepath'] == file['filepath']:
                    self.files.remove(file)
                    #print("Removed:", file['filepath'])

        ###### registry
        marked_for_removal = []
        for obj in self.reg_keys:
            for deleted in self.deleted_reg_keys:
                if deleted['key'] == obj['key']:
                    if 'last_observed' in obj and datetime.datetime.strptime(
                            obj['last_observed'], '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                                deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        marked_for_removal.append(
                            (obj['key'], datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    elif 'time' in obj and datetime.datetime.strptime(
                            obj['time'], '%Y-%m-%dT%H:%M:%S.%fZ') < datetime.datetime.strptime(
                                deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        marked_for_removal.append(
                            (obj['key'], datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
                    elif 'time' not in obj and 'last_observed' not in obj:
                        # TODO: unsure if obj should be removed; no timestamps to compare - make it switchable with parameter?
                        marked_for_removal.append(
                            (obj['key'], datetime.datetime.strptime(deleted['time'], '%Y-%m-%dT%H:%M:%S.%fZ')))
        # check timestamps; if object is still seen after its removal event, keep the observable!
        for index, marked in enumerate(marked_for_removal):
            #print("Marked for removal:", marked[0])
            for obj in self.reg_keys:
                if marked[0] == obj['key']:
                    if 'last_observed' in obj and datetime.datetime.strptime(
                            obj['last_observed'], '%Y-%m-%dT%H:%M:%S.%fZ') > marked[1] and marked in marked_for_removal:
                        marked_for_removal.remove(marked)
                        #print("NOT removed:", obj['key'])
                    elif 'time' in obj and datetime.datetime.strptime(
                            obj['time'], '%Y-%m-%dT%H:%M:%S.%fZ') > marked[1] and marked in marked_for_removal:
                        marked_for_removal.remove(marked)
                        #print("NOT removed:", obj['key'])
        # remove marked observables
        for obj in self.reg_keys[:]:
            for marked in marked_for_removal:
                if marked[0] == obj['key'] and obj in self.reg_keys:
                    self.reg_keys.remove(obj)
                    #print("Removed:", obj['key'])
        #pprint(self.deleted_reg_values)

        # # same procedure with reg values
        # marked_for_removal = []
        # for k1, obj in self.reg_values.items():
        #     for k2, del_obj in self.deleted_reg_values.items():
        #         if k1 == k2:
        #             pprint(del_obj)
        #             # TODO!!

    def load_blacklist(self):
        try:
            blacklist_file = open(self.options.get("blacklist"), 'r')
            self.blacklist = yaml.load(blacklist_file)
            blacklist_file.close()
            log.info("blacklist loaded: {0}".format(self.options.get("blacklist")))
        except Exception as e:
            self.blacklist = {}
            log.warning("Invalid or no blacklist found at {0}: {1}".format(self.options.get("blacklist"), e))

    # checks if a domain is known for given ip, then checks if the domain is blacklisted
    def check_ip_domain(self, ip):
        for domain in self.domains:
            for bl_domain in self.blacklist.get('Domain', []):
                for i in range(1, len(domain.keys())):
                    if (re.match(bl_domain, domain['0']['value']) and ip == domain[str(i)]['value']):
                        return True
        return False

    # checks if a given observable is blacklisted
    def is_blacklisted(self, obj):
        if 'type' in obj and obj['type'] == 'domain-name':
            for domain in self.blacklist.get('Domain', []):
                if re.match(domain, obj['value'], flags=re.IGNORECASE):
                    return True
            #print('- ' + re.escape(obj['value']))
        if '0' in obj and obj['0']['type'] == 'network-traffic':
            if '1' in obj:
                if self.check_ip_domain(obj['1']['value']):
                    return True
            for bl_obj in self.blacklist.get('NetworkTraffic', []):
                if 'dst_addr' in bl_obj and '1' in obj and re.match(bl_obj['dst_addr'], obj['1']['value']):
                    if 'dst_port' in bl_obj:
                        if re.match(str(bl_obj['dst_port']), str(obj['0']['dst_port'])):
                            return True
                        else:
                            continue
                    else:
                        return True
            #print('- dst_addr: ' + re.escape(obj['1']['value']) + '  dst_port: ' + str(obj['0']['dst_port']))
        if 'type' in obj and obj['type'] == 'windows-registry-key':
            for bl_obj in self.blacklist.get('RegistryKey', []):
                if self.traverse_bl(obj, bl_obj):
                    return True
            #print('- key: ' + re.escape(obj['key']))
        if 'type' in obj and obj['type'] == 'mutex':
            for bl_obj in self.blacklist.get('Mutex', []):
                if re.match(bl_obj, obj['name'], flags=re.IGNORECASE):
                    return True
            #print('- ' + re.escape(obj['name']))
        if '0' in obj and obj['0']['type'] == 'file':
            for bl_obj in self.blacklist.get('File', []):
                if 'path' in bl_obj:
                    if not '1' in obj or not re.match(bl_obj['path'], obj['1']['path'], flags=re.IGNORECASE):
                        continue
                if 'name' in bl_obj:
                    if not '0' in obj or not re.match(bl_obj['name'], obj['0']['name'], flags=re.IGNORECASE):
                        continue
                return True
            #if '1' in obj:
            #    print('- path: ' + re.escape(obj['1']['path']) + '\n  name: ' + re.escape(obj['0']['name']))
            #else:
            #    print('- name: ' + re.escape(obj['0']['name']))
        if '0' in obj and obj['0']['type'] == 'directory':
            for bl_obj in self.blacklist.get('Directory', []):
                if re.match(bl_obj, obj['0']['path'], flags=re.IGNORECASE):
                    return True
            for bl_obj in self.blacklist.get('File', []):
                if 'path' in bl_obj and re.match(bl_obj['path'], obj['0']['path'], flags=re.IGNORECASE):
                    return True
            #print('- ' + re.escape(obj['0']['path']) + '$')
        if '0' in obj and obj['0']['type'] == 'process':
            for bl_obj in self.blacklist.get('Process', []):
                if self.traverse_bl(obj['0'], bl_obj):
                    return True
            #print(obj)
        return False

    def traverse_bl(self, obj, bl, at_least_one_key_in_bl=False):
        """
        implements a recursive blacklist matching;
        in the blacklist a dict can be defined, which has to match structure of the observable
        """
        # create a dict used for checking if every property on BL-item is matched
        bl_matched = {}
        if type(bl) is dict:
            for key in bl:
                bl_matched[key] = False

        if type(obj) is dict:
            for key in obj.keys():
                if key in bl:
                    at_least_one_key_in_bl = True
                    if type(bl[key]) == dict:
                        result = self.traverse_bl(obj[key], bl[key], True)
                        if not result:
                            return False
                        bl_matched[key] = True
                    elif type(bl[key]) is str:
                        try:
                            result = re.match(bl[key], obj[key], flags=re.IGNORECASE)
                            if not result:
                                return False
                            bl_matched[key] = True
                        except:
                            return False
                    elif type(bl[key]) is int:
                        try:
                            result = bl[key] == obj[key]
                            if not result:
                                return False
                            bl_matched[key] = True
                        except:
                            return False
                    elif type(bl[key]) is list:
                        for ele1 in bl[key]:
                            matched = False
                            for ele2 in obj[key]:
                                result = self.traverse_bl(ele2, ele1, True)
                                if result:
                                    matched = True
                            if not matched:
                                return False
                            bl_matched[key] = True
            if not at_least_one_key_in_bl:
                return False
            # if not every property on BL-item is matched, return false
            for key, matched in bl_matched.items():
                if matched is False:
                    return False
        elif type(obj) is str:
            try:
                result = re.match(bl, obj, flags=re.IGNORECASE)
                if not result:
                    return False
            except:
                return False
        return True

    def get_terminated_pids(self, debug):
        """
        Parses the debug object in order to determine which pids have terminated
        """
        for line in debug['log']:
            pids = re.findall(r"Process with pid (?P<pid>\d+) has terminated", line)
            for pid in pids:
                self.terminated_pids.append(pid)
        self.terminated_pids = [int(i) for i in self.terminated_pids]


# following two functions taken from: https://stackoverflow.com/a/319293
def is_valid_ipv4(ip):
    """
    Validates IPv4 addresses.
    """
    pattern = re.compile(
        r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None


def is_valid_ipv6(ip):
    """
    Validates IPv6 addresses.
    """
    pattern = re.compile(
        r"""
        ^
        \s*                         # Leading whitespace
        (?!.*::.*::)                # Only a single whildcard allowed
        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
        (?:                         # Repeat 6 times:
            [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
        ){6}                        #
        (?:                         # Either
            [0-9a-f]{0,4}           #   Another group
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            [0-9a-f]{0,4}           #   Last group
            (?: (?<=::)             #   Colon iff preceeded by exacly one colon
             |  (?<!:)              #
             |  (?<=:) (?<!::) :    #
             )                      # OR
         |                          #   A v4 address with NO leading zeros 
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?: \.
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            ){3}
        )
        \s*                         # Trailing whitespace
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None
