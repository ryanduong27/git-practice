# Standard Library
import os
import json
import argparse
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Third-party  Library
from lxml import etree
from elasticsearch.helpers import scan
from elasticsearch import Elasticsearch


PROCESS_STATUS = {
    '0': 'not running when connected or disconnected',
    '1': 'run when disconnected only',
    '2': 'run when connected only',
    '3': 'running both when connected and disconnected'
}

WARNING_MSG = 'There are too many transactions impacted, please investigate'

ENVS = ['nv', 'nj', 'us3', 'us4', 'us5', 'us6', 'us7', 'us8', 'psrow']


WM_SIG_QUERY = {
    "_source": [
        "gc_transaction", "operator_name", "primary_source",
        "username", "time", "request_body"
        ],
    "query": {
        "bool": {
            "must": [{
                    "match_phrase": {
                        "gc_authorized": {
                            "query": 1
                        }
                    }
                },
                {
                  "wildcard": {
                    "applications.signature": {
                      "value": "*{sig}*"
                    }
                  }
                },
                {
                    "query_string": {
                        "query": "gdk OR plugin",
                        "fields": ["solution"]
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "yyyy-MM-dd HH:mm:ss",
                            "gte": "{start}",
                            "lte": "{end}"
                        }
                    }
                }
            ],
            "must_not": [{
                "query_string": {
                    "query": "ip# OR user_id#",
                    "fields": ["full_result"]
                }
            }]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}

WM_AUTHSIG_QUERY = {
    "_source": [
        "gc_transaction", "gc_error", "operator_name",
        "primary_source", "username", "time", "request_body"
        ],
    "query": {
        "bool": {
            "must": [{
                    "match_phrase": {
                        "applications.signature": {
                            "query": "{authsig}"
                        }
                    }
                },
                {
                    "match_phrase": {
                        "gc_authorized": {
                            "query": 1
                        }
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "yyyy-MM-dd HH:mm:ss",
                            "gte": "{start}",
                            "lte": "{end}"
                        }
                    }
                }
            ],
            "must_not": [{
                "query_string": {
                    "query": "ip# OR user_id#",
                    "fields": ["full_result"]
                }
            }]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}

WMI_EXE_QUERY = {
    "_source": [
        "gc_transaction", "time", "operator_name", "username",
        "primary_source", "username", "time", "request_body"
        ],
    "query": {
        "bool": {
            "must": [{
                    "match_phrase": {
                        "gc_authorized": {
                            "query": 1
                        }
                    }
                },
                {
                    "match_phrase": {
                        "applications.running": {
                            "query": "{process}"
                        }
                    }
                },
                {
                    "query_string": {
                        "query": "gdk OR plugin OR ios",
                        "fields": ["solution"]
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "yyyy-MM-dd HH:mm:ss",
                            "gte": "{start}",
                            "lte": "{end}"
                        }
                    }
                }
            ],
            "must_not": [{
                "query_string": {
                    "query": "ip# OR user_id#",
                    "fields": ["full_result"]
                }
            }]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}

ANDROID_FLA_YES = {
    "_source": [
        "gc_transaction", "time", "operator_name",
        "username", "primary_source", "username", "time"
    ],
    "query": {
        "bool": {
            "should": [{
                    "bool": {
                        "must": [{
                                "match_phrase": {
                                    "gc_authorized": {
                                        "query": 1
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "solution": {
                                        "query": "android"
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "format": "yyyy-MM-dd HH:mm:ss",
                                        "gte": "{start}",
                                        "lte": "{end}"
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "applications.installed": {
                                        "query": "{process}"
                                    }
                                }
                            }
                        ],
                        "must_not": [{
                            "query_string": {
                                "query": "ip# OR user_id#",
                                "fields": ["full_result"]
                            }
                        }]
                    }
                },
                {
                    "bool": {
                        "must": [{
                                "match_phrase": {
                                    "gc_authorized": {
                                        "query": 1
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "solution": {
                                        "query": "android"
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "format": "yyyy-MM-dd HH:mm:ss",
                                        "gte": "{start}",
                                        "lte": "{end}"
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "applications.mocked": {
                                        "query": "{process}"
                                    }
                                }
                            }
                        ],
                        "must_not": [{
                            "query_string": {
                                "query": "ip# OR user_id#",
                                "fields": ["full_result"]
                            }
                        }]
                    }
                },
                {
                    "bool": {
                        "must": [{
                                "match_phrase": {
                                    "gc_authorized": {
                                        "query": 1
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "solution": {
                                        "query": "android"
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "format": "yyyy-MM-dd HH:mm:ss",
                                        "gte": "{start}",
                                        "lte": "{end}"
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "applications.running": {
                                        "query": "{process}"
                                    }
                                }
                            }
                        ],
                        "must_not": [{
                            "query_string": {
                                "query": "ip# OR user_id#",
                                "fields": ["full_result"]
                            }
                        }]
                    }
                }
            ]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}

ANDROID_FLA_NO = {
    "_source": [
        "gc_transaction", "time", "operator_name",
        "username", "primary_source", "username", "time"
    ],
    "query": {
        "bool": {
            "should": [
                {
                    "bool": {
                        "must": [{
                                "match_phrase": {
                                    "gc_authorized": {
                                        "query": 1
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "solution": {
                                        "query": "android"
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "format": "yyyy-MM-dd HH:mm:ss",
                                        "gte": "{start}",
                                        "lte": "{end}"
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "applications.mocked": {
                                        "query": "{process}"
                                    }
                                }
                            }
                        ],
                        "must_not": [{
                            "query_string": {
                                "query": "ip# OR user_id#",
                                "fields": ["full_result"]
                            }
                        }]
                    }
                },
                {
                    "bool": {
                        "must": [{
                                "match_phrase": {
                                    "gc_authorized": {
                                        "query": 1
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "solution": {
                                        "query": "android"
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "format": "yyyy-MM-dd HH:mm:ss",
                                        "gte": "{start}",
                                        "lte": "{end}"
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "applications.running": {
                                        "query": "{process}"
                                    }
                                }
                            }
                        ],
                        "must_not": [{
                            "query_string": {
                                "query": "ip# OR user_id#",
                                "fields": ["full_result"]
                            }
                        }]
                    }
                }
            ]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}

ANDROID_OTHER_YES = {
    "_source": [
        "gc_transaction", "time", "operator_name",
        "username", "primary_source", "username", "time"
    ],
    "query": {
        "bool": {
            "should": [{
                    "bool": {
                        "must": [{
                                "match_phrase": {
                                    "gc_authorized": {
                                        "query": 1
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "solution": {
                                        "query": "android"
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "format": "yyyy-MM-dd HH:mm:ss",
                                        "gte": "{start}",
                                        "lte": "{end}"
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "applications.installed": {
                                        "query": "{process}"
                                    }
                                }
                            }
                        ],
                        "must_not": [{
                            "query_string": {
                                "query": "ip# OR user_id#",
                                "fields": ["full_result"]
                            }
                        }]
                    }
                },
                {
                    "bool": {
                        "must": [{
                                "match_phrase": {
                                    "gc_authorized": {
                                        "query": 1
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "solution": {
                                        "query": "android"
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "format": "yyyy-MM-dd HH:mm:ss",
                                        "gte": "{start}",
                                        "lte": "{end}"
                                    }
                                }
                            },
                            {
                                "match_phrase": {
                                    "applications.running": {
                                        "query": "{process}"
                                    }
                                }
                            }
                        ],
                        "must_not": [{
                            "query_string": {
                                "query": "ip# OR user_id#",
                                "fields": ["full_result"]
                            }
                        }]
                    }
                }
            ]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}

ANDROID_OTHER_NO = {
    "_source": [
        "gc_transaction", "time", "operator_name",
        "username", "primary_source", "username", "time"
    ],
    "query": {
        "bool": {
            "must": [{
                    "match_phrase": {
                        "gc_authorized": {
                            "query": 1
                        }
                    }
                },
                {
                    "match_phrase": {
                        "solution": {
                            "query": "android"
                        }
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "yyyy-MM-dd HH:mm:ss",
                            "gte": "{start}",
                            "lte": "{end}"
                        }
                    }
                },
                {
                    "match_phrase": {
                        "applications.running": {
                            "query": "{process}"
                        }
                    }
                }
            ],
            "must_not": [{
                "query_string": {
                    "query": "ip# OR user_id#",
                    "fields": ["full_result"]
                }
            }]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}

TOTAL_USE_QUERY = {
    "_source": ["gc_transaction"],
    "query": {
        "bool": {
            "must": [{
                "range": {
                    "@timestamp": {
                        "format": "yyyy-MM-dd HH:mm:ss",
                        "gte": "{start}",
                        "lte": "{end}"
                    }
                }
            }]
        }
    },
    "aggs": {
        "1": {
            "cardinality": {
                "field": "username"
            }
        }
    }}


def customize_data(func):
    """
    Function customize impact report for every package
    """
    def swapper(*args, **kwargs):
        raw_data, file, useOption, style = func(*args, **kwargs)

        # Unless use wrapper return a dict data after scrooling
        if not useOption:
            return raw_data

        # Create a temporary list to  save data after proceeding
        raw_data_temp = []

        # Extract for Sig impact
        for data in raw_data:
            # Get request body from scroller
            request_body = data.get('request_body')

            # If package is SIG is exclude signature from request body
            if style in ['sig', 'authsig']:

                if style == 'sig':
                    sig = file.get('signature').lower()
                    pattern = f"//ps[contains(text(),'{sig}')]"

                    # Parse request body with the above pattern
                    elements = parse_xml(request_body, pattern)

                    # If signature we must follow algorthm version to check
                    # Whether with this sig if blocked
                    # will impact other process
                    algorithm_ver = file.get('algorithm_ver')
                    algorithm_ver = int(float(algorithm_ver))

                    # Create a list and loop each result after
                    # parsing in request body
                    parse_process = list()
                    for element in elements:
                        # Get list signatures after parsing request body
                        signatures = element.text.split(',')

                        # Get attribute process name
                        process_name = element.get('process_name')

                        index = algorithm_ver - 1
                        if sig == signatures[index]:
                            parse_process.append(process_name)

                else:
                    sig = file.get('author_signature').lower()
                    pattern = f"//app[@signature='{sig}']/text()"

                    parse_process = parse_xml(request_body, pattern)
                    parse_process = [
                        process_name
                        for process_name in parse_process
                        ]

                # Because we just care the different process name so
                # exclude process name is same as value in field executable
                executing_process = file.get('executable', '').lower()
                process_name = set(parse_process) - set([executing_process])

                # Update a string of processes into field process_name
                data.update({'process_name': ', '.join(list(process_name))})
                
                pattern = f"//ps[@process_name='{executing_process}']"
                parse_process = parse_xml(request_body, pattern)
                ps_tag = [
                    etree.tostring(ps).decode('UTF-8')
                    for ps in parse_process
                ]
                data.update({'ps_tag': ', '.join(ps_tag)})

                # Delete property request_body
                del data['request_body']

                # If after excluding have no process delete this scroll
                if not process_name:
                    continue

                # Append into temporary list
                raw_data_temp.append(data)

            # Else means packages are exe
            else:
                process_name = file.get('executable')
                data.update({'process_name': process_name})

                if style == 'wmi_exe':
                    pattern = f"//ps[@process_name='{process_name.lower()}']"
                    parse_process = parse_xml(request_body, pattern)

                    ps_tag = [
                        etree.tostring(ps).decode('UTF-8')
                        for ps in parse_process
                        ]

                    data.update({'ps_tag': ', '.join(ps_tag)})

                    raw_data_temp.append(data)
                    del data['request_body']
                else:
                    raw_data_temp = raw_data

        # Convert raw data with new version
        raw_data = raw_data_temp

        # Count total result
        total = len(raw_data)

        # Count distinct
        get_distinct = set([i.get('username') for i in raw_data])
        total_distinct = len(get_distinct)

        return raw_data, file, total, total_distinct

    return swapper


def parse_xml(xml: str, pattern: str):
    """
    Function parse xml by a pattern
    """
    formated_xml = xml.lower().encode('UTF-8')
    doc = etree.fromstring(formated_xml)
    return doc.xpath(pattern)


class ImpactReport:
    def __init__(self, cwd):
        self.CWD = cwd
        self.ELK_CONFIG = self.get_kibana_account()

    def get_path(self, destination: str) -> str:
        """
        fucntion get absolute path to
        current working directory
        and file inside here
        """
        return os.path.join(self.CWD, destination)

    def get_kibana_account(self):
        """
        Function get kibana configuration in local environment
        -> return a elasticsearch config
        """
        # With local environment get content of
        # kibana configuration in .credential directory
        home_path = os.path.expanduser("~")
        kibana_key = os.path.join(home_path, '.credentials/kibana.json')

        # Open file kibana.json to get configuration
        with open(kibana_key, 'r') as kibana:
            str_content = kibana.read()
            json_content = json.loads(str_content)

            # Get attribute general connection string
            connecttion_string = json_content.get('connecttion_string')

            # https auth in local env
            http_auth = json_content.get('http_auth')
            user_name = http_auth.get('userName')
            password = http_auth.get('password')

        # Get configuration
        elk_config = Elasticsearch(
            hosts=[connecttion_string],
            http_auth=(user_name, password),
            use_ssl=True
            )
        
        return elk_config

    def categorize(self, folder: str) -> dict:
        """
        Return a list of sig jsons and a list of exe jsons
        Read the content in the __super__.json file
        SIG: if "_SIG_" in title each json,
        EXE: if "_SIG_" not in title each json
        Each SIG json path, read the file
        and parse the content to get signature and os
        """

        # Initialize object to store sig
        group = {'sig_list': [], 'exe_list': [], 'authsig_list': []}

        # Open file supper json to get content
        with open(folder + '/__super__.json', 'r') as super_file:
            super_data = json.load(super_file)

        # Scan every file in super file to get file name of json file
        for child in super_data:

            # Get file name in super file
            file_name = child.get('files')[0]
            title = child.get('title')

            # Open this file to get content
            file_path = os.path.join(folder, file_name)
            json_file = open(file_path, 'r')

            # Load data and update to
            json_data = json.load(json_file)
            child.update(json_data)

            # We have 3 main group for package
            if '_SIG_' in title:
                group['sig_list'].append(child)
            elif '_AUTHSIG_' in title:
                group['authsig_list'].append(child)
            else:
                try:
                    child['executable'] = child['process_name']
                except:
                    raise ValueError(f"Not found field process name in {title}")
                group['exe_list'].append(child)
        return group

    def run_elk_query(self, query: str, envs: list = None,
                      get_scroller: bool = False,
                      get_aggs: bool = False) -> dict:
        """
        Function return a dict with:
        Key: Name of env,
        Value: a list [total_record, scroller]
        """
        search_result = []
        # If not submit a list envs -> get default as geocomply indexs
        if not envs:
            envs = ENVS

        query = eval(query)

        for env in envs:
            index_pattern = f'geocomply-{env}*'

            overall_search = self.ELK_CONFIG.search(
                index=index_pattern,
                body=query,
                size=1,
                scroll='1m'
            )
            total_record = overall_search['hits']['total']['value']

            print('--------------')
            print(query)
            print(env)
            print(total_record)
            print('--------------')

            if get_scroller:
                scroller = scan(
                    self.ELK_CONFIG,
                    query,
                    index=index_pattern,
                    size=500, scroll='5m',
                    clear_scroll=True
                    )
            else:
                scroller = None

            if get_aggs and overall_search.get('aggregations'):
                aggs_value = overall_search['aggregations']['1']['value']
            else:
                aggs_value = 0

            search_result.append({
                "env": env,
                "total_record": total_record,
                "scroller": scroller,
                "aggs_value": aggs_value
            })

        return search_result

    @customize_data
    def scroll_elk_data(self, generator_obj, file: dict,
                        use_option: bool = False,
                        style: str = None) -> set:

        """
        Function get a generator object of ELS
        Scroll and return a value in field _source
        """
        result = []
        for row in generator_obj['scroller']:
            _source = row['_source']
            result.append(_source)
        return result, file, use_option, style

    def proceed_impact(self, file: dict,
                       query: str, style: str) -> dict:
        impact_result = {}
        # Run search for all environments
        search_result = self.run_elk_query(
            query, get_scroller=True, get_aggs=True
            )

        # Loop each result when query in each env
        for result in search_result:
            env = result.get('env')
            total_record = result.get('total_record')
            total_distinct = result.get('aggs_value')

            # In case total record > 1000 we will not check
            if total_record >= 10000:
                detail = [{'WARNING': WARNING_MSG}]
                total = total_record
            else:
                detail, _, total, total_distinct = self.scroll_elk_data(
                    result, file, use_option=True, style=style
                    )

            # Impact too impact with pass this case
            impact_result[env] = {
                'detail': detail,
                'total': total,
                'total_distinct': total_distinct
            }
        return impact_result

    def get_exe_query(self, file: dict) -> set:
        """
        Function choose ELS query for suitable OS
        """
        # Get operating system from file
        os = file.get('os')

        if os in ['win', 'mac', 'ios']:
            query = str(WMI_EXE_QUERY)
            style = 'wmi_exe'

        elif os == 'android':

            _type_ = file.get('type', 'OTHER').upper()
            is_installed = file.get('check_installed_packages', 'NO').upper()

            if _type_ == 'FLA':
                if is_installed == 'YES':
                    query = str(ANDROID_FLA_YES)
                else:
                    query = str(ANDROID_FLA_NO)
            else:
                if is_installed == 'YES':
                    query = str(ANDROID_OTHER_YES)
                else:
                    query = str(ANDROID_OTHER_NO)

            style = 'android_exe'

        else:
            query = style = ''

        return query, style

    def run_exe_impact(self, files: dict, start_date: str,
                       end_date: str) -> dict:
        """
        Function run impact report for file EXE
        """
        master_result = {}
        # Run every file on dispatch to suitable function
        for file in files:
            # Get some basic info
            title = file.get('title')
            els_query, style = self.get_exe_query(file)
            process_name = file.get('executable').lower()
            
            # Create param for query
            query_param = (
                ('{process}', process_name),
                ('{start}', start_date),
                ('{end}', end_date)
            )

            # Fill param in query
            for param in query_param:
                els_query = els_query.replace(*param)

            master_result[title] = self.proceed_impact(file, els_query, style)
        return master_result

    def run_sig_impact(self, files: dict, start_date: str,
                       end_date: str) -> dict:
        """
        Function run impact report for file SIG
        """
        master_result = {}
        # Run every file on dispatch to suitable function
        for file in files:
            # Get some basic info
            style = 'sig'
            title = file.get('title')
            signature = file.get('signature').lower()
            els_query = str(WM_SIG_QUERY)
            
            # Create param for query
            query_param = (
                ('{sig}', signature),
                ('{start}', start_date),
                ('{end}', end_date)
            )
            for param in query_param:
                els_query = els_query.replace(*param)

            # Proceed impact report
            master_result[title] = self.proceed_impact(file, els_query, style)

        return master_result

    def run_authsig_impact(self, files: dict,
                           start_date: str, end_date: str) -> dict:
        """
        Function run impact report for file AUTHOR SIG
        """
        master_result = {}
        # Run every file on dispatch to suitable function
        for file in files:

            # Get some basic info
            style = 'authsig'
            title = file.get('title')
            author_signature = file.get('author_signature')
            els_query = str(WM_AUTHSIG_QUERY)
            
            # Create param for query
            query_param = (
                ('{authsig}', author_signature),
                ('{start}', start_date),
                ('{end}', end_date)
            )
            for param in query_param:
                els_query = els_query.replace(*param)

            master_result[title] = self.proceed_impact(file, els_query, style)
        return master_result

    def get_total_user(self, start_date: str, end_date: str) -> dict:
        """Function caculate all user may be impacted """
        els_query = str(TOTAL_USE_QUERY)

        els_query = els_query.replace(
            '{start}', start_date
            )

        els_query = els_query.replace(
            '{end}', end_date
            )

        result = self.run_elk_query(
            els_query, get_aggs=True
            )

        return result

    def merge_data(self, files: list, impact_data: dict) -> list:
        """Merge impact result for exact this file"""
        for file in files:
            # Get title of this file
            title = file.get('title')

            # Get impact result of this file
            merge_data = impact_data.get(title)

            # Merge to this object
            file.update({"impact_data": merge_data})

            # Get process status of this file
            active_status = file.get('active_status', '')
            process_status = PROCESS_STATUS.get(active_status, '')
            file['process_status'] = process_status

        return files

    def make_json_sheet(self, data):
        """Get basic information for json sheet"""
        result = {
            'OS': data.get('os', ' '),
            'Type': data.get('type', ' '),
            'Signature': data.get('author_signature',
                                  data.get('signature', ' ')
                                  ),
            'Process Name': data.get('executable', ' '),
            'Title': data.get('title', ' '),
            'Type of Process Name': data.get('active_status', ' '),
            'Note': data.get('process_status',),
        }

        impact_data = data.get('impact_data')
        for env in impact_data:
            result.update({env: impact_data[env].get('total')})
        return result

    def make_basic_info(self, data):
        result = {
            "File": data.get('title', ''),
            "Process Name": data.get('executable', ''),
            "Signature": data.get('author_signature',
                                  data.get('signature', '')
                                  )
        }
        df = pd.DataFrame.from_dict(result, orient='index')
        return df

    def make_sumary_info(self, data, user_data):
        result = {
            "Env": [
                "Total number of Transactions for the period: ",
                "Number of potential blocked Transactions:",
                "% of Transactions:",
                "Total number of Users for the period: ",
                "Number of potential blocked Users:",
                "% of Users:"
            ]
        }
        for element in user_data:

            current_env = element.get('env')
            elk_pattern = f'geocomply-{current_env}'
            impact_data = data['impact_data'][current_env]

            # Total number of Transactions for the period
            total_transaction = element.get('total_record', 0)

            # Number of potential blocked Transactions:
            count_in_env = impact_data.get('total', 0)

            # Total number of Users for the period:
            total_user = element.get('aggs_value', 0)

            # Number of potential blocked Users:
            total_unique_user = impact_data.get('total_distinct', 0)

            # % of Transactions:
            transaction_percentage = 0
            if total_transaction:
                transaction_percentage = count_in_env / total_transaction

            # % of Users:
            user_percentage = 0
            if total_user:
                user_percentage = total_unique_user / total_user

            result.update({
                elk_pattern: [
                    total_transaction,
                    count_in_env,
                    transaction_percentage,
                    total_user,
                    total_unique_user,
                    user_percentage
                ]
            })

        df = pd.DataFrame.from_dict(result)
        return df

    def make_file_name(self, path: str) -> str:
        # Because folder input can be
        # a path so must get the last word
        split_name = path.split('/')
        return split_name[-1]

    def make_report(self, files: list, user_data: dict, **kwargs):
        """
        Function make a report after receiving alll data
        """
        # Create file name
        file_name = self.make_file_name(kwargs.get('xlsx_name'))
        filename = self.get_path(
            'Impact_Report_{}_{}_{}.xlsx'
            .format(file_name,
                    (kwargs['start_date']).split(' ')[0],
                    (kwargs['end_date']).split(' ')[0]
                    ))

        # Start a excel instance
        writer = pd.ExcelWriter(filename, engine='xlsxwriter')

        # Create workbook for edit file
        workbook = writer.book

        # Create a border format for report
        border_format = workbook.add_format()
        border_format.set_border(1)

        # Header of sheet JSON
        json_sheet_content = []

        initial_json_sheet = pd.DataFrame([])
        initial_json_sheet.to_excel(writer, sheet_name='Json File')
        for index, content in enumerate(files):
            # Colect data from file json
            json_sheet_content.append(self.make_json_sheet(content))

            sheet_name = str(index + 1)

            # The first three rows is stored data of title,
            # executable and signature
            basic_info = self.make_basic_info(content)
            basic_info.to_excel(
                writer, sheet_name=sheet_name,
                header=False
                )
            print(basic_info)

            # Insert information of any env
            sumery_info = self.make_sumary_info(content, user_data)
            sumery_info.to_excel(
                writer, sheet_name=sheet_name,
                index=False, startrow=5
                )
            print(sumery_info)

            start_row = 13
            # # Detail information
            for key, value in content.get('impact_data').items():

                # If this env is empty ->> pass
                if not len(value.get('detail')):
                    continue

                section = pd.DataFrame([{'title': key.upper()}])
                detail = pd.DataFrame(value.get('detail'))

                section.to_excel(writer, sheet_name=sheet_name,
                                 header=False, index=False, startrow=start_row)
                detail.to_excel(writer, sheet_name=sheet_name,
                                index=False, startrow=start_row + 1)
                start_row = start_row + section.shape[0] + detail.shape[0] + 3

        # Make Json sheet
        df = pd.DataFrame(json_sheet_content)
        cols_to_order = [
            'OS', 'Type', 'Signature', 'Process Name',
            'Title', 'Type of Process Name', 'Note'
            ]
        new_columns = cols_to_order + (df.columns.drop(cols_to_order).tolist())
        df = df[new_columns]
        df.to_excel(writer, sheet_name='Json File', index=False)

        # Formating after create a primary report
        json_sheet = writer.sheets['Json File']
        for index, content in enumerate(json_sheet_content):

            # Add hyper link for JSON sheet
            this_sheet = str(index+1)

            # Create hyperlink for json sheet
            json_sheet.write_url(
                index + 1, 4,
                url="internal:{}!A1".format(this_sheet),
                string=content.get("Title")
                )

            # Get decoration
            decoration = writer.sheets[this_sheet]

            # Adjust column
            decoration.set_column('A:Z', 30)
            decoration.conditional_format(
                "A1:Z10000",
                {
                    'type': 'no_blanks',
                    'format': border_format
                    })

            # Add hyper link for element sheet
            decoration.write_url(
                0, 2,
                url="internal:'Json File'!A1",
                string='JSON FILE')

            # Format percentage for row show percentage
            percentage_format = workbook.add_format(
                {
                    'num_format': '0.000000%;[Red]-0.00%'
                    }
                )
            decoration.set_row(8, None, percentage_format)
            decoration.set_row(11, None, percentage_format)

        # Format json sheet
        json_sheet.set_column("A:G", 30)

        # Create fo
        format_value = workbook.add_format({
            'bg_color': '#FFC7CE',
            'font_color': '#9C0006',
            'border': 1
            })

        # Format if have value impact
        json_sheet.conditional_format(
            'H2:P10000', {
                'type': 'cell',
                'criteria': '>',
                'value': 0,
                'format':  format_value}
                )

        # Format json sheet
        json_sheet.conditional_format(
            "A1:P{}".format(str(len(json_sheet_content)+1)),
            {
                'type': 'no_blanks',
                'format': border_format
                })
        
        # Format json sheet
        json_sheet.conditional_format(
            "A1:P{}".format(str(len(json_sheet_content)+1)),
            {
                'type': 'blanks',
                'format': border_format
                })
        
        
        # Format for duplicate signatures
        duplicate_format = workbook.add_format({
                                'bg_color': '#ECE62C',
                                'font_color': '#4F4507'
                                })
        duplicate_range = "C2:C{}".format(str(len(json_sheet_content)+1))
        print(duplicate_range)
        json_sheet.conditional_format(
            duplicate_range,
            {
                'type': 'duplicate',
                'format':duplicate_format
            })

        writer.save()
        writer.close()

    def main(self, folder: str, start_date: str, end_date: str):
        print('Start Impact Report')
        # Categorize file .json
        categoried_dict = self.categorize(folder)
        sig_files = categoried_dict.get('sig_list')
        exe_files = categoried_dict.get('exe_list')
        authsig_files = categoried_dict.get('authsig_list')

        # Run impact report for each kind of file
        executor = ThreadPoolExecutor(max_workers=4)

        # Submit function to pool
        sig_impact_result = {}
        if sig_files:
            sig_impact_run = executor.submit(
                self.run_sig_impact, sig_files,
                start_date, end_date
                )

        exe_impact_result = {}
        if exe_files:
            exe_impact_run = executor.submit(
                self.run_exe_impact, exe_files,
                start_date, end_date
                )

        authsig_impact_result = {}
        if authsig_files:
            run_authsig_run = executor.submit(
                self.run_authsig_impact, authsig_files,
                start_date, end_date
            )

        # Run user data in this period
        print('\nGet user in period {} - {}'.format(start_date, end_date))
        user_data_run = executor.submit(
            self.get_total_user, start_date, end_date)

        # Get all result
        user_data = user_data_run.result()
        if sig_files:
            sig_impact_result = sig_impact_run.result()
        if exe_files:
            exe_impact_result = exe_impact_run.result()
        if authsig_files:
            authsig_impact_result = run_authsig_run.result()
        
        print("Merge all impact results")
        # Get all file
        files = [*sig_files, *exe_files, *authsig_files]

        # Merge result after check sig and exe
        impact_data = {
            **sig_impact_result,
            **exe_impact_result,
            **authsig_impact_result
            }
        
        print("Merge data")
        # Merge to original file
        files = self.merge_data(files, impact_data)
        
        print("Make report")
        # Make report
        self.make_report(
            files=files,
            user_data=user_data, xlsx_name=folder,
            start_date=start_date, end_date=end_date
            )
        return 0


def adjust_date(str_date: str) -> str:
    try:
        adjust = datetime.strptime(str_date, '%Y-%m-%d')
    except Exception as e:
        print(e)
        adjust = datetime.strptime(str_date, '%Y-%m-%d %H:%M:%S')

    return adjust


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Please input parametters.')

    parser.add_argument('folder', help="AF-1300, AF-1360, ...")

    parser.add_argument('-f', '--start_date', help="YYYY-MM-DD",
                        required=True, default="")

    parser.add_argument('-t', '--end_date', help="YYYY-MM-DD",
                        required=True, default="")

    args = parser.parse_args()

    cwd = os.getcwd()
    new_report = ImpactReport(cwd)

    folder = os.path.join(cwd, args.folder)
    start_date = adjust_date(args.start_date).strftime('%Y-%m-%d 00:00:00.000000')
    end_date = adjust_date(args.end_date).strftime('%Y-%m-%d 23:59:59.999999')

    new_report.main(
        folder=folder,
        start_date=start_date,
        end_date=end_date
        )
