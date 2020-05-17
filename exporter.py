#!/usr/bin/env python3
"""
Very simple HTTP server in python for logging requests
Usage::
    ./server.py [<port>]
"""
from requests import get, post
from json import loads
from time import time, strftime
from http.server import BaseHTTPRequestHandler, HTTPServer
from logging import basicConfig, info, INFO
from yaml import safe_load
str_time = "%d/%B/%Y, %H:%M:%S"

def print_metric(message, metric="bash exporter metrics", gauge="gauge", result=None):
    message = str(message)
    result = str(result)
    answer = '# HELP ' + message + ' ' + metric + '\n' + '# TYPE ' + message + ' ' + gauge + '\n' + message + ' ' + result
    return answer

def auth_conf(Field):
    with open(auth_file) as conf:
        data = safe_load(conf.read().encode('utf-8'))
    return data[Field]

def blockcypher(env):
    hname = "api.blockcypher.com"
    job = "api_request_limits"
    verb = "limit_hour"
    verb_time = "answer_time"
    bc_token = auth_conf(env)['token']
    bc_url = 'https://api.blockcypher.com/v1/tokens'

    start_time = time()
    with get(bc_url + '/' + bc_token, timeout=5) as w:
        data = loads(w.text)
    last_time = time() - start_time
    limits = data['limits']['api/hour']
    try:
        hits = data['hits']['api/hour']
    except:
        hits = 0
    last_hits = limits - hits
    message = str('bcypher{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="' + verb + '"}')
    mess_time = str('bcypher{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="' + verb_time + '"}')
    metr_1 = print_metric(message=message, result=last_hits)
    metr_2 = print_metric(message=mess_time, result=last_time)
    return metr_1 + '\n' + metr_2 + '\n'

def btc_disk(env, stage='stage', **kwargs):
    from kubernetes.config import load_kube_config
    from kubernetes.client import CoreV1Api
    from kubernetes.stream import stream
    from os import environ
    hname = auth_conf('kubernetes_' + stage)['hostname']
    job = "Bitcoin_Status"
    key_list = []
    value_list = []
    for key, value in kwargs.items():
        key_list.append(key)
        value_list.append(value)
    environ["GOOGLE_APPLICATION_CREDENTIALS"] = '/root/gke.json'
    load_kube_config(context=auth_conf('kubernetes_' + stage)['context'])
    v1 = CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=auth_conf('kubernetes_' + stage)['namespace'])
    for pod in pods.items:
        if len(kwargs) == 2:
            if pod.metadata.labels[key_list[0]] == value_list[0] and pod.metadata.labels[key_list[1]] == value_list[1]:
                bitcoin_pod = pod.metadata.name
        elif len(kwargs) == 1:
            if pod.metadata.labels[key_list[0]] == value_list[0]:
                bitcoin_pod = pod.metadata.name
        else:
            return 'Only 2 kwargs.'
    exec_command = ['/bin/sh', '-c', 'df --output=size,avail /opt/bitcoind |tail -1']
    exec_answer = stream(v1.connect_get_namespaced_pod_exec, bitcoin_pod, 'default',
                         command=exec_command, stderr=True, stdin=False, stdout=True, tty=False)
    disk_0, disk_1 = exec_answer.split()
    answer_0 = print_metric('btc{env="'+ env + '",hostname="' + hname + '",job="' + job + '",verb="disk_kb"}', result=disk_0)
    answer_1 = print_metric('btc{env="'+ env + '",hostname="' + hname + '",job="' + job + '",verb="disk_avail_kb"}', result=disk_1)
    return answer_0 + '\n' + answer_1 + '\n'

def btc_currency():
    env = "Bitcoin_Currency"
    hname = "min-api.cryptocompare.com"
    job = "Bitcoin_Currency_Status"
    params = {'fsym': 'BTC', 'tsyms': 'USD,RUB,THB'}
    req = get(url='https://min-api.cryptocompare.com/data/price', params=params, timeout=5)
    response = loads(req.content)
    response['status_code'] = req.status_code
    req.close()
    btcusdc = response['USD']
    btcrub = response['RUB']
    btcthb = response['THB']
    answer = []
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="btcusdc"}', result=btcusdc) + '\n')
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="btcrub"}', result=btcrub) + '\n')
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="btcthb"}', result=btcthb) + '\n')
    return answer[0] + answer[1] + answer[2]

def btc(chain="testnet"):
    hname = auth_conf(Field='btc_node_' + chain)['host']
    env="Node-" + chain
    job = "Bitcoin_Status"
    verb_1 = chain + "_node"
    verb_2 = "request_time"
    verb_3 = "blocks"
    verb_4 = "head"
    verb_5 = "difference"
    verb_6 = "answer"
    verb_7 = "remote_answer"
    if chain == 'testnet':
        r_site = "api.bitaps.com"
        RemoteURL = "https://" + r_site + "/btc/" + chain + "/v1/blockchain/block/last"
        params = {}
    if chain == 'mainnet':
        r_site = "insight.bitpay.com"
        RemoteURL = "https://" + r_site + "/api/status"
        params = {'q': 'getBlockCount'}

    URL = "https://" + hname + ":443"
    BASIC = {'Authorization': 'Basic ' + auth_conf(Field='btc_node_' + chain)['basic'], 'accept': '*/*'}
    DATA_BINARY = {'jsonrpc': '1.0', 'id': 'curltext', 'method': 'getblockchaininfo', 'params': []}

    start_time = time()
    try:
        answer = post(url=URL, timeout=5, json=DATA_BINARY, headers=BASIC)
    except:
        pass

    end_time = time() - start_time
    try:
        status_code = answer.status_code
        resp = loads(answer.content)
        answer.close()
        item = 1
    except:
        status_code = 504
        item = 0

    try:
        remote_request = get(RemoteURL, timeout=5, params=params)
        remote_answer = loads(remote_request.content)
        remote_code = remote_request.status_code
        remote_request.close()
        if chain == 'testnet':
            remote_headers = remote_answer['data']['block']['height']
        if chain == 'mainnet':
            remote_headers = remote_answer['info']['blocks']
        rem_req = False
    except:
        remote_headers = 0
        remote_code = 504
        rem_req = True

    try:
        blocks = resp['result']['blocks']
        req = resp['result']['initialblockdownload']
    except:
        blocks = 0
        req = True

    if remote_headers and blocks:
        difference = blocks - remote_headers
    else:
        remote_headers = -1
        difference = -1

    answer = []
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="' + verb_1 + '"}', result=item) + '\n')
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="' + verb_2 + '"}', result=end_time) + '\n')
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="' + verb_3 + '"}', result=blocks) + '\n')
    answer.append(print_metric('btc{env="api.bitaps.com",hostname="api.bitaps.com",job="' + job + '",verb="' + verb_4 + '"}', result=remote_headers) + '\n')
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="' + verb_5 + '"}', result=difference) + '\n')
    answer.append(print_metric('btc{env="' + env + '",hostname="' + hname + '",job="' + job + '",verb="' + verb_6 + '"}', result=status_code) + '\n')
    answer.append(print_metric('btc{env="api.bitaps.com",hostname="api.bitaps.com",job="' + job + '",verb="' + verb_7 + '"}', result=remote_code) + '\n')

    if not req and status_code == 200:
        if not rem_req:
            return answer[0] + answer[1] + answer[2] + answer[3] + answer[4] + answer[5] + answer[6]
        else:
            return answer[0] + answer[1] + answer[2] + answer[5] + answer[6]
    elif not rem_req:
        return answer[0] + answer[1] + answer[3] + answer[5] + answer[6]
    else:
        return answer[0] + answer[1] + answer[5] + answer[6]

#------------------------------------------------------------------------------------------------------------------

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        if self.path == '/bcypher_dev':
            self.data_bcypher_dev = blockcypher(env="blockcypher-dev")
            self.content_length = len(self.data_bcypher_dev)
        elif self.path == '/bcypher_stage':
            self.data_bcypher_stage = blockcypher(env="blockcypher-stage")
            self.content_length = len(self.data_bcypher_stage)
        elif self.path == '/bcypher_prod':
            self.data_bcypher_prod = blockcypher(env="blockcypher-prod")
            self.content_length = len(self.data_bcypher_prod)
        elif self.path == '/btc_disk_testnet':
            self.data_btc_disk_testnet = btc_disk(env="Node-testnet", stage='stage', app='btccore-testnet-node', release='bitcoincore-testnet-node')
            self.content_length = len(self.data_btc_disk_testnet)
        elif self.path == '/btc_disk_mainnet':
            self.data_btc_disk_mainnet = btc_disk(env="Node-mainnet", stage='production', release='bitcoincore-mainnet-node')
            self.content_length = len(self.data_btc_disk_mainnet)
        elif self.path == '/btc_currency':
            self.data_btc_currency = btc_currency()
            self.content_length = len(self.data_btc_currency)
        elif self.path == '/btc_node_testnet':
            self.data_btc_testnet = btc(chain="testnet")
            self.content_length = len(self.data_btc_testnet)
        elif self.path == '/btc_node_mainnet':
            self.data_btc_mainnet = btc(chain="mainnet")
            self.content_length = len(self.data_btc_mainnet)
        else:
            self.data = b'Out of range\nUse:\n/bcypher_dev\n/bcypher_stage\n/bcypher_prod\n/btc_disk_testnet\n' \
                        b'/btc_disk_mainnet\n/btc_currency\n/btc_node_testnet\n/btc_node_mainnet\n'
            self.content_length = len(self.data)
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', self.content_length)
        self.send_header('Connection', 'close')
        self.end_headers()

    def do_GET(self):
        if self.path == '/bcypher_dev':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_bcypher_dev.encode('utf-8'))
        elif self.path == '/bcypher_stage':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_bcypher_stage.encode('utf-8'))
        elif self.path == '/bcypher_prod':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_bcypher_prod.encode('utf-8'))
        elif self.path == '/btc_disk_testnet':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_btc_disk_testnet.encode('utf-8'))
        elif self.path == '/btc_disk_mainnet':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_btc_disk_mainnet.encode('utf-8'))
        elif self.path == '/btc_currency':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_btc_currency.encode('utf-8'))
        elif self.path == '/btc_node_testnet':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_btc_testnet.encode('utf-8'))
        elif self.path == '/btc_node_mainnet':
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data_btc_mainnet.encode('utf-8'))
        else:
            info("[%s], GET request, Path: %s Headers: %s", strftime(str_time), str(self.path), str(self.headers).replace('\n', ' '))
            self._set_response()
            self.wfile.write(self.data)

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data.decode('utf-8'))

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=9095):
    basicConfig(level=INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    info('[%s], Starting httpd...', strftime(str_time))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    info('[%s], Stopping httpd...', strftime(str_time))

if __name__ == '__main__':
    from sys import argv
    from os import path
    from sys import exit as sys_exit
    auth_file = 'auth.conf.yaml'
    from os import geteuid
    if not geteuid() == 0:
        sys_exit("\nOnly root can run this script\n")
    if not path.isfile(auth_file):
        sys_exit("\nFile " + auth_file + " not exist\n")
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        try:
            run()
        except:
            pass
