# py_exporter
## **This repository is not intended for General use.**
Use: `python3.8`  
Install requirement: `python3.8 -m pip install -r requirement.txt`  
To start usage: `./exporter.py [<port>]`  
Before start you must create config file: `auth.conf.yaml`  
And add config:
```
blockcypher-dev:
  token: '<TOKEN>'
blockcypher-stage:
  token: '<TOKEN>'
blockcypher-prod:
  token: '<TOKEN>'
btc_node_testnet:
  basic: '<Basic Auth>'
  host: '<Host>'
btc_node_mainnet:
  basic: '<Basic Auth>'
  host: '<Host>'
kubernetes_stage:
  context: '<GKE Context>'
  hostname: '<Text>'
  namespace: '<Namespace>'
kubernetes_production:
  context: '<GKE Context>'
  hostname: '<Text>'
  namespace: '<Namespace>'
```
