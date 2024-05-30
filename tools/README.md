# PonziGuard

PonziGuard is an efficient Ponzi scheme detection approach based on contract runtime information and graph neural networks.

### <u>**Experiments on Gound-Truth Dataset**</u>

We conducted  experiments on a Gound-Truth Dataset and prove that PonziGuard is effective.

### <u>**Experiments in open environments**</u> 

We also conducted a preliminary experiment to verify the performance of PonziGuard in open environments.Using PonziGuard we have found 805 Ponzi contracts on Ethereum Mainnet in approximately 14,000,000 blocks, which have resulted in an estimated economic loss of 281,700 Ether or approximately $500 million USD.

### <u>Tool</u>

The code provided in `./tools` serves as a simple pipeline of PonziGuard.

The complete code will be open-sourced after the conference is hold.

### <u>Require</u>

Solidity Compiler

```shell
#install solc-select
pip install solc-select
#install solc
solc-select install [solc-version]
#switch the solc version 
solc-select use [solc-version]
```

Golang v1.16.6 or later

```shell
mkdir ~/go && cd ~/go
wget https://dl.google.com/go/go1.16.6.linux-amd64.tar.gz
tar -C /usr/local -zxvf  go1.16.6.linux-amd64.tar.gz
vim /etc/profile
# add export GOROOT=/usr/local/go, export PATH=$PATH:$GOROOT/bin
source /etc/profile
```

slither
```shell
python3 -m pip install slither-analyzer
```

Prepare your pretrained Doc2vec model in `./tools/PonziGuard/CRBG/model/yourModel`

### <u>Run</u>

Build the source of the instrumented Geth

```shell
cd ./tools/PonziGuard/geth_detect
make geth
```

Run the instrumented Geth 

```shell
geth --identity "TestNode2" --rpc -rpcaddr "0.0.0.0"  --rpcport "8545" --rpccorsdomain "*" --port "30303" --nodiscover  --rpcapi "db,eth,net,web3,miner,net,personal,net,txpool,admin"  --networkid 1900   --datadir "./private_data" --nat "any"   --unlock 0 --password "./private_data/pwd.txt"  --mine --allow-insecure-unlock --rpc.allow-unprotected-txs
```

Run the Geth console

```shell
cd private_data
geth attach ipc:geth.ipc
```

Deploy under-tested smart contracts in the private chain and generate transaction sequences to invoke the contracts.

```shell
cd Transaction_Generator/SourceCode
python3 deploy --path '/yourContractPath'
```

You can replay the historical transactions in Geth console.

```shell
debug.traceBlockBynumber("BlockNumber")
```

Taint Engine in `./tools/PonziGuard/taint_engine` will marks and tracks the propagation paths of sensitive data in contracts and construct Contract Runtime Behavior Graph in `./tools/PonziGuard/CRBG`.


The output of raw graphs is in `./tools/PonziGuard/CRBG/CRBG_output_onehot`, to complete the CRBG  construction, run:

```shell
cd ./tools/PonziGuard/CRBG
python  CRBG_process.py
```

The CRBG output is in `./tools/PonziGuard/CRBG/CRBG_output`.

### <u>Notice</u>
Some paths in the project need to be changed to match your own execution environment.