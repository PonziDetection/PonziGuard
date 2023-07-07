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

Prepare your pretrained Doc2vec model in `./tools/PonziGuard/CRBG/model/yourModel`

### <u>Run</u>

Build the source of the instrumented Geth

```shell
cd ./tools/PonziGuard/geth_detect
make geth
```

Run the instrumented Geth 

```shell
./tools/PonziGuard/geth_detect/build/bin/geth --identity "TestNode2" --rpc -rpcaddr "0.0.0.0"  --rpcport "8545" --rpccorsdomain "*" --port "30303" --nodiscover  --rpcapi "db,eth,net,web3,miner,net,personal,net,txpool,admin"  --networkid 1900   --datadir "../ChainData" --nat "any"   --unlock 0 --password "./ChainData/pwd.txt"  --mine --allow-insecure-unlock --rpc.allow-unprotected-txs
```

Deploy under-tested smart contracts in the private chain manually or by following the guidance of Contractfuzzer.

After deploying the smart contracts within the private chain, you also need to prepare the directory for the smart contracts. 

```shell
tested_contract
    verified_contract_abis
    verified_contract_bins
    verified_contract_abi_sig  (function signature from contract's abi)
    verified_contract_bin_sig  (function signature pairs from contract's bin)
    fuzzer
        config
            IntSeeds.json
            UintSeeds.json
            ....
            contracts.list
            addr_map.csv
```

Invoke the smart contracts or replay the historical transactions in `./tools/PonziGuard/ChainData` to generate CRBG of smart contracts.

```shell
cd ./tools/PonziGuard/ContractFuzzer && ./run.sh --contracts_dir ./tested_contract
```

```shell
#in Geth console
debug.traceBlockBynumber("BlockNumber")
```

Taint Engine in `./tools/PonziGuard/taint_engine` will marks and tracks the propagation paths of sensitive data in contracts and construct Contract Runtime Behavior Graph in `./tools/PonziGuard/CRBG`.

The output of raw graphs is in `./tools/PonziGuard/CRBG/CRBG_output_onehot`, to complete the CRBG  construction, run:

```shell
cd ./tools/PonziGuard/CRBG
python -u CRBG.py
```

The CRBG output is in `./tools/PonziGuard/CRBG/CRBG_output`.