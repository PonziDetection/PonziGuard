# pip install solc-py-x, slither-analyzer, web3

import solcx.version
from web3 import Web3
from solc_select.solc_select import(
    install_artifacts,
    installed_versions,
    switch_global_version
)

import os
import json
import time
import re
import solcx
import argparse
import ContractAnalyzer
import TransactionSequenceGeneration

def cli_args():
    parser = argparse.ArgumentParser(
        description='help',
        usage='\n  input sol file dir path'
    )

    parser.add_argument(
        '-p', '--path',
        type=str,
        help='Sol file dir path'
    )

    return parser.parse_args()

def compare_version(version_1, version_2):
    """
        compare version
    """
    v1 = version_1.split('.')
    v2 = version_2.split('.')
    if int(v1[1]) > int(v2[1]):
        return version_1
    elif int(v1[1]) == int(v2[1]) and int(v1[2]) > int(v2[2]):
        return version_1
    else:
        return version_2

def get_solc_version(code):
    """
        get solidity version from code
    """
    min_version = '0.4.11'
    try:
        version = re.findall(r'pragma\ssolidity\s*\D*(\d+\.\d+\.\d+)', code)[0]
    except:
        print('use minimum version that works')
        return min_version

    # for version in versions:
        # min_version = compare_version(min_version, version.groups()[0])
    min_version = compare_version(min_version, version)


    return min_version

def deploy(filename: str, file_path: str, w3: Web3):
    try:
        with open(file_path) as f:
            text = f.read()
        
        version = get_solc_version(text)
        if not version in installed_versions():
            install_artifacts(version)
        
        switch_global_version(version, True)

        if not version in [v.public for v in solcx.get_installed_solc_versions()]:
            solcx.install_solc(version)

        constructor = TransactionSequenceGeneration.getTransactionSequence(filename, ContractAnalyzer.analyze_contract(file_path), 1)

        contract_id, contract_interface = solcx.compile_files(
            source_files = file_path,
            output_values = ['abi', 'bin'],
            solc_version = version
        ).popitem()
        with open(f"/home/lrc/PonziGuard/ponziback/tools/PonziGuard/Transaction_Generator/output/{filename}.abi", "w") as f:
            f.write(json.dumps(contract_interface['abi'], indent=4))
        
        if constructor != None:
            tx_hash = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin']).constructor(**constructor['randomParameterValues']).transact({'from': w3.eth.accounts[0], 'gas': 10000000})

        else:
            tx_hash = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin']).constructor().transact({'from': w3.eth.accounts[0], 'gas': 10000000})

        return tx_hash, contract_interface['abi']
    
    except Exception as e:
        print(e)
        return False

if __name__ == '__main__':
    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
    args = cli_args()
    path: str = args.path
    try:
        with open('/home/lrc/PonziGuard/ponziback/tools/PonziGuard/Transaction_Generator/contract.json', 'r') as f:
            if f.read != '':
                addr_contract: dict = json.loads(f.read())
            
            else:
                addr_contract = {}

    except:
        with open('/home/lrc/PonziGuard/ponziback/tools/PonziGuard/Transaction_Generator/contract.json', 'w') as f:
            pass

        addr_contract = {}

    deployed = list(addr_contract.keys())

    if w3.is_connected():
        # account that send tx
        account = w3.eth.accounts[0]

        print('------ test net has been connected ------')
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            prefix = filename.split('.')[0]
            if prefix in deployed:
                continue

            ############ Deploy contract ############
            try:
                tx_hash, abi = deploy(prefix, file_path, w3)
                time.sleep(10)
                address = w3.eth.get_transaction_receipt(tx_hash)['contractAddress']
                print(f' ------ Deploy Done ------\n{account} deploys a contract: {address}')
                with open('/home/lrc/PonziGuard/ponziback/tools/PonziGuard/Transaction_Generator/contract.json', 'w') as f:
                    addr_contract[prefix] = {'address': address, 'txn': []}
                    f.write(json.dumps(addr_contract, indent=4))

            except Exception as e:
                print(' ------ Deploy Fail ------ ')
                print(e.args[0])
                continue

            # example of sending tx
            # contract: Contract = w3.eth.contract(address=address, abi=abi)
            # tx = contract.functions[name_of_method_to_call](*args_of_method).transact({'from': account, 'gas': 2000000, 'gasPrice': '10000000'})

            ############ Send tx ############

            try:
                contract = w3.eth.contract(address=address, abi=abi)
                # load and build tx args
                with open(f"/home/lrc/PonziGuard/ponziback/tools/PonziGuard/Transaction_Generator/output/{prefix}.json", "r") as f:
                    tranSeq = json.loads(f.read())[prefix]

                for seq in tranSeq:
                    for tranItem in seq:
                        # full_name = tranItem["full_name"]
                        name = tranItem['name']
                        params = tranItem['parameters']
                        randomValueArray = [tranItem['randomParameterValues'][k] for k in params]

                        if tranItem['payable']:
                            # 
                            caller = {
                                'from': account,
                                'value': tranItem['value'],
                                'gas': 2000000,
                                'gasPrice': '10000000'
                            }
                            if name == 'fallback':
                                tx_hash: bytes = contract.fallback(*randomValueArray).transact(caller)
                            else:
                                tx_hash: bytes = contract.functions[name](*randomValueArray).transact(caller)
                        
                        else:
                            # 
                            caller = {
                                'from': account,
                                'gas': 2000000,
                                'gasPrice': '10000000'
                            }
                            if name == 'fallback':
                                tx_hash: bytes = contract.fallback(*randomValueArray).transact(caller)
                            else:
                                tx_hash: bytes = contract.functions[name](*randomValueArray).transact(caller)
                    
                        print(f' ------ Txn sent ------\nTxn: {tx_hash.hex()} sent from {account} to {address}')
                        with open('/home/lrc/PonziGuard/ponziback/tools/PonziGuard/Transaction_Generator/contract.json', 'w') as f:
                            addr_contract[prefix]['txn'].append(tx_hash.hex())
                            f.write(json.dumps(addr_contract, indent=4))

                        time.sleep(2)
            except Exception as e:
                print(' ------ tx send Fail ------ ')
                print(e.args[0])
                continue

    else:
        print('------ test net connecting failed ------')