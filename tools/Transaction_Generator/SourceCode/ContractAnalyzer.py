import slither

def analyze_contract(contractFile):
    slitherInstance = slither.Slither(contractFile)

    results = {}

    # Fet all funtions
    contracts = slitherInstance.contracts

    # Interate contracts
    for contract in contracts:
        if contract.contract_kind == 'library' or contract.contract_kind == 'inferface' or contract.contract_kind == 'abstract':
            continue

        functions = contract.functions
        if contract.constructor != None:
            constructor = contract.constructor
            constructorInfo = {
                "full_name": contract.constructor.full_name,
                "name": 'constructor',
                "visibility": contract.constructor.visibility,
                "payable": contract.constructor.payable
            }
            
            constructorParameters = {}
            for parameter in constructor.parameters:
                constructorParameters[parameter.name] = parameter.type.name

            constructorInfo["parameters"] = constructorParameters

            # Get internal calls
            internalCalls = []

            # Interate fintions internally called by this function
            for ir in constructor._internal_calls:
                internalCalls.append(ir.name)

            # Get state variables written by this function
            reads = []
            writes = []
            for ir in constructor.state_variables_read:
                reads.append(ir.full_name)
            
            for ir in constructor.state_variables_written:
                writes.append(ir.full_name)
            
            constructorInfo["internalCalls"] = internalCalls
            constructorInfo["reads"] = reads
            constructorInfo["writes"] = writes

            results['constructor'] = constructorInfo
        
        for function in functions:
            if function.name == 'slitherConstructorVariables' or function.is_constructor or function.is_constructor_variables:
                continue

            funcInfo = {
                "full_name": function.full_name,
                "name": function.name,
                "visibility": function.visibility,
                "payable": function.payable
            }

            parameters = {}

            for parameter in function.parameters:
                parameters[parameter.name] = parameter.type.name

            funcInfo["parameters"] = parameters

            # Get internal calls
            internalCalls = []

            # Interate fintions internally called by this function
            for ir in function._internal_calls:
                internalCalls.append(ir.name)

            # Get state variables written by this function
            reads = []
            writes = []
            for ir in function.state_variables_read:
                reads.append(ir.full_name)
            
            for ir in function.state_variables_written:
                writes.append(ir.full_name)
            
            funcInfo["internalCalls"] = internalCalls
            funcInfo["reads"] = reads
            funcInfo["writes"] = writes

            results[function.name] = funcInfo

    return results