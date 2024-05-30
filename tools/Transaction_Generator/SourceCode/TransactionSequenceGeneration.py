from web3 import Web3
import json
import random
import secrets
import time

random.seed(time.time())


def getRandInt(length: int):
    return random.randint(-50,50)


def getRandUint(length: int):
    return random.randint(0,50)


def getRandFix():
    random_float = random.uniform(0.0, 1.0)

    # 将随机浮点数转换为 Solidity 的 `fixed` 或 `ufixed` 类型
    random_fixed = hex(int(random_float * 2**128))
    return random_fixed


def getRandUfixed():
    random_float = random.uniform(-1.0, 0.0)

    # 将随机浮点数转换为 Solidity 的 `fixed` 或 `ufixed` 类型
    random_fixed = hex(int(random_float * 2**128))
    return random_fixed


def getRandBool():
    randomBool = random.choice([True, False])

    # 将随机布尔值转换为 Solidity 的 `bool` 类型
    randomBool_solidity = str(randomBool).lower()
    return randomBool_solidity


def getRandAddress():
    return Web3.to_checksum_address("0x" + secrets.token_hex(20))


def getRandString():
    randomString = secrets.token_urlsafe(32)

    # 将随机字符串转换为 Solidity 的 `string` 类型
    randomString_solidity = '"' + randomString + '"'
    return randomString_solidity


def getRandByteArray():
    random_bytes = secrets.token_bytes(32)
    # 将随机字节数组转换为 Solidity 的 `bytes` 类型
    return "0x" + random_bytes.hex()


def getRandArray():
    random_array = [random.randint(0, 100) for i in range(5)]

    # 将随机数组转换为 Solidity 的 `uint256[]` 类型
    return "[" + ", ".join(map(str, random_array)) + "]"


def getRandStruct():
    return {'key': 'value'}


def getRandMapping():
    return {'index': 'value'}


def getRandEnum():
    return None

def getRandString():
    return random.randbytes(random.randint(1,40)).hex()


def getF_all(contractInfo: dict) -> dict:
    F_all = {}
    for functions in contractInfo.items():
        for function, functionInfo in functions.items():
            F_all[function] = functionInfo
    # print(F_all)
    return F_all


def getF_kws(F_all: dict) -> dict:
    F_kws = {}
    keywords = [
        "enter",
        "init",
        "invest",
        "fallback"
    ]
    for function in F_all:
        if function in keywords:
            F_kws[function] = F_all[function]
    return F_kws


def getF_payable(F_all: dict) -> dict:
    F_payable = {}
    for function in F_all:
        if F_all[function]["payable"] == True:
            F_payable[function] = F_all[function]
    return F_payable


def getF_writable(F_all: dict) -> dict:
    F_writable = {}
    for function in F_all:
        if len(F_all[function]["writes"]) > 0:
            F_writable[function] = F_all[function]
    return F_writable


def randomChoose(F_kws: dict, F_all: dict, p=0.6):
    if len(F_kws) <= 0:
        return False

    random.seed(time.time())
    randomNum = random.random()
    res = {}
    if randomNum < p:
        res = F_kws[random.choice(list(F_kws.keys()))]
        while res["visibility"] == "private":
            res = F_kws[random.choice(list(F_kws.keys()))]

    else:
        res = F_all[random.choice(list(F_all.keys()))]
        while res["visibility"] == "private":
            res = F_all[random.choice(list(F_all.keys()))]

    return res


def generateTransaction(func: dict, payableCount: int):
    # 复制函数信息
    tx = func.copy()
    # 如果函数可支付，则设置交易的价值为递增的随机值
    if tx["payable"]:
        tx["value"] = random.randint(payableCount, payableCount + 10)

    randomParam = {}  # 初始化随机参数字典
    params: dict = tx["parameters"]  # 获取函数的参数信息
    for p in params.keys():  # 遍历参数
        # 根据参数类型生成随机值
        if params[p] == "address":
            randomParam[p] = getRandAddress()

        elif params[p][0: 3] == "int":
            randomParam[p] = getRandInt(eval(params[p][3:]))

        elif params[p][0: 4] == "uint":
            randomParam[p] = getRandUint(eval(params[p][4:]))

        elif params[p] == "fixed":
            randomParam[p] = getRandFix()

        elif params[p] == "ufixed":
            randomParam[p] = getRandUfixed()

        elif params[p] == "bool":
            randomParam[p] = getRandBool()

        elif params[p] == "bytes":
            randomParam[p] = getRandByteArray()

        elif params[p] == "array":
            randomParam[p] = getRandArray()

        elif params[p] == "struct":
            randomParam[p] = getRandStruct()

        elif params[p] == "enum":
            randomParam[p] = getRandEnum()

        elif params[p] == "mapping":
            randomParam[p] = getRandMapping()

        elif params[p] == "string":
            randomParam[p] = getRandString()

    tx["randomParameterValues"] = randomParam  # 将随机参数值添加到交易信息中

    return tx  # 返回生成的交易信息


def getDependency(F_all: dict, functionName: str) -> dict:
    deps = {}  # 初始化依赖字典
    writes = F_all[functionName]["writes"]  # 获取指定函数的写操作
    for function in F_all:  # 遍历所有函数
        # 如果有函数读取了指定函数的写操作，则将该函数添加到依赖字典中
        if len(set(F_all[function]["reads"]) & set(writes)) > 0:
            deps[function] = F_all[function]

    return deps  # 返回依赖字典


def removeUncallable(F_all: dict):
    toBeRemoved = []  # 初始化待移除列表
    for func in F_all:  # 遍历所有函数
        # 如果函数在合约名称中或者可见性为私有，则将其添加到待移除列表中
        if func == 'constructor' or F_all[func]["visibility"] == "private" or F_all[func]["visibility"] == "internal":
            toBeRemoved.append(func)
    for func in toBeRemoved:  # 遍历待移除列表
        del F_all[func]  # 从函数字典中移除对应的函数

    return F_all


def transacSeqGenerator(F_all: dict, Max: int):
    # 从合约信息中提取函数信息
    F_kws = getF_kws(F_all)  # 获取包含关键字的函数
    F_payable = getF_payable(F_all)  # 获取可支付的函数
    F_writable = getF_writable(F_all)  # 获取可写入状态变量的函数
    payableCount = 0  # 初始化可支付函数计数
    g = 0  # 初始化序列计数
    SeedPool = []  # 初始化交易序列的种子池
    while g < Max:  # 循环直到达到最大序列数
        txs = []  # 初始化交易序列的空列表

        while len(txs) < len(F_all):  # 循环直到包含所有函数
            # 根据关键字、可支付或可写入随机选择一个函数
            func = randomChoose(F_kws, F_all)
            if not func:  # 如果根据关键字未选择到函数，则尝试可支付
                func = randomChoose(F_payable, F_all)
                if not func:  # 如果仍未选择到函数，则尝试可写入
                    func = randomChoose(F_writable, F_all)
                    if not func:
                        break
            tx = generateTransaction(func, payableCount)  # 为选择的函数生成交易
            if func["payable"]:  # 如果函数可支付，则增加可支付计数
                payableCount += 10
            txs.append(tx)  # 将交易添加到序列中
            while len(txs) < len(F_all):  # 循环直到包含所有函数
                dep = getDependency(F_all, txs[-1]["name"])  # 获取序列中最后一个交易的依赖函数
                if dep != {}:  # 如果存在依赖函数
                    func_dep = randomChoose(
                        dep, F_all)  # 随机选择一个依赖函数
                else:  # 如果未找到依赖函数，则随机选择一个函数
                    func_dep = randomChoose(F_all, F_all)
                tx = generateTransaction(
                    func_dep, payableCount)  # 为选择的依赖函数生成交易
                if func_dep["payable"]:  # 如果依赖函数可支付，则增加可支付计数
                    payableCount += 10
                txs.append(tx)  # 将交易添加到序列中
        SeedPool.append(txs)  # 将交易序列添加到种子池中
        g += 1  # 增加序列计数

    # res = {contractName: SeedPool}  # 创建包含合约名称和种子池的结果字典
    # save = json.dumps(res, indent=4)  # 将结果字典转换为带缩进的JSON字符串
    # file = open("./{}.json".format(contractName), 'w')  # 以写入模式打开以合约名称命名的文件
    # file.write(save)  # 将JSON字符串写入文件
    return SeedPool  # 返回生成的种子池


def getTransactionSequence(filename: str, contractsInfo: dict, Max: int):
    """
    生成交易序列的函数，用于分析合约并生成交易序列

    Args:
    path (str): 合约文件路径
    Max (int): 生成的交易序列的最大值

    Returns:
    dict: 包含合约名和对应交易序列的字典
    """
    seedPool = {}
    if hasattr(contractsInfo, 'constructor'):
        constructor = contractsInfo['constructor']
        callable_functions = removeUncallable(contractsInfo)  # 移除不可调用的函数

        # 产生序列
        seedPool[filename] = transacSeqGenerator(
            callable_functions,
            Max
        )

        construct = generateTransaction(constructor, 0)

        with open(f"/home/lrc/PonziGuard/ponziback/tools/Transaction_Generator/output/{filename}.json", "w") as f:
            f.write(json.dumps(seedPool, indent=4))

        return construct
    
    else:
        callable_functions = removeUncallable(contractsInfo)  # 移除不可调用的函数

        # 产生序列
        seedPool[filename] = transacSeqGenerator(
            callable_functions,
            Max
        )

        with open(f"/home/lrc/PonziGuard/ponziback/tools/Transaction_Generator/output/{filename}.json", "w") as f:
            f.write(json.dumps(seedPool, indent=4))

        return None