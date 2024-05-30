// This code is an implementation of the Taint Engine used for analyzing and tracking taint data flow in smart contract execution.
// The Taint Engine marks and tracks the propagation paths of sensitive data in a program, 
// The Taint Engine help demonstrate the contract runtime behaviour, aiding in the discovery of potential security vulnerabilities such as Ponzi scheme.


package vm

import (
	//"errors"
	//"fmt"
	//"math/big"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
	"CRBG"

)


//1. Spread of stains, spread of stain nodes

//2. The src instruction introduces stains and records the source node of the stains

//3. The sink instruction checks for stains and adds data edges

func opAdd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {

	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Add(&x, y)

	//taint propagation
	tx, ntx:= scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)

	return nil, nil, nil
}

func opSub(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Sub(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	
	return nil, nil, nil
}

func opMul(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mul(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opDiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Div(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opSdiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SDiv(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opMod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mod(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opSmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SMod(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opExp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	base, exponent := scope.Stack.pop(), scope.Stack.peek()
	exponent.Exp(&base, exponent)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opSignExtend(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	back, num := scope.Stack.pop(), scope.Stack.peek()
	num.ExtendSign(num, &back)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opNot(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x := scope.Stack.peek()
	x.Not(x)
	return nil, nil, nil
}



//sink
func opLt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Lt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//Check for parameter taint and add data edges
    //taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
		
	}
    scope.Taint_stack.push(tx | ty, nodes)

	/*if (tx | ty) & CALLVALUE_FLAG > 0{
		Global_taint_flag |= COMPARE_CALLVALUE_FLAG
		scope.Taint_stack.push(COMPARE_CALLVALUE_FLAG)
	} else if ((tx | ty) & CALLBALANCE_FLAG > 0) || ((tx | ty) & STORED_VALUE > 0) {
		Global_taint_flag |= COMPARE_BALANCE_FLAG
		scope.Taint_stack.push(COMPARE_BALANCE_FLAG)
	} else{
		scope.Taint_stack.push(tx | ty)
	}
	*/
	return nil, nil, nil
}

//sink
func opGt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Gt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}

	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//Check for parameter taint and add data edges
    //taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
    scope.Taint_stack.push(tx | ty, nodes)

	/*if (tx | ty) & CALLVALUE_FLAG > 0{
		Global_taint_flag |= COMPARE_CALLVALUE_FLAG
		scope.Taint_stack.push(COMPARE_CALLVALUE_FLAG)
	} else if ((tx | ty) & CALLBALANCE_FLAG > 0) || ((tx | ty) & STORED_VALUE > 0) {
		Global_taint_flag |= COMPARE_BALANCE_FLAG
		scope.Taint_stack.push(COMPARE_BALANCE_FLAG)
	} else{
		scope.Taint_stack.push(tx | ty)
	}
	*/
	return nil, nil, nil
}

//sink
func opSlt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Slt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//Check for parameter taint and add data edges
	//Check for parameter taint and add data edges
    //taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

//sink
func opSgt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Sgt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//Check for parameter taint and add data edges
    //taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

//sink
func opEq(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//Check for parameter taint and add data edges
    //taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
    scope.Taint_stack.push(tx | ty, nodes)

	/*if (tx | ty) & CALLVALUE_FLAG > 0{
		Global_taint_flag |= COMPARE_CALLVALUE_FLAG
		scope.Taint_stack.push(COMPARE_CALLVALUE_FLAG)
	} else if ((tx | ty) & CALLBALANCE_FLAG > 0) || ((tx | ty) & STORED_VALUE > 0){
		Global_taint_flag |= COMPARE_BALANCE_FLAG
		scope.Taint_stack.push(COMPARE_BALANCE_FLAG)
	} else {
		scope.Taint_stack.push(tx | ty)
	}*/

	return nil, nil, nil
}

func opIszero(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x := scope.Stack.peek()
	if x.IsZero() {
		x.SetOne()
	} else {
		x.Clear()
	}
	return nil, nil, nil
}

func opAnd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.And(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opOr(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Or(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opXor(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Xor(&x, y)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opByte(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	th, val := scope.Stack.pop(), scope.Stack.peek()
	val.Byte(&th)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

func opAddmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	tz, ntz := scope.Taint_stack.pop()

	if z.IsZero() {
		z.Clear()
		//taint propagation
		scope.Taint_stack.push(tz, ntz)
	} else {
		z.AddMod(&x, &y, z)
		//taint node sinks
		nodes := append(ntx, nty...)
		scope.Taint_stack.push(tx | ty, nodes)
	}
	return nil, nil, nil
}

func opMulmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	z.MulMod(&x, &y, z)
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx, nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Lsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx, nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Rsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx, nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	return nil, nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	//taint propagation
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
    scope.Taint_stack.push(tx | ty, nodes)
	if shift.GtUint64(256) {
		if value.Sign() >= 0 {
			value.Clear()
		} else {
			// Max negative shift: all bits set
			value.SetAllOne()
		}
		return nil, nil, nil
	}
	n := uint(shift.Uint64())
	value.SRsh(value, n)
	return nil, nil, nil
}

func opSha3(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	offset, size := scope.Stack.pop(), scope.Stack.peek()
	//Zan cun size!!!!!
	size_tmp := int64(size.Uint64())
	data := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	if interpreter.hasher == nil {
		interpreter.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	evm := interpreter.evm
	if evm.Config.EnablePreimageRecording {
		evm.StateDB.AddPreimage(interpreter.hasherBuf, data)
	}

	size.SetBytes(interpreter.hasherBuf[:])
	//Transfer of taint memory to the taint stack 
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	//pop []int and nodes [][]int
	t_data, nt_data:= scope.Taint_mem.Get(int64(offset.Uint64()), size_tmp)
	flag := SAFE_FLAG
	nodes := []int{}
	//merge
	for i := int64(0); i < size_tmp; i++ {
		flag = flag | t_data[i]
		nodes = append(nodes, nt_data[i]...)
	}
	scope.Taint_stack.push(flag, nodes)
	return nil, nil, nil
}

//src
func opAddress(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Address().Bytes()))
	//push taint and save the current node
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

//src
func opBalance(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	slot.SetFromBig(interpreter.evm.StateDB.GetBalance(address))
	//taint stack
	scope.Taint_stack.pop()
	//push taint and save the current node
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

//src
func opOrigin(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Origin.Bytes()))

	//push taint and save the current node
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

//src
func opCaller(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Caller().Bytes()))
	//push taint and save the current node
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

//src
func opCallValue(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	v, _ := uint256.FromBig(scope.Contract.value)
	scope.Stack.push(v)
	//push taint and save the current node
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

//src
func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	x := scope.Stack.peek()
	if offset, overflow := x.Uint64WithOverflow(); !overflow {
		data := getData(scope.Contract.Input, offset, 32)
		x.SetBytes(data)
	} else {
		x.Clear()
	}
	//taint stack
	scope.Taint_stack.pop()
	//push taint and save the current node
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

//src
func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(scope.Contract.Input))))
	//taint stack
	//push taint and save the current node
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

//src
func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = 0xffffffffffffffff
	}
	// These values are checked for overflow during gas cost calculation
	memOffset64 := memOffset.Uint64()
	length64 := length.Uint64()
	scope.Memory.Set(memOffset64, length64, getData(scope.Contract.Input, dataOffset64, length64))


	//taint stack
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	
	var t_value []int
	var nodes [][]int
    current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}

	for i := int64(0); i < int64(length64); i++ {
		//push taint []int
		t_value = append(t_value, TAINT_FLAG)
		//push taint node [][]int
		nodes = append(nodes, node)
	}
	scope.Taint_mem.Set(memOffset64, length64, t_value, nodes)
	return nil, nil, nil
}


func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(interpreter.returnData))))
	//taint stack
	//push empty node
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)

	offset64, overflow := dataOffset.Uint64WithOverflow()
	//taint stack
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	if overflow {
		return nil, nil, ErrReturnDataOutOfBounds
	}
	// we can reuse dataOffset now (aliasing it for clarity)
	var end = dataOffset
	end.Add(&dataOffset, &length)
	end64, overflow := end.Uint64WithOverflow()
	if overflow || uint64(len(interpreter.returnData)) < end64 {
		return nil, nil, ErrReturnDataOutOfBounds
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[offset64:end64])
	//taint memory
	//taint determined by returnflag,push empty node
	var nodes [][]int
	node := []int{}
	for i := int64(0); i < int64(length.Uint64()); i++ {
		//push empty node [][]int
		nodes = append(nodes, node)
	}

	scope.Taint_mem.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnFlag[offset64:end64], nodes)
	return nil, nil, nil
}

func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	slot := scope.Stack.peek()
	slot.SetUint64(uint64(interpreter.evm.StateDB.GetCodeSize(slot.Bytes20())))
	//taint stack
	scope.Taint_stack.pop()
	//push empty node []int
    node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	l := new(uint256.Int)
	l.SetUint64(uint64(len(scope.Contract.Code)))
	scope.Stack.push(l)
	//taint stack
	//push empty node []int
    node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	var (
		memOffset  = scope.Stack.pop()
		codeOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	codeCopy := getData(scope.Contract.Code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)
	//taint memory
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()

	var t_value []int
	//push empty node[][]int
	var nodes [][]int
	node := []int{}
	for i := uint64(0); i < length.Uint64(); i++ {
		t_value = append(t_value, SAFE_FLAG)
		nodes = append(nodes, node)
	}
	scope.Taint_mem.Set(memOffset.Uint64(), length.Uint64(), t_value, nodes)
	return nil, nil, nil
}

func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	var (
		stack      = scope.Stack
		a          = stack.pop()
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	//taint stack
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()

	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	addr := common.Address(a.Bytes20())
	codeCopy := getData(interpreter.evm.StateDB.GetCode(addr), uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)
	//taint memory
	var t_value []int
	//push empty node[][]int
	var nodes [][]int
	node := []int{}
	for i := int64(0); i < int64(length.Uint64()); i++ {
		t_value = append(t_value, SAFE_FLAG)
		nodes = append(nodes, node)
	}
	scope.Taint_mem.Set(memOffset.Uint64(), length.Uint64(), t_value, nodes)
	return nil, nil, nil
}

// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//   (1) Caller tries to get the code hash of a normal contract account, state
// should return the relative code hash and set it as the result.
//
//   (2) Caller tries to get the code hash of a non-existent account, state should
// return common.Hash{} and zero will be set as the result.
//
//   (3) Caller tries to get the code hash for an account without contract code,
// state should return emptyCodeHash(0xc5d246...) as the result.
//
//   (4) Caller tries to get the code hash of a precompiled account, the result
// should be zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean,
// all precompile accounts on mainnet have been transferred 1 wei, so the return
// here should be emptyCodeHash.
// If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//   (5) Caller tries to get the code hash for an account which is marked as suicided
// in the current transaction, the code hash of this account should be returned.
//
//   (6) Caller tries to get the code hash for an account which is marked as deleted,
// this account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	if interpreter.evm.StateDB.Empty(address) {
		slot.Clear()
	} else {
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
	}
	//taint stack
	scope.Taint_stack.pop()
	//push empty node []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opGasprice(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	v, _ := uint256.FromBig(interpreter.evm.GasPrice)
	scope.Stack.push(v)
	//taint stack
	//push empty node []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

//src
func opBlockhash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	num := scope.Stack.peek()
	//taint stack
	scope.Taint_stack.pop()
	num64, overflow := num.Uint64WithOverflow()
	if overflow {
		num.Clear()
		//taint stack
		//push empty node []int
	    node := []int{}
		scope.Taint_stack.push(SAFE_FLAG, node)
		return nil, nil, nil
	}
	var upper, lower uint64
	upper = interpreter.evm.Context.BlockNumber.Uint64()
	if upper < 257 {
		lower = 0
	} else {
		lower = upper - 256
	}
	if num64 >= lower && num64 < upper {
		num.SetBytes(interpreter.evm.Context.GetHash(num64).Bytes())
		//taint stack
		//push taint node
        current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	    node := []int{current_node}
	    scope.Taint_stack.push(TAINT_FLAG, node)
	} else {
		num.Clear()
		//taint stack
		//push empty node []int
		node := []int{}
		scope.Taint_stack.push(SAFE_FLAG, node)
	}
	return nil, nil, nil
}

func opCoinbase(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Context.Coinbase.Bytes()))
	//taint stack
	//push empty node []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

//src
func opTimestamp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Time)
	scope.Stack.push(v)
	//taint stack
	//push taint node
	current_node := len(CRBG.ContractGraph[CRBG.CurrentContract].X)-1
	node := []int{current_node}
	scope.Taint_stack.push(TAINT_FLAG, node)
	return nil, nil, nil
}

func opNumber(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.BlockNumber)
	scope.Stack.push(v)
	//taint stack
	//push empty node []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opDifficulty(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Difficulty)
	scope.Stack.push(v)
	//taint stack
	//push empty node []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opGasLimit(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(interpreter.evm.Context.GasLimit))
	//taint stack
	//push empty node []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opPop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.pop()
	//taint stack
	scope.Taint_stack.pop()
	return nil, nil, nil
}

//sink
func opMload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	v := scope.Stack.peek()
	offset := int64(v.Uint64())
	v.SetBytes(scope.Memory.GetPtr(offset, 32))

	//Check the parameters for taint, add edges

	tx, ntx := scope.Taint_stack.pop()
	if tx == TAINT_FLAG{
		CRBG.AddDFGEdge(ntx)
	}

	//check taint from memory, add edges
	t_data, nt_data := scope.Taint_mem.Get(offset, 32)
	//merge t_data
	t := 0
	for i := 0; i < len(t_data); i++{
		t = t | t_data[i]
	}
	//if tainted, merge nt_data into 2d, add data edges
	nodes := []int{}
	if t == TAINT_FLAG{
		for j := 0; j < len(nt_data); j++{
			nodes = append(nodes, nt_data[j]...)
		}
		CRBG.AddDFGEdge(nodes)
	}
    //push taint ，push taint src_nodes
	flag := SAFE_FLAG
	for i := 0; i < 32; i++ {
		flag = flag | t_data[i]
	}
	scope.Taint_stack.push(flag, nodes)
	return nil, nil, nil
}

//sink
func opMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	// pop value of the stack
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.Set32(mStart.Uint64(), &val)
	//taint memory


	//tx represents the location and ty represents the data stored in memory

	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//Check the parameters for taint, add edges
    //taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}


	slice_ty := make([]int, 32)
	nodes2 := [][]int{}
	for i := 0; i < 32; i++ {
		slice_ty[i] = ty
		nodes2 = append(nodes2, nty)
	}
	scope.Taint_mem.Set(mStart.Uint64(), 32, slice_ty, nodes2)
	return nil, nil, nil
}

//sink
func opMstore8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	off, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.store[off.Uint64()] = byte(val.Uint64())
	//taint memory


	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
    //Check the parameters for taint, add edges
    //taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
	scope.Taint_mem.store[int64(off.Uint64())] = ty
	scope.Taint_mem.node_index[int64(off.Uint64())] = nty
	return nil, nil, nil
}

//sink
func opSload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	loc := scope.Stack.peek()
	loc_temp := *loc
	hash := common.Hash(loc.Bytes32())
	val := interpreter.evm.StateDB.GetState(scope.Contract.Address(), hash)
	loc.SetBytes(val.Bytes())

	//taint stack
	tx, ntx := scope.Taint_stack.pop()
    //Check the parameters for taint, add edges
	if tx == TAINT_FLAG{
		CRBG.AddDFGEdge(ntx)
	}

	//check taint from storage, add edges
	t_data, nt_data := ContractStorage[CRBG.CurrentContract].Load(loc_temp)
	if t_data == TAINT_FLAG{
		CRBG.AddDFGEdge(nt_data)
	}

	scope.Taint_stack.push(t_data, nt_data)



	/*
	C := Caller[Rcv_addr]
	V := Value[Rcv_addr]
	if C.IsExist(loc_temp) {
		scope.Taint_stack.push(tv | STORED_CALLER)
	} else if V.IsExist(loc_temp) {
		scope.Taint_stack.push(tv | STORED_VALUE)
	} else {
		scope.Taint_stack.push(tv)
	}*/
	return nil, nil, nil
}

//sink
func opSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	loc := scope.Stack.pop()
	val := scope.Stack.pop()
	interpreter.evm.StateDB.SetState(scope.Contract.Address(),
		loc.Bytes32(), val.Bytes32())


    //Check the parameters for taint, add edges
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
	//save TaintStorage, only the second parameter and loc
	ContractStorage[CRBG.CurrentContract].Store(ty, nty, loc)
	
	/*
	if tv & CALLVALUE_FLAG > 0 {
		Global_taint_flag |= STORE_CALLVALUE_FLAG
		V := Value[Rcv_addr]
		if !V.IsExist(loc){
			V.Push(loc)
			Value[Rcv_addr] = V
		}
	}
	if tv & CALLER_FLAG > 0 {
		Global_taint_flag |= STORE_CALLER_FLAG
		C := Caller[Rcv_addr]
		if !C.IsExist(loc){
			C.Push(loc)
			Caller[Rcv_addr] = C
		}
	}*/
	return nil, nil, nil
}

func opJump(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	pos := scope.Stack.pop()
	//taint stack
    scope.Taint_stack.pop()

	if !scope.Contract.validJumpdest(&pos) {
		return nil, nil, ErrInvalidJump
	}
	*pc = pos.Uint64()
	return nil, nil, nil
}
//sink
func opJumpi(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	pos, cond := scope.Stack.pop(), scope.Stack.pop()
    //Check the parameters for taint, add edges
	tx, ntx := scope.Taint_stack.pop()
	ty, nty := scope.Taint_stack.pop()
	//taint node sinks
	nodes := append(ntx,nty...)
	if tx | ty == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
	/*

	if ty & COMPARE_CALLVALUE_FLAG > 0 {
		Global_taint_flag |= JUMPI_AFTERCALLVALUE
	}
	if ty & COMPARE_BALANCE_FLAG > 0  {
		Global_taint_flag |= JUMPI_AFTERBALANCE
	}*/

	if !cond.IsZero() {
		if !scope.Contract.validJumpdest(&pos) {
			return nil, nil, ErrInvalidJump
		}
		*pc = pos.Uint64()
	} else {
		*pc++
	}
	return nil, nil, nil
}

func opJumpdest(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	return nil, nil, nil
}

func opPc(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(*pc))
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opMsize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(scope.Memory.Len())))
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opGas(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(scope.Contract.Gas))
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	return nil, nil, nil
}

func opCreate(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	var (
		value        = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)
	//taint stack
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_mem.Get(int64(offset.Uint64()),int64(size.Uint64()))

	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}
	// reuse size int for stackvalue
	stackvalue := size

	scope.Contract.UseGas(gas)
	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		bigVal = value.ToBig()
	}
	//add returnFlag
	res, returnFlag, addr, returnGas, suberr := interpreter.evm.Create(scope.Contract, input, gas, bigVal)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
    //taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		return res, returnFlag, nil
	}
	return nil, nil, nil
}

func opCreate2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	var (
		endowment    = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		salt         = scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)
	//taint stack
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	scope.Taint_mem.Get(int64(offset.Uint64()),int64(size.Uint64()))

	// Apply EIP150
	gas -= gas / 64
	scope.Contract.UseGas(gas)
	// reuse size int for stackvalue
	stackvalue := size
	//TODO: use uint256.Int instead of converting with toBig()
	bigEndowment := big0
	if !endowment.IsZero() {
		bigEndowment = endowment.ToBig()
	}
	//add returnFlag
	res, returnFlag, addr, returnGas, suberr := interpreter.evm.Create2(scope.Contract, input, gas,
		bigEndowment, &salt)
	// Push item on the stack based on the returned error.
	if suberr != nil {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		return res, returnFlag, nil
	}
	return nil, nil, nil
}
//sink
func opCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	stack := scope.Stack
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	// We can use this as a temporary value
	temp := stack.pop()
	//taint stack
	scope.Taint_stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	//taint stack
	t1, nt1 :=  scope.Taint_stack.pop()
	t2, nt2 :=  scope.Taint_stack.pop()
	t3, nt3 :=  scope.Taint_stack.pop()
	t4, nt4 :=  scope.Taint_stack.pop()
	t5, nt5 :=  scope.Taint_stack.pop()
	t6, nt6 :=  scope.Taint_stack.pop()
	
	
	
	//Check the parameters for taint, add edges
	//taint node sinks
	nodes := append(nt1,nt2...)
	nodes = append(nodes,nt3...)
	nodes = append(nodes,nt4...)
	nodes = append(nodes,nt5...)
	nodes = append(nodes,nt6...)

	if t1 | t2 | t3 | t4 | t5 | t6 == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
	/*if t1 & STORED_CALLER > 0{
		Global_taint_flag |= CALL_TO_CALLER
	}*/
	
	toAddr := common.Address(addr.Bytes20())
	// Get the arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	scope.Taint_mem.Get(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	var bigVal = big0
	//TODO: use uint256.Int instead of converting with toBig()
	// By using big0 here, we save an alloc for the most common case (non-ether-transferring contract calls),
	// but it would make more sense to extend the usage of uint256.Int
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}
	//add returnFlag []int
	ret, returnFlag, returnGas, err := interpreter.evm.Call(scope.Contract, toAddr, args, gas, bigVal)

	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
		//taint memory  ReturnFlag needs to be added, ignoring the return memory value, nodes push empty nodes [][]int
		nodes := [][]int{}
		for i := int64(0); i < int64(retSize.Uint64()); i++{
			nodes = append(nodes, node)
		}
		scope.Taint_mem.Set(retOffset.Uint64(), retSize.Uint64(), returnFlag, nodes)
	}
	scope.Contract.Gas += returnGas

	return ret, returnFlag, nil
}
//sink
func opCallCode(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	//taint stack
	scope.Taint_stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

    t1, nt1 :=  scope.Taint_stack.pop()
	t2, nt2 :=  scope.Taint_stack.pop()
	t3, nt3 :=  scope.Taint_stack.pop()
	t4, nt4 :=  scope.Taint_stack.pop()
	t5, nt5 :=  scope.Taint_stack.pop()
	t6, nt6 :=  scope.Taint_stack.pop()
	//Check the parameters for taint, add edges
	//taint node sinks
	nodes := append(nt1,nt2...)
	nodes = append(nodes,nt3...)
	nodes = append(nodes,nt4...)
	nodes = append(nodes,nt5...)
	nodes = append(nodes,nt6...)

	if t1 | t2 | t3 | t4 | t5 | t6 == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}
	
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	scope.Taint_mem.Get(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}
	//add returnFlag
	ret, returnFlag, returnGas, err := interpreter.evm.CallCode(scope.Contract, toAddr, args, gas, bigVal)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)

	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
		//taint memory  ReturnFlag needs to be added, ignoring the return memory value, nodes push empty nodes [][]int
		nodes := [][]int{}
		for i := int64(0); i < int64(retSize.Uint64()); i++{
			nodes = append(nodes, node)
		}
		scope.Taint_mem.Set(retOffset.Uint64(), retSize.Uint64(), returnFlag, nodes)
	}
	scope.Contract.Gas += returnGas

	return ret, returnFlag, nil
}
//sink
func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	stack := scope.Stack
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// We use it as a temporary value
	temp := stack.pop()
	//taint stack
	scope.Taint_stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	//taint stack
    t1, nt1 :=  scope.Taint_stack.pop()
	t2, nt2 :=  scope.Taint_stack.pop()
	t3, nt3 :=  scope.Taint_stack.pop()
	t4, nt4 :=  scope.Taint_stack.pop()
	t5, nt5 :=  scope.Taint_stack.pop()
	t6, nt6 :=  scope.Taint_stack.pop()
	//Check the parameters for taint, add edges
	//taint node sinks
	nodes := append(nt1,nt2...)
	nodes = append(nodes,nt3...)
	nodes = append(nodes,nt4...)
	nodes = append(nodes,nt5...)
	nodes = append(nodes,nt6...)

	if t1 | t2 | t3 | t4 | t5 | t6 == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	scope.Taint_mem.Get(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	//add returnFlag
	ret, returnFlag, returnGas, err := interpreter.evm.DelegateCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)
	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
		//taint memory  ReturnFlag needs to be added, ignoring the return memory value, nodes push empty nodes [][]int
		nodes := [][]int{}
		for i := int64(0); i < int64(retSize.Uint64()); i++{
			nodes = append(nodes, node)
		}
		scope.Taint_mem.Set(retOffset.Uint64(), retSize.Uint64(), returnFlag, nodes)
	}
	scope.Contract.Gas += returnGas

	return ret, returnFlag, nil
}
//sink
func opStaticCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	//taint stack
	scope.Taint_stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	//taint stack
    t1, nt1 :=  scope.Taint_stack.pop()
	t2, nt2 :=  scope.Taint_stack.pop()
	t3, nt3 :=  scope.Taint_stack.pop()
	t4, nt4 :=  scope.Taint_stack.pop()
	t5, nt5 :=  scope.Taint_stack.pop()
	t6, nt6 :=  scope.Taint_stack.pop()
	//Check the parameters for taint, add edges
	//taint node sinks
	nodes := append(nt1,nt2...)
	nodes = append(nodes,nt3...)
	nodes = append(nodes,nt4...)
	nodes = append(nodes,nt5...)
	nodes = append(nodes,nt6...)

	if t1 | t2 | t3 | t4 | t5 | t6 == TAINT_FLAG{
		CRBG.AddDFGEdge(nodes)
	}

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	scope.Taint_mem.Get(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	//add returnFlag
	ret, returnFlag, returnGas, err := interpreter.evm.StaticCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	//taint stack push SAFE_FLAG and empty node  []int
	node := []int{}
	scope.Taint_stack.push(SAFE_FLAG, node)

	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
		//taint memory  ReturnFlag needs to be added, ignoring the return memory value, nodes push empty nodes [][]int
		nodes := [][]int{}
		for i := int64(0); i < int64(retSize.Uint64()); i++{
			nodes = append(nodes, node)
		}
		scope.Taint_mem.Set(retOffset.Uint64(), retSize.Uint64(), returnFlag, nodes)
	}
	scope.Contract.Gas += returnGas

	return ret, returnFlag, nil
}

func opReturn(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	//taint memory
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	//[]int [][]int  Ignore returning nodes in memory 
	taint_ret, _ := scope.Taint_mem.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	taint_flag := SAFE_FLAG
	for i := int64(0); i < int64(size.Uint64()); i++ {
		taint_flag = taint_flag | taint_ret[i]
	}

	Global_taint_flag |= taint_flag
	//add return
	return ret, taint_ret, nil
}

func opRevert(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	//taint stack and memory
	scope.Taint_stack.pop()
	scope.Taint_stack.pop()
	taint_ret, _:= scope.Taint_mem.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	taint_flag := SAFE_FLAG
	for i := uint64(0); i < size.Uint64(); i++ {
		taint_flag = taint_flag | taint_ret[i]
	}

	Global_taint_flag |= taint_flag
	//add return
	return ret, nil, nil
}

func opStop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	return nil, nil, nil
}

func opSuicide(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	beneficiary := scope.Stack.pop()
	//taint stack
	scope.Taint_stack.pop()
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	interpreter.evm.StateDB.AddBalance(beneficiary.Bytes20(), balance)
	interpreter.evm.StateDB.Suicide(scope.Contract.Address())
	return nil, nil, nil
}

// following functions are used by the instruction jump  table

// make log instruction function
func makeLog(size int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
		topics := make([]common.Hash, size)
		stack := scope.Stack
		mStart, mSize := stack.pop(), stack.pop()
		for i := 0; i < size; i++ {
			addr := stack.pop()
			topics[i] = addr.Bytes32()
		}

		d := scope.Memory.GetCopy(int64(mStart.Uint64()), int64(mSize.Uint64()))
		interpreter.evm.StateDB.AddLog(&types.Log{
			Address: scope.Contract.Address(),
			Topics:  topics,
			Data:    d,
			// This is a non-consensus field, but assigned here because
			// core/state doesn't know the current block number.
			BlockNumber: interpreter.evm.Context.BlockNumber.Uint64(),
		})
		//taint stack
		scope.Taint_stack.pop()
		scope.Taint_stack.pop()

		for i := 0; i < size; i++ {
			scope.Taint_stack.pop()
		}

		return nil, nil, nil
	}
}

// opPush1 is a specialized version of pushN
func opPush1(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
	var (
		codeLen = uint64(len(scope.Contract.Code))
		integer = new(uint256.Int)
	)
	*pc += 1
	if *pc < codeLen {
		scope.Stack.push(integer.SetUint64(uint64(scope.Contract.Code[*pc])))
		//taint stack push SAFE_FLAG and empty node  []int
	    node := []int{}
	    scope.Taint_stack.push(SAFE_FLAG, node)
	} else {
		scope.Stack.push(integer.Clear())
	    //taint stack push SAFE_FLAG and empty node  []int
	    node := []int{}
	    scope.Taint_stack.push(SAFE_FLAG, node)
	}
	return nil, nil, nil
}

// make push instruction function
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
		codeLen := len(scope.Contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := new(uint256.Int)
		scope.Stack.push(integer.SetBytes(common.RightPadBytes(
			scope.Contract.Code[startMin:endMin], pushByteSize)))

		*pc += size
		//taint stack push SAFE_FLAG and empty node  []int
	    node := []int{}
	    scope.Taint_stack.push(SAFE_FLAG, node)
		return nil, nil, nil
	}
}

// make dup instruction function
func makeDup(size int64) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
		scope.Stack.dup(int(size))
		//taint stack
		scope.Taint_stack.dup(int(size))
		return nil, nil, nil
	}
}

// make swap instruction function
func makeSwap(size int64) executionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size++
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, []int, error) {
		scope.Stack.swap(int(size))
		//taint stack
		scope.Taint_stack.swap(int(size))
		return nil, nil, nil
	}
}


