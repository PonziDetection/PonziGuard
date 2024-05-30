// This code is an implementation of the Taint Engine used for analyzing and tracking taint data flow in smart contract execution.
// The Taint Engine marks and tracks the propagation paths of sensitive data in a program, 
// The Taint Engine help demonstrate the contract runtime behaviour, aiding in the discovery of potential security vulnerabilities such as Ponzi scheme.

package vm

import(
	//"fmt"
	//"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
) 

//taint flag
const SAFE_FLAG int = 0
const TAINT_FLAG int = 1
/*
const PONZI_FLAG = COMPARE_CALLVALUE_FLAG | JUMPI_AFTERCALLVALUE | STORE_CALLVALUE_FLAG | STORE_CALLER_FLAG | COMPARE_BALANCE_FLAG | JUMPI_AFTERBALANCE | CALL_TO_CALLER
const POTENTIAL_PONZI_FLAG = COMPARE_CALLVALUE_FLAG | JUMPI_AFTERCALLVALUE | STORE_CALLVALUE_FLAG | STORE_CALLER_FLAG | COMPARE_BALANCE_FLAG | JUMPI_AFTERBALANCE
*/

type Callertype struct{
	addr []uint256.Int
}
type Valuetype struct{
	addr []uint256.Int
}

var Value = map[string]Valuetype{}
var Caller = map[string]Callertype{} //Caller['0x...'] ———> Callertype

func (v *Valuetype) Push(loc uint256.Int){
	v.addr = append(v.addr,loc)
}

func (v *Valuetype) IsExist(loc uint256.Int) bool{
	var j = len(v.addr)
	for i := 0; i<j; i++{
		if v.addr[i] == loc{
			return true
		}
	}
	return false
}

//func (v map[common.Address]Valuetype) Reset(){
	//var value_empty Valuetype
	//v.addr = value_empty.addr
//}

func (c *Callertype) Push(loc uint256.Int){
	c.addr = append(c.addr,loc)
}

func (c *Callertype) IsExist(loc uint256.Int) bool{
	var j = len(c.addr)
	for i := 0; i<j; i++{
		if c.addr[i] == loc{
			return true
		}
	}
	return false
}

//func (c map[common.Address]Callertype) Reset(){
	//var caller_empty Callertype
	//c.addr = caller_empty.addr
//}

var Rcv_addr string 

var Global_taint_flag = SAFE_FLAG
var ponzi_flag = "untested"