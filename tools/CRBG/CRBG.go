package CRBG

import("os"
"fmt"
//"encoding/json"
//"io/ioutil"

)
const X_dim = 72
const Edge_dim = 15
type Node struct{
	index int
	attr [X_dim]int
}

type Edge struct{
	src int
	dest int
	attr [Edge_dim]int
}

type Graph struct {
	X []Node
	edge []Edge
	y int

}
var ContractGraph = make(map[string]*Graph)
//var GraphIndex int = -1
//var AddFlag bool = false 
var CurrentContract string = ""
var RecordFlag bool = false


var OpList []OpCode = []OpCode{
	STOP,
	ADD,
	MUL,
	SUB,
	DIV,
	SDIV,
	MOD,
	SMOD,
	ADDMOD,
	MULMOD,
	EXP,
	SIGNEXTEND,
	LT,
	GT,
	SLT,
	SGT,
	EQ,
	ISZERO,
	AND,
	XOR,
	OR,
	NOT,
	BYTE,
	SHA3,
	ADDRESS,  //24
	BALANCE, //25
	ORIGIN, //26
	CALLER, //27
	CALLVALUE,//28
	CALLDATALOAD,//29
	CALLDATASIZE,//30
	CALLDATACOPY,//31
	CODESIZE,
	CODECOPY,
	GASPRICE,
	EXTCODESIZE,
	EXTCODECOPY,
	BLOCKHASH,//37
	COINBASE,
	TIMESTAMP,//39
	NUMBER,
	DIFFICULTY,
	GASLIMIT,
	POP,
	MLOAD,
	MSTORE,
	SLOAD,
	SSTORE,
	JUMP,
	JUMPI,
	PC,
	MSIZE,
	GAS,
	JUMPDEST,
	PUSH1,
	DUP1,
	SWAP1,
	LOG0,
	CREATE,
	CALL,
	CALLCODE,
	RETURN,
	SELFDESTRUCT,
	DELEGATECALL,
	REVERT,
	RETURNDATACOPY,
	RETURNDATASIZE,
	STATICCALL,
	EXTCODEHASH,
	SAR,
	SHR,
	SHL}


func PrintGraph_onehot(path string){

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil{
		fmt.Println("open file err=", err)
		return
	}
	defer file.Close()
	//print nodes
	fmt.Fprintf(file,"Contract %s:\nNode:\n", CurrentContract)
	//fmt.Fprintf(file,"AddFlag: %t\n",AddFlag)
    for _, node := range ContractGraph[CurrentContract].X{
		fmt.Fprintf(file,"%d\n",node.attr)
	}

    //print edges
	fmt.Fprintf(file,"Edge:\n")
    for _, edge := range ContractGraph[CurrentContract].edge{
		fmt.Fprintf(file,"src:%d dest:%d attr:%d\n", edge.src, edge.dest, edge.attr)
	}
	return
}

/*func PrintEdge(path string){

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil{
		fmt.Println("open file err=", err)
		return
	}
	defer file.Close()
	fmt.Fprintf(file,"Edge:\n")

    for _, edge := range ContractGraph[CurrentContract].edge{
		fmt.Fprintf(file,"src:%d dest:%d attr:%d\n", edge.src, edge.dest, edge.attr)
	}
	return
}*/


func AddAEdge(node int){
	//current node
    current_node := len(ContractGraph[CurrentContract].X)-1
	//src attr
	attr := ContractGraph[CurrentContract].X[node].attr
	//Determine node category based on attr
	kind := 0
	for j := 0; j < len(OpList); j++{
		if attr[j] != 0{
			kind = j
			break
		}
	}
	edge_attr := [Edge_dim]int{}
	switch kind{
	case 25: 
		edge_attr[6] = 1 //BALANCE edge
	case 39:
		edge_attr[7] = 1 //TIMESTAMP edge
	case 37:
		edge_attr[8] = 1 //BLOCKHASH edge
	case 24:
		edge_attr[9] = 1 //ADDRESS edge
	case 27, 26:
		edge_attr[10] = 1 //CALLER/ORIGIN edge
	case 28:
		edge_attr[11] = 1 //CALLVALUE edge
	case 29, 31:
		edge_attr[12] = 1 //CALLDATALOAD/CALLDATACOPY edge
	case 30:
		edge_attr[13] = 1 //CALLDATASIZE edge
	}
	new_edge := Edge{node, current_node, edge_attr}
	ContractGraph[CurrentContract].edge = append(ContractGraph[CurrentContract].edge, new_edge)
}

func AddDFGEdge(nodes []int){
	if RecordFlag == true{
		//Add an edge to each node in the nodes
		//Remove duplicate nodes and avoid duplicate edges
	    nodes = unique(nodes)
	    for i := 0; i < len(nodes); i++{
		    //Nodes in the node stack 
		    node := nodes[i]
		    AddAEdge(node)
	    }
	}
}

func unique(arr []int) []int{
	var arr_len int = len(arr)
	for i:= 0; i < arr_len; i++ {
		for j := i + 1; j < arr_len; j++{
			if arr[i] == arr[j]{
				arr = append(arr[:i], arr[i+1:]...)
				arr_len --
				i--
				break
			}
		}
	}
	return arr[:arr_len]
}


//Add a node and set its properties

func AddNode(op OpCode){
	//Merge op
	var search_op OpCode = op
	//Location of op
	var op_index int = 0
	//node attribution
	attr := [X_dim]int{}

	switch search_op {
	case MSTORE8:
		search_op = MSTORE
	case PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8, PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16, PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24, PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32:
		search_op = PUSH1
	case DUP2,DUP3,DUP4,DUP5,DUP6,DUP7,DUP8,DUP9,DUP10,DUP11,DUP12,DUP13,DUP14,DUP15,DUP16:
		search_op = DUP1
	case SWAP2,SWAP3,SWAP4,SWAP5,SWAP6,SWAP7,SWAP8,SWAP9,SWAP10,SWAP11,SWAP12,SWAP13,SWAP14,SWAP15,SWAP16:
		search_op = SWAP1
	case LOG1,LOG2,LOG3,LOG4:

		search_op = LOG0
	case CREATE2:
		search_op = CREATE
	}
	for i := 0; i<len(OpList); i++{
		if OpList[i] == search_op{
			op_index = i
			break
		}
	}
	//current graph: ContractGraph[CurrentContract]
	//Set node attribution
	attr[op_index] = 1
	//new node
	new_node := Node{len(ContractGraph[CurrentContract].X),attr}
	ContractGraph[CurrentContract].X = append(ContractGraph[CurrentContract].X, new_node)
	return
}


//Add a control flow edge
func AddCFGEdge(){
	//src_op default to STOP
	var src_op OpCode = STOP
	//edge_attr
	edge_attr := [Edge_dim]int{}
	//current graph ContractGraph[CurrentContract]
	//current node
	current_node := len(ContractGraph[CurrentContract].X)-1
	if current_node <= 0{
		return
	}
	src_node := current_node-1
    //Determine the instruction type src based on the attributes of the src node_ Op

	attr := ContractGraph[CurrentContract].X[src_node].attr
	for i := 0; i < len(attr); i++{
		if attr[i] != 0{
			src_op = OpList[i]
			break
		}
	}
	/*set edge_attr：
	  adjacent edges 
      Unconditional jump edge-JUMP
      Conditional jump edge-JUMPI
      CREATE edge-CREATE/CREATE2
      CALL edge-CALL/CALLCODE/DELEGATECALL/STATICCALL
      RETURN edge-RETURN

	  [0,0,0,0,0,0]
    */
    switch src_op {
	case JUMP:
		edge_attr[1] = 1 //Unconditional jump edge
	case JUMPI:
		edge_attr[2] = 1 //Conditional jump edge
	case CREATE, CREATE2:
		edge_attr[3] = 1 //CREATE edge
	case CALL, CALLCODE, DELEGATECALL, STATICCALL:
		edge_attr[4] = 1 //CALL edge
	case RETURN:
		edge_attr[5] = 1 //RETURN edge
	case STOP:
		edge_attr[14] = 1 // Connecting edge 
	default:
		edge_attr[0] = 1 //adjacent edges
	}
	new_edge := Edge{src_node, current_node, edge_attr}
	ContractGraph[CurrentContract].edge = append(ContractGraph[CurrentContract].edge, new_edge)
}