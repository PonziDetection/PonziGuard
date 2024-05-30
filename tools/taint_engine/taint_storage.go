// This code is an implementation of the Taint Engine used for analyzing and tracking taint data flow in smart contract execution.
// The Taint Engine marks and tracks the propagation paths of sensitive data in a program, 
// The Taint Engine help demonstrate the contract runtime behaviour, aiding in the discovery of potential security vulnerabilities such as Ponzi scheme.

package vm
import(
	"github.com/holiman/uint256"
)

/*var TaintStoragePool = sync.Pool{
	New: func() interface{} {
		return &TaintStorage{}
	},
}

func NewTaintStorage() *TaintStorage {
	return TaintStoragePool.Get().(*TaintStorage)
}
*/

type TaintStorage struct{
	data []int
	node_index [][]int
	address []uint256.Int
}

var ContractStorage = make(map[string]*TaintStorage)



func (t *TaintStorage) Store(data int, node []int, addr uint256.Int){
	i, j := is_exsit(t, addr)
	if i == false {
		t.data = append(t.data, data)
		t.node_index = append(t.node_index, node)
		t.address = append(t.address, addr)
	}else{
		t.data[j] = data
		t.node_index[j] = node
	}

}

func is_exsit(t *TaintStorage, addr uint256.Int) (bool, int){
	l := len(t.data)
	for i := 0; i < l; i ++ {
		if t.address[i] == addr{
			return true, i
		}
	}
	return false, 0


}

func (t *TaintStorage) Load(addr uint256.Int) (data int, node []int){
	i, j := is_exsit(t, addr)
	if i == false{
		return SAFE_FLAG, []int{}
	}else{
		return t.data[j], t.node_index[j]
	}
}