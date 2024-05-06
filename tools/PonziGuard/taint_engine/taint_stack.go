// This code is an implementation of the Taint Engine used for analyzing and tracking taint data flow in smart contract execution.
// The Taint Engine marks and tracks the propagation paths of sensitive data in a program, 
// The Taint Engine help demonstrate the contract runtime behaviour, aiding in the discovery of potential security vulnerabilities such as Ponzi scheme.

package vm

import "fmt"
import "encoding/json"
import "sync"
//import "os"

//node_index: record the index of taint node
type TaintStack struct {
	data []int
	node_index [][]int
}

var TaintstackPool = sync.Pool{
	New: func() interface{} {
		return &TaintStack{data: make([]int, 0, 16)}
	},
}

func newtaintstack() *TaintStack {
	return TaintstackPool.Get().(*TaintStack)
}

func returnTaintStack(s *TaintStack) {
	s.data = s.data[:0]
	TaintstackPool.Put(s)
}

//func newtaintstack() *TaintStack {
//	return &TaintStack{data: make([]int, 0, 1024)}
//}

func (st *TaintStack) Data() []int {
	return st.data
}

func (st *TaintStack) NodeIndex() [][]int {
	return st.node_index
}


func (st *TaintStack) push(d int, node []int) {
	// NOTE push limit (1024) is checked in baseCheck
	//stackItem := new(big.Int).Set(d)
	//st.data = append(st.data, stackItem)
	st.data = append(st.data, d)
	st.node_index = append(st.node_index, node)
}
/*
func (st *TaintStack) pushN(ds ...int, nodes ...[]int) {
	st.data = append(st.data, ds...)
	st.node_index = append(st.node_index, nodes...)
}
*/
func (st *TaintStack) pop() (ret int, node []int) {
	ret = st.data[len(st.data)-1]
	st.data = st.data[:len(st.data)-1]
    
	node = st.node_index[len(st.node_index)-1]
	st.node_index = st.node_index[:len(st.node_index)-1]

	return
}

func (st *TaintStack) len() int {
	return len(st.data)
}

func (st *TaintStack) nlen() int {
	return len(st.node_index)
}

func (st *TaintStack) swap(n int) {
	st.data[st.len()-n], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-n]

    st.node_index[st.nlen()-n], st.node_index[st.nlen()-1] = st.node_index[st.nlen()-1], st.node_index[st.nlen()-n]

}

func (st *TaintStack) dup(n int) {
	st.push(st.data[st.len()-n], st.node_index[st.nlen()-n])
}

func (st *TaintStack) peek() (int, []int) {
	return st.data[st.len()-1], st.node_index[st.nlen()-1]
}

// Back returns the n'th item in stack
func (st *TaintStack) Back(n int) (int, []int) {
	return st.data[st.len()-n-1], st.node_index[st.nlen()-n-1]
}

func (st *TaintStack) require(n int) error {
	if st.len() < n {
		return fmt.Errorf("stack underflow (%d <=> %d)", len(st.data), n)
	}
	return nil
}

func (st *TaintStack) Print() {
	fmt.Println("### stack ###")
	if len(st.data) > 0 {
		for i, val := range st.data {
			fmt.Printf("%-3d  %v\n", i, val)
		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}

func (st *TaintStack) JPrint() {
	if j_data, err := json.Marshal(st.data); err == nil {
		fmt.Printf("TaintStack:%s\n", j_data)
	}
}

func main() {
	var t_stack TaintStack
	t_stack.data = append(t_stack.data, 1)
	t_stack.data = append(t_stack.data, 2)
	t_stack.data = append(t_stack.data, 3)
	t_stack.Print()
	print("pop: ")
	println(t_stack.pop())
	t_stack.Print()
}
