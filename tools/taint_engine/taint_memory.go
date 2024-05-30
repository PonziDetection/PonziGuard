// This code is an implementation of the Taint Engine used for analyzing and tracking taint data flow in smart contract execution.
// The Taint Engine marks and tracks the propagation paths of sensitive data in a program, 
// The Taint Engine help demonstrate the contract runtime behaviour, aiding in the discovery of potential security vulnerabilities such as Ponzi scheme.

package vm

import "fmt"
import "encoding/json"
//import "os"

// Memory implements a simple memory model for the ethereum virtual machine.
//node_index: record the index of taint node
type TaintMemory struct {
	store       []int
	node_index [][]int
	lastGasCost uint64
}

func NewTaintMemory() *TaintMemory {
	return &TaintMemory{}
}

// Set sets offset + size to value
func (m *TaintMemory) Set(offset, size uint64, value []int, nodes [][]int) {
	// length of store may never be less than offset + size.
	// The store should be resized PRIOR to setting the memory
	if size > uint64(len(m.store)) {
		panic("INVALID memory: store empty")
	}

	// It's possible the offset is greater than 0 and size equals 0. This is because
	// the calcMemSize (common.go) could potentially return 0 when size is zero (NO-OP)
	if size > 0 {
		copy(m.store[offset:offset+size], value)
		/*file, err := os.OpenFile("/home/lrc/myproject/crush.txt", os.O_RDWR|os.O_CREATE, 0644)
	    if err != nil{
		    fmt.Println("open file err=", err)
		    return
	    }
	    defer file.Close()
	    fmt.Fprintf(file,"len of m.store %d:\n", len(m.store))
		fmt.Fprintf(file,"len of m.node_index %d:\n", len(m.node_index))
		*/
		copy(m.node_index[offset:offset+size], nodes)
	}
}

// Resize resizes the memory to size
func (m *TaintMemory) Resize(size uint64) {
	if uint64(m.Len()) < size {
		m.store = append(m.store, make([]int, size-uint64(m.Len()))...)
		m.node_index = append(m.node_index, make([][]int, size-uint64(m.NLen()))...)
	}
}

// Get returns offset + size as a new slice
func (m *TaintMemory) Get(offset, size int64) (cpy []int, nodes [][]int) {
	if size == 0 {
		return nil, nil
	}

	if len(m.store) > int(offset) {
		cpy = make([]int, size)
		copy(cpy, m.store[offset:offset+size])
		nodes = make([][]int,size)
		copy(nodes, m.node_index[offset:offset+size])

		return
	}

	return
}

// GetPtr returns the offset + size
func (m *TaintMemory) GetPtr(offset, size int64) ([]int, [][]int) {
	if size == 0 {
		return nil, nil
	}

	if len(m.store) > int(offset) {
		return m.store[offset : offset+size], m.node_index[offset : offset + size]
	}

	return nil, nil
}

// Len returns the length of the backing slice
func (m *TaintMemory) Len() int {
	return len(m.store)
}

func (m *TaintMemory) NLen() int {
	return len(m.node_index)
}


// Data returns the backing slice
func (m *TaintMemory) Data() []int {
	return m.store
}


func (m *TaintMemory) NodeIndex() [][]int {
	return m.node_index
}

func (m *TaintMemory) Print() {
	fmt.Printf("# mem %d bytes #\n", len(m.store))
	if len(m.store) > 0 {
		addr := 0
		for i := 0; i+32 <= len(m.store); i += 32 {
			fmt.Printf("%03d: % x\n", addr, m.store[i:i+32])
			addr++
		}
	} else {
		fmt.Println("-- empty --")
	}
}

func (m *TaintMemory) JPrint() {
	if j_data, err := json.Marshal(m.store); err == nil {
		fmt.Printf("TaintMemory:%s\n", j_data)
	}
}
