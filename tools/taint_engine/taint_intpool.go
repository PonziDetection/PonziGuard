// This code is an implementation of the Taint Engine used for analyzing and tracking taint data flow in smart contract execution.
// The Taint Engine marks and tracks the propagation paths of sensitive data in a program, 
// The Taint Engine help demonstrate the contract runtime behaviour, aiding in the discovery of potential security vulnerabilities such as Ponzi scheme.

package vm

//import "math/big"

//var checkVal = big.NewInt(-42)

const taintPoolLimit = 256

// intPool is a pool of big integers that
// can be reused for all big.Int operations.
type TaintIntPool struct {
	pool *TaintStack
}

func newTaintIntPool() *TaintIntPool {
	return &TaintIntPool{pool: newtaintstack()}
}

// get retrieves a big int from the pool, allocating one if the pool is empty.
// Note, the returned int's value is arbitrary and will not be zeroed!
func (p *TaintIntPool) get() int {
	if p.pool.len() > 0 {
		ret, _:= p.pool.pop()
		return ret
	}
	return SAFE_FLAG
}

// getZero retrieves a big int from the pool, setting it to zero or allocating
// a new one if the pool is empty.
func (p *TaintIntPool) getZero() int {
	if p.pool.len() > 0 {
		p.pool.pop()
	}
	return SAFE_FLAG
}

// put returns an allocated big int to the pool to be later reused by get calls.
// Note, the values as saved as is; neither put nor get zeroes the ints out!
func (p *TaintIntPool) put(is ...int) {
	if len(p.pool.data) > taintPoolLimit {
		return
	}
	for _, i := range is {
		node := []int{}
		p.pool.push(i, node)
	}
}
