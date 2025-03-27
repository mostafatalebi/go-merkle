package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

type Hashed [32]byte

func castToHashedType[k comparable, T string | []byte](val T) Hashed {
	var h = Hashed{}
	var hexRep, _ = hex.DecodeString(string(val))
	copy(h[:], hexRep[:])
	return h
}

type Merkle struct {
	Values []string
	Tree   *Node
	Nodes  []*Node
	lock   *sync.RWMutex
}

type Node struct {
	Value  string
	Left   *Node
	Right  *Node
	Hash   Hashed
	Copied bool
}

func NewMerkleTree() *Merkle {
	return &Merkle{
		Values: make([]string, 0),
		lock:   &sync.RWMutex{},
	}
}

// NewNode
// creates either a leaf node or a branch node
// if right and left are nil, it is considered a leaf node
// the hash will automatically be calculated from the passed value
func NewNode(value string, left, right *Node) (*Node, error) {
	var h Hashed
	var err error
	if value != "" {
		h, err = HashFromStr(value)
		if err != nil {
			return nil, err
		}
	}
	return &Node{
		Value:  value,
		Right:  right,
		Left:   left,
		Hash:   h,
		Copied: false,
	}, nil
}

// NewBranch
// creates a node as branch, but without any value and
// instead allows setting hash directly
func NewBranch(hashVal Hashed, right, left *Node) *Node {
	return &Node{
		Value:  "",
		Right:  right,
		Left:   left,
		Hash:   hashVal,
		Copied: false,
	}
}

// Adds leaf values from which the tree will be created
func (m *Merkle) InsertMulti(s ...string) *Merkle {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.Values = append(m.Values, s...)

	return m
}

// Creates a complete tree from exiting leaves
func (m *Merkle) CreateTree() {
	m.lock.Lock()
	defer m.lock.Unlock()
	var count = len(m.Values)
	if count == 0 {
		return
	} else if count&1 == 1 {
		m.Values = append(m.Values, m.Values[count-1])
	}
	var updatedCount = len(m.Values)

	for i := 0; i < updatedCount; i += 2 {
		var n, _ = NewNode(m.Values[i], nil, nil)
		var n2, _ = NewNode(m.Values[i+1], nil, nil)
		m.Nodes = append(m.Nodes, n, n2)
	}

	//	m.createBranches(m.Branches[0:], 0)

	m.Tree = m.putIntoTree(m.Nodes)
}

func (m *Merkle) putIntoTree(nodes []*Node) *Node {
	var n *Node
	var err error
	if len(nodes)&1 == 1 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}
	if len(nodes) == 2 {
		n, _ := NewNode("", nil, nil)
		n.Left = nodes[0]
		n.Right = nodes[1]
		n.Hash, err = MakeHash(nodes[0].Hash, nodes[1].Hash)
		n.Value = nodes[0].Value + ";" + nodes[1].Value
		if err != nil {
			panic(err)
		}
		return n
	}
	var midPoint = len(nodes) / 2
	var left = m.putIntoTree(nodes[0:midPoint])
	var right = m.putIntoTree(nodes[midPoint:])
	n, err = NewNode("", left, right)
	if err != nil {
		panic(err)
	}
	n.Hash, _ = MakeHash(left.Hash, right.Hash)
	n.Value = left.Value + ";" + right.Value
	return n
}

// Creates a single hash from several hashes
func MakeHash(v ...Hashed) (Hashed, error) {
	var crp = sha256.New()
	var joined = make([]byte, 32*len(v))
	var i = 0
	for _, each := range v {
		for _, vv := range each {
			joined[i] = vv
			i++
		}
	}
	b, err := crp.Write(joined)
	if err != nil {
		return Hashed{}, err
	} else if b == 0 {
		return Hashed{}, errors.New("no bytes written to sha256, but also no error was returned")
	}
	return [32]byte(crp.Sum(nil)), nil
}

func HashFromStr(v string) (Hashed, error) {
	var crp = sha256.New()
	b, err := crp.Write([]byte(v))
	if err != nil {
		return Hashed{}, err
	} else if b == 0 {
		return Hashed{}, errors.New("no bytes written to sha256, but also no error was returned")
	}
	return [32]byte(crp.Sum(nil)), nil
}

// Print
// Prints the tree fully with indentation
// Use this function for printing the tree
func (m *Merkle) Print() {
	m.printTree(m.Tree, "")
}

func (m *Merkle) printTree(root *Node, pad string) {
	if root != nil {
		fmt.Printf("%s %x [%s]\n", pad, root.Hash, root.Value)
		m.printTree(root.Left, pad+" -- -- ")
		m.printTree(root.Right, pad+" -- -- ")
	}
}

// rootHash is the root hash against which we need to verify the transaction
// proofPath a list of nodes (leaf and branches) which are required to re-calculate
// the hashes upward until to the root
// index the current leaf index, which tells us its position in the tree
// so we know if we should start sibling leaf's hash before it or after it
// returns the calculated hash, and no error if the proof is verified
func VerifyProof(rootHash, leaf Hashed, proofPath []Hashed, index int) (resultHash Hashed, err error) {
	resultHash = leaf
	var indexInUse = index
	for i := 0; i < len(proofPath); i++ {
		if indexInUse&1 == 0 {
			resultHash, err = MakeHash(resultHash, proofPath[i])
		} else {
			resultHash, err = MakeHash(proofPath[i], resultHash)
		}
		// divide it by 2, to move one level up
		indexInUse >>= 1
	}
	if resultHash != rootHash {
		err = errors.New("hashes do not match, verification of the proof failed")
	}
	return resultHash, err
}
