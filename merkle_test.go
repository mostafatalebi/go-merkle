package merkle

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerkleTree(t *testing.T) {
	var merkle = NewMerkleTree()
	var rawList = []string{"R1", "R2", "R3", "R4"}
	var hashesList = make([]Hashed, 0)
	for _, v := range rawList {
		h, err := HashFromStr(v)
		assert.NoError(t, err)
		assert.NotEmpty(t, h)
		assert.Len(t, h, 32)
		hashesList = append(hashesList, h)
	}
	merkle.InsertMulti(rawList...)
	merkle.CreateTree()
	b1, _ := MakeHash(hashesList[0], hashesList[1])
	b2, _ := MakeHash(hashesList[2], hashesList[3])
	assert.Equal(t, b1, merkle.Tree.Left.Hash, fmt.Sprintf("bytes are not equal:\n%x\n%x", b1, merkle.Tree.Right.Hash))
	assert.Equal(t, b2, merkle.Tree.Right.Hash, fmt.Sprintf("bytes are not equal:\n%x\n%x", b2, merkle.Tree.Right.Hash))

	r, err := VerifyProof(merkle.Tree.Hash, merkle.Tree.Left.Left.Hash,
		[]Hashed{merkle.Tree.Left.Right.Hash, merkle.Tree.Right.Hash}, 0)
	assert.NoError(t, err)
	assert.Equal(t, r, merkle.Tree.Hash)
}
