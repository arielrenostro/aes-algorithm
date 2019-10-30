package crypto128

import (
	"ss-crypto/tables"
)

func Crypto(data, key []byte) []byte {
	expandedKey := keyExpansion(key)
	roundKeys := generateRoundKeys(expandedKey)

	stateMatrices := generateAllStateMatrix(data)

	return nil
}

/*
   ########################
   ###                  ###
   ###   STATE MATRIX   ###
   ###                  ###
   ########################
*/

func generateAllStateMatrix(bytes []byte) {
	size := len(bytes) / 16
	if size == 0 {
		size = 1
	}
	matrices := make([][][]byte, size)
	for i := 0; i < size; i++ {
		matrices[i] = createMatrix(4, 4)
	}

	for x := 0; x < size; x++ {
		for y := 0; y < 4; y++ {
			for z := 0; z < 4; z++ {
				matrices[x][y][z] = bytes[(x*16)+(y*4)+(z)]
			}
		}
	}
}

/*
   #####################
   ###               ###
   ###   ROUND KEY   ###
   ###               ###
   #####################
*/

func generateRoundKeys(expandedKey [][]byte) [][]byte {
	roundKeys := createMatrix(44, 4)
	populateRoundKeysByExpandedKey(roundKeys, expandedKey)

	for i := 4; i < 44; i = i + 4 {
		lastWordRoundKey := roundKeys[i-1]
		firstWordRoundKey := roundKeys[i-4]
		idxRoundKey := (i / 4) - 1
		roundKeys[i] = generateFirstWordRoundKey(lastWordRoundKey, firstWordRoundKey, idxRoundKey)
		roundKeys[i+1] = xorNew(roundKeys[i-3], roundKeys[i])
		roundKeys[i+2] = xorNew(roundKeys[i-2], roundKeys[i+1])
		roundKeys[i+3] = xorNew(roundKeys[i-1], roundKeys[i+2])
	}

	return roundKeys
}

func generateFirstWordRoundKey(lastWordRoundKey, firstWordRoundKey []byte, idxRoundKey int) []byte {
	wordRoundKey := make([]byte, len(lastWordRoundKey))
	copy(wordRoundKey, lastWordRoundKey)
	rotWord(wordRoundKey)
	subWord(wordRoundKey)
	roundConstant := generateRoundConstant(idxRoundKey)
	xor(wordRoundKey, roundConstant)
	xor(wordRoundKey, firstWordRoundKey)
	return wordRoundKey
}

func generateRoundConstant(idx int) []byte {
	roundConstant := make([]byte, 4)
	roundConstant[0] = tables.RoundConstantMatrix()[idx]
	return roundConstant
}

func subWord(bytes []byte) {
	sbox := tables.Sbox()
	for i := 0; i < len(bytes); i++ {
		high, low := breakByteInMiddle(bytes[i])
		bytes[i] = sbox[high][low]
	}
}

func rotWord(bytes []byte) {
	first := bytes[0]
	for i := 1; i < len(bytes); i++ {
		bytes[i-1] = bytes[i]
	}
	bytes[len(bytes)-1] = first
}

func populateRoundKeysByExpandedKey(roundKeys, expandedKey [][]byte) {
	for i := 0; i < len(expandedKey); i++ {
		for x := 0; x < len(expandedKey[i]); x++ {
			roundKeys[i][x] = expandedKey[x][i]
		}
	}
}

/*
   #########################
   ###					  ###
   ###   KEY EXPANSION   ###
   ###					  ###
   #########################
*/
func keyExpansion(key []byte) [][]byte {
	keyLen := len(key)
	expandedKey := createMatrix(4, 4)
	for i := 0; i < keyLen; i++ {
		expandedKey[i%4][i/4] = key[i]
	}
	return expandedKey
}

/*
   #################
   ###			  ###
   ###   UTILS   ###
   ###			  ###
   #################
*/
func createMatrix(x, y int) [][]byte {
	matrix := make([][]byte, x)
	for i := 0; i < x; i++ {
		matrix[i] = make([]byte, y)
	}
	return matrix
}

func xorNew(a, b []byte) []byte {
	result := make([]byte, len(a))
	copy(result, a)
	xor(result, b)
	return result
}

func xor(result, matrix []byte) {
	for i := 0; i < len(result); i++ {
		result[i] = result[i] ^ matrix[i]
	}
}

func breakByteInMiddle(b byte) (byte, byte) {
	low := b & 15
	high := (b & 240) >> 4
	return high, low
}
