package crypto128

import (
	"ss-crypto/tables"
)

func Crypto(data, key []byte) []byte {
	expandedKey := keyExpansion(key)
	roundKeys := generateRoundKeys(expandedKey)
	stateMatrices := generateAllStateMatrix(data)
	cryptoMatrices(stateMatrices, roundKeys)
	return joinMatrices(stateMatrices)
}

func joinMatrices(matrices [][][]byte) []byte {
	encryptedLen := getEncryptedResultLenByMatrices(matrices)
	result := make([]byte, encryptedLen)

	for x, matrix := range matrices {
		for y, line := range matrix {
			for z, byte_ := range line {
				result[(x*16)+(y*4)+z] = byte_
			}
		}
	}

	return result
}

func cryptoMatrices(matrices [][][]byte, roundKeys [][]byte) {
	for _, matrix := range matrices {
		cryptoMatrix(matrix, roundKeys)
	}
}

func cryptoMatrix(matrix, roundKeys [][]byte) {
	cryptoRoundKey(matrix, roundKeys, 0)

	for idxRoundKey := 1; idxRoundKey < (len(roundKeys)/4)-1; idxRoundKey++ {
		subWordMatrix(matrix)
		shiftRows(matrix)
		mixColumns(matrix)
		cryptoRoundKey(matrix, roundKeys, idxRoundKey)
	}

	subWordMatrix(matrix)
	shiftRows(matrix)
	cryptoRoundKey(matrix, roundKeys, 10)
}

func mixColumns(matrix [][]byte) {
	for x, line := range matrix {
		for y, byte_ := range line {
			line[y] = galoisMultiply(byte_, x, y)
		}
	}
}

func galoisMultiply(byte_ byte, x, y int) byte {
	multiply := tables.Multiply()[x][y]
	if byte_ == 0 || multiply == 0 {
		return 0
	}
	if byte_ == 1 {
		return multiply
	}
	if multiply == 1 {
		return byte_
	}

	sum := byte_ + multiply
	if sum >= 255 {
		sum -= 255
	}

	high, low := breakByteInMiddle(sum)
	galois := tables.Galois()[high][low]

	high, low = breakByteInMiddle(galois)
	return tables.E()[high][low]
}

func shiftRows(matrix [][]byte) {
	for x, line := range matrix {
		lenLine := len(line)
		newLine := make([]byte, lenLine)

		for y := 0; y < lenLine; y++ {
			idx := y + x
			if idx >= lenLine {
				idx = idx - lenLine
			}
			newLine[y] = line[idx]
		}

		matrix[x] = line
	}
}

func subWordMatrix(matrix [][]byte) {
	for _, line := range matrix {
		subWord(line)
	}
}

func cryptoRoundKey(matrix, roundKeys [][]byte, idxRoundKey int) {
	idxRoundKey = idxRoundKey * 4

	for i := 0; i < len(matrix); i++ {
		xor(matrix[i], roundKeys[i+idxRoundKey])
	}
}

func getEncryptedResultLenByMatrices(matrices [][][]byte) int {
	matricesLen := len(matrices)
	matrixLen := len(matrices[0])
	lineLen := len(matrices[0][0])
	return matricesLen * matrixLen * lineLen
}

/*
   ########################
   ###                  ###
   ###   STATE MATRIX   ###
   ###                  ###
   ########################
*/

func generateAllStateMatrix(bytes []byte) [][][]byte {
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
	// TODO Verify the last block
	return matrices
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
