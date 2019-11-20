package crypto128

import (
	"fmt"
	"io"
	"os"
	"ss-crypto/tables"
	"ss-crypto/utils"
)

func Crypto(source, dest *os.File, key []byte) {
	bufferSize := 4096
	routinesCount := 4
	byterPerRoutine := bufferSize / routinesCount

	tables.InitTables()

	expandedKey := keyExpansion(key)
	roundKeys := generateRoundKeys(expandedKey)

	paddingCreated := false
	parts := utils.CreateMatrix(routinesCount, byterPerRoutine)
	buffer := make([]byte, bufferSize)
	for {
		count, e := source.Read(buffer)
		if count == 0 && e == io.EOF {
			break
		}
		if e != nil {
			panic(e)
		}

		if count != len(buffer) {
			paddingCreated = true

			paddingSize := count % 16
			if paddingSize == 0 {
				paddingSize = 16
			}

		} else {
			for i := 0; i < len(parts); i++ {
				offset := i * len(parts[i])
				if offset > 0 {
					offset--
				}
				copyArrayData(buffer, parts[i], offset)
			}
		}

		// TODO executar as rotinas de cripto

		for i := 0; i < len(parts); i++ {
			_, e := dest.Write(parts[i])
			if e != nil {
				panic(e)
			}
		}
	}

	if !paddingCreated {
		// TODO criar padding e cripto
	}

	//cryptoMatrix(matrix, roundKeys)
	//
	//createPadding();
}

func copyArrayData(source []byte, dest []byte, offset int) {
	x := offset
	for i := 0; i < len(dest); i++ {
		dest[i] = source[x]
		x++
	}
}

func printMatrices(matrices [][][]byte, title string) {
	if !utils.Debug() {
		return
	}

	for x := 0; x < len(matrices); x++ {
		fmt.Print("\n" + title)
		fmt.Println(x)

		utils.PrintMatrix(matrices[x], true)
	}
}

func cryptoMatrix(matrix [][]byte, roundKeys [][][]byte) [][]byte {
	cryptoRoundKey(matrix, roundKeys, 0)

	for idxRoundKey := 1; idxRoundKey < len(roundKeys); idxRoundKey++ {
		subWordMatrix(matrix)
		matrix = utils.InvertMatrix(matrix)
		shiftRows(matrix)
		if idxRoundKey < len(roundKeys)-1 {
			matrix = mixColumns(matrix)
		}
		matrix = utils.InvertMatrix(matrix)
		cryptoRoundKey(matrix, roundKeys, idxRoundKey)
	}

	return matrix
}

func mixColumns(matrix [][]byte) [][]byte {
	newMatrix := utils.CreateMatrix(4, 4)

	for x := 0; x < len(matrix); x++ {
		for y := 0; y < len(matrix[x]); y++ {
			galoisValues := make([]byte, len(matrix[x]))
			for m := 0; m < len(galoisValues); m++ {
				galoisValues[m] = galoisMultiply(matrix[m][y], tables.Multiply[x][m])
			}
			for _, galoisValue := range galoisValues {
				newMatrix[x][y] = newMatrix[x][y] ^ galoisValue
			}
		}
	}

	return newMatrix
}

func galoisMultiply(byte_ byte, multiply byte) byte {
	if byte_ == 0 || multiply == 0 {
		return 0
	}
	if byte_ == 1 {
		return multiply
	}
	if multiply == 1 {
		return byte_
	}

	high, low := breakByteInMiddle(byte_)
	galoisOfByte := tables.Galois[high][low]

	high, low = breakByteInMiddle(multiply)
	galoisOfMultiply := tables.Galois[high][low]

	var sum int
	sum = int(galoisOfByte) + int(galoisOfMultiply)
	if sum > 0xFF {
		sum -= 0xFF
	}

	high, low = breakByteInMiddle(byte(sum))
	return tables.E[high][low]
}

func shiftRows(matrix [][]byte) {
	for x := 0; x < len(matrix); x++ {
		line := make([]byte, len(matrix[x]))
		copy(line, matrix[x])

		for y := 0; y < len(line); y++ {
			idx := y + x
			if idx >= len(line) {
				idx = idx - len(line)
			}
			matrix[x][y] = line[idx]
		}
	}
}

func subWordMatrix(matrix [][]byte) {
	for _, line := range matrix {
		subWord(line)
	}
}

func cryptoRoundKey(matrix [][]byte, roundKeys [][][]byte, idxRoundKey int) {
	for i := 0; i < len(matrix); i++ {
		xor(matrix[i], roundKeys[idxRoundKey][i])
	}
}

func createPadding(bytes []byte) (int, []byte) {
	size := int(len(bytes)/16) + 1
	paddingSize := len(bytes) % 16
	if paddingSize == 0 {
		paddingSize = 16
	}

	newBytesSize := len(bytes) + paddingSize
	newBytes := make([]byte, newBytesSize)
	copy(newBytes, bytes)
	for i := len(bytes); i < newBytesSize; i++ {
		newBytes[i] = byte(paddingSize)
	}

	return size, newBytes
}

/*
   #####################
   ###               ###
   ###   ROUND KEY   ###
   ###               ###
   #####################
*/

func generateRoundKeys(expandedKey [][]byte) [][][]byte {
	roundKeys := make([][][]byte, 11)
	roundKeys[0] = expandedKey

	for i := 1; i < 11; i++ {
		roundKeys[i] = utils.CreateMatrix(4, 4)
		lastWordRoundKey := roundKeys[i-1][3]
		firstWordRoundKey := roundKeys[i-1][0]
		roundKeys[i][0] = generateFirstWordRoundKey(lastWordRoundKey, firstWordRoundKey, i)
		roundKeys[i][1] = xorNew(roundKeys[i-1][1], roundKeys[i][0])
		roundKeys[i][2] = xorNew(roundKeys[i-1][2], roundKeys[i][1])
		roundKeys[i][3] = xorNew(roundKeys[i-1][3], roundKeys[i][2])
	}

	printMatrices(roundKeys, "RoundKey ")

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
	roundConstant[0] = tables.RoundConstantMatrix[idx]
	return roundConstant
}

func subWord(bytes []byte) {
	for i := 0; i < len(bytes); i++ {
		high, low := breakByteInMiddle(bytes[i])
		bytes[i] = tables.Sbox[high][low]
	}
}

func rotWord(bytes []byte) {
	first := bytes[0]
	for i := 1; i < len(bytes); i++ {
		bytes[i-1] = bytes[i]
	}
	bytes[len(bytes)-1] = first
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
	expandedKey := utils.CreateMatrix(4, 4)
	for i := 0; i < keyLen; i++ {
		expandedKey[i/4][i%4] = key[i]
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
