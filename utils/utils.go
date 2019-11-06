package utils

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func CreateMatrix(x, y int) [][]byte {
	matrix := make([][]byte, x)
	for i := 0; i < x; i++ {
		matrix[i] = make([]byte, y)
	}
	return matrix
}

func PrintHexArray(bytes []byte) {
	for _, x := range bytes {
		dst := make([]byte, hex.EncodedLen(1))
		hex.Encode(dst, []byte{x})

		fmt.Printf("0x%s ", dst)
	}
	fmt.Print("\n")
}

func PrintMatrix(matrix [][]byte, invert bool) {
	if invert {
		matrix = InvertMatrix(matrix)
	}
	for y := 0; y < len(matrix); y++ {
		PrintHexArray(matrix[y])
	}
}

func InvertMatrix(matrix [][]byte) [][]byte {
	newMatrix := CreateMatrix(4, 4)
	for y := 0; y < 4; y++ {
		for z := 0; z < 4; z++ {
			newMatrix[z][y] = matrix[y][z]
		}
	}
	return newMatrix
}

func h(s string) byte {
	decoded, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return decoded[0]
}

func HexToBytes(hexStr string) []byte {
	hexs := strings.Split(hexStr, "0x")
	result := make([]byte, len(hexs)-1)
	for i, hex := range hexs {
		if i == 0 {
			continue
		}
		hex = strings.Trim(hex, " ")
		result[i-1] = h(hex)
	}
	return result
}

func Debug() bool {
	return false
}

func GeneratePadding() bool {
	return true
}
