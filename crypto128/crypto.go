package crypto128

func Crypto(data []byte, key []byte) []byte {
	expandedKey := keyExpansion(key)
	roundKeys := generateRoundKeys(expandedKey)
}

func generateRoundKeys(expandedKey [][]byte) [][]byte {
	roundKeys := make([][]byte, 44)
	populateRoundKeysByExpandedKey(roundKeys, expandedKey)

	for i := 1; i < 10; i++ {
		first := generateFirstWordRoundKey(roundKeys[(i*4)-1])

	}
}

func generateFirstWordRoundKey(wordRoundKeyParam []byte) []byte {
	wordRoundKey := make([]byte, len(wordRoundKeyParam))
	copy(wordRoundKey, wordRoundKeyParam)
	// TODO CONTINUE
}

func populateRoundKeysByExpandedKey(roundKeys [][]byte, expandedKey [][]byte) {
	for i := 0; i < len(expandedKey); i++ {
		for x := 0; x < len(expandedKey); x++ {
			roundKeys[i][x] = expandedKey[x][i]
		}
	}
}

func keyExpansion(key []byte) [][]byte {
	keyLen := len(key)
	expandedKey := make([][]byte, 4)
	for i := 0; i < keyLen; i++ {
		expandedKey[i % 4][i / 4] = key[i]
	}
	return expandedKey
}
