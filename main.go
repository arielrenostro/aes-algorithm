package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"ss-crypto/crypto128"
	"strconv"
	"strings"
)

func main() {
	fmt.Println("#######################################")
	fmt.Println("#            FURB 2019/2              #")
	fmt.Println("# Desenvolvimento de sistemas seguros #")
	fmt.Println("# Ariel Adonai Souza e Gabriel...     #")
	fmt.Println("#######################################")

	if len(os.Args) != 4 {
		panic("cripto -kKEY -sSource.bin -dDest.bin")
	}

	args := *getArgs()
	exists := fileExists(args["-d"])
	if exists {
		panic("Destination file already exists")
	}
	exists = fileExists(args["-s"])
	if !exists {
		panic("Source file not exists")
	}

	source, e := ioutil.ReadFile(args["-s"])
	check(e)

	key := parseKey(args["-k"])
	encryptedData := crypto128.Crypto(source, key)

	e = ioutil.WriteFile(args["-d"], encryptedData, 0644)
	check(e)
}

func parseKey(keyRaw string) []byte {
	bytesStr := strings.Split(keyRaw, ",")

	bytes := make([]byte, len(bytesStr))
	for i, byteStr := range bytesStr {
		byteInt, e := strconv.Atoi(byteStr)
		check(e)

		bytes[i] = byte(byteInt)
	}

	return bytes
}

func fileExists(fileName string) bool {
	_, err := os.Stat(fileName)
	return !os.IsNotExist(err)
}

func getArgs() *map[string]string {
	args := make(map[string]string)
	for _, arg := range os.Args {
		if arg[0] == '-' {
			args[arg[:2]] = arg[2:]
		}
	}
	return &args
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}