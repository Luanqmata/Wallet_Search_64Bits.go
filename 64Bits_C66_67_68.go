package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"meugo/crypto/base58"

	"runtime"

	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/ripemd160"
)

const (
	prefix = "00000000000000000000000000000000000000000000000" // mudar de acordo com a carteira
)

var chaves_desejadas = map[string]bool{
	"13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so": true, // mudar todas as carteiras conforme o que procura
	"1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9": true,
	"1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ": true,
}
var contador = 0

func geradorChaves() []string {
	chavesGeradas := make(map[string]struct{})
	chaves := make([]string, 0)

	for {
		suffix := make([]byte, 9) // mudar de acordo com a quantidade de bits
		_, err := rand.Read(suffix)
		if err != nil {
			log.Fatalf("Falha ao gerar chave: %v", err)
		}

		chaveGerada := prefix + hex.EncodeToString(suffix)[:17]  // mudar de acordo com os bits 

		if _, ok := chavesGeradas[chaveGerada]; !ok {
			chavesGeradas[chaveGerada] = struct{}{}
			chaves = append(chaves, chaveGerada)
			contador++
			return chaves
		}
	}
}
func generateWif(privKeyHex string) string {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		log.Fatal(err)
	}

	extendedKey := append([]byte{byte(0x80)}, privKeyBytes...)
	extendedKey = append(extendedKey, byte(0x01))

	firstSHA := sha256.Sum256(extendedKey)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]

	finalKey := append(extendedKey, checksum...)

	wif := base58.Encode(finalKey)
	return wif
}

func createPublicHash160(privKeyHex string) []byte {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		log.Fatal(err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

	compressedPubKey := privKey.PubKey().SerializeCompressed()

	pubKeyHash := hash160(compressedPubKey)
	return pubKeyHash
}

func hash160(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	sha256Hash := h.Sum(nil)

	r := ripemd160.New()
	r.Write(sha256Hash)
	return r.Sum(nil)
}

func encodeAddress(pubKeyHash []byte) string {
	version := byte(0x00)
	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := doubleSha256(versionedPayload)[:4]
	fullPayload := append(versionedPayload, checksum...)
	return base58.Encode(fullPayload)
}

func doubleSha256(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// 31 red , 32 verde ,33 amarelo , 34 azul, 35 rosa , 30 cinza ,36 zul ciano
func main() {
	for {
		chaves := geradorChaves()
		found := false // Flag para indicar se encontramos a chave desejada

		for _, chave := range chaves {
			generateWif(chave)
			pubKeyHash := createPublicHash160(chave)
			address := encodeAddress(pubKeyHash)
			if chaves_desejadas[address] {
				fmt.Printf("\x1b[36m \n\n|--------------%s----------------|\n", address)
				fmt.Printf("\x1b[35m|----------------------ATENÇÃO-PRIVATE-KEY-----------------------|")
				fmt.Printf("\x1b[36m \n|%s|", chave)
				found = true // Marca que encontramos a chave desejada
				break        // Interrompe o loop interno
			} else {
				fmt.Printf("\x1b[34m %s\n", chave)
			}
		}

		if found {
			break // Interrompe o loop externo se encontrou a chave desejada
		}
	}
	numCPU := runtime.NumCPU()
	fmt.Println("\x1b[35m\n                              ______")
	fmt.Println("                             |      |")
	fmt.Println("                             |OOPS! |")
	fmt.Println("                             |WALLET|")
	fmt.Println("                             |FOUND!|")
	fmt.Println("                             |______|")
	fmt.Print("\x1b[36m|--------------------------------------------------by-Luan-BSC---|")
	fmt.Print("\n|-----------------------China-LOOP-MENU------------------------- |")
	fmt.Printf("\n|		Nucleis do processador usados: %d		 |", numCPU)
	fmt.Print("\n|		Chaves Analisadas:	", contador)
	fmt.Print("\n|________________________________________________________________|")
}
