package main

import (
	"fmt"
	"log"

	"github.com/kachamaka/argon2hash/argon2hash"
)

func main() {

	hash, err := argon2hash.GenerateFromPassword("testPass")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hash)
	match, err := argon2hash.ComparePasswordAndHash("testPass", hash)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(match)

}
