package main

import (
	"fmt"
	"log"

	"github.com/kachamaka/argon2custom/argon2custom"
)

func main() {

	hash, err := argon2custom.GenerateFromPassword("testPass")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hash)
	match, err := argon2custom.ComparePasswordAndHash("testPass", hash)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(match)

}
