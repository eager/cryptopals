package main

import (
	"log"
	"os"
	"strconv"
)

type MainFunc func()

func main() {

	args := os.Args

	if len(args) != 2 {
		log.Fatalf("Exactly one argument (challenge number) required: %s", args)
	}

	c, err := strconv.Atoi(args[1])
	if err != nil {
		log.Fatalf("could not parse challenge number: %v", err)
	}

	challenges := map[int]MainFunc{
		9:  main9,
		10: main10,
		11: main11,
		12: main12,
		13: main13,
	}

	if challenges[c] == nil {
		log.Fatalf("no challenge found: %d", c)
	}

	challenges[c]()
}
