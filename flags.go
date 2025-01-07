package main

import "fmt"

type stringArray []string

// String is an implementation of the flag.Value interface
func (i *stringArray) String() string {
	return fmt.Sprintf("%v", *i)
}

// Set is an implementation of the flag.Value interface
func (i *stringArray) Set(value string) error {
	*i = append(*i, value)
	return nil
}
