package main

import (
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"testing"
)

func getBytes(function string, args []string) [][]byte {
	bytes := make([][]byte, 0, len(args)+1)
	bytes = append(bytes, []byte(function))
	for _, s := range args {
		bytes = append(bytes, []byte(s))
	}
	return bytes
}

func TestInvoke(t *testing.T) {
	bst := new(kevlarChainCode)
	stub := shim.NewMockStub("kevlar", bst)

	if stub != nil {
		fmt.Println("OK")
	}

	argStr := "08021206616c6963653218012a210335efb24a694a3211c355a040d353e8dc97a85aee6464feea465ea496765e48fa"
	res := stub.MockInvoke("3", getBytes("createProof", []string{argStr}))

	if res.Status != shim.OK {
		err := errors.New(res.Message)
		fmt.Println(err)
	}
}
