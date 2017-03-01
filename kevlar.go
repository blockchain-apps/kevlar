/*
Copyright (c) 2016 Skuchain,Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/skuchain/kevlar/ProofElements"
	"github.com/skuchain/kevlar/ProofTx"
)

// This chaincode implements the ledger operations for the proofchaincode

// ProofChainCode example simple Chaincode implementation
type kevlarChainCode struct {
}

func (t *kevlarChainCode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	return nil, nil
}

//ProofChainCode.Invoke runs a transaction against the current state
func (t *kevlarChainCode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	//Proofs Chaincode should have one transaction argument. This is body of serialized protobuf
	if len(args) == 0 {
		fmt.Println("Zero arguments found")
		return nil, errors.New("Zero arguments found")
	}

	argsBytes, err := hex.DecodeString(args[0])
	if err != nil {
		fmt.Println("Invalid argument expected hex")
		return nil, errors.New("Invalid argument expected hex")
	}
	argsProof := proofTx.ProofTX{}
	err = proto.Unmarshal(argsBytes, &argsProof)
	if err != nil {
		fmt.Println("Invalid argument expected protocol buffer")
		return nil, errors.New("Invalid argument expected protocol buffer")
	}
	fmt.Println(function)
	fmt.Println(argsProof)

	switch function {

	case "createProof":
		name := argsProof.Name
		threshold := argsProof.Threshold
		publicKeys := argsProof.PubKeys
		nameCheckBytes, err := stub.GetState("Proof:" + name)
		if len(nameCheckBytes) != 0 {
			fmt.Printf("Proof Name:%s already claimed\n", name)
			return nil, fmt.Errorf("Proof Name:%s already claimed", name)
		}
		if int(threshold) > len(publicKeys) {
			fmt.Printf("Invalid Threshold of %d for %d keys\n", threshold, len(publicKeys))
			return nil, fmt.Errorf("Invalid Threshold of %d for %d keys ", threshold, len(publicKeys))
		}
		switch argsProof.Type {
		case proofTx.ProofTX_SECP256K1:
			newProof := new(ElementProof.SecP256k1ElementProof)
			newProof.ProofName = name
			newProof.State = ElementProof.Initialized
			newProof.Threshold = int(threshold)
			for _, keybytes := range publicKeys {
				pubKey, errF := btcec.ParsePubKey(keybytes, btcec.S256())
				if errF != nil {
					fmt.Printf("Invalid Public Key: %v\n", keybytes)
					return nil, fmt.Errorf("Invalid Public Key: %v", keybytes)
				}
				newProof.PublicKeys = append(newProof.PublicKeys, *pubKey)
			}
			bufferData := newProof.ToBytes()
			err = stub.PutState("Proof:"+name, bufferData)
			if err != nil {
				fmt.Printf("Error Saving Proof to Data %s\n", err)
				return nil, fmt.Errorf("Error Saving Proof to Data %s", err)
			}
		case proofTx.ProofTX_SECP256K1SHA2:
			fmt.Println("Creating Sha2 Proof")
			newProof := ElementProof.SecP256k1SHA2ElementProof{}
			newProof.ProofName = name
			newProof.State = ElementProof.Initialized
			newProof.Threshold = int(threshold)

			for _, keybytes := range publicKeys {
				pubKey, errF := btcec.ParsePubKey(keybytes, btcec.S256())
				if errF != nil {
					fmt.Printf("Invalid Public Key: %v\n", keybytes)
					return nil, fmt.Errorf("Invalid Public Key: %v", keybytes)
				}
				newProof.PublicKeys = append(newProof.PublicKeys, *pubKey)
			}

			for _, digest := range argsProof.Digests {
				if len(digest) != 32 {
					fmt.Println("Invalid Digest Length")
					return nil, fmt.Errorf("Invalid Digest Length")
				}
				var fixedDigest [32]byte
				copy(fixedDigest[:], digest)
				newProof.Digests = append(newProof.Digests, fixedDigest)
			}

			bufferData := newProof.ToBytes()
			err = stub.PutState("Proof:"+name, bufferData)
			if err != nil {
				fmt.Printf("Error Saving Proof to Data %s\n", err)
				return nil, fmt.Errorf("Error Saving Proof to Data %s", err)
			}
		default:
			fmt.Println("Invalid Proof Type")
			return nil, errors.New("Invalid Proof Type")
		}

		//Verify that these are publicKeys

		return nil, nil

	case "signProof":
		proofBytes, err := stub.GetState("Proof:" + argsProof.Name)
		if err != nil || len(proofBytes) == 0 {
			fmt.Printf("Could not retrieve:%s\n", argsProof.Name)
			return nil, fmt.Errorf("Could not retrieve:%s", argsProof.Name)
		}

		secpProof := new(ElementProof.SecP256k1ElementProof)
		secpShaProof := new(ElementProof.SecP256k1SHA2ElementProof)

		err = secpProof.FromBytes(proofBytes)
		if err == nil {
			result := secpProof.Signed(&argsProof.Signatures, argsProof.Data)
			if result == false {
				fmt.Println("Invalid Signatures")
				return nil, errors.New("Invalid Signatures")
			}
			proofBytes = secpProof.ToBytes()

			stub.PutState("Proof:"+secpProof.Name(), proofBytes)
		}

		err = secpShaProof.FromBytes(proofBytes)
		if err == nil {
			result := secpShaProof.Signed(&argsProof.Signatures, argsProof.Data)
			if result == false {
				fmt.Println("Invalid Signatures")
				return nil, errors.New("Invalid Signatures")
			}
			result = secpShaProof.Hash(argsProof.PreImages)
			if result == false {
				fmt.Println("Invalid Preimages")
				return nil, errors.New("Invalid Preimages")
			}
			proofBytes = secpShaProof.ToBytes()
			stub.PutState("Proof:"+secpShaProof.Name(), proofBytes)
		}

		return nil, nil

	case "revokeProof":
		proofBytes, err := stub.GetState("Proof:" + argsProof.Name)
		if err != nil || len(proofBytes) == 0 {
			fmt.Printf("Could not retrieve:%s\n", argsProof.Name)
			return nil, fmt.Errorf("Could not retrieve:%s", argsProof.Name)
		}

		secpProof := new(ElementProof.SecP256k1ElementProof)
		secpShaProof := new(ElementProof.SecP256k1SHA2ElementProof)

		err = secpProof.FromBytes(proofBytes)
		if err == nil {
			result := secpProof.Revoked(&argsProof.Signatures)
			if result == false {
				return nil, errors.New("Invalid Signatures")
			}
			proofBytes = secpProof.ToBytes()

			stub.PutState("Proof:"+secpProof.Name(), proofBytes)
		}

		err = secpShaProof.FromBytes(proofBytes)
		if err == nil {
			result := secpShaProof.Revoked(&argsProof.Signatures)
			if result == false {
				fmt.Println("Invalid Signatures")
				return nil, errors.New("Invalid Signatures")
			}
			proofBytes = secpShaProof.ToBytes()
			stub.PutState("Proof:"+secpShaProof.Name(), proofBytes)
		}
		return nil, nil

	case "supercedeProof":

		proofBytes, err := stub.GetState("Proof:" + argsProof.Name)
		if err != nil || len(proofBytes) == 0 {
			fmt.Printf("Could not retrieve:%s\n", argsProof.Name)
			return nil, fmt.Errorf("Could not retrieve:%s", argsProof.Name)
		}

		nameCheck, err := stub.GetState("Proof:" + argsProof.Supercede.Name)
		if len(nameCheck) > 0 {
			fmt.Printf("Invalid Superceding Name:%s\n", argsProof.Supercede.Name)
			return nil, fmt.Errorf("Invalid Superceding Name:%s", argsProof.Supercede.Name)
		}
		secpProof := new(ElementProof.SecP256k1ElementProof)
		secpShaProof := new(ElementProof.SecP256k1SHA2ElementProof)
		supercededBits, err := proto.Marshal(argsProof.GetSupercede())
		supercedeDigest := sha256.Sum256(supercededBits)
		digestHex := hex.EncodeToString(supercedeDigest[:])

		name := argsProof.Supercede.Name
		threshold := argsProof.Supercede.Threshold
		publicKeys := argsProof.Supercede.PubKeys

		if int(threshold) > len(publicKeys) {
			fmt.Printf("Invalid Threshold of %d for %d keys\n", threshold, len(publicKeys))
			return nil, fmt.Errorf("Invalid Threshold of %d for %d keys ", threshold, len(publicKeys))
		}

		var bufferData []byte
		switch argsProof.Supercede.Type {
		case proofTx.SupercededBy_SECP256K1:
			newProof := new(ElementProof.SecP256k1ElementProof)
			newProof.ProofName = name
			newProof.State = ElementProof.Initialized
			newProof.Threshold = int(threshold)
			for _, keybytes := range publicKeys {
				pubKey, errF := btcec.ParsePubKey(keybytes, btcec.S256())
				if errF != nil {
					fmt.Printf("Invalid Public Key: %v\n", keybytes)
					return nil, fmt.Errorf("Invalid Public Key: %v", keybytes)
				}
				newProof.PublicKeys = append(newProof.PublicKeys, *pubKey)
			}
			bufferData = newProof.ToBytes()

		case proofTx.SupercededBy_SECP256K1SHA2:
			newProof := ElementProof.SecP256k1SHA2ElementProof{}
			newProof.ProofName = name
			newProof.State = ElementProof.Initialized
			newProof.Threshold = int(threshold)

			for _, keybytes := range publicKeys {
				pubKey, errF := btcec.ParsePubKey(keybytes, btcec.S256())
				if errF != nil {
					fmt.Printf("Invalid Public Key: %v\n", keybytes)
					return nil, fmt.Errorf("Invalid Public Key: %v", keybytes)
				}
				newProof.PublicKeys = append(newProof.PublicKeys, *pubKey)
			}

			for _, digest := range argsProof.Supercede.Digests {
				if len(digest) != 32 {
					fmt.Println("Invalid Digest Length")
					return nil, fmt.Errorf("Invalid Digest Length")
				}
				var fixedDigest [32]byte
				copy(fixedDigest[:], digest)
				newProof.Digests = append(newProof.Digests, fixedDigest)
			}

			bufferData = newProof.ToBytes()

		default:
			fmt.Println("Invalid Proof Type")
			return nil, errors.New("Invalid Proof Type")
		}

		err = secpProof.FromBytes(proofBytes)
		if err == nil {
			result := secpProof.Supercede(&argsProof.Signatures, digestHex, argsProof.Supercede.Name)
			if result == false {
				fmt.Printf("Invalid Signatures. Digest: %s\n", digestHex)
				return nil, errors.New("Invalid Signatures")
			}
			proofBytes = secpProof.ToBytes()

			stub.PutState("Proof:"+secpProof.Name(), proofBytes)
		}

		err = secpShaProof.FromBytes(proofBytes)
		if err == nil {
			result := secpShaProof.Supercede(&argsProof.Signatures, digestHex, argsProof.Supercede.Name)
			if result == false {
				fmt.Printf("Invalid Signatures. Digest: %s\n", digestHex)
				return nil, errors.New("Invalid Signatures")
			}
			proofBytes = secpShaProof.ToBytes()
			stub.PutState("Proof:"+secpShaProof.Name(), proofBytes)
		}

		err = stub.PutState("Proof:"+name, bufferData)
		if err != nil {
			fmt.Printf("Error Saving Proof to Data %s\n", err)
			return nil, fmt.Errorf("Error Saving Proof to Data %s", err)
		}

		return nil, nil
	default:
		fmt.Println("Invalid function type")
		return nil, errors.New("Invalid function type")
	}
}

// Query callback representing the query of a chaincode
func (t *kevlarChainCode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	fmt.Printf("function: %s", function)
	switch function {
	case "status":
		if len(args) != 1 {
			return nil, fmt.Errorf("No argument specified")
		}
		name := args[0]
		proofBytes, err := stub.GetState("Proof:" + name)

		if err != nil || len(proofBytes) == 0 {
			return nil, fmt.Errorf("%s is not found", name)
		}
		secpProof := new(ElementProof.SecP256k1ElementProof)
		secpShaProof := new(ElementProof.SecP256k1SHA2ElementProof)

		err = secpProof.FromBytes(proofBytes)
		if err == nil {
			return secpProof.ToJSON(), nil
		}

		err = secpShaProof.FromBytes(proofBytes)
		if err == nil {
			return secpShaProof.ToJSON(), nil
		}

		return nil, nil
	default:
		return nil, errors.New("Unsupported operation")
	}
}

func main() {
	err := shim.Start(new(kevlarChainCode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s\n", err)
	}
}
