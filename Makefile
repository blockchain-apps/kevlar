all: proto

proto: protoc_middleman_go

protoc_middleman_go: kevlar_tx_proto
	@touch protoc_middleman_go
	
kevlar_tx_proto: ./ProofTx/proofTx.proto
	rm -f ./ProofTx/proofTx.pb.go
	protoc --go_out=./ ./ProofTx/proofTx.proto

test:
	go test -run Invoke