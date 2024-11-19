package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	sourceChainRPC        = ""
	targetChainRPC        = ""
	privateKey            = ""
	contractAddress       = ""
	targetContractAddress = ""
)

func main() {
	sourceClient, err := ethclient.Dial(sourceChainRPC)
	if err != nil {
		log.Fatalf("Failed to connect to source chain: %v", err)
	}
	defer sourceClient.Close()

	targetClient, err := ethclient.Dial(targetChainRPC)
	if err != nil {
		log.Fatalf("Failed to connect to target chain: %v", err)
	}
	defer targetClient.Close()

	privateKeyECDSA, err := crypto.HexToECDSA(strings.TrimPrefix(privateKey, "0x"))
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Failed to get public key")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Subscribe to events on the source chain
	query := ethereum.FilterQuery{
		Addresses: []common.Address{common.HexToAddress(contractAddress)},
	}

	logs := make(chan types.Log)
	sub, err := sourceClient.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatalf("Failed to subscribe to events: %v", err)
	}

	fmt.Println("Listening for events on the source chain...")

	// Relay transactions to the target chain
	for {
		select {
		case err := <-sub.Err():
			log.Fatalf("Subscription error: %v", err)
		case vLog := <-logs:
			fmt.Printf("New event: %+v\n", vLog)

			// Extract and process the event data
			data := vLog.Data

			// Relay the data to the target chain
			err := relayToTargetChain(targetClient, fromAddress, privateKeyECDSA, data)
			if err != nil {
				log.Printf("Failed to relay transaction: %v", err)
			} else {
				fmt.Println("Transaction relayed successfully!")
			}
		}
	}
}

// relayToTargetChain relays data to the target chain
func relayToTargetChain(client *ethclient.Client, fromAddress common.Address, privateKey *ecdsa.PrivateKey, data []byte) error {
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %v", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get gas price: %v", err)
	}

	// Create the transaction to the target contract
	tx := types.NewTransaction(
		nonce,
		common.HexToAddress(targetContractAddress),
		big.NewInt(0),
		300000,
		gasPrice,
		data,
	)

	// Sign the transaction
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get network ID: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Send the transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction sent: %s\n", signedTx.Hash().Hex())
	return nil
}
