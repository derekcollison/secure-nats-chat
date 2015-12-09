// Copyright 2015 Derek Collison All rights reserved.

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"

	"github.com/nats-io/nats"
)

func usage() {
	log.Fatalf("Usage: nats-chat <subject> <key> \n")
}

const (
	natsUrl    = "nats://demo.nats.io:4443"
	serverName = "demo.nats.io"
)

// Hold name, key and subject
var name, subj, key string
var keyHash []byte

// Cipher block
var block cipher.Block

func main() {
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		usage()
	}
	subj, key = args[0], args[1]
	h := sha256.New()
	h.Write([]byte(key))
	keyHash = h.Sum(nil)

	// Create cipher
	var err error
	block, err = aes.NewCipher(keyHash)
	if err != nil {
		log.Fatalf("Can't create cipher: %v\n", err)
	}

	nc, err := nats.SecureConnect(natsUrl)
	if err != nil {
		log.Fatalf("Got an error on Connect with Secure Options: %+v\n", err)
	}
	log.Printf("Securely connected to %s", natsUrl)
	ec, _ := nats.NewEncodedConn(nc, nats.GOB_ENCODER)

	// Messages we send
	type natsChat struct {
		Name string
		Msg  []byte
	}

	// Setup signal handlers to signal leaving.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		for range c {
			fmt.Printf("\n\n")
			exit := &natsChat{Name: name, Msg: encrypt("<left>\n")}
			ec.Publish(subj, exit)
			ec.Flush()
			os.Exit(0)
		}
	}()

	// Collect the name
	fmt.Printf("Enter Name: ")
	fmt.Scanln(&name)

	// Subscribe to messages
	ec.Subscribe(subj, func(msg *natsChat) {
		if msg.Name == name {
			return
		}
		//		fmt.Printf("Received a message! %+v\n", msg)
		fmt.Printf("\r[%s] %s", msg.Name, decrypt(msg.Msg))
		fmt.Printf("[%s] ", name)
	})

	// Send welcome
	welcome := &natsChat{Name: name, Msg: encrypt("<joined>\n")}
	ec.Publish(subj, welcome)

	// Wait on new messages to send
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("[%s] ", name)
		msg, _ := reader.ReadString('\n')
		ec.Publish(subj, natsChat{Name: name, Msg: encrypt(msg)})
	}

	runtime.Goexit()
}

func encrypt(msg string) []byte {
	plaintext := []byte(msg)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("Can't read crypto/rand: %v\n", err)
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext
}

func decrypt(ciphertext []byte) string {
	iv := ciphertext[:aes.BlockSize]
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])
	return string(plaintext)
}
