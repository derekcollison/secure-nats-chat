// Copyright(c) 2015 Derek Collison (derek.collison@gmail.com)

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"

	"github.com/nats-io/nats"
)

func usage() {
	log.Fatalf("Usage: nats-chat <subject> <key>\n")
}

const (
	natsUrl    = "nats://demo.nats.io:4443"
	serverName = "demo.nats.io"
)

// Hold name, key and subject
var name, subj, key string
var keyHash []byte

// Cipher
var gcm cipher.AEAD
var nonce []byte

// Messages we send
type chat struct {
	Name string
	Msg  []byte
}

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
	block, err := aes.NewCipher(keyHash)
	if err != nil {
		log.Fatalf("Can't create cipher: %v\n", err)
	}
	gcm, err = cipher.NewGCMWithNonceSize(block, sha256.Size)
	if err != nil {
		log.Fatalf("Can't create gcm: %v\n", err)
	}

	// Generate the nonce
	h.Write([]byte(subj))
	h.Write(keyHash)
	nonce = h.Sum(nil)

	// Connect securely to NATS
	nc, err := nats.SecureConnect(natsUrl)
	if err != nil {
		log.Fatalf("Got an error on Connect with Secure Options: %+v\n", err)
	}
	log.Printf("Securely connected to %s", natsUrl)
	ec, _ := nats.NewEncodedConn(nc, nats.GOB_ENCODER)

	// Setup signal handlers to signal leaving.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		for range c {
			fmt.Printf("\n\n")
			if name != "" {
				exit := &chat{Name: name, Msg: encrypt("<left>\n")}
				ec.Publish(subj, exit)
				ec.Flush()
			}
			os.Exit(0)
		}
	}()

	// Collect the name
	fmt.Printf("Enter Name: ")
	fmt.Scanln(&name)

	// Create a reader for stdin
	reader := bufio.NewReader(os.Stdin)

	// Subscribe to messages
	ec.Subscribe(subj, func(msg *chat) {
		if msg.Name == name {
			return
		}
		fmt.Printf("\033[2K\r[%s] %s", msg.Name, decrypt(msg))
		fmt.Printf("[%s] ", name)
	})

	// Send welcome
	welcome := &chat{Name: name, Msg: encrypt("<joined>\n")}
	ec.Publish(subj, welcome)

	// Wait on new messages to send
	for {
		fmt.Printf("[%s] ", name)
		msg, _ := reader.ReadString('\n')
		ec.Publish(subj, chat{Name: name, Msg: encrypt(msg)})
	}

	runtime.Goexit()
}

func encrypt(msg string) []byte {
	plaintext := []byte(msg)
	return gcm.Seal(nil, nonce, plaintext, []byte(name))
}

func decrypt(msg *chat) string {
	v, err := gcm.Open(nil, nonce, msg.Msg, []byte(msg.Name))
	if err != nil {
		return "<unable to decrypt, wrong key?>\n"
	}
	return string(v)
}
