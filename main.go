package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	ci "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
)

func main() {
	size := flag.Int("bitsize", 2048, "select the bitsize of the key to generate")
	typ := flag.String("type", "RSA", "select type of key to generate (RSA or Ed25519)")
	file := flag.Bool("f", false, "output public and private key to files, instead of stdout")
	prvout := flag.String("prvout", "priv.key", "output file for private key")
	pidout := flag.String("pidout", "peer.id", "output file for peer id")

	flag.Parse()

	var atyp int
	switch strings.ToLower(*typ) {
	case "rsa":
		atyp = ci.RSA
	case "ed25519":
		atyp = ci.Ed25519
	default:
		fmt.Fprintln(os.Stderr, "unrecognized key type: ", *typ)
		os.Exit(1)
	}

	priv, pub, err := ci.GenerateKeyPair(atyp, *size)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *file {
		pidf, err := os.Create(*pidout)
		if err != nil {
			log.Fatalf("failed to open pid file: %v\n", err)
		}
		defer pidf.Close()
		if _, err := pidf.WriteString(pid.Pretty()); err != nil {
			log.Fatalf("failed to write pid to file: %v\n", err)
		}
	} else {
		fmt.Fprintln(os.Stdout, pid.Pretty())
	}

	data, err := priv.Bytes()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	b64data := base64.StdEncoding.EncodeToString(data)

	if *file {
		privf, err := os.Create(*prvout)
		if err != nil {
			log.Fatalf("failed to open private key file: %v\n", err)
		}
		defer privf.Close()
		if _, err := privf.WriteString(b64data); err != nil {
			log.Fatalf("failed to write to private key file: %v\n", err)
		}
	} else {
		fmt.Fprintln(os.Stdout, b64data)
	}
}
