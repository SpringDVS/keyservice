package main

import (
	"log"
	"encoding/json"
	"encoding/hex"
	"crypto/sha256"
	"math/rand"
	"time"
	"strconv"
)

type ProtocolAction int

func ErrorResponse(protomsg *ProtocolMessage, message string) string {
	
	log.Println("Failed to perform action -- " + message + " [ "+protomsg.InteractionId+" ]")
	return "{\"result\":\"error\",\"response\":\"" + message + "\"}"
}

func SuccessResponse(message string) string {
	return "{\"result\":\"ok\",\"response\":" + message +"}"
}

const (
	KeyGen ProtocolAction = iota
	Import ProtocolAction = iota
	Sign ProtocolAction = iota
)

type ProtocolData struct {

}

type ProtocolMessage struct {
	InteractionId,
	PublicKey,
	PrivateKey,
	SubjectKey,
	Passphrase,
	Name,
	Email string
}

func MessageFromString(bytes []byte, iid string) (ProtocolMessage, error) {
	
	var f interface{}
	
	message := ProtocolMessage{}
	
	message.InteractionId = iid
	err := json.Unmarshal(bytes, &f)
	
	if err != nil {
		return message,err
	}
	
	for k,vi := range f.(map[string]interface{}) {
		v := vi.(string) 
		switch k {
			case "email": message.Email = v
			case "name": message.Name = v
			case "public": message.PublicKey = v
			case "private": message.PrivateKey = v
			case "subject": message.SubjectKey = v
			case "passphrase": message.Passphrase = v
		}
	}
		return message,nil
}

func GenerateInteractionId() string {
	hasher := sha256.New224()
	partA := strconv.FormatInt(time.Now().UnixNano(), 16);
	rand.Seed(time.Now().UnixNano())
	partB := strconv.FormatInt(rand.Int63(), 16);
	
	hasher.Write([]byte(string(partA + partB)))
	return hex.EncodeToString(hasher.Sum(nil))
}

func JsonKeyPair(public, private string) string {
	pub,_ := json.Marshal(public)
	pri,_ := json.Marshal(private)
	m := "{\"public\":"+string(pub)+",\"private\":"+string(pri)+"}"
	return SuccessResponse(m)
}

func JsonPublicKey(public string) string {
	pub,_ := json.Marshal(public)
	m := "{\"public\":"+string(pub)+"}"
	return SuccessResponse(m)
}

func JsonCertificate(name, email,  keyid string, signatures []string) string {
	jsigs, _ := json.Marshal(signatures)
	m := "{\"name\":\"" + name + "\",\"email\":\"" + email + "\",\"keyid\":\"" + keyid + "\",\"sigs\":" + string(jsigs) + "}"
	return SuccessResponse(m)
}  

