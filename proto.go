package main

import (
	"encoding/json"
)

type ProtocolAction int

func ErrorResponse(message string) string {
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
	PublicKey,
	PrivateKey,
	SubjectKey,
	Passphrase,
	Name,
	Email string
}

func MessageFromString(bytes []byte) (ProtocolMessage, error) {
	var f interface{}
	
	message := ProtocolMessage{}
	
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

