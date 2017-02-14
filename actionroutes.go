package main

import (
	"net/http"
	"bytes"
	"log"
)


func HandleActionGenerateKey(w http.ResponseWriter, r *http.Request)  {
    buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)
	msg, err := MessageFromString(buf.Bytes())
	if err != nil{
		log.Fatal("Error: ", err)
	}
	w.Write([]byte(ActionKeyGen(msg)))
}

func HandleActionExpandKey(w http.ResponseWriter, r *http.Request)  {
    buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)
	msg, err := MessageFromString(buf.Bytes())
	if err != nil{
		log.Fatal("Error: ", err)
	}
	w.Write([]byte(ActionExpandKey(msg)))
}

func HandleActionSignKey(w http.ResponseWriter, r *http.Request)  {
    buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)
	msg, err := MessageFromString(buf.Bytes())
	if err != nil{
		log.Fatal("Error: ", err)
	}
	w.Write([]byte(ActionSignKey(msg)))
}

func HandleActionUpdateKey(w http.ResponseWriter, r *http.Request)  {
    buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)
	msg, err := MessageFromString(buf.Bytes())
	if err != nil{
		log.Fatal("Error: ", err)
	}
	w.Write([]byte(ActionUpdateKey(msg)))
}