package main

import (
	"net/http"
	"bytes"
	"log"
)


func logInteraction(action, iid string, r *http.Request) {
	
	remote := r.Header.Get("x-forwarded-for")
	
	if remote == "" {
		remote = r.RemoteAddr
	}
	
	log.Println("Servicing", action, "request from", remote, "[ "+iid+" ]")
}

func HandleActionGenerateKey(w http.ResponseWriter, r *http.Request)  {
	iid := GenerateInteractionId()
	logInteraction("`generate`", iid, r)

	buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)
	msg, err := MessageFromString(buf.Bytes(),iid)
	if err != nil{
		w.Write([]byte(ErrorResponse(&msg, "Bad JSON formatted request")))
		return
	}
	w.Write([]byte(ActionKeyGen(msg)))
}

func HandleActionExpandKey(w http.ResponseWriter, r *http.Request)  {

	iid := GenerateInteractionId()
	logInteraction("`expand`", iid, r)

	buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)    
	msg, err := MessageFromString(buf.Bytes(),iid)
	if err != nil{
		w.Write([]byte(ErrorResponse(&msg, "Bad JSON formatted request")))
		return
	}
	w.Write([]byte(ActionExpandKey(msg)))
}

func HandleActionSignKey(w http.ResponseWriter, r *http.Request)  {
	
	iid := GenerateInteractionId()
	logInteraction("`sign`",iid, r)
    
    buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)
	msg, err := MessageFromString(buf.Bytes(),iid)
	if err != nil{
		w.Write([]byte(ErrorResponse(&msg, "Bad JSON formatted request")))
		return
	}
	w.Write([]byte(ActionSignKey(msg)))
}

func HandleActionUpdateKey(w http.ResponseWriter, r *http.Request)  {
	
	iid := GenerateInteractionId()
	logInteraction("`update`", iid, r)
	
    buf := bytes.NewBuffer(nil)
	buf.ReadFrom(r.Body)
	msg, err := MessageFromString(buf.Bytes(),iid)
	if err != nil{
		w.Write([]byte(ErrorResponse(&msg, "Bad JSON formatted request")))
		return
	}
	w.Write([]byte(ActionUpdateKey(msg)))
}