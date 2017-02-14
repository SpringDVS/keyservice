package main 

import (
	"bytes"
	"encoding/hex"
	"encoding/binary"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func ActionKeyGen(message ProtocolMessage) string {
	if message.Name == "" || message.Email == "" || message.Passphrase == "" {
		return ErrorResponse(&message, "Mandatory field left blank")
	}
	

	// ToDo: Check the default config 
	entity,err := openpgp.NewEntity(message.Name,"",message.Email,nil)
	
	
	// Encrypt method available after merging CL #7753647
	entity.PrivateKey.Encrypt([]byte(message.Passphrase))
	
	for _,sub := range entity.Subkeys {
		// encrypt each subkey with the same passphrase
		sub.PrivateKey.Encrypt([]byte(message.Passphrase))
	}
	pribuf, err := entityPrivateArmor(entity)
	if err != nil {
		return ErrorResponse(&message, "Error encoding private key armor")
	}
	pubbuf, err := entityPublicArmor(entity)
	if err != nil {
		return ErrorResponse(&message, "Error encoding public key armor")
	}
	
	return JsonKeyPair(pubbuf, pribuf)
}

func ActionExpandKey(message ProtocolMessage) string {
	if message.PublicKey == "" {
		return ErrorResponse(&message, "Mandatory field left blank")
	}
	
	
	bufr := bytes.NewReader([]byte(message.PublicKey))
	
	block, err := armor.Decode(bufr)
	
	if err != nil {
		return ErrorResponse(&message, "Error decoding public armor")
	}
	
	if block.Type != openpgp.PublicKeyType {
		return ErrorResponse(&message, "Does not decode to public key")
	}
	
	blockr := packet.NewReader(block.Body)
	entity, err := openpgp.ReadEntity(blockr)
	
	if err != nil {
		return ErrorResponse(&message, "Error decoding public entity from block")
	}	
	var name, email, keyid string
	var m string
	for _, ident := range entity.Identities {

		signatures := make([]string, len(ident.Signatures) + 1)

		n := *ident.SelfSignature.IssuerKeyId;
		name = ident.UserId.Name
		email = ident.UserId.Email
		keyid = keyidToLongId(n)
		
		i := 0
		signatures[i] = keyid
		i++
		for _,sig := range ident.Signatures {
			n = *sig.IssuerKeyId;
			signatures[i] = keyidToLongId(n)
			i++
		}
		
		m = JsonCertificate(name, email, keyid, signatures)
	}
	
	return m
	
}

func ActionSignKey(message ProtocolMessage) string {
	if message.PublicKey == "" || message.PrivateKey == "" || message.Passphrase == "" {
		return ErrorResponse(&message, "Mandatory field left blank")
	}
	
	
	pubr := bytes.NewReader([]byte(message.PublicKey))
	prir := bytes.NewReader([]byte(message.PrivateKey))
	
	blockpub, err := armor.Decode(pubr)
	if err != nil {
		return ErrorResponse(&message, "Error decoding public armor")
	}
	
	blockpri, err := armor.Decode(prir)
	if err != nil {
		return ErrorResponse(&message, "Error decoding private armor")
	}
	

	if blockpub.Type != openpgp.PublicKeyType {
		return ErrorResponse(&message, "Does not decode as public key")
	}
	
	if blockpri.Type != openpgp.PrivateKeyType {
		return ErrorResponse(&message, "Does not decode as private key")
	}
	
	bpubr := packet.NewReader(blockpub.Body)
	bprir := packet.NewReader(blockpri.Body)
	
	entitypub, err := openpgp.ReadEntity(bpubr)
	if err != nil {
		return ErrorResponse(&message, "Error decoding public entity from block")
	}
	entitypri, err := openpgp.ReadEntity(bprir)
	if err != nil {
		return ErrorResponse(&message, "Error decoding private entity from block")
	}
	
	err = entitypri.PrivateKey.Decrypt([]byte(message.Passphrase))
	if err != nil {
		return ErrorResponse(&message, "Bad passphrase")
	}
	
	for _,v := range entitypub.Identities  {
		entitypub.SignIdentity(v.Name, entitypri, nil)
	}


	if err != nil {
		return ErrorResponse(&message,err.Error())
	}
	armor, err := entityPublicArmor(entitypub)
	if err != nil {
		return ErrorResponse(&message,err.Error())
	}

	return JsonPublicKey(armor)
}

func ActionUpdateKey(message ProtocolMessage) string {
	if message.PublicKey == "" || message.SubjectKey == "" {
		return ErrorResponse(&message, "Mandatory field left blank")
	}
	
	pubr := bytes.NewReader([]byte(message.PublicKey))
	subr := bytes.NewReader([]byte(message.SubjectKey))
	
	blockpub, err := armor.Decode(pubr)
	if err != nil {
		return ErrorResponse(&message, "Error decoding public armor")
	}
	
	blocksub, err := armor.Decode(subr)
	if err != nil {
		return ErrorResponse(&message, "Error decoding subject armor")
	}
	
	bpubr := packet.NewReader(blockpub.Body)
	bsubr := packet.NewReader(blocksub.Body)
	
	entitypub, err := openpgp.ReadEntity(bpubr)
	if err != nil {
		return ErrorResponse(&message, "Error decoding public entity from block")
	}
	entitysub, err := openpgp.ReadEntity(bsubr)
	if err != nil {
		return ErrorResponse(&message, "Error decoding subject entity from block")
	}
	
	for name, identity := range entitypub.Identities {
		for _, pubsig := range identity.Signatures {
			exists := false
			
			for _, subsig := range entitysub.Identities[name].Signatures {
				if subsig.IssuerKeyId == pubsig.IssuerKeyId {
					exists = true
					break
				}
			}
			
			if !exists {
				entitysub.Identities[name].Signatures = append(entitysub.Identities[name].Signatures, pubsig)
			}
		}
	} 

	armor, err := entityPublicArmor(entitysub)
	if err != nil {
		return ErrorResponse(&message,err.Error())
	}

	return JsonPublicKey(armor)
}

func entityPublicArmor(entity *openpgp.Entity) (string, error) {
	buf := bytes.NewBuffer(nil)
	keyw, err := armor.Encode(buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return "", err
	}
	entity.Serialize(keyw)
	keyw.Close()
	
	return buf.String(),nil
}

func entityPrivateArmor(entity *openpgp.Entity) (string, error) {
	buf := bytes.NewBuffer(nil)
	keyw, err := armor.Encode(buf, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		return "", err
	}
	entity.SerializePrivate(keyw,nil)
	keyw.Close()
	
	return buf.String(),nil
}

func keyidToLongId(keyid uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, keyid)
	return hex.EncodeToString(buf)
}