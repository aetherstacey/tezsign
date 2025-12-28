package main

import (
	"github.com/tez-capital/tezsign/secure"
	"github.com/tez-capital/tezsign/signerpb"
	"google.golang.org/protobuf/proto"
)

func marshalOK(ok bool) []byte {
	b, _ := proto.Marshal(&signerpb.Response{
		Payload: &signerpb.Response_Ok{
			Ok: &signerpb.Ok{
				Ok: ok,
			},
		},
	})

	return b
}

func marshalErr(code uint32, msg string) []byte {
	b, _ := proto.Marshal(&signerpb.Response{
		Payload: &signerpb.Response_Error{
			Error: &signerpb.Error{
				Code:    code,
				Message: msg,
			},
		},
	})

	return b
}

func wipeReq(r *signerpb.Request) {
	switch p := r.Payload.(type) {
	case *signerpb.Request_Unlock:
		if p.Unlock != nil && p.Unlock.Passphrase != nil {
			secure.MemoryWipe(p.Unlock.Passphrase)
			p.Unlock.Passphrase = nil
		}
	case *signerpb.Request_NewKeys:
		if p.NewKeys != nil && p.NewKeys.Passphrase != nil {
			secure.MemoryWipe(p.NewKeys.Passphrase)
			p.NewKeys.Passphrase = nil
		}
	case *signerpb.Request_DeleteKeys:
		if p.DeleteKeys != nil && p.DeleteKeys.Passphrase != nil {
			secure.MemoryWipe(p.DeleteKeys.Passphrase)
			p.DeleteKeys.Passphrase = nil
		}
	}
}
