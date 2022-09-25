package resolver

import (
	"context"

	"github.com/miekg/dns"
)

func Lookup(req dns.Question, ctx context.Context) dns.RR {
	if req.Name == "" {
		return nil
	}
	msg := dns.Msg{}
	msg.SetQuestion(req.Name, req.Qclass)
	//dns.ExchangeContext(ctx,)
	return nil
}
