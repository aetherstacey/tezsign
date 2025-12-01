package common

import (
	"context"

	"github.com/google/gousb"
)

type result struct {
	n   int
	err error
}

type libusbWriter struct {
	ep *gousb.OutEndpoint
}

func newLibusbWriter(ep *gousb.OutEndpoint) *libusbWriter {
	return &libusbWriter{ep: ep}
}

func (w *libusbWriter) WriteContext(ctx context.Context, p []byte) (int, error) {
	for {
		n, err := w.ep.WriteContext(ctx, p)
		if err != nil {
			return n, err
		}
		if n == len(p) {
			w.ep.WriteContext(ctx, []byte{}) // ZLP
			return n, nil
		}
		p = p[n:]
	}
}
