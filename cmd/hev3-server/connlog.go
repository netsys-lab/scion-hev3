package main

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// connLog writes one JSON line per QUIC connection of the SCION listener
// when the connection ends: how long the server kept state for it, what
// it sent and received, and how it was closed. It exists for experiments
// that measure what the connection attempts of a client cost a server
// (draft-john-scion-happy-eyeballs, Experiment Goals).
type connLog struct {
	mu sync.Mutex
	w  io.Writer
}

type connRecord struct {
	Start      time.Time `json:"start"`
	ConnID     string    `json:"conn_id"`
	LifetimeMs float64   `json:"lifetime_ms"`
	SentPkts   int       `json:"sent_pkts"`
	SentBytes  int       `json:"sent_bytes"`
	RecvPkts   int       `json:"recv_pkts"`
	RecvBytes  int       `json:"recv_bytes"`
	Closed     bool      `json:"closed"`              // a close event was recorded
	Initiator  string    `json:"initiator,omitempty"` // "local" (server) or "remote" (client)
	Trigger    string    `json:"trigger,omitempty"`   // e.g. "idle_timeout"
	Reason     string    `json:"reason,omitempty"`
	AppError   *uint64   `json:"app_error,omitempty"`
	ConnError  *uint64   `json:"conn_error,omitempty"`
}

// tracer is the quic.Config.Tracer of the SCION listener.
func (l *connLog) tracer(_ context.Context, isClient bool, id quic.ConnectionID) qlogwriter.Trace {
	if isClient {
		return nil
	}
	return &connTrace{log: l, rec: connRecord{Start: time.Now(), ConnID: id.String()}}
}

type connTrace struct {
	log  *connLog
	mu   sync.Mutex
	rec  connRecord
	open int
	done bool
}

func (t *connTrace) SupportsSchemas(schema string) bool { return schema == qlog.EventSchema }

func (t *connTrace) AddProducer() qlogwriter.Recorder {
	t.mu.Lock()
	t.open++
	t.mu.Unlock()
	return (*connRecorder)(t)
}

type connRecorder connTrace

func (r *connRecorder) RecordEvent(ev qlogwriter.Event) {
	t := (*connTrace)(r)
	t.mu.Lock()
	defer t.mu.Unlock()
	switch e := ev.(type) {
	case qlog.PacketSent:
		t.rec.SentPkts++
		t.rec.SentBytes += e.Raw.Length
	case *qlog.PacketSent:
		t.rec.SentPkts++
		t.rec.SentBytes += e.Raw.Length
	case qlog.PacketReceived:
		t.rec.RecvPkts++
		t.rec.RecvBytes += e.Raw.Length
	case *qlog.PacketReceived:
		t.rec.RecvPkts++
		t.rec.RecvBytes += e.Raw.Length
	case qlog.ConnectionClosed:
		t.closed(e)
	case *qlog.ConnectionClosed:
		t.closed(*e)
	}
}

func (t *connTrace) closed(e qlog.ConnectionClosed) {
	t.rec.Closed = true
	t.rec.Initiator = string(e.Initiator)
	t.rec.Trigger = string(e.Trigger)
	t.rec.Reason = e.Reason
	if e.ApplicationError != nil {
		v := uint64(*e.ApplicationError)
		t.rec.AppError = &v
	}
	if e.ConnectionError != nil {
		v := uint64(*e.ConnectionError)
		t.rec.ConnError = &v
	}
}

// Close ends one producer; the record is written when the last one ends.
func (r *connRecorder) Close() error {
	t := (*connTrace)(r)
	t.mu.Lock()
	t.open--
	if t.open > 0 || t.done {
		t.mu.Unlock()
		return nil
	}
	t.done = true
	rec := t.rec
	t.mu.Unlock()
	rec.LifetimeMs = float64(time.Since(rec.Start)) / float64(time.Millisecond)
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	t.log.mu.Lock()
	defer t.log.mu.Unlock()
	_, err = t.log.w.Write(append(b, '\n'))
	return err
}
