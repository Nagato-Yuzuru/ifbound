package ipc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestFrameGolden records the exact JSON payload of each frame that this
// package writes. A peer of the same protocol version reads these bytes, so
// a change here is a wire change. Make it on purpose only.
func TestFrameGolden(t *testing.T) {
	protected := true
	tests := []struct {
		name string
		env  envelope
		want string
	}{
		{
			name: "observe",
			env: envelopeOf(typeObserve, observeBody{
				QName: "a.example.", Addrs: []string{"192.0.2.1", "2001:db8::1"}, TTLSeconds: 60, TimeoutMS: 500,
			}),
			want: `{"v":3,"type":"observe","body":{"qname":"a.example.","addrs":["192.0.2.1","2001:db8::1"],"ttl_s":60,"timeout_ms":500}}`,
		},
		{
			name: "observe without addresses",
			env:  envelopeOf(typeObserve, observeBody{QName: "a.example.", Addrs: []string{}, TimeoutMS: 1}),
			want: `{"v":3,"type":"observe","body":{"qname":"a.example.","addrs":[],"ttl_s":0,"timeout_ms":1}}`,
		},
		{
			name: "probe",
			env:  envelopeOf(typeProbe, probeBody{QName: "p.example."}),
			want: `{"v":3,"type":"probe","body":{"qname":"p.example."}}`,
		},
		{
			name: "ack without body",
			env:  envelopeOf(typeAck, nil),
			want: `{"v":3,"type":"ack"}`,
		},
		{
			name: "ack of an observation",
			env:  envelopeOf(typeAck, ackBody{Protected: &protected}),
			want: `{"v":3,"type":"ack","body":{"protected":true}}`,
		},
		{
			name: "reject",
			env:  envelopeOf(typeReject, rejectBody{Reason: "no"}),
			want: `{"v":3,"type":"reject","body":{"reason":"no"}}`,
		},
		{
			name: "status request",
			env:  envelopeIn(controlVersion, typeStatus, nil),
			want: `{"v":1,"type":"status"}`,
		},
		{
			name: "status with empty lists",
			env:  envelopeIn(controlVersion, typeAck, boundStatus(StatusReport{Daemon: "dev", State: StateReady, Config: "ab"})),
			want: `{"v":1,"type":"ack","body":{"daemon":"dev","state":"ready","reasons":null,"warnings":null,"policies":null,"retain_restart":false,"config":"ab"}}`,
		},
		{
			name: "status with lists",
			env: envelopeIn(controlVersion, typeAck, boundStatus(StatusReport{
				Daemon:        "dev",
				State:         StateDegraded,
				Reasons:       []string{"r"},
				Warnings:      []Warning{{Source: "s", Text: "t"}},
				Policies:      []PolicyCount{{Name: "web", Addrs: 2}},
				RetainRestart: true,
				Config:        "ab",
			})),
			want: `{"v":1,"type":"ack","body":{"daemon":"dev","state":"degraded","reasons":["r"],"warnings":[{"source":"s","text":"t"}],"policies":[{"name":"web","addrs":2}],"retain_restart":true,"config":"ab"}}`,
		},
		{
			name: "apply",
			env:  envelopeIn(controlVersion, typeApply, applyBody{Config: []byte("x = 1\n"), DeadlineMS: 1700000000000}),
			want: `{"v":1,"type":"apply","body":{"config":"eCA9IDEK","deadline_unix_ms":1700000000000}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeFrame(&buf, tt.env); err != nil {
				t.Fatalf("writeFrame: %v", err)
			}
			frame := buf.Bytes()
			if n := binary.BigEndian.Uint32(frame); int(n) != len(frame)-4 {
				t.Fatalf("length prefix %d, payload %d bytes", n, len(frame)-4)
			}
			if got := string(frame[4:]); got != tt.want {
				t.Errorf("payload\n got %s\nwant %s", got, tt.want)
			}
		})
	}
}
