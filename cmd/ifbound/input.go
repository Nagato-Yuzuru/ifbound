package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Nagato-Yuzuru/ifbound/internal/ipc"
)

// frameRoom is the part of a frame that is not the file: the envelope,
// the field names, and the deadline.
const frameRoom = 1024

// maxConfigBytes is the largest file that fits in one frame. The file
// travels as base64 in JSON, so 3 bytes take 4.
const maxConfigBytes = (ipc.MaxFrameSize - frameRoom) / 4 * 3

var errFileTooLarge = errors.New("file too large")

// readInput reads the file at path, at most maxConfigBytes. The read ends
// when ctx ends: a FIFO or a device can block it. The reading goroutine
// then stays until the read returns or the process exits. It sends into a
// buffered channel, so it never blocks on a caller that is gone.
func readInput(ctx context.Context, path string) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := readLimited(path)
		done <- result{data, err}
	}()
	select {
	case r := <-done:
		return r.data, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("reading %s: %w", path, ctx.Err())
	}
}

func readLimited(path string) (data []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err // the error has the path
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	data, err = io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err // the error has the path
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("%s: %w (max %d bytes)", path, errFileTooLarge, maxConfigBytes)
	}
	return data, nil
}
