package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRingBuffer(t *testing.T) {
	// write size greater than cap
	buf := NewRingBuffer(10)
	n, err := buf.Write([]byte("12345678901"))
	require.NoError(t, err)
	require.Equal(t, n, 11)
	require.Equal(t, []byte("2345678901"), buf.Bytes())

	// write size lower than cap
	buf = NewRingBuffer(10)
	n, err = buf.Write([]byte("12345"))
	require.NoError(t, err)
	require.Equal(t, n, 5)
	require.Equal(t, []byte("12345"), buf.Bytes())

	// write size exact equal to cap
	n, err = buf.Write([]byte("67890"))
	require.NoError(t, err)
	require.Equal(t, n, 5)
	require.Equal(t, []byte("1234567890"), buf.Bytes())

	// write overlap
	n, err = buf.Write([]byte("12345"))
	require.NoError(t, err)
	require.Equal(t, n, 5)
	require.Equal(t, []byte("6789012345"), buf.Bytes())

	// write overlap, copy some.
	buf = NewRingBuffer(10)
	n, err = buf.Write([]byte("123456"))
	require.NoError(t, err)
	require.Equal(t, n, 6)
	require.Equal(t, []byte("123456"), buf.Bytes())
	n, err = buf.Write([]byte("789012345"))
	require.NoError(t, err)
	require.Equal(t, n, 9)
	require.Equal(t, []byte("6789012345"), buf.Bytes())
}

func TestRunScript(t *testing.T) {
	o, err := RunScript(
		`#!/bin/bash

printf '%s\n' "$@"`,
		&ScriptOption{},
		"--argsnotexists", t.Name())
	require.NoError(t, err)
	require.Equal(t, `--argsnotexists
`+t.Name()+"\n", o)
}

func TestRunScriptFail(t *testing.T) {
	o, err := RunScript(
		`#!/bin/bash

printf '%s\n' "$@"
exit 2`,
		&ScriptOption{},
		"--argsnotexists", t.Name())
	require.Error(t, err)
	require.Equal(t, `--argsnotexists
`+t.Name()+"\n", o)
}

func TestChanWrite(t *testing.T) {
	var ch = NewChan[string](0)
	var lines []string
	go func() {
		for line := range ch.Reader() {
			t.Log("read: ", line)
			lines = append(lines, line)
		}
	}()
	w := ChanWriter(ch)
	for _, c := range []string{
		"123",
		"456\n789",
		"\n012\n",
	} {
		n, err := w.Write([]byte(c))
		require.NoError(t, err)
		require.Equal(t, len(c), n)
	}
	time.Sleep(time.Millisecond * 100) // wait channel consume
	require.Equal(t, []string{"123456", "789", "012"}, lines)
}
