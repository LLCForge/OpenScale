package sshclient

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Subsystem opens a named subsystem ("sftp") on the signed-in connection
// (#855). The returned stream carries the subsystem's stdin and stdout;
// closing it ends the session channel.
func (c *Client) Subsystem(name string) (io.ReadWriteCloser, error) {
	if name == "" || len(name) > 64 {
		return nil, errors.New("sshclient: geçersiz alt sistem adı")
	}
	sess, err := c.c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshclient: oturum açılamadı: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	if err := sess.RequestSubsystem(name); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("sshclient: %s alt sistemi açılamadı: %w", name, err)
	}
	return &subsystem{sess: sess, in: stdin, out: stdout}, nil
}

type subsystem struct {
	sess *ssh.Session
	in   io.WriteCloser
	out  io.Reader
	once sync.Once
	err  error
}

func (s *subsystem) Read(p []byte) (int, error)  { return s.out.Read(p) }
func (s *subsystem) Write(p []byte) (int, error) { return s.in.Write(p) }

func (s *subsystem) Close() error {
	s.once.Do(func() {
		_ = s.in.Close()
		s.err = s.sess.Close()
		if errors.Is(s.err, io.EOF) {
			s.err = nil
		}
	})
	return s.err
}
