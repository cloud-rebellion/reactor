package supervisor

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestChildOutputAbsoluteDrainWindowBoundsContinuousWrites(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	processExited := make(chan struct{})
	deadlineTimer := time.AfterFunc(time.Second, func() { _ = read.Close() })
	defer deadlineTimer.Stop()
	reader := &childOutputReader{
		pipe: read, processExited: processExited,
		absoluteDeadline: time.Now().Add(150 * time.Millisecond),
	}
	close(processExited)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := write.Write([]byte("x")); err != nil {
					return
				}
			}
		}
	}()
	buf := make([]byte, 1)
	for {
		_, err := reader.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		if err != nil {
			t.Fatalf("read continuous child output: %v", err)
		}
	}
}
