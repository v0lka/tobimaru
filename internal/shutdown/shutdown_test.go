package shutdown

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestRegisterAndShutdown(t *testing.T) {
	var order []string
	m := NewManager()

	m.Register("first", func() error {
		order = append(order, "first")
		return nil
	})
	m.Register("second", func() error {
		order = append(order, "second")
		return nil
	})
	m.Register("third", func() error {
		order = append(order, "third")
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.Shutdown(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Hooks should execute in reverse order (LIFO).
	expected := []string{"third", "second", "first"}
	if len(order) != len(expected) {
		t.Fatalf("got %d hooks executed, want %d: %v", len(order), len(expected), order)
	}
	for i, name := range expected {
		if order[i] != name {
			t.Errorf("hook %d: got %q, want %q", i, order[i], name)
		}
	}
}

func TestShutdownWithError(t *testing.T) {
	m := NewManager()
	cleanupErr := errors.New("cleanup failed")
	m.Register("failing", func() error {
		return cleanupErr
	})
	m.Register("success", func() error {
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.Shutdown(ctx)
	if err == nil {
		t.Fatal("got nil, want error")
	}
	if !errors.Is(err, cleanupErr) {
		t.Errorf("got %v, want cleanup failed error", err)
	}
}

func TestShutdownTimeout(t *testing.T) {
	m := NewManager()
	m.Register("slow", func() error {
		time.Sleep(2 * time.Second)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := m.Shutdown(ctx)
	if err == nil {
		t.Fatal("got nil, want timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want DeadlineExceeded", err)
	}
}

func TestShutdownPartialErrors(t *testing.T) {
	var executed []string
	m := NewManager()

	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("hook%d", i)
		m.Register(name, func() error {
			executed = append(executed, name)
			if name == "hook2" {
				return errors.New("failure in " + name)
			}
			return nil
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.Shutdown(ctx)
	if err == nil {
		t.Fatal("got nil, want error")
	}

	// All hooks should have been attempted despite hook2's failure.
	if len(executed) != 3 {
		t.Errorf("got %d hooks executed, want 3: %v", len(executed), executed)
	}
}

func TestWaitForSignal(t *testing.T) {
	m := NewManager().WithSignals(syscall.SIGUSR1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	notifyCtx := m.WaitForSignal(ctx)

	// Send SIGUSR1 to ourself.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to send signal: %v", err)
	}

	<-notifyCtx.Done()
	if err := notifyCtx.Err(); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
}

func TestEmptyManager(t *testing.T) {
	m := NewManager()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.Shutdown(ctx)
	if err != nil {
		t.Fatalf("got %v, want nil error for empty manager", err)
	}
}

func TestConcurrentRegistration(t *testing.T) {
	m := NewManager()
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			m.Register(fmt.Sprintf("hook%d", n), func() error { return nil })
		}(i)
	}
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.Shutdown(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
