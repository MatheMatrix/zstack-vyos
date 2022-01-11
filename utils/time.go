package utils

import (
	"fmt"
	"github.com/pkg/errors"
	"time"
)

func LoopRunUntilSuccessOrTimeout(fn func() bool, timeout, interval time.Duration) error {
	expiredTime := time.Now().Add(timeout)
	ch := make(chan bool, 1)
	tk := time.NewTicker(interval)
	defer tk.Stop()

	go func() {
		ch <- fn()
	}()

	for {
		select {
		case r := <-ch:
			if r {
				return nil
			}
			go func() {
				ch <- fn()
			}()
		case now := <-tk.C:
			if now.After(expiredTime) {
				return errors.New(fmt.Sprintf("timeout after %v", timeout))
			}
		}
	}
}
