package utils

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
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
		case now := <-tk.C:
			if now.After(expiredTime) {
				return errors.New(fmt.Sprintf("timeout after %v", timeout))
			}
			go func() {
				ch <- fn()
			}()
		}
	}
}

func ParseISO8601(date string) (time.Time, error) {
	parsedTime, err := time.Parse(time.RFC3339, date)
	if err == nil {
		return parsedTime, nil
	}
	parsedTime, err = time.Parse("2006-01-02T15:04:05Z07:00", date)
	if err == nil {
		return parsedTime, nil
	}
	parsedTime, err = time.Parse("2006-01-02T15:04:05", date)
	if err == nil {
		return parsedTime, nil
	}
	return time.Time{}, errors.Wrap(err, fmt.Sprintf("failed to parse date: %s", date))
}
