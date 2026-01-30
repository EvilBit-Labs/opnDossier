//go:build stress

package processor

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerPoolStress tests the worker pool under heavy concurrent load.
func TestWorkerPoolStress(t *testing.T) {
	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](runtime.NumCPU()))
	defer wp.Close()

	const numJobs = 10000
	var completed atomic.Int32
	var errCount atomic.Int32

	// Submit jobs in a separate goroutine
	go func() {
		for i := range numJobs {
			job := Job[int, int]{
				ID:    string(rune(i % 1000)), // Avoid creating huge strings
				Input: i,
				Process: func(_ context.Context, input int) (int, error) {
					// Simulate some work
					result := input * 2
					for j := 0; j < 100; j++ {
						result = result ^ j
					}
					return result, nil
				},
			}
			if err := wp.Submit(job); err != nil {
				errCount.Add(1)
			}
		}
	}()

	// Collect results
	timeout := time.After(30 * time.Second)
	for completed.Load() < numJobs-errCount.Load() {
		select {
		case result := <-wp.Results():
			if result.Err != nil {
				t.Errorf("unexpected error: %v", result.Err)
			}
			completed.Add(1)
		case <-timeout:
			t.Fatalf("timeout: completed %d of %d jobs, %d submit errors",
				completed.Load(), numJobs, errCount.Load())
		}
	}

	if completed.Load() < int32(numJobs*95/100) {
		t.Errorf("expected at least 95%% completion, got %d/%d", completed.Load(), numJobs)
	}
}

// TestWorkerPoolMemoryPressure tests the worker pool under memory pressure.
func TestWorkerPoolMemoryPressure(t *testing.T) {
	ctx := context.Background()
	wp := NewWorkerPool[[]byte, int](ctx, WithWorkerCount[[]byte, int](4))
	defer wp.Close()

	const numJobs = 1000
	const dataSize = 10 * 1024 // 10KB per job

	var completed atomic.Int32

	// Submit jobs with larger payloads
	go func() {
		for i := range numJobs {
			data := make([]byte, dataSize)
			for j := range data {
				data[j] = byte(i % 256)
			}

			job := Job[[]byte, int]{
				ID:    string(rune(i % 1000)),
				Input: data,
				Process: func(_ context.Context, input []byte) (int, error) {
					// Process the data
					sum := 0
					for _, b := range input {
						sum += int(b)
					}
					return sum, nil
				},
			}
			//nolint:errcheck // Stress test
			wp.Submit(job)
		}
	}()

	// Collect results
	timeout := time.After(30 * time.Second)
	for completed.Load() < numJobs {
		select {
		case result := <-wp.Results():
			if result.Err != nil {
				t.Errorf("unexpected error: %v", result.Err)
			}
			completed.Add(1)
		case <-timeout:
			t.Fatalf("timeout: completed %d of %d jobs", completed.Load(), numJobs)
		}
	}
}

// TestWorkerPoolErrorRecovery tests recovery from errors under load.
func TestWorkerPoolErrorRecovery(t *testing.T) {
	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx,
		WithWorkerCount[int, int](4),
		WithMaxRetries[int, int](3),
	)
	defer wp.Close()

	const numJobs = 100
	var completed atomic.Int32
	var errorCount atomic.Int32
	errExpected := errors.New("expected error")

	// Submit jobs where some will fail
	go func() {
		for i := range numJobs {
			job := Job[int, int]{
				ID:    string(rune(i)),
				Input: i,
				Process: func(_ context.Context, input int) (int, error) {
					// Fail on multiples of 7
					if input%7 == 0 {
						return 0, errExpected
					}
					return input * 2, nil
				},
			}
			//nolint:errcheck // Stress test
			wp.Submit(job)
		}
	}()

	// Collect results
	timeout := time.After(30 * time.Second)
	for completed.Load()+errorCount.Load() < numJobs {
		select {
		case result := <-wp.Results():
			if result.Err != nil {
				errorCount.Add(1)
			} else {
				completed.Add(1)
			}
		case <-timeout:
			t.Fatalf("timeout: completed %d, errors %d, total %d",
				completed.Load(), errorCount.Load(), numJobs)
		}
	}

	// Verify we got the expected number of errors
	expectedErrors := int32(0)
	for i := range numJobs {
		if i%7 == 0 {
			expectedErrors++
		}
	}

	if errorCount.Load() != expectedErrors {
		t.Errorf("expected %d errors, got %d", expectedErrors, errorCount.Load())
	}
}

// TestWorkerPoolCancellation tests graceful cancellation under load.
func TestWorkerPoolCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](4))

	const numJobs = 10000
	var submitted atomic.Int32

	// Submit jobs rapidly
	go func() {
		for i := range numJobs {
			job := Job[int, int]{
				ID:    string(rune(i % 1000)),
				Input: i,
				Process: func(ctx context.Context, input int) (int, error) {
					// Simulate longer work
					select {
					case <-ctx.Done():
						return 0, ctx.Err()
					case <-time.After(10 * time.Millisecond):
						return input * 2, nil
					}
				},
			}
			if err := wp.Submit(job); err != nil {
				break // Pool closed
			}
			submitted.Add(1)
		}
	}()

	// Let some jobs process
	time.Sleep(100 * time.Millisecond)

	// Cancel and verify clean shutdown
	cancel()
	wp.Close()

	if !wp.IsClosed() {
		t.Error("pool should be closed after cancel")
	}

	// Verify we submitted at least some jobs
	if submitted.Load() == 0 {
		t.Error("expected at least some jobs to be submitted")
	}
}

// TestProcessBatchStress tests batch processing under load.
func TestProcessBatchStress(t *testing.T) {
	ctx := context.Background()
	const batchSize = 5000

	inputs := make([]int, batchSize)
	for i := range inputs {
		inputs[i] = i
	}

	results, err := ProcessBatch(ctx, inputs, func(_ context.Context, input int) (int, error) {
		// Simulate processing
		result := input
		for j := 0; j < 50; j++ {
			result = result ^ j
		}
		return result, nil
	}, WithWorkerCount[int, int](runtime.NumCPU()))
	if err != nil {
		t.Fatalf("batch processing failed: %v", err)
	}

	if len(results) != batchSize {
		t.Errorf("expected %d results, got %d", batchSize, len(results))
	}

	// Verify all results are present
	errorCount := 0
	for _, r := range results {
		if r.Err != nil {
			errorCount++
		}
	}

	if errorCount > 0 {
		t.Errorf("expected 0 errors, got %d", errorCount)
	}
}
