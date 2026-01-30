package processor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNewWorkerPool(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx)
	defer wp.Close()

	if wp.WorkerCount() < 1 {
		t.Errorf("expected at least 1 worker, got %d", wp.WorkerCount())
	}

	if wp.IsClosed() {
		t.Error("new pool should not be closed")
	}
}

func TestWorkerPoolWithOptions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx,
		WithWorkerCount[int, int](4),
		WithMaxRetries[int, int](2),
	)
	defer wp.Close()

	if wp.WorkerCount() != 4 {
		t.Errorf("expected 4 workers, got %d", wp.WorkerCount())
	}
}

func TestWorkerPoolSubmitAndProcess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](2))
	defer wp.Close()

	// Submit a job that doubles the input
	job := Job[int, int]{
		ID:    "test-1",
		Input: 5,
		Process: func(_ context.Context, input int) (int, error) {
			return input * 2, nil
		},
	}

	err := wp.Submit(job)
	if err != nil {
		t.Fatalf("failed to submit job: %v", err)
	}

	// Wait for result
	select {
	case result := <-wp.Results():
		if result.Err != nil {
			t.Errorf("unexpected error: %v", result.Err)
		}
		if result.Value != 10 {
			t.Errorf("expected 10, got %d", result.Value)
		}
		if result.JobID != "test-1" {
			t.Errorf("expected job ID 'test-1', got '%s'", result.JobID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result")
	}
}

func TestWorkerPoolMultipleJobs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](4))
	defer wp.Close()

	numJobs := 100
	var submitted int32

	// Submit jobs concurrently
	go func() {
		for i := range numJobs {
			job := Job[int, int]{
				ID:    string(rune(i)),
				Input: i,
				Process: func(_ context.Context, input int) (int, error) {
					return input * input, nil
				},
			}
			if err := wp.Submit(job); err == nil {
				atomic.AddInt32(&submitted, 1)
			}
		}
	}()

	// Collect results
	results := make(map[int]int)
	var mu sync.Mutex

	for range numJobs {
		select {
		case result := <-wp.Results():
			if result.Err != nil {
				t.Errorf("unexpected error: %v", result.Err)
				continue
			}
			mu.Lock()
			r, _ := utf8.DecodeRuneInString(result.JobID)
			results[int(r)] = result.Value
			mu.Unlock()
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for results, got %d of %d", len(results), numJobs)
		}
	}

	if len(results) != numJobs {
		t.Errorf("expected %d results, got %d", numJobs, len(results))
	}
}

func TestWorkerPoolErrorHandling(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](2))
	defer wp.Close()

	expectedErr := errors.New("processing failed")
	job := Job[int, int]{
		ID:    "error-job",
		Input: 1,
		Process: func(_ context.Context, _ int) (int, error) {
			return 0, expectedErr
		},
	}

	err := wp.Submit(job)
	if err != nil {
		t.Fatalf("failed to submit job: %v", err)
	}

	select {
	case result := <-wp.Results():
		if result.Err == nil {
			t.Error("expected error, got nil")
		}
		if !errors.Is(result.Err, expectedErr) {
			t.Errorf("expected error %v, got %v", expectedErr, result.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result")
	}
}

func TestWorkerPoolWithRetries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx,
		WithWorkerCount[int, int](1),
		WithMaxRetries[int, int](2),
	)
	defer wp.Close()

	var attempts int32
	job := Job[int, int]{
		ID:    "retry-job",
		Input: 1,
		Process: func(_ context.Context, _ int) (int, error) {
			attempt := atomic.AddInt32(&attempts, 1)
			if attempt < 3 {
				return 0, errors.New("temporary failure")
			}
			return 42, nil
		},
	}

	err := wp.Submit(job)
	if err != nil {
		t.Fatalf("failed to submit job: %v", err)
	}

	select {
	case result := <-wp.Results():
		if result.Err != nil {
			t.Errorf("expected success after retries, got error: %v", result.Err)
		}
		if result.Value != 42 {
			t.Errorf("expected 42, got %d", result.Value)
		}
		if atomic.LoadInt32(&attempts) != 3 {
			t.Errorf("expected 3 attempts, got %d", attempts)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result")
	}
}

func TestWorkerPoolContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](2))

	// Submit a job that takes a while
	job := Job[int, int]{
		ID:    "slow-job",
		Input: 1,
		Process: func(ctx context.Context, _ int) (int, error) {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(10 * time.Second):
				return 42, nil
			}
		},
	}

	err := wp.Submit(job)
	if err != nil {
		t.Fatalf("failed to submit job: %v", err)
	}

	// Cancel context
	cancel()

	// Wait for pool to close
	wp.Close()

	if !wp.IsClosed() {
		t.Error("pool should be closed after cancel")
	}
}

func TestWorkerPoolClose(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](2))

	// Close the pool
	wp.Close()

	if !wp.IsClosed() {
		t.Error("pool should be closed")
	}

	// Submit should fail after close
	job := Job[int, int]{
		ID:    "post-close",
		Input: 1,
		Process: func(_ context.Context, _ int) (int, error) {
			return 1, nil
		},
	}

	err := wp.Submit(job)
	if !errors.Is(err, ErrWorkerPoolClosed) {
		t.Errorf("expected ErrWorkerPoolClosed, got %v", err)
	}

	// Multiple closes should not panic
	wp.Close()
	wp.Close()
}

func TestWorkerPoolCancel(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](2))

	// Cancel immediately
	wp.Cancel()

	if !wp.IsClosed() {
		t.Error("pool should be closed after cancel")
	}
}

func TestProcessBatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	inputs := []int{1, 2, 3, 4, 5}

	results, err := ProcessBatch(ctx, inputs, func(_ context.Context, input int) (int, error) {
		return input * 2, nil
	}, WithWorkerCount[int, int](2))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != len(inputs) {
		t.Errorf("expected %d results, got %d", len(inputs), len(results))
	}

	// Check all results are correct (order may vary)
	sum := 0
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("unexpected error in result: %v", r.Err)
		}
		sum += r.Value
	}

	// Sum of 2*1 + 2*2 + 2*3 + 2*4 + 2*5 = 30
	expectedSum := 30
	if sum != expectedSum {
		t.Errorf("expected sum %d, got %d", expectedSum, sum)
	}
}

func TestProcessBatchEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	results, err := ProcessBatch(ctx, []int{}, func(_ context.Context, input int) (int, error) {
		return input, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestProcessBatchWithErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	inputs := []int{1, 2, 3}
	expectedErr := errors.New("even number error")

	results, err := ProcessBatch(ctx, inputs, func(_ context.Context, input int) (int, error) {
		if input%2 == 0 {
			return 0, expectedErr
		}
		return input, nil
	}, WithWorkerCount[int, int](2))
	if err != nil {
		t.Fatalf("batch processing failed: %v", err)
	}

	if len(results) != len(inputs) {
		t.Errorf("expected %d results, got %d", len(inputs), len(results))
	}

	// Count errors
	errorCount := 0
	for _, r := range results {
		if r.Err != nil {
			errorCount++
		}
	}

	// Only input 2 should cause an error
	if errorCount != 1 {
		t.Errorf("expected 1 error, got %d", errorCount)
	}
}

func TestCalculateDefaultWorkers(t *testing.T) {
	t.Parallel()

	workers := calculateDefaultWorkers()
	if workers < 1 {
		t.Errorf("default workers should be at least 1, got %d", workers)
	}
}

// Benchmark tests

func BenchmarkWorkerPoolSubmit(b *testing.B) {
	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](4))
	defer wp.Close()

	job := Job[int, int]{
		ID:    "bench",
		Input: 1,
		Process: func(_ context.Context, input int) (int, error) {
			return input * 2, nil
		},
	}

	b.ResetTimer()
	for b.Loop() {
		//nolint:errcheck,gosec // Benchmark doesn't need error handling
		wp.Submit(job)
	}
}

func BenchmarkProcessBatch(b *testing.B) {
	ctx := context.Background()
	inputs := make([]int, 1000)
	for i := range inputs {
		inputs[i] = i
	}

	b.ResetTimer()
	for b.Loop() {
		//nolint:errcheck,gosec // Benchmark doesn't need error handling
		ProcessBatch(ctx, inputs, func(_ context.Context, input int) (int, error) {
			return input * 2, nil
		}, WithWorkerCount[int, int](4))
	}
}

func BenchmarkWorkerPoolParallel(b *testing.B) {
	ctx := context.Background()
	wp := NewWorkerPool[int, int](ctx, WithWorkerCount[int, int](4))
	defer wp.Close()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			job := Job[int, int]{
				ID:    "bench",
				Input: 1,
				Process: func(_ context.Context, input int) (int, error) {
					return input * 2, nil
				},
			}
			//nolint:errcheck,gosec // Benchmark doesn't need error handling
			wp.Submit(job)
		}
	})
}
