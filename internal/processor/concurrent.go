// Package processor provides interfaces and types for processing OPNsense configurations.
package processor

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"sync"
)

// WorkerPoolDefaults contains default configuration values for the worker pool.
const (
	// DefaultWorkerCount is the default number of workers (NumCPU - 1, minimum 1).
	DefaultWorkerCount = 0 // 0 means auto-detect
	// DefaultJobQueueSize is the default job queue buffer size multiplier.
	DefaultJobQueueSize = 2
)

// ErrWorkerPoolClosed is returned when operations are attempted on a closed pool.
var ErrWorkerPoolClosed = errors.New("worker pool is closed")

// Job represents a unit of work to be processed by the worker pool.
type Job[T any, R any] struct {
	// ID uniquely identifies this job for tracking.
	ID string
	// Input is the data to be processed.
	Input T
	// Process is the function that processes the input and returns a result.
	Process func(ctx context.Context, input T) (R, error)
}

// Result represents the outcome of processing a job.
type Result[R any] struct {
	// JobID is the ID of the job that produced this result.
	JobID string
	// Value is the result of successful processing.
	Value R
	// Err is any error that occurred during processing.
	Err error
}

// WorkerPool manages a pool of workers for concurrent job processing.
// It supports context-based cancellation and graceful shutdown.
type WorkerPool[T any, R any] struct {
	workers    int
	jobs       chan Job[T, R]
	results    chan Result[R]
	ctx        context.Context //nolint:containedctx // Required for worker pool lifecycle management
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closeOnce  sync.Once
	closed     bool
	closedMu   sync.RWMutex
	maxRetries int
}

// WorkerPoolOption configures a WorkerPool.
type WorkerPoolOption[T any, R any] func(*WorkerPool[T, R])

// WithWorkerCount sets the number of workers in the pool.
func WithWorkerCount[T, R any](count int) WorkerPoolOption[T, R] {
	return func(wp *WorkerPool[T, R]) {
		if count > 0 {
			wp.workers = count
		}
	}
}

// WithMaxRetries sets the maximum number of retries for failed jobs.
func WithMaxRetries[T, R any](retries int) WorkerPoolOption[T, R] {
	return func(wp *WorkerPool[T, R]) {
		if retries >= 0 {
			wp.maxRetries = retries
		}
	}
}

// NewWorkerPool creates a new WorkerPool with the specified context and options.
// If worker count is not specified or is 0, it defaults to NumCPU-1 (minimum 1).
func NewWorkerPool[T, R any](ctx context.Context, opts ...WorkerPoolOption[T, R]) *WorkerPool[T, R] {
	ctx, cancel := context.WithCancel(ctx)

	wp := &WorkerPool[T, R]{
		workers:    calculateDefaultWorkers(),
		ctx:        ctx,
		cancel:     cancel,
		maxRetries: 0,
	}

	// Apply options
	for _, opt := range opts {
		opt(wp)
	}

	// Initialize channels with buffer based on worker count
	wp.jobs = make(chan Job[T, R], wp.workers*DefaultJobQueueSize)
	wp.results = make(chan Result[R], wp.workers*DefaultJobQueueSize)

	// Start workers
	wp.startWorkers()

	return wp
}

// calculateDefaultWorkers returns the default number of workers.
// Uses NumCPU-1 to leave one core for the main program, minimum 1.
func calculateDefaultWorkers() int {
	numCPU := runtime.NumCPU()
	if numCPU <= 1 {
		return 1
	}
	return numCPU - 1
}

// startWorkers starts the worker goroutines.
func (wp *WorkerPool[T, R]) startWorkers() {
	for range wp.workers {
		wp.wg.Add(1)
		go wp.worker()
	}
}

// worker is the main worker goroutine that processes jobs from the queue.
func (wp *WorkerPool[T, R]) worker() {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobs:
			if !ok {
				return
			}
			wp.processJob(job)
		}
	}
}

// processJob executes a single job and sends the result.
func (wp *WorkerPool[T, R]) processJob(job Job[T, R]) {
	var result Result[R]
	result.JobID = job.ID

	// Process with retries if configured
	var lastErr error
	for attempt := 0; attempt <= wp.maxRetries; attempt++ {
		select {
		case <-wp.ctx.Done():
			result.Err = wp.ctx.Err()
			wp.sendResult(result)
			return
		default:
		}

		value, err := job.Process(wp.ctx, job.Input)
		if err == nil {
			result.Value = value
			wp.sendResult(result)
			return
		}
		lastErr = err
	}

	result.Err = lastErr
	wp.sendResult(result)
}

// sendResult sends a result to the results channel if not closed.
func (wp *WorkerPool[T, R]) sendResult(result Result[R]) {
	select {
	case <-wp.ctx.Done():
		return
	case wp.results <- result:
	}
}

// Submit adds a job to the work queue.
// Returns ErrWorkerPoolClosed if the pool is closed.
// Returns context error if the context is cancelled while waiting.
func (wp *WorkerPool[T, R]) Submit(job Job[T, R]) error {
	wp.closedMu.RLock()
	if wp.closed {
		wp.closedMu.RUnlock()
		return ErrWorkerPoolClosed
	}
	wp.closedMu.RUnlock()

	select {
	case <-wp.ctx.Done():
		return wp.ctx.Err()
	case wp.jobs <- job:
		return nil
	}
}

// Results returns the results channel for reading processed results.
func (wp *WorkerPool[T, R]) Results() <-chan Result[R] {
	return wp.results
}

// Close gracefully shuts down the worker pool.
// It stops accepting new jobs, waits for in-flight jobs to complete,
// and closes the results channel.
func (wp *WorkerPool[T, R]) Close() {
	wp.closeOnce.Do(func() {
		wp.closedMu.Lock()
		wp.closed = true
		wp.closedMu.Unlock()

		// Close jobs channel to signal workers to stop
		close(wp.jobs)

		// Wait for all workers to finish
		wp.wg.Wait()

		// Cancel context and close results
		wp.cancel()
		close(wp.results)
	})
}

// Cancel immediately cancels all pending work and shuts down the pool.
func (wp *WorkerPool[T, R]) Cancel() {
	wp.cancel()
	wp.Close()
}

// WorkerCount returns the number of workers in the pool.
func (wp *WorkerPool[T, R]) WorkerCount() int {
	return wp.workers
}

// IsClosed returns true if the pool has been closed.
func (wp *WorkerPool[T, R]) IsClosed() bool {
	wp.closedMu.RLock()
	defer wp.closedMu.RUnlock()
	return wp.closed
}

// ProcessBatch processes a batch of inputs using the worker pool and collects all results.
// ProcessBatch processes a slice of inputs concurrently using a worker pool and returns the collected results.
//
// It submits each input as a job to a new WorkerPool created with the provided context and options. If submission is interrupted
// (for example by context cancellation), only results for the jobs successfully submitted are collected and returned. If ctx is
// canceled during submission or result collection, the function returns the partial results along with ctx.Err(). The worker pool
// is closed before ProcessBatch returns.
func ProcessBatch[T, R any](
	ctx context.Context,
	inputs []T,
	processFn func(ctx context.Context, input T) (R, error),
	opts ...WorkerPoolOption[T, R],
) ([]Result[R], error) {
	if len(inputs) == 0 {
		return []Result[R]{}, nil
	}

	wp := NewWorkerPool(ctx, opts...)
	defer wp.Close()

	// Track number of successfully submitted jobs
	submittedCount := make(chan int, 1)

	// Submit all jobs
	go func() {
		submitted := 0
		for i, input := range inputs {
			job := Job[T, R]{
				ID:      strconv.Itoa(i),
				Input:   input,
				Process: processFn,
			}
			if err := wp.Submit(job); err != nil {
				// Signal how many jobs were submitted before error/cancellation
				submittedCount <- submitted
				return
			}
			submitted++
		}
		// Signal all jobs were submitted successfully
		submittedCount <- submitted
	}()

	// Wait for submission goroutine to report count
	expectedResults := <-submittedCount

	// Collect results only for submitted jobs
	results := make([]Result[R], 0, expectedResults)
	for range expectedResults {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case result, ok := <-wp.Results():
			if !ok {
				return results, nil
			}
			results = append(results, result)
		}
	}

	return results, nil
}