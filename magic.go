package magic

import (
	"context"
	"fmt"
	"runtime"
)

type job struct {
	input      []byte
	reference  FileType
	resultChan chan *FileType
}

// LookupConfig is a struct that contains configuration details to modify the default Lookup behavior
type LookupConfig struct {
	ConcurrencyEnabled bool // the search will be performed concurrently by multiple worker goroutines when this field is set to true. The search will be carried out by the calling goroutine if set to false.
	WorkerCount        int  // number of worker goroutines to be spawned if concurrency is set to true. If set to -1, workerCount will be set to use all the available cores.
}

// ErrUnknown infers the file type cannot be determined by the provided magic bytes
var ErrUnknown = fmt.Errorf("unknown file type")

// Lookup looks up the file type based on the provided magic bytes. You should provide at least the first 1024 bytes of the file in this slice.
// A magic.ErrUnknown will be returned if the file type is not known.
func Lookup(bytes []byte) (*FileType, error) {
	return lookup(bytes, true, -1)
}

// LookupWithConfig looks up the file type based on the provided magic bytes, and a given configuration. You should provide at least the first 1024 bytes of the file in this slice.
// A magic.ErrUnknown will be returned if the file type is not known.
func LookupWithConfig(bytes []byte, config LookupConfig) (*FileType, error) {
	return lookup(bytes, config.ConcurrencyEnabled, config.WorkerCount)
}

// LookupSync lookups up the file type based on the provided magic bytes without spawning any additional goroutines. You should provide at least the first 1024 bytes of the file in this slice.
// A magic.ErrUnknown will be returned if the file type is not known.
func LookupSync(bytes []byte) (*FileType, error) {
	return lookup(bytes, false, 0)
}

func lookup(bytes []byte, concurrent bool, workers int) (*FileType, error) {
	// additional worker count check: avoid deadlock when worker count is set to zero
	if !concurrent || workers == 0 {
		for _, t := range Types {
			ft := t.check(bytes, 0)
			if ft != nil {
				return ft, nil
			}
		}
		return nil, ErrUnknown
	}

	// use all available cores
	workerCount := runtime.GOMAXPROCS(0)
	if workers > -1 && workers < workerCount {
		workerCount = workers
	}
	workChan := make(chan job)
	resultChan := make(chan *FileType)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// spawn workers
	for i := 0; i < workerCount; i++ {
		go worker(ctx, workChan)
	}

	awaiting := len(Types)

	// queue work
	go func() {
		for _, t := range Types {
			select {
			case <-ctx.Done():
				return
			case workChan <- job{
				input:      bytes,
				reference:  t,
				resultChan: resultChan,
			}:
			}
		}

	}()

	for {
		result := <-resultChan
		if result != nil {
			return result, nil
		}
		awaiting--
		if awaiting <= 0 {
			break
		}
	}

	return nil, ErrUnknown
}

func worker(ctx context.Context, work chan job) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-work:
			select {
			case <-ctx.Done():
				return
			case job.resultChan <- job.reference.check(job.input, job.reference.Offset):
			}
		}
	}
}
