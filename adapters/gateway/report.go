package gateway

import (
	"context"
	"github.com/rs/zerolog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Sender interface {
	SendData(data []byte) bool
}
type Report struct {
	eventProcessed   int64
	eventSendProblem int64
	eventJSONProblem int64
	Send             Sender
	dataChan         chan []byte
	wg               *sync.WaitGroup
	ctx              context.Context
	logger           zerolog.Logger
}

// createLogger initializes and returns a new `zerolog.Logger` configured with the given log level.
// It sets the output to `os.Stdout` with RFC3339 time format and includes the process PID in the log context.
func initializeLogger(logLevel zerolog.Level) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
		Level(logLevel).
		With().
		Timestamp().
		Str("instanceId", "reporter").
		Logger()
}

func NewReport(ctx context.Context, wg *sync.WaitGroup, loglevel zerolog.Level) *Report {
	return &Report{
		ctx:      ctx,
		wg:       wg,
		dataChan: make(chan []byte, 10),
		logger:   initializeLogger(loglevel),
	}
}

func (r *Report) WithSender(sender Sender) *Report {
	r.Send = sender
	return r
}

func (r *Report) Processed() {
	atomic.AddInt64(&r.eventProcessed, 1)
}

func (r *Report) Report(data []byte) {
	select {
	case r.dataChan <- data:
		return
	default:
		return
	}
}

func (r *Report) Start() {
	r.logger.Info().Msg("reporter start")
	if r.Send == nil {
		r.logger.Error().Msg("Sender not configured")
		return
	}
	r.wg.Add(1)
	go r.start()
}

func (r *Report) start() {

	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		close(r.dataChan)
		r.logger.Warn().Msg("Reporter stoping")
		ticker.Stop()
		r.wg.Done()
	}()

	for {
		select {
		case <-r.ctx.Done():
			r.logger.Info().Msg("reporter stop")
			return
		case b := <-r.dataChan:
			if !r.Send.SendData(b) {
				atomic.AddInt64(&r.eventSendProblem, 1)
			}
			atomic.AddInt64(&r.eventJSONProblem, 1)
		case <-ticker.C:
			processed := atomic.LoadInt64(&r.eventProcessed)
			withProblem := atomic.LoadInt64(&r.eventJSONProblem)
			problems := atomic.LoadInt64(&r.eventSendProblem)
			r.logger.Info().Msgf("error event processed: %d, event JSON issue: %d, event send problem: %d", processed, withProblem, problems)
		}
	}

}
