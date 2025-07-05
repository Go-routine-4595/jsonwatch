package service

import (
	"encoding/json"
	"fmt"
	"github.com/Go-routine-4595/jsonwatch/model"
	"github.com/rs/zerolog"
	"os"
	"time"
)

type Reporter interface {
	Report(data []byte)
	Processed()
}

type Service struct {
	logger zerolog.Logger
	Reporter
}

func NewService(reporter Reporter, loglevel zerolog.Level) *Service {
	logger := initializeLogger(loglevel)
	logger.Info().Msg("service start")
	return &Service{
		logger:   logger,
		Reporter: reporter,
	}
}

// createLogger initializes and returns a new `zerolog.Logger` configured with the given log level.
// It sets the output to `os.Stdout` with RFC3339 time format and includes the process PID in the log context.
func initializeLogger(level zerolog.Level) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
		Level(level).
		With().
		Timestamp().
		Str("instance", "service").
		Logger()
}

func (s *Service) SendData(events []byte) {
	var fctsMsgs []model.FCTSDataModel

	s.logger.Debug().Msgf("received data: %s", string(events))
	s.logger.Info().Msgf("received data size: %d", len(events))
	s.Reporter.Processed()
	if !json.Valid(events) {
		errorMsg := message("not available", "not available", fmt.Sprintf("invalid JSON data message size: %d", len(events)))
		errorByte, _ := json.Marshal(errorMsg)
		s.Reporter.Report(errorByte)
	}

	err := json.Unmarshal(events, &fctsMsgs)
	if err != nil {
		errorMsg := message("not available", "not available", fmt.Sprintf("invalid JSON data message size: %s", err.Error()))
		errorByte, _ := json.Marshal(errorMsg)
		s.Reporter.Report(errorByte)
	}

	for _, item := range fctsMsgs {
		if payloadVal, exists := item.Annotations["payload"]; exists {
			if payloadStr, ok := payloadVal.(string); ok {
				payload := []byte(payloadStr)

				if payload != nil {
					if len(payload) > 0 {
						if !json.Valid(payload) {
							errorMsg := message(item.Annotations["uuid"].(string), item.SiteCode, "invalid JSON payload")
							errorByte, _ := json.Marshal(errorMsg)
							s.Reporter.Report(errorByte)
						}
					}
				}
			}
		}
		if uuidVal, exists := item.Annotations["uuid"]; exists {
			if uuidStr, ok := uuidVal.(string); ok {
				uuid := []byte(uuidStr)
				s.logger.Info().Msgf("received data uuid: %s", uuid)
			}
		}
	}
}

func message(uuid string, site_code string, msg string) model.FCTSDataModel {
	return model.FCTSDataModel{
		SiteCode:   site_code,
		SensorId:   "BAG-Data-Publish-Error",
		Value:      "Error detected",
		DataSource: "DataPublish Checker",
		TimeStamp:  time.Now().Format(time.RFC3339),
		Uom:        "string",
		Quality:    1,
		Annotations: map[string]interface{}{
			"uuid":    uuid,
			"payload": msg,
		},
	}
}
