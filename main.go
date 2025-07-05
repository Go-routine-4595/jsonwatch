package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Go-routine-4595/jsonwatch/adapters/controller"
	"github.com/Go-routine-4595/jsonwatch/adapters/gateway"
	"github.com/Go-routine-4595/jsonwatch/model"
	"github.com/Go-routine-4595/jsonwatch/service"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	controller.MqttConfig `yaml:"MqttConfig"`
}

var logLevel map[string]zerolog.Level = map[string]zerolog.Level{
	"Trace":    zerolog.TraceLevel,
	"Debug":    zerolog.DebugLevel,
	"Info":     zerolog.InfoLevel,
	"Warn":     zerolog.WarnLevel,
	"Error":    zerolog.ErrorLevel,
	"Fatal":    zerolog.FatalLevel,
	"Panic":    zerolog.PanicLevel,
	"Disabled": zerolog.Disabled,
}

const (
	config = "config.yaml"
)

func main() {
	var (
		conf     Config
		svc      model.IService
		mqtt     *controller.MqttController
		reporter *gateway.Report
		wg       *sync.WaitGroup
		ctx      context.Context
		args     []string
		sig      chan os.Signal
		cancel   context.CancelFunc
		err      error
	)

	args = os.Args

	wg = &sync.WaitGroup{}

	if len(args) == 1 {
		fmt.Println("reading configuraiotn file: ", config)
		conf = openConfigFile(config)
	} else {
		fmt.Println("reading configuraiotn file: ", args[1])
		conf = openConfigFile(args[1])
	}

	// log level
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Str("instanceId", "myid").Logger()
	log.Info().Msg("a message")
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	if _, exists := logLevel[conf.MqttConfig.LogLevel]; !exists {
		conf.MqttConfig.LogLevel = "Info"
		log.Warn().Msgf("log level %s not found, using default level %s", conf.MqttConfig.LogLevel, "Info")
		conf.MqttConfig.LogLevelZ = zerolog.InfoLevel
	} else {
		conf.MqttConfig.LogLevelZ = logLevel[conf.MqttConfig.LogLevel]
	}

	ctx, cancel = context.WithCancel(context.Background())

	// new gateway reporter
	reporter = gateway.NewReport(ctx, wg, zerolog.InfoLevel)

	// new server
	svc = service.NewService(reporter, conf.MqttConfig.LogLevelZ)

	// new controller
	mqtt, err = controller.NewMqttController(ctx, wg, conf.MqttConfig, svc)
	if err != nil {
		processError(err)
	}

	reporter.WithSender(mqtt)

	sig = make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()
	reporter.Start()
	mqtt.Start()
	// give 500 ms grace period to flush all logs
	time.Sleep(500 * time.Millisecond)
	wg.Wait()
}

func openConfigFile(s string) Config {
	if s == "" {
		s = "config.yaml"
	}

	f, err := os.Open(s)
	if err != nil {
		processError(errors.Join(err, errors.New("open config.yaml file")))
	}
	defer f.Close()

	var config Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&config)
	if err != nil {
		processError(err)
	}
	return config

}

func processError(err error) {
	fmt.Println(err)
	os.Exit(2)
}
