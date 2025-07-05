package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Go-routine-4595/jsonwatch/model"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

type MqttConfig struct {
	Connection   string `yaml:"ConnectionString"`
	Topic        string `yaml:"Topic"`
	Key          string `yaml:"Key"`
	ErrorPublish string `yaml:"ErrorPublish"`
	LogLevel     string `yaml:"LogLevel"`
	LogLevelZ    zerolog.Level
}

type MqttController struct {
	Topic        string
	MgtUrl       string
	ErrorPublish string
	logger       zerolog.Logger
	opt          *mqtt.ClientOptions
	ClientID     uuid.UUID
	client       mqtt.Client
	svc          model.IService
	wg           *sync.WaitGroup
	ctx          context.Context
	ErroChan     chan []byte
}

// createLogger initializes and returns a new `zerolog.Logger` configured with the given log level.
// It sets the output to `os.Stdout` with RFC3339 time format and includes the process PID in the log context.
func initializeLogger(logLevel zerolog.Level) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
		Level(logLevel).
		With().
		Timestamp().
		Str("instance", "controller").
		Logger()
}

// NewMqttController initializes a new Mqtt instance with given configuration, log level, and context.
// It sets up the logger, client options, and handles connection and reconnection behaviors.
// It also handles graceful disconnection upon context cancellation and returns the created Mqtt instance or error.
func NewMqttController(ctx context.Context, wg *sync.WaitGroup, conf MqttConfig, svc model.IService) (*MqttController, error) {
	var (
		err error
		l   zerolog.Logger
		cid uuid.UUID
	)

	l = initializeLogger(conf.LogLevelZ)
	cid = uuid.NewV4()
	c := &MqttController{
		Topic:        conf.Topic,
		MgtUrl:       conf.Connection,
		logger:       l,
		ClientID:     cid,
		svc:          svc,
		wg:           wg,
		ctx:          ctx,
		ErrorPublish: conf.ErrorPublish,
		ErroChan:     make(chan []byte, 10),
		opt: mqtt.NewClientOptions().
			AddBroker(conf.Connection).
			SetClientID("jsonwatcher-" + cid.String()).
			SetCleanSession(true).
			SetAutoReconnect(true).
			SetTLSConfig(&tls.Config{
				InsecureSkipVerify: true,
			}),
	}
	c.opt = c.opt.SetConnectionLostHandler(c.ConnectLostHandler())
	c.opt = c.opt.SetOnConnectHandler(c.ConnectHandler())

	err = c.Connect()

	return c, err
}

func (m *MqttController) Start() {
	m.logger.Info().Msg("Mqtt start")

	// Check subscription error
	if token := m.client.Subscribe(m.Topic, 0, m.processMessage); token.Wait() && token.Error() != nil {
		m.logger.Error().Err(token.Error()).Msg("Failed to subscribe to topic")
		m.wg.Done()
		return
	}

	m.wg.Add(1)
	defer func() {
		m.client.Disconnect(250)
		close(m.ErroChan)
		m.logger.Warn().Msg("Mqtt disconnect")
		m.wg.Done()
	}()

	for {
		select {
		case data := <-m.ErroChan:
			if token := m.client.Publish(m.ErrorPublish, 0, false, data); token.Wait() && token.Error() != nil {
				m.logger.Error().Err(token.Error()).Msg("Failed to publish error message")
			}
		case <-m.ctx.Done():
			return
		}
	}

}

func (m *MqttController) SendData(data []byte) bool {
	select {
	case m.ErroChan <- data:
		return true
	default:
		return false
	}
}

// processMessage handles incoming MQTT messages by processing the payload and performing relevant operations.
func (m *MqttController) processMessage(client mqtt.Client, msg mqtt.Message) {
	m.logger.Debug().Msgf("Received message: %s", string(msg.Payload()))
	m.svc.SendData(msg.Payload())
}

// Connect establishes a connection to the MQTT broker using the provided client options.
// If the connection fails, it logs the error and returns an aggregated error.
func (m *MqttController) Connect() error {
	m.client = mqtt.NewClient(m.opt)
	if token := m.client.Connect(); token.Wait() && token.Error() != nil {
		m.logger.Error().Err(token.Error()).Msg("Error connecting to mqtt broker")
		return errors.Join(token.Error(), errors.New("error connecting to mqtt broker"))
	}
	return nil
}

// ConnectHandler returns a function that logs a message when the MQTT client successfully connects to the broker.
func (m *MqttController) ConnectHandler() func(client mqtt.Client) {
	return func(client mqtt.Client) {
		m.logger.Info().Msg("Forwarder connected to mqtt broker")
	}
}

// ConnectLostHandler returns a function that handles MQTT connection loss by logging a warning message with the error details.
func (m *MqttController) ConnectLostHandler() func(client mqtt.Client, err error) {
	return func(client mqtt.Client, err error) {
		m.logger.Warn().Err(err).Msg("Forwarder connection Lost")
	}
}

/*
// NewController initializes and returns a new Controller instance with the specified configuration and service.
// It sets up a logger, loads TLS certificates, and handles errors with insecure skip verify as fallback.
func NewController(conf ControllerConfig, svc model.IService) *Controller {
	logger := initializeLogger(conf.LogLevel)

	btls := false
	tlsConfig, err := cert.LoadCert(conf.Key, conf.Cert, conf.CABundle)
	if err != nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		btls = false
		logger.Error().Err(err).Msg("Failed to load CA certificate; using insecure connection")
	}
	if btls {
		var (
			s string
			e error
		)
		s = cert.ShowCertificatePool(tlsConfig.RootCAs)
		logger.Debug().Msgf("Checking certificates pool: \n%s \n ", s)
		s, e = cert.ShowCertificate(conf.Cert)
		if e != nil {
			logger.Error().Err(e).Msg("Failed to show certificate")
		} else {
			logger.Debug().Msgf("Checking certificates client:\n%s \n ", s)
		}
		s, e = cert.ShowCertificate(conf.CABundle)
		if e != nil {
			logger.Error().Err(e).Msg("Failed to show certificate")
		} else {
			logger.Debug().Msgf("Checking certificates CA bundle \n%s \n ", s)
		}
		s, e = cert.ShowCertificatePoolFromFile(conf.CABundle)
		if e != nil {
			logger.Error().Err(e).Msg("Failed to show certificate")
		} else {
			logger.Debug().Msgf("Checking certificates Pool from file \n%s \n ", s)
		}
	}

	return &Controller{
		ConnectionString: conf.ConnectionString,
		QueueName:        conf.QueueName,
		Svc:              svc,
		cfgTls:           tlsConfig,
		logger:           logger,
		dialtls:          btls,
	}
}

// createLogger initializes and returns a new `zerolog.Logger` configured with the given log level.
// It sets the output to `os.Stdout` with RFC3339 time format and includes the process PID in the log context.
func initializeLogger(logLevel int) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
		Level(zerolog.Level(logLevel)+zerolog.InfoLevel).
		With().
		Timestamp().
		Int("pid", os.Getpid()).
		Logger()
}

// loadCert loads and returns a configured tls.Config using the provided ControllerConfig for TLS settings.
// It reads the CA bundle, certificate, and key files specified in the config. If any file is missing, it returns an error.
// The function also handles loading X.509 key pairs and appending CA certificates to a new certificate pool.
// Note: InsecureSkipVerify is set to true regardless of the config setting.
func loadCert(conf ControllerConfig) (*tls.Config, error) {
	if conf.Key == "" || conf.Cert == "" || conf.CABundle == "" {
		return nil, fmt.Errorf("missing key, cert or ca bundle")
	}

	certlClient, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %v", err)
	}

	caCert, err := os.ReadFile(conf.CABundle)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificates")
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{certlClient},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}, nil
}
*/
