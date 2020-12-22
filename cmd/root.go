package cmd

import (
	"fmt"
	"net/http"

	srv "github.com/cludden/terraform-registry/pkg/server"
	"github.com/go-playground/validator"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var CLI struct {
	Server server `cmd:"" help:"start registry server"`
}

type server struct {
	Config string `short:"c" help:"configuration file path"`
}

// Run defines server command entrypoint
func (cmd *server) Run() error {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	if cmd.Config != "" {
		viper.SetConfigFile(cmd.Config)
	} else {
		viper.AddConfigPath("/etc/terraform-registry")
		viper.AddConfigPath(".")
	}

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("error reading config: %v", err)
	}

	var conf srv.Config
	if err := viper.Unmarshal(&conf); err != nil {
		return fmt.Errorf("error parsing config: %v", err)
	}

	if err := validator.New().Struct(&conf); err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	server, err := srv.NewServer(conf)
	if err != nil {
		return err
	}

	logrus.Infoln("server listening on :8000")
	return http.ListenAndServe(":8000", server)
}
