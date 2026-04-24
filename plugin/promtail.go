package plugin

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"zstack-vyos/server"
	"zstack-vyos/utils"

	log "github.com/sirupsen/logrus"
)

const (
	PROMTAIL_CONFIG_PATH     = "/promtail/config"
	PROMTAIL_CONFIG          = "promtail-config.yaml"
	PROMTAIL_TEMPLATE_CONFIG = "promtail-config.template.yaml"
)

func getPromtailRootPath() string {
	return filepath.Join(utils.GetZvrRootPath(), "promtail/")
}

type ConfigPromtailCmd struct {
	Enable    bool   `json:"enable"`
	LogTarget string `json:"logTarget"`
}

type PromtailConfig struct {
	Server struct {
		HTTPListenPort int `yaml:"http_listen_port"`
		GRPCListenPort int `yaml:"grpc_listen_port"`
	} `yaml:"server"`

	Positions struct {
		Filename string `yaml:"filename"`
	} `yaml:"positions"`

	Clients []struct {
		URL string `yaml:"url"`
	} `yaml:"clients"`

	ScrapeConfigs []interface{} `yaml:"scrape_configs"`
}

func promtailConfigHandler(ctx *server.CommandContext) interface{} {
	cmd := &ConfigPromtailCmd{}
	ctx.GetCommand(cmd)

	if !utils.IsEuler2203() {
		return nil
	}

	PROMTAIL_CONFIG_PATH := filepath.Join(getPromtailRootPath(), PROMTAIL_CONFIG)
	PROMTAIL_TEMPLATE_CONFIG_PATH := filepath.Join(getPromtailRootPath(), PROMTAIL_TEMPLATE_CONFIG)
	mnHost := cmd.LogTarget
	if utils.IsIpv6Address(cmd.LogTarget) {
		mnHost = fmt.Sprintf("[%s]", cmd.LogTarget)
	}
	lokiURL := fmt.Sprintf("http://%s:3100/loki/api/v1/push", mnHost)

	if cmd.Enable {
		if _, err := os.Stat(PROMTAIL_CONFIG_PATH); os.IsNotExist(err) {
			log.Warnf("Promtail config file not found: %s", PROMTAIL_CONFIG_PATH)
			if _, err := os.Stat(PROMTAIL_TEMPLATE_CONFIG_PATH); os.IsNotExist(err) {
				log.Warnf("Promtail config template not found: %s. Using default behavior.", PROMTAIL_TEMPLATE_CONFIG_PATH)
			} else {
				log.Infof("Copying template config from %s to %s", PROMTAIL_TEMPLATE_CONFIG_PATH, PROMTAIL_CONFIG_PATH)
				err := utils.CopyFile(PROMTAIL_TEMPLATE_CONFIG_PATH, PROMTAIL_CONFIG_PATH)
				if err != nil {
					log.Errorf("Failed to copy template config: %+v", err)
					return nil
				}
			}
		}
		configData, err := os.ReadFile(PROMTAIL_CONFIG_PATH)
		if err != nil {
			log.Errorf("Failed to read promtail config file: %+v", err)
			return nil
		}
		var config PromtailConfig
		err = yaml.Unmarshal(configData, &config)
		if err != nil {
			log.Errorf("Failed to parse promtail config file: %+v", err)
			return nil
		}

		currentURL := ""
		if len(config.Clients) > 0 {
			currentURL = config.Clients[0].URL
		}

		if currentURL != lokiURL {
			log.Infof("Updating Promtail configuration...")
			config.Clients = []struct {
				URL string `yaml:"url"`
			}{
				{URL: lokiURL},
			}

			newConfigData, err := yaml.Marshal(&config)
			if err != nil {
				log.Errorf("Failed to marshal updated promtail config: %+v", err)
				return nil
			}

			err = os.WriteFile(PROMTAIL_CONFIG_PATH, newConfigData, 0644)
			if err != nil {
				log.Errorf("Failed to write updated promtail config: %+v", err)
				return nil
			}

			log.Infof("Promtail configuration updated successfully")
		} else {
			log.Infof("Promtail configuration is already up-to-date")
		}

		isActiveCmd := utils.Bash{
			Command: "systemctl is-active --quiet promtail",
		}

		if err := isActiveCmd.Run(); err != nil {
			log.Infof("Promtail is not running, starting the service...")
			startCmd := utils.Bash{
				Command: "systemctl start promtail",
				Sudo:    true,
			}
			if err := startCmd.Run(); err != nil {
				log.Errorf("Failed to start promtail: %+v", err)
			} else {
				log.Infof("Promtail started successfully")
			}

			enableCmd := utils.Bash{
				Command: "systemctl enable promtail",
				Sudo:    true,
			}
			if err := enableCmd.Run(); err != nil {
				log.Errorf("Failed to enable promtail at boot: %+v", err)
			} else {
				log.Infof("Promtail enabled at boot successfully")
			}
		} else if currentURL != lokiURL {
			log.Infof("Promtail configuration changed, restarting the service...")
			restartCmd := utils.Bash{
				Command: "systemctl restart promtail",
				Sudo:    true,
			}
			if err := restartCmd.Run(); err != nil {
				log.Errorf("Failed to restart promtail: %+v", err)
			} else {
				log.Infof("Promtail restarted successfully")
			}
		} else {
			log.Infof("Promtail is running and configuration is up-to-date, no restart needed.")
		}
	} else {
		stopCmd := utils.Bash{
			Command: "systemctl is-active --quiet promtail && systemctl stop promtail",
			Sudo:    true,
		}
		if err := stopCmd.Run(); err != nil {
			log.Errorf("Failed to stop promtail: %+v", err)
		} else {
			log.Infof("Promtail stopped successfully")
		}
		disableCmd := utils.Bash{
			Command: "systemctl disable promtail",
			Sudo:    true,
		}
		if err := disableCmd.Run(); err != nil {
			log.Errorf("Failed to disable promtail at boot: %+v", err)
		} else {
			log.Infof("Promtail disabled at boot successfully")
		}
		if err := os.Remove(PROMTAIL_CONFIG_PATH); err != nil {
			if os.IsNotExist(err) {
				log.Warnf("Promtail config file already deleted: %s", PROMTAIL_CONFIG_PATH)
			} else {
				log.Errorf("Failed to delete promtail config file: %+v", err)
			}
		} else {
			log.Infof("Promtail config file deleted: %s", PROMTAIL_CONFIG_PATH)
		}
	}

	return nil
}

func PromtailEntryPoint() {
	server.RegisterAsyncCommandHandler(PROMTAIL_CONFIG_PATH, promtailConfigHandler)
}
