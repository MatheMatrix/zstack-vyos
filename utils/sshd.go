package utils

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"text/template"

	"path/filepath"

	"github.com/pkg/errors"
)

const (
	SSHD_CONFIG_FILE   = "/etc/ssh/sshd_config"
	SSHD_TEMPLATE_FILE = "template/sshd_tmpl"
)

type SshdInfo struct {
	Port                   int
	ListenAddress          string
	ListenAddress6         string
	Keys                   []string
	PasswordAuthentication string
}

func getSshConfigFileTemp() string {
	return filepath.Join(GetUserHomePath(), "sshd_config")
}

func getSshKeysPath() string {
	return filepath.Join(GetUserHomePath(), ".ssh/authorized_keys")
}

func NewSshServer() *SshdInfo {
	sshAttr := SshdInfo{
		Port:                   22,
		PasswordAuthentication: "no",
	}
	return &sshAttr
}

func normalizeSshListenAddress(address string) string {
	parsed := net.ParseIP(address)
	if parsed == nil || parsed.IsUnspecified() {
		return ""
	}
	return address
}

func (s *SshdInfo) normalizeListenAddresses() {
	s.ListenAddress = normalizeSshListenAddress(s.ListenAddress)
	s.ListenAddress6 = normalizeSshListenAddress(s.ListenAddress6)
}

func (s *SshdInfo) SetPorts(port int) *SshdInfo {
	if port > 0 {
		s.Port = port
	}

	return s
}

func (s *SshdInfo) SetListen(address string) *SshdInfo {
	if address != "" {
		address = normalizeSshListenAddress(address)
		if address == "" {
			return s
		}
		parsed := net.ParseIP(address)
		if parsed.To4() == nil {
			s.ListenAddress6 = address
		} else {
			s.ListenAddress = address
		}
	}

	return s
}

func (s *SshdInfo) SetKeys(pub_key string) *SshdInfo {
	if pub_key != "" {
		s.Keys = append(s.Keys, pub_key)
	}

	return s
}

func (s *SshdInfo) SetPasswordAuthentication(passwordAuthentication string) *SshdInfo {
	if passwordAuthentication != "" {
		s.PasswordAuthentication = passwordAuthentication
	}

	return s
}

func (s *SshdInfo) ConfigService() error {
	var (
		buf  bytes.Buffer
		tmpl *template.Template
		err  error
	)

	text := sshdTemplate

	if IsEuler2203() {
		text = sshdTemplateEuler
	} else if runtime.GOARCH == "arm64" {
		text = sshdTemplateArm
		listenAddress := s.ListenAddress
		if listenAddress == "" {
			listenAddress = s.ListenAddress6
		}
		if listenAddress != "" {
			_ = Retry(func() error {
				var e error
				listener, e := net.Listen("tcp", net.JoinHostPort(listenAddress, fmt.Sprintf("%d", s.Port)))
				if e != nil {
					return nil
				} else {
					_ = listener.Close()
					return errors.New("ssh is not configured, wait 5 seconds")
				}
			}, 5, 5)
		}
	}

	s.normalizeListenAddresses()
	if tmpl, err = template.New("ssh.conf").Parse(text); err != nil {
		return err
	}
	if err = tmpl.Execute(&buf, s); err != nil {
		return err
	}
	if err = os.WriteFile(getSshConfigFileTemp(), buf.Bytes(), 0664); err != nil {
		return err
	}
	// bash := Bash{
	// 	Command: fmt.Sprintf("mv %s %s", getSshConfigFileTemp(), SSHD_CONFIG_FILE),
	// 	Sudo:    true,
	// }
	// bash.Run()

	if err = CopyFile(getSshConfigFileTemp(), SSHD_CONFIG_FILE); err != nil {
		return err
	}

	if len(s.Keys) != 0 {
		keys_str := strings.Join(s.Keys, "\n")
		file, err := CreateFileIfNotExists(getSshKeysPath(), os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}

		SetFileOwner(getSshKeysPath(), GetZvrUser(), "users")

		defer file.Close()

		if _, err := file.WriteString(keys_str); err != nil {
			return err
		}

	}

	s.RestareServer()

	return nil
}

func (s *SshdInfo) RestareServer() error {
	return ServiceOperation("sshd", "restart")
}

func (s *SshdInfo) StopService() error {
	return ServiceOperation("sshd", "stop")
}
