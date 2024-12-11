package utils

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	Standard = "Standard"
	Stub     = "Stub"
	NSSA     = "NSSA"

	None      = "None"
	MD5       = "MD5"
	Plaintext = "Plaintext"
)

func GetOspfJsonFile() string {
	return filepath.Join(GetZvrZsConfigPath(), "ospf.json")
}

const ospfAddTemplate = `'configure terminal
router ospf
ospf router-id {{.RouterIdCmd}}
{{range .NetworkCmd}}
network {{.Network}} area {{.AreaId}}
{{- end}}
{{range .AreaCmd}}
{{if eq .Type "Stub"}}area {{.Id}} stub{{end}}
{{if eq .Auth "Plaintext"}}area {{.Id}} authentication{{else if eq .Auth "MD5"}}area {{.Id}} authentication message-digest{{end}}
{{- end}}
{{range .IfaceCmd}}
interface {{.Name}}
{{if eq .Auth "Plaintext"}}
ip ospf authentication
ip ospf authentication-key {{.Password}}
{{else if eq .Auth "MD5"}}
ip ospf authentication message-digest
ip ospf message-digest-key {{.Key}} md5 {{.Password}}
{{- end}}
{{- end}}
exit'
`

const ospfDeleteTemplate = `'configure terminal
router ospf
{{if .RouterIdCmd}}no ospf router-id {{.RouterIdCmd}}{{end}}
{{range .NetworkCmd}}
no network {{.Network}} area {{.AreaId}}
{{- end}}
{{range .AreaCmd}}
{{if eq .Type "Stub"}}no area {{.Id}} stub{{end}}
{{if eq .Auth "Plaintext"}}no area {{.Id}} authentication{{else if eq .Auth "MD5"}}no area {{.Id}} authentication{{end}}
{{- end}}
{{range .IfaceCmd}}
interface {{.Name}}
{{if eq .Auth "Plaintext"}}
no ip ospf authentication
no ip ospf authentication-key {{.Password}}
{{else if eq .Auth "MD5"}}
no ip ospf authentication message-digest
no ip ospf message-digest-key {{.Key}} md5 {{.Password}}
{{- end}}
{{- end}}
exit'
`

type IfaceAttrs struct {
	Name     string
	Auth     string
	Key      string
	Password string
}
type NetworkAttrs struct {
	Network string
	AreaId  string
}
type AreaAttrs struct {
	Id   string
	Auth string
	Type string
}

type VtyshOspfCmd struct {
	RouterIdCmd string
	IfaceCmd    map[string]IfaceAttrs
	NetworkCmd  []NetworkAttrs
	AreaCmd     map[string]AreaAttrs
	isDelete    bool
}

func NewVtyshOspfCmd() *VtyshOspfCmd {
	cmd := &VtyshOspfCmd{
		RouterIdCmd: "",
		IfaceCmd:    make(map[string]IfaceAttrs),
		NetworkCmd:  []NetworkAttrs{},
		AreaCmd:     make(map[string]AreaAttrs),
		isDelete:    false,
	}

	return cmd
}

func (v *VtyshOspfCmd) SetRouteId(routeId string) *VtyshOspfCmd {
	v.RouterIdCmd = routeId

	return v
}

func (v *VtyshOspfCmd) SetInterface(ifname string, authType string, authParam string) *VtyshOspfCmd {
	attr := IfaceAttrs{}
	if authType == Plaintext {
		attr = IfaceAttrs{
			Name:     ifname,
			Auth:     authType,
			Key:      "",
			Password: authParam,
		}
	} else if authType == MD5 {
		tmp := strings.Split(authParam, "/")
		attr = IfaceAttrs{
			Name:     ifname,
			Auth:     authType,
			Key:      tmp[0],
			Password: tmp[1],
		}
	} else {
		attr = IfaceAttrs{
			Name:     ifname,
			Auth:     authType,
			Key:      "",
			Password: "",
		}
	}
	v.IfaceCmd[ifname] = attr

	return v
}

func (v *VtyshOspfCmd) AddNetwork(network string, areaId string) *VtyshOspfCmd {
	attrs := NetworkAttrs{
		Network: network,
		AreaId:  areaId,
	}
	v.NetworkCmd = append(v.NetworkCmd, attrs)

	return v
}

func (v *VtyshOspfCmd) SetArea(areaId string, areaType string, authType string) *VtyshOspfCmd {
	attr := AreaAttrs{
		Id:   areaId,
		Type: areaType,
		Auth: authType,
	}
	v.AreaCmd[areaId] = attr

	return v
}

func (v *VtyshOspfCmd) SetDelete() *VtyshOspfCmd {
	v.isDelete = true

	return v
}

func (v *VtyshOspfCmd) Apply() error {
	var (
		tmpl *template.Template
		buf  bytes.Buffer
		err  error
	)

	if len(v.AreaCmd) == 0 && len(v.IfaceCmd) == 0 && len(v.NetworkCmd) == 0 {
		log.Debugf("ospf command is empty, no need invoke vtysh")
		return nil
	}
	if v.isDelete {
		if tmpl, err = template.New("deleteOspf").Parse(ospfDeleteTemplate); err != nil {
			return err
		}
		if err = tmpl.Execute(&buf, v); err != nil {
			return err
		}
	} else {
		if tmpl, err = template.New("addOspf").Parse(ospfAddTemplate); err != nil {
			return err
		}
		if err = tmpl.Execute(&buf, v); err != nil {
			return err
		}
	}

	bash := Bash{
		Command: fmt.Sprintf("vtysh -d ospfd -E -c %s", &buf),
	}

	if ret, out, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		return errors.Errorf("ospf command error: %+v", out)
	}

	return nil
}
