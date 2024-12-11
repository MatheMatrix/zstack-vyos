package utils

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const pimdAddTemplate = `'configure terminal
ip multicast rpf-lookup-mode mrib-then-urib
{{range $i, $iface := .InterfaceCmd}}
interface {{$iface.Name}}
ip pim
ip igmp
exit
{{- end}}
{{range $r, $rp := .RpCmd}}
ip pim rp {{$rp.RpAddress}} {{$rp.GroupAddress}}
{{- end}}
end'
`

const pimdDeleteTemplate = `'configure terminal
{{range $i, $iface := .InterfaceCmd}}
interface {{$iface.Name}}
no ip pim
no ip igmp
exit
{{- end}}
{{range $r, $rp := .RpCmd}}
no ip pim rp {{$rp.RpAddress}} {{$rp.GroupAddress}}
{{- end}}
end'
`

type InterfaceAttrs struct {
	Name string
}

type RpAttrs struct {
	RpAddress    string
	GroupAddress string
}

type VtyshPimdCmd struct {
	InterfaceCmd map[string]InterfaceAttrs
	RpCmd        map[string]RpAttrs
	isDelete     bool
}

func NewVtyshPimdCmd() *VtyshPimdCmd {
	cmd := &VtyshPimdCmd{
		InterfaceCmd: make(map[string]InterfaceAttrs),
		RpCmd:        make(map[string]RpAttrs),
		isDelete:     false,
	}
	return cmd
}

func (v *VtyshPimdCmd) SetInterface(ifname string) *VtyshPimdCmd {
	attr := InterfaceAttrs{
		Name: ifname,
	}
	v.InterfaceCmd[ifname] = attr
	return v
}

func (v *VtyshPimdCmd) DeleteInterface(ifname string) *VtyshPimdCmd {
	delete(v.InterfaceCmd, ifname)
	return v
}

func (v *VtyshPimdCmd) SetRp(rpAddress string, groupAddress string) *VtyshPimdCmd {
	key := fmt.Sprintf("%s-%s", rpAddress, groupAddress)
	attr := RpAttrs{
		RpAddress:    rpAddress,
		GroupAddress: groupAddress,
	}
	v.RpCmd[key] = attr
	return v
}

func (v *VtyshPimdCmd) DeleteRp(rpAddress string, groupAddress string) *VtyshPimdCmd {
	key := fmt.Sprintf("%s-%s", rpAddress, groupAddress)
	delete(v.RpCmd, key)
	return v
}

func (v *VtyshPimdCmd) SetDelete() *VtyshPimdCmd {
	v.isDelete = true
	return v
}

func (v *VtyshPimdCmd) Apply() error {
	var (
		tmpl *template.Template
		buf  bytes.Buffer
		err  error
	)

	if len(v.InterfaceCmd) == 0 && len(v.RpCmd) == 0 {
		log.Debugf("pimd command is empty, no need invoke vtysh")
		return nil
	}

	if v.isDelete {
		if tmpl, err = template.New("deletePimd").Parse(pimdDeleteTemplate); err != nil {
			return err
		}
		if err = tmpl.Execute(&buf, v); err != nil {
			return err
		}
	} else {
		if tmpl, err = template.New("addPimd").Parse(pimdAddTemplate); err != nil {
			return err
		}
		if err = tmpl.Execute(&buf, v); err != nil {
			return err
		}
	}

	bash := Bash{
		Command: fmt.Sprintf("vtysh -c %s", &buf),
	}

	if ret, out, _, err := bash.RunWithReturn(); ret != 0 || err != nil {
		return errors.Errorf("pimd command error: %+v", out)
	}

	return nil
}

