package utils

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

func formatVersion(versionNo string) int {
	if versionNo == "" {
		return -1
	}
	no := 0
	nos := strings.Split(versionNo, ".")
	if len(nos) != 3 {
		return -1
	}

	for i, n := range nos {
		j, err := strconv.Atoi(n)
		if err != nil || j >= 100 || j < 0 {
			return -1
		}
		no += j * int(math.Pow(100, float64((2-i))))
	}
	return no
}

// CompareVersion
//*   Compare two version numbers
//*   version string format: x.y.z, ( 0 <= x, y, y < 100)
func CompareVersion(version1, version2 string) (error, int) {
	version1No, version2No := formatVersion(version1), formatVersion(version2)
	if version1No == -1 || version2No == -1 {
		return errors.New("version string format error"), 0
	}

	return nil, version1No - version2No
}

// ValidVersionString
//*   Compare two version numbers
//*   version string format: x.y.z, ( 0 <= x, y, y < 100)
func ValidVersionString(version string) bool {
	versionList := strings.Split(version, ".")
	if len(versionList) != 3 {
		return false
	}
	for _, n := range versionList {
		j, err := strconv.Atoi(n)
		if err != nil || j >= 100 || j < 0 {
			return false
		}
	}
	return true
}

func IsVYOS() bool {
	// vbash is a special bash in VyOS image that removed
	// most of the system informations, such as release info, kernel info...,
	// so there is no elegant way to identify VyOS guest.
	//
	// If u think of a better way, thanks to modify it.
	// PS: The way should be universal on different platform.
	//     x86: vyos/generic-linux, arm64: vyos/generic-linux, loong64: generic-linux
	if exist, _ := PathExists("/bin/vbash"); !exist {
		return false
	}
	return true
}

func GetZvrUser() string {
	if IsVYOS() {
		return "vyos"
	}
	return "zstack"
}

func GetUserHomePath() string {
	if IsVYOS() {
		return "/home/vyos/"
	}
	return "/home/zstack/"
}

func GetZvrRootPath() string {
	return GetUserHomePath() + "zvr/"
}

func GetZvrZsConfigPath() string {
	return GetZvrRootPath() + ".zstack_config/"
}

func GetThirdPartyBinPath() string {
	if IsVYOS() {
		return "/opt/vyatta/sbin/"
	}
	return "/usr/local/bin/"
}
