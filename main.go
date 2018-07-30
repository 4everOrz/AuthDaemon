package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/kylelemons/go-gypsy/yaml"
)

var (
	delay      int
	ConfigFile *yaml.File
	count      int
)

func init() {
	var err error
	ConfigFile, err = yaml.ReadFile("config/DaemonConf.yaml")
	if err != nil {
		fmt.Println("read config file failed!")
	}
	delay, _ = strconv.Atoi(GetString("delay"))
}

func main() {
	fmt.Println("The Daemon of AuthService is running...")
	fmt.Println("The interval of restarting AuthService is " + strconv.Itoa(delay) + " minutes")
	ticker := time.NewTicker(60 * time.Second) //15天 1296000  一周 604800  1天 86400
	startprocess()
	for {
		select {
		case <-ticker.C:
			count++
			if count >= delay {
				killprocess()
				time.Sleep(1 * time.Second)
				startprocess()
				count = 0
			}
		}
	} /**/
}

func startprocess() {
	cmd := exec.Command("cmd.exe", "/c", "start", "startprocess.bat")
	if err := cmd.Run(); err != nil {
		fmt.Println("error:", err)
	}
}
func killprocess() {
	cmd := exec.Command("cmd.exe", "/c", "start", "killprocess.bat")
	if err := cmd.Run(); err != nil {
		fmt.Println("error:", err)
	}
}
func GetString(key string) string {
	str, err := ConfigFile.Get(key)
	if err != nil {
		fmt.Println("read configfile failed!")
	}
	return str
}
