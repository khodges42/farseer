package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

type connectionConfig struct {
	Username string
	Password string
	KeyFile string
	Hosts []string
	Function string
	Query []string
	RemoteCommand string
	sshConfig *ssh.ClientConfig
	Port string
	Until string
	Since string
	Unit string
}

type connectionOutputs struct {
	results []connectionOutput
}

type connectionOutput struct {
	hostname string
	output string
}

type journalCtlLog struct {
	Host string
	Timestamp int `json:"__REALTIME_TIMESTAMP,string"`
	BootId string `json:"_BOOT_ID"`
	Priority string `json:"PRIORITY"`
	JHostname string `json:"_HOSTNAME"`
	PID string `json:"_PID"`
	UID string `json:"_UID"`
	SELinuxContext string `json:"_SELINUX_CONTEXT"`
	GID string `json:"_GID"`
	SyslogID string `json:"SYSLOG_IDENTIFIER"`
	CodeFile string `json:"CODE_FILE"`
	CodeLine string `json:"CODE_LINE"`
	MessageID string `json:"MESSAGE_ID"`
	Message string `json:"MESSAGE"`
	Unit string `json:"UNIT"`
}


func main(){
	connConfig, err := verifyArgs(getCliFlags())
	connConfig.RemoteCommand = generateRemoteCommand(connConfig)
	connConfig.sshConfig, err = generateConfig(connConfig)
	if err != nil {
		log.Fatalf("Failed while generating connection config: %s",err)
		os.Exit(1)
	}
	output := connectToHosts(connConfig)
	parsedOutputs := parseJournalCtlOutput(output, connConfig)

	if strings.ToUpper(connConfig.Function) == "JOURNALCTL"{
		displayJournalOutput(parsedOutputs)
	} else {
		displayOutput(parsedOutputs)
	}



}

func displayJournalOutput(output []journalCtlLog){
	for _, result := range output {
		if len(result.Message) > 1 {
			fmt.Printf("%s\t%s\t%s\n", result.Host, time.Unix(int64(result.Timestamp/ 1000000),0 ), result.Message)
		}
	}
}

func displayOutput(output []journalCtlLog){
	for _, result := range output {
		if len(result.Message) > 1 {
			fmt.Printf("%s\t%s\n", result.Host, result.Message)
		}
	}
}

func parseJournalCtlOutput (output connectionOutputs, connConfig connectionConfig)([]journalCtlLog) {
	logs := []journalCtlLog{}
	for _, result := range output.results {
		splitResByLine := strings.Split(result.output, "\n")
		for _, line := range splitResByLine {
			var logln = &journalCtlLog{}
			logln.Host = result.hostname
			err := json.Unmarshal([]byte(line), logln)
			if err != nil {
				logln.Message = line
			}
			logs = append(logs, *logln)
		}
	}
	logs = sortLogs(logs)
	return logs
}

func sortLogs(logs []journalCtlLog) ([]journalCtlLog) {
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp < logs[j].Timestamp
	})
	return logs
}

func connectToHosts (connConfig connectionConfig) (connectionOutputs){
	results := make(chan string, 10)
	timeout := time.After(15 * time.Second)
	outputMap := connectionOutputs{}

	for _, hostname := range connConfig.Hosts {
		go func(hostname string) {
			out, err := executeRemoteCommand(hostname, connConfig)
			if err != nil {
				out = fmt.Sprintf("Farsight error: %s\n", err)
			}
			results <- out
		}(hostname)
	}

	for i := 0; i < len(connConfig.Hosts); i++ {
		op := connectionOutput{}
		op.hostname = connConfig.Hosts[i]
		select {
		case res := <-results:
			op.output = fmt.Sprintf(res)
		case <-timeout:
			op.output = fmt.Sprintf("timed out")
		}
		outputMap.results = append(outputMap.results, op)
	}
	return outputMap
}

func executeRemoteCommand (hostname string, cliArgs connectionConfig) (string, error) {
	client, err := connectToHost(hostname, cliArgs)
	if err != nil {
		client.Close()
		return "", err
	}

	session, err := startSession(client)
	if err != nil {
		client.Close()
		return "", err
	}


	out, err := session.CombinedOutput(cliArgs.RemoteCommand)
	if err != nil {
		client.Close()
		return "", err
	}

	return string(out), nil
}

func generateRemoteCommand (cliArgs connectionConfig) (cmd string) {
	switch funct := strings.ToUpper(cliArgs.Function); funct {
	case "JOURNALCTL":
		cmd = strings.Join([]string{ generateJournalctlString(cliArgs),
							strings.Join(cliArgs.Query, " | ")}, " ")

	case "CAT":
		cmd = fmt.Sprintf("cat %s %s", cliArgs.Query[0], strings.Join(cliArgs.Query[1:], " | "))
	default:
		cmd = fmt.Sprintf("%s %s", cliArgs.Function, strings.Join(cliArgs.Query, " | "))
	}
	return cmd
}

func generateJournalctlString (cliArgs connectionConfig) (cmd string){
	cmd_string := "sudo journalctl -o json"

	if cliArgs.Unit != "" {
		cmd_string = strings.Join([]string{cmd_string, fmt.Sprintf("-u %s", cliArgs.Unit)},
			" ")
	}

	if cliArgs.Since != "" {
		cmd_string = strings.Join([]string{cmd_string, fmt.Sprintf("--since \"%s\"", cliArgs.Since)},
		" ")
	}

	if cliArgs.Until != "" {
		cmd_string = strings.Join([]string{cmd_string, fmt.Sprintf("--until \"%s\"", cliArgs.Until)},
			" ")
	}

	return cmd_string
}

func startSession (client *ssh.Client) (*ssh.Session, error) {
	session, err := client.NewSession()
	if err != nil {
		fmt.Println(err)
		client.Close()
		return nil, err
	}
	return session, nil
}

func generateConfig (cliargs connectionConfig) (*ssh.ClientConfig, error) {
	var authMethod ssh.AuthMethod
	var hostKey ssh.PublicKey

	if len(cliargs.Password) > 0 {
		authMethod = ssh.Password(cliargs.Password)
	} else if len(cliargs.KeyFile) > 0 {
		key, err := ioutil.ReadFile(cliargs.KeyFile)
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("Can't read key!")
			return nil, err
		} else {
			authMethod = ssh.PublicKeys(signer)
		}
	}
	sshConfig := &ssh.ClientConfig{
		User: cliargs.Username,
		Auth: []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey() //todo
	return sshConfig, nil
}

func connectToHost(hostname string, cliargs connectionConfig) (*ssh.Client, error) {
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", hostname, cliargs.Port), cliargs.sshConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func verifyArgs(cliArgs connectionConfig)(connectionConfig, error) {
	if len(cliArgs.Hosts) > 0 && len(cliArgs.Function) > 0 {
		if len(cliArgs.Username) <= 0 {
			usr, _ := user.Current()
			cliArgs.Username = usr.Username
		}

		if len(cliArgs.KeyFile) <= 0 {
			usr, _ := user.Current()
			cliArgs.KeyFile = fmt.Sprintf("%s/.ssh/id_rsa", usr.HomeDir)
		}



		return cliArgs, nil
	} else {
		err := errors.New("could not parse CLI arguments")
		return cliArgs, err
	}
}

func getCliFlags() (connectionConfig){
	userName := flag.String("u", "", "Username")
	password:= flag.String("p", "", "Password")
	sshKey := flag.String("i", "", "SSH Key file")
	hostList := flag.String("h", "", "File or string of hosts, comma separated.")
	function := flag.String("f", "", "Name of File or Function (journalctl)")
	query := flag.String("q", "", "Regex Query String(s), comma separated.")
	since := flag.String("since", "", "Journalctl Since string (5 min ago)")
	until := flag.String("until", "", "Journalctl Until string (5 min ago)")
	port := flag.String("port", "22", "SSH Port.")
	unit := flag.String("unit", "", "SystemD unit")

	flag.Parse()

	return connectionConfig{
		Username: *userName,
		Password: *password,
		KeyFile: *sshKey,
		Hosts: ParseCSV(*hostList),
		Function: *function,
		Query: ParseCSV(*query),
		Port: *port,
		Until: *until,
		Since: *since,
		Unit: *unit,
	}
}

func ParseCSV(csvData string) ([]string) {
	if len(csvData) > 0 {
		var csvString string
		looksLikeCSVString, _ := regexp.MatchString("([\\s]*[a-z0-9A-Z]+,[\\s]*[a-z0-9A-Z]+)", csvData)
		if looksLikeCSVString { // It's a CSV string
			csvString = csvData
		} else { // It looks like a file
			if _, err := os.Stat(csvData); os.IsNotExist(err) { // If the file doesn't exist just use the string
				csvString = csvData
			} else { // It's a file. Read it and parse.
				c, err := ioutil.ReadFile(csvData)
				if err != nil {
					return []string{}
				} else {
					csvString = string(c)
				}
			}
		}
		return strings.Split(SpaceMap(csvString), ",")
	}
	return []string{}
}

func SpaceMap(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}