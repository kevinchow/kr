package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/kryptco/kr"
	"github.com/kryptco/kr/krdclient"

	"github.com/urfave/cli"
)

func addCommand(c *cli.Context) (err error) {
	go func() {
		kr.Analytics{}.PostEventUsingPersistedTrackingID("kr", "add", nil, nil)
	}()

	// ensure there's a user@server or alias to add to
	if len(c.Args()) < 1 {
		PrintFatal(os.Stderr, "kr add <user@server or SSH alias>")
		return
	}

	server := c.Args()[0]

	portFlag := c.String("port")
	publicKeyFlag := c.String("public-key")

	var authorizedKeyString string

	// check if input is from stdin
	fi, _ := os.Stdin.Stat()

	if (fi.Mode() & os.ModeCharDevice) == 0 {
		reader := bufio.NewReader(os.Stdin)
		publicKeyStdin, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		authorizedKeyString = publicKeyStdin

	} else if publicKeyFlag != "" {
		authorizedKeyString = publicKeyFlag
	} else {
		me, err := krdclient.RequestMe()
		if err != nil {
			PrintFatal(os.Stderr, "error retrieving your public key: ", err.Error())
		}

		authorizedKeyString, err = me.AuthorizedKeyStringWithoutEmail()
		if err != nil {
			PrintFatal(os.Stderr, err.Error())
		}
	}

	authorizedKey := append([]byte(authorizedKeyString), []byte("\n")...)

	PrintErr(os.Stderr, "Adding SSH public key to %s", server)

	authorizedKeyReader := bytes.NewReader(authorizedKey)
	args := []string{server}
	if portFlag != "" {
		args = append(args, "-p "+portFlag)
	}
	args = append(args, createAddKeyScriptOrFatal())
	sshCommand := exec.Command("ssh", args...)
	sshCommand.Stdin = authorizedKeyReader
	sshCommand.Stdout = os.Stdout
	sshCommand.Stderr = os.Stderr
	sshCommand.Run()
	return
}

func createAddKeyScriptOrFatal() string {
	// Atomically update keys using mv and random file name
	nonceFileName, err := kr.Rand256Base62()
	if err != nil {
		PrintFatal(os.Stderr, err.Error())
	}
	return fmt.Sprintf("bash -c 'read keys; mkdir -m 700 -p ~/.ssh && touch ~/.ssh/authorized_keys && grep \"$keys\" ~/.ssh/authorized_keys 2>/dev/null 1>/dev/null || { mv ~/.ssh/authorized_keys ~/.ssh/%s && echo $keys >> ~/.ssh/%s && mv ~/.ssh/%s ~/.ssh/authorized_keys; } ; chmod 600 ~/.ssh/authorized_keys'", nonceFileName, nonceFileName, nonceFileName)

}
