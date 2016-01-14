package main

import (
	"github.com/vishvananda/netns"
	"gopkg.in/alecthomas/kingpin.v2"
	"encoding/json"
	"strings"
	"runtime"
	"os"
	"os/exec"
	"net"
	"bufio"
	"bytes"
)

type Container struct {
	Command string
	Created int
	Id      string
	Image   string
	Names   []string
	Ports   []string
	Status  string
  Labels  []string
}

var (
  app = kingpin.New("go-docker-iptables", "A tool to manage iptables inside containers from the host")
  Debug = app.Flag("debug","Enable verbose loggin").Bool()
)

func main() {
  kingpin.MustParse(app.Parse(os.Args[1:]))

  if *Debug {
		log.Printf("Go docker iptables started")
	}

  if err != nil {
		panic(err)
  }

  for {
    containers, _:= get_containers()
    for _, c:= range containers {
			if *Debug {
				log.Printf("Container: %s = %s", c.Id, c.PrimaryName())
			}
		}
	}
}

func get_containers() ([]Container, error) {
	c, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		return nil, err
	}

	if *Debug {
		log.Println("Sending request...")
	}
	_, err = c.Write([]byte("GET /containers/json HTTP/1.0\r\n\r\n"))
	if err != nil {
		return nil, err
	}
	var result []byte

	var in_bytes = make([]byte, 102400)
	for {
		num, err := c.Read(in_bytes)
		result = append(result, in_bytes...)
		if err != nil || num < len(in_bytes) {
			break
		}
	}
	result = bytes.Trim(result, "\x00")
	results := bytes.SplitN(result, []byte{'\r', '\n', '\r', '\n'}, 2)
	jsonBlob := results[1]
	if *Debug {
		log.Println("Got response:")
		log.Println(string(jsonBlob))
	}

	var containers []Container
	err = json.Unmarshal(jsonBlob, &containers)
	return containers, err
}

