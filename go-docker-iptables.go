package main

import (
//	"github.com/vishvananda/netns"
	"gopkg.in/alecthomas/kingpin.v2"
	"encoding/json"
	"strings"
//	"runtime"
	"os"
//	"os/exec"
	"net"
//	"bufio"
	"bytes"
  "log"
//  "fmt"
//  "io/ioutil"
//  "reflect"
  "strconv"
)

type Container struct {
	Command string
	Created int
	Id      string
	Image   string
	Names   []string
	Ports   []string
	Status  string
  Labels  map[string]string
}

type firewall struct {
	Input struct {
		Rules []rules
	}
	Output struct {
		Rules []rules
	}
  Forward struct {
		Rules []rules
	}
}

type rules struct {
	Source string
  SourcePort int
  Destination string
  DestinationPort int
  Proto string
  Type string
}

var (
  app = kingpin.New("go-docker-iptables", "A tool to manage iptables inside containers from the host")
  Debug = app.Flag("debug","Enable verbose loggin").Bool()
  LabelDef = app.Flag("label", "Iptables search label").Default("com.iptables").String()
)

func main() {
  kingpin.MustParse(app.Parse(os.Args[1:]))

  if *Debug {
		log.Printf("Go docker iptables started")
		log.Printf("Using %s as search label", *LabelDef)
	}

  Firewall := &firewall{}
// Input: []rules, Output: []rules, Forward: []rules }

//  for {

    
    containers, _:= get_containers()
    for _, c:= range containers {
			if *Debug {
				log.Printf("Focus on Container: %s = %s", c.Id, c.PrimaryName())
        c.GetRules( *Firewall )

			}
		}
//	}


  Firewall.PrintRules()
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

func (c Container) PrimaryName() string {
	primary_name := c.Names[0]
	if primary_name == "" {
		return ""
	}
	primary_name = strings.Trim(primary_name, "/")
	return primary_name
}

func (c Container) GetRules(fw firewall) {

  for k, v := range c.Labels {
    if strings.HasPrefix(k, *LabelDef ) {
      // pull the chain from the LabelDef
      chain := strings.SplitAfter(k, *LabelDef )[1]
      // Loop over the possible chains
      switch {
				case  strings.Contains((strings.ToLower(chain)), "input"): {
          chainpos :=  strings.SplitAfter(chain, "input.")[1]
					if *Debug { 
						log.Printf( "Input Chain : %s on position %s", v, chainpos )
					}
          pos, err := strconv.Atoi(chainpos)
          if err != nil {
						log.Println("Illegal position defined for %s and %s",k,v)
					}
					fw.AddInputRule(pos ,v)
				}
				case  strings.Contains((strings.ToLower(chain)), "output"): {
          chainpos :=  strings.SplitAfter(chain, "output.")[1]
					if *Debug { 
						log.Printf( "Output Chain : %s on position %s", v, chainpos )
					}
				}
				case  strings.Contains((strings.ToLower(chain)), "forward"): {
          chainpos :=  strings.SplitAfter(chain, "forward.")[1]
					if *Debug { 
						log.Printf( "Forward Chain : %s on position %s", v, chainpos )
					}
				}


			}

//      if *Debug { 
//        log.Printf( "Key : %s Value %s" ,k,v )
//      }
    }


  }
}

func (f firewall) AddInputRule(pos int, rule string) {
  if *Debug {
    log.Printf( "Pos : %v Rule %s" ,pos,rule )
  }
  f.Input.Rules[pos].Source = rule
}

func (f firewall) PrintRules() {

  for _ , rule := range f.Input.Rules {

    if *Debug {
      log.Printf( "Source : %s SourcePort %s" , rule.Source , rule.SourcePort )
    }

  }
}

