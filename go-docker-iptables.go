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
//	"bufio"
	"bytes"
  "log"
  "fmt"
  "io/ioutil"
//  "reflect"
  "strconv"
)


const (
	iptablesPath = "/usr/sbin/iptables"
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
  SourcePort string
  Destination string
  DestinationPort string 
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

//  for {

    
			containers, _:= get_containers()
			for _, c:= range containers {
				Firewall := &firewall{ }
				Firewall.Input.Rules = make([]rules, 100)
				Firewall.Output.Rules = make([]rules, 100)
				Firewall.Forward.Rules = make([]rules, 100)

				if *Debug {
					log.Printf("Focus on Container: %s = %s", c.Id, c.PrimaryName())
				}
					c.GetRules( *Firewall )		

        err := c.ApplyRules( *Firewall )
				if err != nil {
					log.Println("Error Applying Rules")
				}

					

				if *Debug {
//					Firewall.PrintRules()
				}
			}
//	}


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

func (c Container) tasksFile() string {
	return fmt.Sprintf("/sys/fs/cgroup/memory/system.slice/docker-%s.scope/tasks", c.Id)
}

func (c Container) firstPid() (int, error) {
	data, err := ioutil.ReadFile(c.tasksFile())
	if err != nil {
		return -1, err
	}
	value, err := strconv.Atoi(strings.SplitN(string(data), "\n", 2)[0])
	if err != nil {
		return -1, err
	}
	return value, nil
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

func (c Container) ApplyRules(fw firewall) error {

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	// Create a new network namespace
	pid, _ := c.firstPid()

  log.Printf( "pid %v", pid)

	newns, _ := netns.GetFromPid(pid)
	defer newns.Close()

	// Switch to the container namespace
	netns.Set(newns)

  // Input
  for pos , rule := range fw.Input.Rules {
  
    if rule.Type != "" {
			sport, _ := strconv.Atoi(rule.SourcePort)
			dport, _ := strconv.Atoi(rule.DestinationPort)

			if *Debug {
				log.Printf( "ApplyRules - Source : %s SourcePort %v Destination : %s DestinationPort : %v Proto : %s Type : %s" , rule.Source , sport , rule.Destination, dport , rule.Proto, rule.Type  )
			}

      args := " -I INPUT " + strconv.Itoa( pos + 1 ) + " -p " + rule.Proto + " --source " + rule.Source + " --destination-port " + rule.DestinationPort + " -j " + strings.ToUpper(rule.Type)

			if *Debug {
				log.Printf( "ApplyRules cmd %s - args : %s", iptablesPath, args  )
			}
     
      cmd := exec.Cmd{Path: iptablesPath, Args: append([]string{iptablesPath}, args)}


  		if err := cmd.Run(); err != nil {
        log.Fatal(err);
	  		return err.(*exec.ExitError)
		  }

		}

  }

	// Switch back to the original namespace
	netns.Set(origns)
	runtime.UnlockOSThread()


  return nil
}

func (f firewall) AddInputRule(pos int, rule string) {
  if *Debug {
    log.Printf( "AddInputRule - Pos : %v Rule %s" ,pos,rule )
  }

  var  R rules
  err := json.Unmarshal([]byte(rule), &R )
	if err != nil {
    log.Println("Couldn't convert json label to rule")
	}
  
  f.Input.Rules[pos] = R

}

func (f firewall) PrintRules() {

  for _ , rule := range f.Input.Rules {
    if rule.Type != "" {
			
			sport, _ := strconv.Atoi(rule.SourcePort)
			dport, _ := strconv.Atoi(rule.DestinationPort)
			if *Debug {
				log.Printf( "PrintRules Input Source : %s SourcePort %v Destination : %s DestinationPort : %v Proto : %s Type : %s" , rule.Source , sport , rule.Destination, dport , rule.Proto, rule.Type  )
			}
		}

  }
  for _ , rule := range f.Output.Rules {
    if rule.Type != "" {
			sport, _ := strconv.Atoi(rule.SourcePort)
			dport, _ := strconv.Atoi(rule.DestinationPort)
			if *Debug {
				log.Printf( "PrintRules Output Source : %s SourcePort %v Destination : %s DestinationPort : %v Proto : %s Type : %s" , rule.Source , sport , rule.Destination, dport , rule.Proto, rule.Type  )
			}
		}
  }
  for _ , rule := range f.Forward.Rules {
    if rule.Type != "" {
			sport, _ := strconv.Atoi(rule.SourcePort)
			dport, _ := strconv.Atoi(rule.DestinationPort)
			if *Debug {
				log.Printf( "PrintRules Forward Source : %s SourcePort %v Destination : %s DestinationPort : %v Proto : %s Type : %s" , rule.Source , sport , rule.Destination, dport , rule.Proto, rule.Type  )
			}

		}
  }
}

