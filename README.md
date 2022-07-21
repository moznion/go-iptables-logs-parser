# iptables-logs-parser [![.github/workflows/check.yml](https://github.com/moznion/go-iptables-logs-parser/actions/workflows/check.yml/badge.svg)](https://github.com/moznion/go-iptables-logs-parser/actions/workflows/check.yml)

An iptables logs parser for Golang.

## Synopsis

```go
import (
	"fmt"

	iptables "github.com/moznion/go-iptables-logs-parser"
)

func main() {
	line := "Jul 21 05:38:28 ubuntu-jammy kernel: [14879.600492] OUT-LOG: IN= OUT=enp0s3 SRC=10.0.2.15 DST=8.8.8.8 LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=6495 DF PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=3",
	parsedLog, err := iptables.Parse(line)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", parsedLog)
	// ^ expected: &Log{
	//    Timestamp:              "Jul 21 05:38:28",
	//    Hostname:               "ubuntu-jammy",
	//    KernelTimestamp:        14879.600492,
	//    Prefix:                 "OUT-LOG:",
	//    InputInterface:         "",
	//    OutputInterface:        "enp0s3",
	//    MACAddress:             "",
	//    Source:                 "10.0.2.15",
	//    Destination:            "8.8.8.8",
	//    Length:                 84,
	//    ToS:                    0,
	//    Precedence:             0,
	//    TTL:                    64,
	//    ID:                     6495,
	//    CongestionExperienced:  false,
	//    DoNotFragment:          true,
	//    MoreFragmentsFollowing: false,
	//    Frag:                   0,
	//    IPOptions:              "",
	//    Protocol:               "ICMP",
	//    Type:                   8,
	//    Code:                   0,
	//    SourcePort:             0,
	//    DestinationPort:        0,
	//    Sequence:               0,
	//    AckSequence:            0,
	//    WindowSize:             0,
	//    Res:                    0,
	//    Urgent:                 false,
	//    Ack:                    false,
	//    Push:                   false,
	//    Reset:                  false,
	//    Syn:                    false,
	//    Fin:                    false,
	//    Urgp:                   0,
	//    TCPOption:              "",
	//  }
}
```

## Author

moznion (<moznion@mail.moznion.net>)

