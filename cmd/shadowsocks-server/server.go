package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

var debug ss.DebugLog

var errAddrType = errors.New("addr type not supported")

func getRequest(conn *ss.Conn) (host string, extra []byte, err error) {
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip addres start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIP = 1 // type is ip address
		typeDm = 3 // type is domain address

		lenIP     = 1 + 4 + 2 // 1addrType + 4ip + 2port
		lenDmBase = 1 + 1 + 2 // 1addrType + 1addrLen + 2port, plus addrLen
	)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, 260, 260)
	var n int
	// read till we get possible domain length field
	ss.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	reqLen := lenIP
	if buf[idType] == typeDm {
		reqLen = int(buf[idDmLen]) + lenDmBase
	} else if buf[idType] != typeIP {
		err = errAddrType
		return
	}

	if n < reqLen { // rare case
		ss.SetReadTimeout(conn)
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	// TODO add ipv6 support
	if buf[idType] == typeDm {
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	} else if buf[idType] == typeIP {
		addrIp := make(net.IP, 4)
		copy(addrIp, buf[idIP0:idIP0+4])
		host = addrIp.String()
	}
	// parse port
	var port int16
	sb := bytes.NewBuffer(buf[reqLen-2 : reqLen])
	binary.Read(sb, binary.BigEndian, &port)

	host += ":" + strconv.Itoa(int(port))
	return
}

func handleConnection(conn *ss.Conn) {
	if debug {
		// function arguments are always evaluated, so surround debug
		// statement with if statement
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	defer conn.Close()

	host, extra, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		debug.Println("error connecting to:", host, err)
		return
	}
	defer remote.Close()
	// write extra bytes read from 
	if extra != nil {
		debug.Println("getRequest read extra data, writing to remote, len", len(extra))
		if _, err = remote.Write(extra); err != nil {
			debug.Println("write request extra error:", err)
			return
		}
	}
	debug.Println("piping", host)
	c := make(chan byte, 2)
	go ss.Pipe(conn, remote, c)
	go ss.Pipe(remote, conn, c)
	<-c // close the other connection whenever one connection is closed
	debug.Println("closing", host)
	return
}

// Add a encrypt table cache to save memory and startup time in case of many
// same password.
// If startup time becomes an issue, save the encrypt table on disk.
var tableCache = map[string]*ss.EncryptTable{}
var tableGetCnt int32

func getTable(password string) (tbl *ss.EncryptTable) {
	tbl, ok := tableCache[password]
	if ok {
		debug.Println("table cache hit for password:", password)
		return
	}
	tbl = ss.GetTable(password)
	tableCache[password] = tbl
	return
}

func run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	encTbl := getTable(password)
	atomic.AddInt32(&tableGetCnt, 1)
	log.Printf("starting server at port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(ss.NewConn(conn, encTbl))
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func main() {
	var configFile string
	var cmdConfig ss.Config

	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 60, "connection timeout (in seconds)")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")

	flag.Parse()

	config, err := ss.ParseConfig(configFile)
	if err != nil {
		enough := enoughOptions(&cmdConfig)
		if !(enough && os.IsNotExist(err)) {
			log.Printf("error reading %s: %v\n", configFile, err)
		}
		if !enough {
			return
		}
		log.Println("using all options from command line")
		config = &cmdConfig
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	ss.SetDebug(debug)

	if len(config.PortPassword) == 0 {
		run(strconv.Itoa(config.ServerPort), config.Password)
	} else {
		if config.ServerPort != 0 {
			log.Println("ignoring server_port and password option, only uses port_password")
		}
		for port, password := range config.PortPassword {
			go run(port, password)
		}
		// Wait all ports have get it's encryption table
		for int(tableGetCnt) != len(config.PortPassword) {
			time.Sleep(1 * time.Second)
		}
		log.Println("all ports ready")
		tableCache = nil // release memory
		c := make(chan byte)
		<-c // block forever
	}
}
