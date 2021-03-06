package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	//1010
	OneTimeAuthMask byte = 0x10
	//1111
	AddrMask        byte = 0xf
)

//连接结构体
type Conn struct {
	net.Conn
	*Cipher
	readBuf  []byte
	writeBuf []byte
	chunkId  uint32
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	return &Conn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:  leakyBuf.Get(),
		writeBuf: leakyBuf.Get()}
}

func (c *Conn) Close() error {
	leakyBuf.Put(c.readBuf)
	leakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	//看上面解析过程传入的应该是一个IP:PORT的字符串，这里为什么要按域名算？
	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// This is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
	//连接服务器，这里的服务器是shadowsocks的server端，及代理服务器
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	//把与代理服务器的连接与加密方式封装成一个连接
	c = NewConn(conn, cipher)

	//如果需要权限验证的话把验证信息加在rawaddr后面
	if cipher.ota {
		if c.enc == nil {
			if _, err = c.initEncrypt(); err != nil {
				return
			}
		}
		// since we have initEncrypt, we must send iv manually
		//这里是使用go原生的conn类写iv变量给server
		conn.Write(cipher.iv)
		rawaddr[0] |= OneTimeAuthMask
		rawaddr = otaConnectAuth(cipher.iv, cipher.key, rawaddr)
	}
	//向代理服务器发一次目标地址，这里是使用封装好的连接对象
	if _, err = c.write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

func (c *Conn) GetIv() (iv []byte) {
	iv = make([]byte, len(c.iv))
	copy(iv, c.iv)
	return
}

func (c *Conn) GetKey() (key []byte) {
	key = make([]byte, len(c.key))
	copy(key, c.key)
	return
}

func (c *Conn) IsOta() bool {
	return c.ota
}

func (c *Conn) GetAndIncrChunkId() (chunkId uint32) {
	chunkId = c.chunkId
	c.chunkId += 1
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		iv := make([]byte, c.info.ivLen)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.initDecrypt(iv); err != nil {
			return
		}
		if len(c.iv) == 0 {
			c.iv = iv
		}
	}

	cipherData := c.readBuf
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	nn := len(b)
	if c.ota {
		chunkId := c.GetAndIncrChunkId()
		b = otaReqChunkAuth(c.iv, chunkId, b)
	}
	headerLen := len(b) - nn

	n, err = c.write(b)
	// Make sure <= 0 <= len(b), where b is the slice passed in.
	//返回的n是指写出去的真实数据，如果在写出去以前因为加密原因增加了一些头信息，则需要减去
	if n >= headerLen {
		n -= headerLen
	}
	return
}

func (c *Conn) write(b []byte) (n int, err error) {
	var iv []byte
	if c.enc == nil {
		iv, err = c.initEncrypt()
		if err != nil {
			return
		}
	}

	cipherData := c.writeBuf
	//这里有一层隐藏含义，如果c.enc没有初始化，则上面代码会初始化并设置iv的值
	//如果已经初始化了，iv没有复制，即这里len(iv)就是0，也就是只有数据长度
	dataSize := len(b) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		//如果这次是初始化，参考上面。则先把iv装进去，也就是iv放在数据前面
		copy(cipherData, iv)
	}

	//这里可以看出来只加密数据，不加密iv
	c.encrypt(cipherData[len(iv):], b)
	n, err = c.Conn.Write(cipherData)
	return
}
