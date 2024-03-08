package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"
)

var ErrShortWrite = errors.New("short write")
var errInvalidWrite = errors.New("invalid write result")
var ErrShortBuffer = errors.New("short buffer")
var EOF = errors.New("EOF")

var ServerMap = make(map[string]string)
var CertMap = make(map[string]*tls.Certificate)
var mu sync.Mutex

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIFAP1KGp8wDQYJKoZIhvcNAQELBQAwgYoxFDASBgNVBAYT
C1BvcnRTd2lnZ2VyMRQwEgYDVQQIEwtQb3J0U3dpZ2dlcjEUMBIGA1UEBxMLUG9y
dFN3aWdnZXIxFDASBgNVBAoTC1BvcnRTd2lnZ2VyMRcwFQYDVQQLEw5Qb3J0U3dp
Z2dlciBDQTEXMBUGA1UEAxMOUG9ydFN3aWdnZXIgQ0EwHhcNMTQxMDIyMjAzMzQ5
WhcNMzExMDIyMjAzMzQ5WjCBijEUMBIGA1UEBhMLUG9ydFN3aWdnZXIxFDASBgNV
BAgTC1BvcnRTd2lnZ2VyMRQwEgYDVQQHEwtQb3J0U3dpZ2dlcjEUMBIGA1UEChML
UG9ydFN3aWdnZXIxFzAVBgNVBAsTDlBvcnRTd2lnZ2VyIENBMRcwFQYDVQQDEw5Q
b3J0U3dpZ2dlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIxi
rTqz7PzrixH3ghmi9fWjtdnLGIMsow5nvXGuIzAL4ZcqxvDV0YOOvfZLppLiV6al
r25/bx2vXfY3OOiDaO0jeSto1XjAw8ptp1Bm16DCrv9aop2K4d6Gsq+VlCB2iglX
GB9H51s8yNb9FG2dql5se6WW5AZQ6dtqjRT/3hcwJJVKDUsKULxM5W2XlgDYFcg5
f+mZJLREDyb37b6Ep5RKyb7p65j5QNmX3V4EpoXidIaTyYlea3BkJ2lIxQeGQOmY
pcadatEMhplHN6Jlt+fPyXTZ43jA4jYHmggJx1hj+ckHkbV0dzf/J5SSeyCX3ZO7
gFYMZvWlWdsXeqGZZ9kCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOCAQEAS2Qt5niKsLWqIfnugrz7gitoy0vFojJvBZSrJMZUMpxRop1g
+LCQ8uv50YAwknvik1VG9AqLL3Jz4FiMBglyjCRp7xvrU43kmh7bIxh0ey6xg5ck
0WV7LgY2qFHhXcna9bpC9qyX0UchefCYLnm4hcOgjPmF701n7fhhYBZ8YzMZBI7h
tuh4y/J6H8ngclQmWTVoClQzqCXm55e/g9oB0eBWMEhtsrXNtQOC8IJJfNVUcHkM
b3F3mQXtAAG/tnoiUdluchnn0x8DdbkEjnVxoIAwDLf2ryJVaq4/RjI/0niS909r
3Erw2iECt21Hh6xB+0V6mAjVNdDdMvtT/EhrEQ==
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCMYq06s+z864sR
94IZovX1o7XZyxiDLKMOZ71xriMwC+GXKsbw1dGDjr32S6aS4lempa9uf28dr132
Nzjog2jtI3kraNV4wMPKbadQZtegwq7/WqKdiuHehrKvlZQgdooJVxgfR+dbPMjW
/RRtnapebHulluQGUOnbao0U/94XMCSVSg1LClC8TOVtl5YA2BXIOX/pmSS0RA8m
9+2+hKeUSsm+6euY+UDZl91eBKaF4nSGk8mJXmtwZCdpSMUHhkDpmKXGnWrRDIaZ
RzeiZbfnz8l02eN4wOI2B5oICcdYY/nJB5G1dHc3/yeUknsgl92Tu4BWDGb1pVnb
F3qhmWfZAgMBAAECggEAZacCJrKoVQ+92NmvBB9DGIZdpIHykvFcdI7b15gvdJf1
1v8rpLI/DpLqrJBk4pEwxMPOfyWZcRZN5H5iH8Mf1C7Oi4dSpCh43Xh/IbIGSysN
imu3unoZSYehlZCq/MK4+0BsgCIRvbgK+dmx1BnJhqvo8KONI6GtZKsH03/e8kxc
EozwGVamwrrZ3ZVpuGusvv7+DSe8u6Vaur0mv1Griq/9Ba/hvY4jzmhfnY+fg5XN
aPHRd1t0V5yBk4AVQBgXDfJ25f7oHyprvUOxNX1DdvXbJzCoFvFB3cfLGxkCgQol
tHGjOGsz03W9lSjBKIZGQaclnRrSz1tNKmX2DgWlAQKBgQDioUxGHBU+RpGW9F0h
XNqCMLlkqho/CKK9UmGGdUDU3Q52upzfK2L+srSDz02JNXA29yGvGuQacnRdndDQ
eVqSFSON7JrwcOSDQHRiDhJuLagyckeI19wLmpJAKvXnRR4Ce+j1yrc5YSo7o0a5
P/u4pV/DVFiZEMpMs1EFABBZoQKBgQCelB5j5QU+mgoQcx1h8D8J9ie7avdlhoEQ
O1VaWlNkg2Vuvccwv1kQ0MM4NWEzMCsy/8VAzsQjMmvg/dFtApQa56HhPV+i7+XA
fPnKmxfOvB3V+xRjkysPhnsPIgv5cLsggd2v4crv5QhZFhnyilkjqeukjpnlAN6A
SGanlb6TOQKBgAkdi7/WKVST6g80TPqmjXNnGk3eOagHZORQh/Osi6sEKSzFXMHt
MNIlxfT3RZsbNyQ+1HACmOIncF7Dlj6MYwQ1LXTr6194aviMgyHehwc/duBwkEgE
xqkA0pkaIUHoGcjnyvr36F66dcRoUNPqqulGXY+xuM6PSlPDcqLM2duBAoGACgDB
4f9CU26YD+2S/uiOsWwrmXDn5imT3pg/jBGCjSaUsWWbOQH49kyU4+jKFtaFAxSL
NslUKfw2Pd0E5uFwwjm2RmT+sWJ8laXMg/FAkTPglezenmFcKACNpqi5JKTtyOEo
QL33dSZ3Xlc8j8YWVV+Uk67DGmTxpBntD8ksWlECgYEA4OdS54sruRNpjGXoVDhH
L0P/svMWeUWxDgKB5gUnVg1JGBDXleLrg00N8/c9WMetVhAtsK3e6OFFqjs63Fpg
zronQw7i1vT0bFhXbjtXf5IKuHiClrb6M8oVNEuGTEnbJK20rtUfVCASu/YB/l66
RwL20Mf5Fll063JW/VokHVo=
-----END PRIVATE KEY-----`)

var GoproxyCa, goproxyCaErr = tls.X509KeyPair(CA_CERT, CA_KEY)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if goproxyCaErr != nil {
		panic("Error parsing builtin CA " + goproxyCaErr.Error())
	}
	var err error
	if GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

type CounterEncryptorRand struct {
	cipher  cipher.Block
	counter []byte
	rand    []byte
	ix      int
}

func NewCounterEncryptorRandFromKey(key interface{}, seed []byte) (r CounterEncryptorRand, err error) {
	var keyBytes []byte
	switch key := key.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		if keyBytes, err = x509.MarshalECPrivateKey(key); err != nil {
			return
		}
	default:
		err = errors.New("only RSA and ECDSA keys supported")
		return
	}
	h := sha256.New()
	if r.cipher, err = aes.NewCipher(h.Sum(keyBytes)[:aes.BlockSize]); err != nil {
		return
	}
	r.counter = make([]byte, r.cipher.BlockSize())
	if seed != nil {
		copy(r.counter, h.Sum(seed)[:r.cipher.BlockSize()])
	}
	r.rand = make([]byte, r.cipher.BlockSize())
	r.ix = len(r.rand)
	return
}

func (c *CounterEncryptorRand) Seed(b []byte) {
	if len(b) != len(c.counter) {
		panic("SetCounter: wrong counter size")
	}
	copy(c.counter, b)
}

func (c *CounterEncryptorRand) refill() {
	c.cipher.Encrypt(c.rand, c.counter)
	for i := 0; i < len(c.counter); i++ {
		if c.counter[i]++; c.counter[i] != 0 {
			break
		}
	}
	c.ix = 0
}

func (c *CounterEncryptorRand) Read(b []byte) (n int, err error) {
	if c.ix == len(c.rand) {
		c.refill()
	}
	if n = len(c.rand) - c.ix; n > len(b) {
		n = len(b)
	}
	copy(b, c.rand[c.ix:c.ix+n])
	c.ix += n
	return
}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}

func signHost(ca tls.Certificate, hosts []string) (cert *tls.Certificate, err error) {
	var x509ca *x509.Certificate

	// Use the provided ca and not the global GoproxyCa for certificate generation.
	if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return
	}

	start := time.Unix(time.Now().Unix()-2592000, 0) // 2592000  = 30 day
	end := time.Unix(time.Now().Unix()+31536000, 0)  // 31536000 = 365 day

	serial := big.NewInt(rand.Int63())
	template := x509.Certificate{
		// TODO(elazar): instead of this ugly hack, just encode the certificate and hash the binary form.
		SerialNumber: serial,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization: []string{"GoProxy untrusted MITM proxy Inc"},
		},
		NotBefore: start,
		NotAfter:  end,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}

	hash := hashSorted(append(hosts, "goproxySignerVersion", ":"+runtime.Version()))
	var csprng CounterEncryptorRand
	if csprng, err = NewCounterEncryptorRandFromKey(ca.PrivateKey, hash); err != nil {
		return
	}

	var certpriv crypto.Signer
	switch ca.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if certpriv, err = rsa.GenerateKey(&csprng, 2048); err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		if certpriv, err = ecdsa.GenerateKey(elliptic.P256(), &csprng); err != nil {
			return
		}
	default:
		err = fmt.Errorf("unsupported key type %T", ca.PrivateKey)
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(&csprng, &template, x509ca, certpriv.Public(), ca.PrivateKey); err != nil {
		return
	}
	return &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate[0]},
		PrivateKey:  certpriv,
	}, nil
}

func main() {
	config := defaultTLSConfig.Clone()
	config.GetCertificate = returnCert
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		// 接收连接
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// 处理连接
		go handleConnection(conn)
	}

}

func returnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	mu.Lock()
	defer mu.Unlock()
	log.Printf("servername:%+v\n", helloInfo.ServerName)
	ServerMap[helloInfo.Conn.RemoteAddr().String()] = helloInfo.ServerName
	// 检查 CertMap 中是否存在证书
	if cert, ok := CertMap[helloInfo.ServerName]; ok {
		log.Printf("cert in the dict\n")
		return cert, nil
	}
	cert, err := signHost(GoproxyCa, []string{helloInfo.ServerName})
	if err != nil {
		log.Printf("%v\n", err)
	}
	CertMap[helloInfo.ServerName] = cert
	return cert, err
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("error %s %d,%v", buffer[:n], n, err)
		return
	}
	ServerHost := ""
	log.Printf("waiting to get servername\n")
	for {
		mu.Lock()
		v, ok := ServerMap[conn.RemoteAddr().String()]
		mu.Unlock()
		if ok {
			log.Printf("found %v\n", v)
			ServerHost = v
			break
		}
	}
	serverConn, err := tls.Dial("tcp", ServerHost+":443", nil)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	fmt.Printf("1st:%s\n",buffer[:n])
	serverConn.Write(buffer[:n])
	log.Printf("connect to server:%v %v \n", ServerHost, err)
	go io.Copy(conn, serverConn)
	_,err=copyBuffer(serverConn, conn,nil)
	log.Printf("exit copy:%v\n",err)
	//n, err = serverConn.Read(buffer)
	//log.Printf("from server:%s %d,%v", buffer[:n], n, err)
}

func copyBuffer(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			fmt.Printf("send:%s\n",buf[0:nr])
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
