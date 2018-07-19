package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/kylelemons/go-gypsy/yaml"
)

/*
#cgo CFLAGS : -I./include
#cgo LDFLAGS: -L./lib  -llibeay32 -lssleay32 -lWS2_32

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>

#include <winsock2.h>

#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define CHK_NULL(x) if ((x)==NULL) exit (-1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(-3); }

int SendPack(char *data,char *ip, int port,char *cert,char *key,char *cacert)
{
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    server_cert;
	char*    str;
	char     buf[4096*2];
	int       seed_int[100]; //存放随机序列

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup()fail:%d/n", GetLastError());
		return -1;
	}

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLSv1_2_client_method());
	CHK_NULL(ctx);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT , NULL);
	SSL_CTX_load_verify_locations(ctx, cacert, "2");


	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	SSL_CTX_set_default_passwd_cb_userdata(ctx,"jb0-43gj5(*(&698*&%$90#6^%$04-3&%*99#xyTRW770%$*&^(UIDV*^&(&^%WF");

	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public key/n");
		exit(-4);
	}


	srand((unsigned)time(NULL));
	for (int i = 0; i < 100; i++)
		seed_int[i] = rand();
	RAND_seed(seed_int, sizeof(seed_int));


//	printf("Begin tcp socket.../n");

	sd = socket(AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(ip);
	sa.sin_port = htons(port);

	err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));
if (err==-1)
	{
		return 0;
	}


//	printf("Begin SSL negotiation /n");

	ssl = SSL_new(ctx);
	CHK_NULL(ssl);

	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);



//	printf("SSL connection using %s/n", SSL_get_cipher(ssl));


	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
//	printf("Server certificate:/n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	CHK_NULL(str);
//	printf("/t subject: %s/n", str);
	//Free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str);
//	printf("/t issuer: %s/n", str);
	//Free(str);

	X509_free(server_cert);


//	printf("Begin SSL data exchange/n");

 err = SSL_write(ssl, data, strlen(data));
	//err = SSL_write(ssl, "a",  strlen("a"));

	CHK_SSL(err);

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);

//	buf[err] = '/0';
//	printf("Got %d chars:'%s'/n", err, buf);
	SSL_shutdown(ssl);


	shutdown(sd, 2);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	struct sockaddr_in  connectedAddr;
	int  len = sizeof(connectedAddr);
	getpeername(sd, (struct sockaddr *)&connectedAddr,&len );
//	printf("connected server address = %s:%d\n", inet_ntoa(connectedAddr.sin_addr), ntohs(connectedAddr.sin_port));


	//system("pause");
	return 1;
}
*/
import "C"

type Pack struct {
	T    string `json:"t"`
	I    int    `json:"i"`
	Cid  string `json:"cid"`
	Tcid string `json:"tcid"`
	Pack string `json:"pack"`
}

var (
	delay      int
	ConfigFile *yaml.File
	count      int
	cert       string
	key        string
	cacert     string
	pack_T     string
	reIP       string
	rePort     int
)

func init() {
	var err error
	ConfigFile, err = yaml.ReadFile("config/DaemonConf.yaml")
	if err != nil {
		fmt.Println("read config file failed!")
	}
	getkey()
}
func getkey() {
	cert = GetString("cli_cert_file")
	key = GetString("cli_key_file")
	cacert = GetString("cli_ca_file")
	delay, _ = strconv.Atoi(GetString("delay"))
	pack_T = GetString("Pack_T")
	reIP = GetString("reIP")
	rePort, _ = strconv.Atoi(GetString("rePort"))
}

func main() {
	fmt.Println("The Daemon of AuthService is running...")
	fmt.Println("The interval of requests sent to AuthService is " + strconv.Itoa(delay) + " seconds")
	ticker := time.NewTicker(1 * time.Second) //15天 1296000  一周 604800  1天 86400
	for {
		select {
		case <-ticker.C:
			count++
			if count >= delay {
				send()
				count = 0
			}
		}
	} /**/
}
func send() {
	pack := Pack{T: pack_T}
	senddata, _ := json.Marshal(pack)
	if C.SendPack(C.CString(string(senddata)), C.CString(reIP), C.int(rePort), C.CString(cert), C.CString(key), C.CString(cacert)) == 1 {
		fmt.Println(time.Now().Format("2006-01-02 15:04:05"), "a request is completed successfully!")
	} else {
		fmt.Println(time.Now().Format("2006-01-02 15:04:05"), "a request is completed with an error!")
		fmt.Println(time.Now().Format("2006-01-02 15:04:05"), "The AuthService will be restarted after "+strconv.Itoa(delay)+" seconds")
		for i := 0; i < delay; i++ {
			time.Sleep(1 * time.Second)
		}
		restart()
	}
}
func restart() {
	/*dir, err := filepath.Abs(filepath.Dir(os.Args[0])) //获取当前路径
	if err != nil {
		log.Fatal(err)
	}
	datapath := dir + "/AuthService.exe"*/
	cmd := exec.Command("cmd.exe", "/c", "start", "run.bat")
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
