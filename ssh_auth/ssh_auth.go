package ssh_auth

import (
	"authPoint/db"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

)

type ServerConfig struct{
	Host string
	Port string
	Username string
	TypeKey string
	Sshkey string
}

var date = time.Now()
var pgdate = time.Now()

func (c *ServerConfig)Socket() string{
	return fmt.Sprintf("%s:%s", c.Host, c.Port)

}

func createSftpSession(s ServerConfig)(*ssh.Client, error){
	sshConfig := &ssh.ClientConfig{
		User: "sysadmin",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:[]ssh.AuthMethod{
			ssh.Password("D_"),
		},
	}
	connect, err := ssh.Dial("tcp",s.Socket(),sshConfig)
	if err !=nil{
		return nil, err
	}
	return connect, nil
}

func createSession(s ServerConfig)(*ssh.Session, ssh.Conn, error){
	sshConfig := &ssh.ClientConfig{
		User: "sysadmin",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:[]ssh.AuthMethod{
			//ssh.Password("12345"),
			ssh.Password("D_"),
		},
	}
	connect, err := ssh.Dial("tcp",s.Socket(),sshConfig)

	if err != nil{
		return nil, nil, err
	}
	session, err := connect.NewSession()
	if err != nil{
		return nil, connect, err
	}
	return session, connect, nil
}

func SSHComand(command string, sci ServerConfig) (string, error){
	session,connect,err := createSession(sci)
	if err != nil{
		if connect != nil{
			connect.Close()
		}
		return "", err
	}
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	err = session.Run(command)

	session.Close()
	connect.Close()

	if err != nil {
		return "",  err
	}
	fmt.Println(stdoutBuf.String())
	return strings.TrimSuffix(stdoutBuf.String(), "\n"), nil
}

func SSHSftp(sci ServerConfig, filename string)(string,error) {
	connect, err := createSftpSession(sci)
	if err != nil {
		if connect != nil {
			connect.Close()
		}
		return "", err
	}
	client,err := sftp.NewClient(connect)
	if err != nil {
		return "",  err
	}
	defer client.Close()
	dstFile, err := client.Create("/home/sysadmin/"+filename)
	if err != nil {
		return "",  err
	}
	defer dstFile.Close()

	srcFile, err := os.Open("/var/www/authPoint/"+filename)
	if err != nil {
		return "",  err
	}
	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return "",  err
	}
	fmt.Printf("%d bytes copied\n", bytes)
	return "success", nil
}

//func Vault_create_role(username string, host string, typeKey string) string  {
func Vault_create_role(data ServerConfig) string  {
	if data.TypeKey == "otp" {
		body := strings.NewReader(`{"key_type": "otp","default_user":"` + data.Username + `","cidr_list": "0.0.0.0/0", "allowed_users": "*"}`)
		req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/ssh/roles/"+data.Username+"_otp", body)
		if err != nil {
			log.Println(err)
		}
		req.Header.Set("X-Vault-Token", "c3")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err)
		}
		defer resp.Body.Close()

		creds := Vault_create_creds(data.Username, data.Host)
		fmt.Println(`{"ipssss": "` + data.Host + `"}`)
		return creds
	} else if data.TypeKey == "ca"{
		body := strings.NewReader(`{"key_type":"ca","allow_user_certificates":true,"default_user":"` + data.Username + `","allowed_users": "*", "ttl":"2000h","default_extensions": [{"permit-port-forwarding": "", "permit-X11-forwarding": "", "permit-pty": ""}]}`)
		//body := strings.NewReader(`{"key_type":"ca","allow_user_certificates":true,"default_user":"` + data.Username + `","allowed_users": "*", "default_extensions": [{"permit-port-forwarding": "", "permit-X11-forwarding": "", "permit-pty": ""}]}`)
		req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/ssh/roles/"+data.Username+"_ca", body)
		if err != nil {
			log.Println(err)
		}
		req.Header.Set("X-Vault-Token", "c3")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err)

		}
		defer resp.Body.Close()
		cert := Vault_create_ca(data.Username, data.Sshkey, data.Host)
		return cert
	}
		err := "no type"
		return err
}
func Vault_create_creds(username string, host string) string {
	body := strings.NewReader(`{"ip": "`+host+`"}`)
    req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/ssh/creds/"+username+"_otp", body)
    if err != nil {
		log.Println(err)
    }
	req.Header.Set("X-Vault-Token", "c3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()
	action := "create one-time ssh passwords "
	date.Format(time.ANSIC)
	db.AddAction(host,username,action,date)
	echo, _ := ioutil.ReadAll(resp.Body)
	return fmt.Sprint(string(echo))
}

func Vault_create_ca(username string, sshKey string, host string) string{
	body := strings.NewReader(`{"valid_principals": "`+username+`","public_key": "`+sshKey+`"}`)
	req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/ssh/sign/"+username+"_ca", body)
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("X-Vault-Token", "c3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()
	action := "create signed ssh certificate "
	date.Format(time.ANSIC)
	db.AddAction(host,username,action,date)
	echo, _ := ioutil.ReadAll(resp.Body)
	return fmt.Sprintf(string(echo))
}

//
func PgNewInstance(response http.ResponseWriter, username string, dbname string, url string) {
	body := strings.NewReader(
		`{"plugin_name": "postgresql-database-plugin","allowed_roles": "`+dbname+`",
			"connection_url":"postgresql://{{username}}:{{password}}@`+url+`:6433/`+dbname+`?sslmode=disable",
			"max_open_connections": 500,"max_connection_lifetime": "5s","username": "vault","password": "OD"}`)
	req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/postgres/config/"+dbname, body)
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("X-Vault-Token", "c")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err == nil{
		CreatePgRole(response,url,username,dbname)
	}else{
		http.Error(response, http.StatusText(400),400)
	}
}

func PgNewWriteInstance(response http.ResponseWriter, username string, dbname string, url string) {
	rolename := dbname+"-write"
	body := strings.NewReader(
		`{"plugin_name": "postgresql-database-plugin","allowed_roles": "`+rolename+`",
			"connection_url":"postgresql://{{username}}:{{password}}@`+url+`:6433/`+dbname+`?sslmode=disable",
			"max_open_connections": 500,"max_connection_lifetime": "5s","username": "vault","password": "OD"}`)
	req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/postgres/config/"+rolename, body)
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("X-Vault-Token", "c3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err == nil{
		CreateWriterPgRole(response,url,username,rolename)
	}else{
		http.Error(response, http.StatusText(400),400)
	}
}

func CreatePgRole(response http.ResponseWriter, url string, username string, dbname string) {
	//body := strings.NewReader(`{"db_name": "`+dbname+`","creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; ALTER ROLE  \"{{name}}\"  WITH SUPERUSER;" ],"default_ttl": "1h","max_ttl": "24h"}`)
	body := strings.NewReader(`{"db_name": "`+dbname+`","creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT readonly TO  \"{{name}}\";" ],"default_ttl": "729h","max_ttl": "730h"}`)
	req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/postgres/roles/"+dbname, body)
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("X-Vault-Token", "c3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err == nil {
		db.AddPgRole(dbname,url)
		action := "instance added "
		date.Format(time.ANSIC)
		//db.AddPgAction(url,username,action,date)
		db.AddPgAction(dbname,username,action,date)
		fmt.Fprintf(response,"New instance role added")
		PgNewWriteInstance(response, username, dbname, url)
	}else{
		http.Error(response, http.StatusText(400),400)
	}
}

func CreateWriterPgRole(response http.ResponseWriter, url string, username string, dbname string) {
	body := strings.NewReader(`{"db_name": "`+dbname+`","creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT readwrite TO  \"{{name}}\";" ],"default_ttl": "729h","max_ttl": "730h"}`)
	req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/postgres/roles/"+dbname, body)
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("X-Vault-Token", "c3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err == nil {
		action := "writer role added "
		date.Format(time.ANSIC)
		//db.AddPgAction(url,username,action,date)
		db.AddPgAction(dbname,username,action,date)
		fmt.Fprintf(response,"New instance role added")
	}else{
		http.Error(response, http.StatusText(400),400)
	}
}


func VaultGetTokenPg(username string, pass string, dbname string) (string, string, error)  {

	//quoted := regexp.MustCompile(`^"(.*)"$`).ReplaceAllString(pass,`\"`)
	body := strings.NewReader(`{"password": "`+pass+`"}`)
	fmt.Println(body)
	//fmt.Println(quoted)
	req, err := http.NewRequest("POST", "https://vault.service.prod.tech:8200/v1/auth/ldap/login/"+username, body)
	if err != nil {
		log.Println(err)
		return "bab request","addpg",err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return "bab request","get token",err
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)

	type Auth struct {
		Client_token string `json:"client_token"`
	}
	type Token struct {
		Token Auth `json:"auth"`
	}
	content := Token{}
	json.Unmarshal([]byte(data), &content)
	token := fmt.Sprintf(content.Token.Client_token) //таким образом преобразуем в строку
	login, password, error := VaultAddPgCred(token,dbname)
	if error !=nil{
		log.Println(err)
		return "bab request","getcred",err
	}
	action := login
	pgdate.Format(time.ANSIC)
	db.AddPgAction(dbname,username,action,pgdate)
	return login, password, error

}

func VaultAddPgCred(token string, dbname string) (string, string, error){
	req, err := http.NewRequest("GET", "https://vault.service.prod.tech:8200/v1/postgres/creds/"+dbname, nil)
	if err != nil {
		return "bab request","addpg",err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "bab request","addpg",err
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	type Credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type Data struct {
		Time int `json:"lease_duration"' `
		Cred Credentials `json:"data"`
	}
	result := Data{}
	json.Unmarshal([]byte(data), &result)
	login := result.Cred.Username
	password := result.Cred.Password
	return login, password, err

}