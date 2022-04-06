package main

import (
	"authPoint/db"
	"authPoint/ssh_auth"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/jtblin/go-ldap-client"
	"github.com/kless/osutil/user/crypt/sha512_crypt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var cookieHandler = securecookie.New(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32))


var client *ldap.LDAPClient

type History struct {
	id int
	data string
	username string
	host string
	actions string
}
type ActivHost struct {
	id int
	host string
}

type PgActivHost struct {
	dbname string
}

// тут мы дёргаем distinguishedName
func getAttribute(request *http.Request) (attribut string){
	if cookie, err :=request.Cookie("session"); err == nil{
		cookieValue :=make(map[string]string)
		if err = cookieHandler.Decode("session",cookie.Value, &cookieValue); err == nil{
			attribut = cookieValue["Raw"]
		}
	}
	return attribut
}
//дёргаем имя пользователя из сессии
func getUserName(request *http.Request) (userName string) {
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	}
	return userName
}

func getCredentialsUser(request *http.Request) (password string, username string){
	if cookie, err:= request.Cookie("session");err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			username = cookieValue["name"]
			password = cookieValue["pass"]
		}
	}
    return username, password
}

func index(w http.ResponseWriter, r *http.Request) {
	r.ParseForm() // parsing parameters
	for k, v := range r.Form {
		fmt.Println("key:", k)
		fmt.Println("val:", strings.Join(v, ""))
	}
	fmt.Fprintf(w, "There is nothing to see here John Snow, go there : http://localhost:9091/loginpage")
}

func loadPage(title string) ([]byte, error) {
	filename := "/var/www/authPoint/pages/" + title + ".html"
	html, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return html, nil
}
//устанавливаем сессию
func setSession(attribute string, userName string, pass string, response http.ResponseWriter){
	value := map[string]string{
		"name" :userName,
		"Raw" :attribute,
		"pass" :pass,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil{
		cookie := &http.Cookie{
			Name: "session",
			Value: encoded,
			Path: "/",
		}
		http.SetCookie(response,cookie)
	}
}

func clearSession(response http.ResponseWriter){
	cookie := &http.Cookie{
		Name: "session",
		Value: "",
		Path: "/",
		MaxAge: -1,
	}
	http.SetCookie(response,cookie)
}

func authUser(login string, pass string) (bool, string, error) {

	ok, user, err := client.Authenticate(login, pass)
	if err != nil {
		fmt.Printf("Error authenticating user %s: %+v", login, err)
	return false,user["distinguishedName"],err
	}
	if !ok {
		fmt.Printf("Authenticating failed for user %s", login)
		return false, user["distinguishedName"],err
	}
	return ok, user["distinguishedName"], err
}

func loginpage(w http.ResponseWriter, r *http.Request) {
	html, err := loadPage("login")
	if err != nil {
		return
	}
	fmt.Fprintf(w, string(html))
}

//var group []string
func loginHandler(response http.ResponseWriter, request *http.Request){
	request.ParseForm()
	login := strings.Join(request.Form["login"], "")
	pass := strings.Join(request.Form["pass"], "")
	if len(request.Form["pass"][0])==0{

		fmt.Fprint(response, "enter pass")
		return
	}
	res, attribute, err := authUser(login, pass)
	redirectTarger := "/loginpage"
	if err != nil {
			fmt.Printf("Failure\n")
		}
	if res{
		setSession(attribute,login,pass,response)
		groups, err := client.GetGroupsOfUser(attribute)
			if len(groups) != 0{
			for _, group := range groups{
				if strings.Contains(group,"OPS") {
					redirectTarger = "/select"
					break
				}
				if strings.Contains(group,"GoSSH") {
					redirectTarger = "/select"
					break
				}else {
					redirectTarger = "/otp"
				}
		if err != nil {
			log.Fatalf("Error getting groups for user %s: %+v", "username", err)
		}}}else {
			redirectTarger = "/otp"
			}}
	http.Redirect(response,request,redirectTarger,302)
}

func logoutHandler(response http.ResponseWriter, request *http.Request){
	clearSession(response)
	http.Redirect(response, request, "/loginpage",302)
}

func randStr(len int) string{
	buff :=make([]byte, len)
	rand.Read(buff)
	str := base64.StdEncoding.EncodeToString(buff)
	return str[:len]
}

func generekHash(text string) string {
	c := sha512_crypt.New()
	hash, err := c.Generate([]byte(text), []byte("$6$usesomesillystringforsalt"))
	if err != nil {
		panic(err)
	}
	return hash
}

func accessSudo(request *http.Request ) bool {
	var comma bool
	status := &comma
	attribute := getAttribute(request)
	groups, err:= client.GetGroupsOfUser(attribute)
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	for _, group := range groups {
		*status = false
		if strings.Contains(group, "OPS") {
			*status = true
			break
		}
	}
	return comma
}

func accessPgSudo(request *http.Request ) bool {
	var comma bool
	status := &comma
	attribute := getAttribute(request)
	groups, err:= client.GetGroupsOfUser(attribute)
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	for _, group := range groups {
		*status = false
		if strings.Contains(group, "PGOPS") {
			*status = true
			break
		}
	}
	return comma
}


// функция создаёт пользователя на хосте + передаёт креды и тип ключа в функции , которые работаю с апи vault
func createUserssh(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	request.ParseForm()
	fmt.Println(username)
	host := strings.Join(request.Form["ip_host"], "")
	sshKey := strings.Join(request.Form["ssh_key"], "")
	typeKey := strings.Join(request.Form["type_key"], "")
	date := time.Now()
	action := "Create account by host "
	sci :=ssh_auth.ServerConfig{
		host,
		"22",
		username,
		typeKey,
		sshKey,
	}
	command := "echo 'D_' | sudo -S adduser   --disabled-password --gecos []  --home /home/"+username+" --shell /bin/bash --force-badname " + username
	commandcentos := "echo 'D_' | sudo -S adduser " + username
	commandaddgroup := "echo 'D_' | sudo -S usermod -aG expresscourier " + username
	success, exitError := ssh_auth.SSHComand(command,sci)
	if exitError != nil{
		http.Error(response,exitError.Error(), http.StatusBadRequest)
	}
	log.Println("Success create", success)
	log.Println("exiError", exitError)
	successcentos, errcentos := ssh_auth.SSHComand(commandcentos,sci)
	if errcentos != nil{
		http.Error(response,exitError.Error(), http.StatusBadRequest)
	}
	log.Println("Success create", successcentos)
	log.Println("exiError", errcentos)
	successgroup, err := ssh_auth.SSHComand(commandaddgroup,sci)
	if err != nil{
		http.Error(response,exitError.Error(), http.StatusBadRequest)
	}

	log.Println("Success create", successgroup)
	log.Println("exiError", err)
	date.Format(time.ANSIC)
	db.AddAction(host,username,action,date)
	sudo :=accessSudo(request)
	if typeKey != "otp" {
		password := randStr(11)
		hash := generekHash(password)
		commandpassgenerik := "echo 'D_' | sudo -S sh -c \"echo "  + "'\"'"+username +":"+hash+"'\"'"+"| chpasswd -e \""
		successpass,exiError := ssh_auth.SSHComand(commandpassgenerik,sci)
		log.Println(successpass)
		fmt.Fprintf(response, "password: '"+password+ "'  ")
		if exiError != nil {
			http.Error(response,exitError.Error(), http.StatusBadRequest)
		}
	}

	if sudo == true{
		if typeKey != "otp"{
			commandsudo := "echo 'D_' | sudo -S adduser " + username + " sudo"
			commandgroupcentos := "echo 'D_' | sudo -S gpasswd -a " +username + " wheel"
			successsudo,exerr := ssh_auth.SSHComand(commandsudo,sci)
			log.Println(successsudo)
			if exerr != nil {
				http.Error(response,exitError.Error(), http.StatusBadRequest)
			}
			successgroupcentos, errgroupcentos  := ssh_auth.SSHComand(commandgroupcentos,sci)
			if errgroupcentos != nil{
				http.Error(response,exitError.Error(), http.StatusBadRequest)
			}
			log.Println("success group sudo ", successgroupcentos)
		}
	}
	if typeKey != "userhost"{
	vault_role := ssh_auth.Vault_create_role(sci)
	dst := &bytes.Buffer{}
	if err := json.Indent(dst, []byte(vault_role), "", "  "); err != nil {
			http.Error(response,err.Error(), http.StatusBadRequest)
	}
	fmt.Println(dst.String())

	fmt.Fprintf(response,dst.String())
	} else {
		log.Println("Success", success)
	}
}

func internalPageHandler(response http.ResponseWriter, request *http.Request) {
	userName := getUserName(request)
	if userName != "" {
		t, err := template.ParseFiles("/var/www/authPoint/pages/form.html")
		if err != nil {
			fmt.Fprintf(response, err.Error())
		}
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		for _, group := range groups {
			if strings.Contains(group, "OPS") {
				t.ExecuteTemplate(response, "form", userName)
				break
			}
			if strings.Contains(group, "GoSSH") {
				t.ExecuteTemplate(response, "form", userName)
				break
			}
		}
	} else {
		http.Error(response,"404",http.StatusNotFound)
	}
}

type ListHost struct {
	Username string
	Activhost []*ActivHost
}

func otpPageHandler(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	if username != "" {
		activhost := HostActiv()
		data := ListHost{
			username,
			activhost,
		}
		t, err := template.ParseFiles("/var/www/authPoint/pages/form_otp.html")
		if err != nil {
			fmt.Fprintf(response, err.Error())
		}
		t.ExecuteTemplate(response,"form_otp", data)
	}else {
		http.Error(response,"404",http.StatusNotFound)
		//http.Redirect(response, request, "/", 302)
	}
}

func HostActiv() []*ActivHost{
	rows, err := db.ListActivHost()
	defer rows.Close()
	bodys := make([]*ActivHost, 0)
	for rows.Next() {
		body := new(ActivHost)
		if err := rows.Scan(&body.host); err != nil{
			fmt.Println(err)
		}
		bodys = append(bodys,body)
	}
	if err = rows.Err(); err !=nil{
		fmt.Println(err)
	}
		return bodys
	}

func selectAssString()  []string {
	results := make([]string, 0)
	rows, err := db.ListPgActiv()
	if err != nil {
		panic(err)
	}
	var scanString string
	for rows.Next() {
		rows.Scan(&scanString)
		results = append(results, scanString)
	}
	return results
}

func selectAsString(dbname string)  []string {
	results := make([]string, 0)
	rows, err := db.GetPgHost(dbname)
	if err != nil {
		panic(err)
	}
	var scanString string
	for rows.Next() {
		rows.Scan(&scanString)
		results = append(results, scanString)
	}
	return results
}

type ViewData struct{
	username string
	Admins bool
}

func selectHandler(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	if username != "" {
		t, err := template.ParseFiles("/var/www/authPoint/pages/select.html")
		if err != nil {
			fmt.Fprintf(response, err.Error())
		}
		data := ViewData{
			username,
			false,
		}
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		for _, group := range groups {
			if strings.Contains(group,"OPS"){
				data.Admins = true
				t.ExecuteTemplate(response, "select", data)
				break
			}
			if strings.Contains(group, "GoSSH") {
				t.ExecuteTemplate(response, "select", data)
				break
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
		//http.Redirect(response, request, "/", 302)
	}
}

func historyHandler(response http.ResponseWriter,request *http.Request){
	username := getUserName(request)
	if username != "" {
		//rows, err := db.HistoryAction()
		//defer rows.Close()
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		if err != nil {
			log.Fatalf("Error getting groups for user %s: %+v", "username", err)
		}
		for _, group := range groups{
			if strings.Contains(group, "OPS") {
				rows, err := db.HistoryAction()
				defer rows.Close()
				bodys := make([]*History, 0)
				for rows.Next() {
					body := new(History)
					if err := rows.Scan(&body.id, &body.data, &body.username, &body.actions, &body.host); err != nil {
						http.Error(response, http.StatusText(500), 500)
						return
					}
					bodys = append(bodys, body)
				}
			if err = rows.Err(); err != nil{
				http.Error(response, http.StatusText(500),500)
				return
			}
			for _, body := range bodys{
				fmt.Fprintf(response,"%s, %s, %s, %s.\n",body.data, body.username, body.host, body.actions,)
			}
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
	}
}

func pgHistoryHandler(response http.ResponseWriter,request *http.Request){
	username := getUserName(request)
	if username != "" {
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		if err != nil {
			log.Fatalf("Error getting groups for user %s: %+v", "username", err)
		}
		for _, group := range groups{
			if strings.Contains(group, "OPS") {
				rows, err := db.PgHistoryAction()
				defer rows.Close()
				bodys := make([]*History, 0)
				for rows.Next() {
					body := new(History)
					if err := rows.Scan(&body.id, &body.data, &body.username, &body.actions, &body.host); err != nil {
						http.Error(response, http.StatusText(500), 500)
						return
					}
					bodys = append(bodys, body)
				}
				if err = rows.Err(); err != nil{
					http.Error(response, http.StatusText(500),500)
					return
				}
				for _, body := range bodys{
					fmt.Fprintf(response,"%s, %s, %s, %s.\n",body.data, body.username, body.host, body.actions,)
				}
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
	}
}

func userHostHandler(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	if username != "" {
		t, err := template.ParseFiles("/var/www/authPoint/pages/userhost.html")
		if err != nil {
			fmt.Fprintf(response, err.Error())
		}
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		for _, group := range groups {
			if strings.Contains(group, "OPS") {
				t.ExecuteTemplate(response, "userhost", username)
				break
			}
			if strings.Contains(group, "GoSSH") {
				t.ExecuteTemplate(response, "userhost", username)
				break
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
	}
}

func formDeleteHandler(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	if username != "" {
		t, err := template.ParseFiles("/var/www/authPoint/pages/form_delete.html")
		if err != nil{
			http.Error(response, http.StatusText(500),500)
		}
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		for _, group := range groups {
			if strings.Contains(group, "OPS") {
				t.ExecuteTemplate(response,"form_delete",username)
				break
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
		//http.Redirect(response, request, "/", 302 )
	}
}

func deleteHandler(response http.ResponseWriter, request *http.Request){
	useradmin := getUserName(request)
	request.ParseForm()
	username := strings.Join(request.Form["username"],"")
	rows, err := db.UserActionHost(username)
	defer rows.Close()
	date := time.Now()
	action := "del user " + username
	host := "all"
	bodys := make([]*History, 0)
	for rows.Next() {
		body := new(History)
		if err := rows.Scan(&body.id, &body.data, &body.username, &body.host, &body.actions); err != nil {
			http.Error(response, http.StatusText(500), 500)
			return
		}
		bodys = append(bodys,body)
		}
		if err = rows.Err(); err !=nil{
			http.Error(response, http.StatusText(500),500)
			return
		}
	for _, body := range bodys{
		fmt.Println(body.username, body.host)
		sci :=ssh_auth.ServerConfig{
			body.host,
			"22",
			body.username,
			"false",
			"false",
		}
		command := "echo 'D_' | sudo -S deluser " + body.username+""
		view ,err := ssh_auth.SSHComand(command,sci)
		if err != nil{
			http.Error(response, err.Error(), http.StatusBadRequest)
		}
		fmt.Fprintf(response,view)
	}
	defer
	db.AddAction(host,useradmin,action,date)
}
//нет возможности обьединить обе структуры ListHost и PgListHost хотя они несут почти одинаковый функционал,
//,из-за разных полей таблицы, возможно в будующем переделать структуру таблицы
type PgListHost struct {
	Username string
	//PgActivhost []*PgActivHost
	PgActivhost []string
}

type CredDb struct {
	Username string
	Login string
	Password string
	//Url    []*PgUrls
	Url    []string
}

func formOnePostgresHandler(response http.ResponseWriter, request *http.Request){
	page := "form_pg"
	formPostgresHandler(response, request, page)
}

func formManyPostgresHandler(response http.ResponseWriter, request *http.Request){
	page := "pg_many_creds_form"
	formPostgresHandler(response, request, page)
}

func formPostgresHandler(response http.ResponseWriter, request *http.Request,page string){
	username :=getUserName(request)
	if username !="" {
		//t,err := template.ParseFiles("/var/www/authPoint/pages/form_pg.html")
		t,err := template.ParseFiles("/var/www/authPoint/pages/"+page+".html")
		if err != nil{
			http.Error(response,http.StatusText(500),500)
		}
		attribute :=getAttribute(request)
		groups, err:= client.GetGroupsOfUser(attribute)
		//activdb := PgHostActiv()
		activdb := selectAssString()
		data := PgListHost{
			username,
			activdb,
		}
		for _, group := range groups{
			if strings.Contains(group, "OPS") {
				t.ExecuteTemplate(response, page, &data)
				break
			}
			if strings.Contains(group, "GoSSH") {
				t.ExecuteTemplate(response, page,  &data)
				break
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
		}
}

func checkWriteAccess(response http.ResponseWriter,request *http.Request, dbNameOutput string) (string) {
	var dbname string
	defaultname := &dbname
	attribute := getAttribute(request)
	groups, err := client.GetGroupsOfUser(attribute)
	if err != nil {
		http.Error(response, http.StatusText(500), 500)
	}
	for _, group := range groups {
		*defaultname = dbNameOutput
		if strings.Contains(group, "PGOPS") {
			*defaultname = dbNameOutput + "-write"

			break
		}
	}
	fmt.Println(dbname)
	return dbname
}

func postgresCheckboxHandler(response http.ResponseWriter, request *http.Request){
	username, pass := getCredentialsUser(request)
	if username != "" {
		t, err := template.ParseFiles("/var/www/authPoint/pages/pg_xml_creds.html")
		if err != nil{
			http.Error(response, http.StatusText(500),500)
		}
		request.ParseForm()
		dbnameArray :=request.Form["db_id"]
		credentials := make(map[string]map[string]map[string]string)
		for _, dbname := range dbnameArray {
			replacer := strings.NewReplacer("{", "", "}", "")
			dbNameOutput := replacer.Replace(dbname)
			login, password, errors := ssh_auth.VaultGetTokenPg(username, pass, dbNameOutput)
			if errors == nil {
				arrayhost := selectAsString(dbNameOutput)
				for _, url := range arrayhost {
					credentials[login] = make(map[string]map[string]string)
					credentials[login][password] = make(map[string]string)
					credentials[login][password][dbNameOutput] = url
				}
			}
		}
			t.ExecuteTemplate(response, "pg_xml_creds_page", credentials)
		}else {
			http.Error(response,"404",http.StatusNotFound)
			}
}

func postgresHandler(response http.ResponseWriter, request *http.Request){
	username, pass := getCredentialsUser(request)
	request.ParseForm()
	dbname := strings.Join(request.Form["dbname"], "")
	t, err := template.ParseFiles("/var/www/authPoint/pages/pg_creds_page.html")
	if err != nil{
		http.Error(response, http.StatusText(500),500)
	}
	dbNameOutputq :=checkWriteAccess(response,request,dbname)
	login, password, errors := ssh_auth.VaultGetTokenPg(username, pass, dbNameOutputq) //тут
	if errors == nil{
		url := selectAsString(dbname)
		data := CredDb{
			Username:username,
			Login:    login,
			Password: password,
			Url:      url,
		}
		t.ExecuteTemplate(response,"pg_creds_page",data)
	}else{
		http.Error(response, http.StatusText(500),500)
	}
	if errors != nil{
		http.Error(response, http.StatusText(500),500)
	}
}

func formPgDistributionHandler(response http.ResponseWriter,request *http.Request){
	username := getUserName(request)
	if username != ""{
		t, err := template.ParseFiles("/var/www/authPoint/pages/pg_distribution.html")
		if err != nil{
			http.Error(response, http.StatusText(500),500)
		}
		attribute := getAttribute(request)
		groups, err :=client.GetGroupsOfUser(attribute)
		for _, group := range groups{
			if strings.Contains(group, "OPS"){
				t.ExecuteTemplate(response,"form_pg_distribution",username)
				break
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
	}
}

func pgDistributionHandler(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	request.ParseForm()
	pgHost := strings.Join(request.Form["address_host"], "")
	dbname := strings.Join(request.Form["db_name"], "")
	ssh_auth.PgNewInstance(response, username, dbname, pgHost)

}

func formPGDeleteHandler(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	if username != "" {
		t, err := template.ParseFiles("/var/www/authPoint/pages/form_pgdb_delete.html")
		if err != nil{
			http.Error(response, http.StatusText(500),500)
		}
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		for _, group := range groups {
			if strings.Contains(group, "OPS") {
				t.ExecuteTemplate(response,"form_pgdb_delete",username)
				break
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
		//http.Redirect(response, request, "/", 302 )
	}
}

func pgDeleteHandler(response http.ResponseWriter, request *http.Request){
	useradmin := getUserName(request)
	request.ParseForm()
	database := strings.Join(request.Form["database_name"],"")
	db.DeletePgDb(database)
	pgdate := time.Now()
	action := "del database " + database
	pgdate.Format(time.ANSIC)
	fmt.Fprintf(response,useradmin)
	defer
		db.AddPgAction(database,useradmin,action,pgdate)
}

func pgSyncAllHost(response http.ResponseWriter, request *http.Request) {
	username :=getUserName(request)
	if username !="" {
		attribute :=getAttribute(request)
		groups, err:= client.GetGroupsOfUser(attribute)
		if err != nil{
			http.Error(response, http.StatusText(500),500)
		}
		activdb := selectAssString()
		pgHost := "pgbouncer.service.prod.tech"
		for _, group := range groups{
			if strings.Contains(group, "OPS") {
				for _, dbname := range activdb {
					ssh_auth.PgNewInstance(response, username, dbname, pgHost)
					fmt.Fprintln(response,"add "+dbname)
					//fmt.Fprintf(response,"add "+dbname)
				}
				break
			}
		}
	}else {
		//http.Error(response,"404",http.StatusNotFound)
		http.Redirect(response, request, "/loginpage", 302 )
	}
}


func form_distributionHandler(response http.ResponseWriter, request *http.Request){
	username := getUserName(request)
	if username != "" {
		t, err := template.ParseFiles("/var/www/authPoint/pages/distribution.html")
		if err != nil{
			http.Error(response, http.StatusText(500),500)
		}
		attribute := getAttribute(request)
		groups, err := client.GetGroupsOfUser(attribute)
		for _, group := range groups {
			if strings.Contains(group, "OPS") {
				t.ExecuteTemplate(response,"form_distribution", username)
				break
			}
		}
	}else {
		http.Error(response,"404",http.StatusNotFound)
		//http.Redirect(response, request, "/", 302 )
	}
}

func distributionHandler(response http.ResponseWriter, request *http.Request){
	command := "echo 'D_' | sudo -S sh -c 'chmod +x /home/sysadmin/config.sh && /home/sysadmin/config.sh'"
	username := getUserName(request)
	otp_config_file := "config.sh"
	ca_keys_file := "trusted-user-ca-keys.pem"
	request.ParseForm()
	host := strings.Join(request.Form["ip_host"], "")
	date := time.Now()
	action := " add new host "
	sci := ssh_auth.ServerConfig{
		host,
		"22",
		username,
		"false",
		"false",
	}
	otp_config, err := ssh_auth.SSHSftp(sci, otp_config_file)
	if err != nil{
		http.Error(response, err.Error(), http.StatusBadRequest)
	}
	ca_key, err := ssh_auth.SSHSftp(sci, ca_keys_file)

	if err != nil{
		http.Error(response, err.Error(), http.StatusBadRequest)
	}
	view ,err := ssh_auth.SSHComand(command,sci)
	if err != nil{
		http.Error(response, err.Error(), http.StatusBadRequest)
	}
	fmt.Println(ca_key)
	fmt.Println(otp_config)
	fmt.Fprintf(response,view)
	date.Format(time.ANSIC)
	if view != ""{
		db.AddAction(host, username, action, date)
		db.AddHost(host)
	}
}

var router = mux.NewRouter()
func main() {
	client = &ldap.LDAPClient{
		Base:         "dc=express,dc=local",
		//Host:         "192.168.0.13",
		Host:         "DC-cod-01.express.local",
		//Port:         389,
		Port:         636,
		InsecureSkipVerify: true,
		//UseSSL:       false,
		UseSSL:       true,
		BindDN:       "cn=testldap, ou=Администраторы,ou=ИТ,ou=Express,dc=express,dc=local",
		BindPassword: "password",
		UserFilter:   "(sAMAccountName=%s)",
		GroupFilter:  "(member=%s)",
		Attributes:   []string{"givenName", "distinguishedName", "mail", "sAMAccountName"},
	}
	defer client.Close()

	router.HandleFunc("/loginpage", loginpage)
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/logout", logoutHandler)
	router.HandleFunc("/", index)
	router.HandleFunc("/ca", internalPageHandler)
	router.HandleFunc("/otp", otpPageHandler)
	router.HandleFunc("/select", selectHandler)
	router.HandleFunc("/userhost", userHostHandler)
	router.HandleFunc("/createUserssh", createUserssh).Methods("POST")
	router.HandleFunc("/logs", historyHandler).Methods("GET")
	router.HandleFunc("/pg_logs", pgHistoryHandler).Methods("GET")
	router.HandleFunc("/form_delete", formDeleteHandler)
	router.HandleFunc("/deletepgdb", pgDeleteHandler).Methods("POST")
	router.HandleFunc("/deleteuser", deleteHandler).Methods("POST")
	router.HandleFunc("/form_pgdb_delete", formPGDeleteHandler)
	router.HandleFunc("/deletepgdb", pgDeleteHandler).Methods("POST")
	router.HandleFunc("/form_distribution", form_distributionHandler)
	router.HandleFunc("/distribution", distributionHandler).Methods("POST")
	//router.HandleFunc("/form_pg", formPostgresHandler)
	router.HandleFunc("/form_pg", formOnePostgresHandler)
	router.HandleFunc("/form_file_pg", formManyPostgresHandler)
	router.HandleFunc("/pgcheackbox", postgresCheckboxHandler)
	router.HandleFunc("/pgcreds", postgresHandler).Methods("POST")
	router.HandleFunc("/form_pg_distribution", formPgDistributionHandler)
	router.HandleFunc("/pg_distribution", pgDistributionHandler).Methods("POST")
	router.HandleFunc("/pg_sync", pgSyncAllHost).Methods("GET")
	http.Handle("/", router)
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("/var/www/authPoint/static/css/"))))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("/var/www/authPoint/static/img/"))))
	http.Handle("/fonts/", http.StripPrefix("/fonts/", http.FileServer(http.Dir("/var/www/authPoint/static/fonts/"))))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("/var/www/authPoint/static/js/"))))

	http.ListenAndServe("0.0.0.0:9091", nil)
}
