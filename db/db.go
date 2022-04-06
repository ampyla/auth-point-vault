package db

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"log"
	"time"
)
//
var db *sql.DB
func InitDb() {

	//conn := "user=vauluser password=qq dbname=vaulssh host=master.atlas-nsk-postgres-el-05-cluster.service.prod.tech sslmode=disable"
	conn := "user=vauluser password=qq dbname=vaulssh host=pgbouncer.service.prod.tech port=6433 sslmode=disable"
	//conn := "user=vauluser password=password dbname=vaulssh host=172.16.184.177 sslmode=disable"

	dbs, err := sql.Open("postgres", conn)
	lol := &db
	*lol = dbs
	if err != nil {
		log.Fatal(err)
	}
	if err = dbs.Ping(); err != nil {
		log.Fatal(" Could not establish a connection with the")
	}
	fmt.Println("success")
}

func AddAction(hostVar string, nameVar string, actionVar string, datetimeVar time.Time){
	InitDb()
	defer db.Close()
	//result,err := db.Exec("insert  into vaulssh (name,host,action ) values ("+nameVar+","+hostVar+","+actionVar+" )")
	result, err := db.Exec("insert  into  sshauth(date,username,host,actions ) values ( $1,$2,$3,$4)",datetimeVar,nameVar,hostVar,actionVar)
	if err != nil{
		log.Println(err)
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("successfully (%d row affected)\n", rowsAffected)
}

func AddPgAction(hostVar string, nameVar string, actionVar string, datetimeVar time.Time){
	InitDb()
	defer db.Close()
	result, err := db.Exec("insert  into  auth_pg_logs(date,username,host,actions ) values ( $1,$2,$3,$4)",datetimeVar,nameVar,hostVar,actionVar)
	if err != nil {
		log.Println(err)
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("successfully (%d row affected pg table)\n", rowsAffected)
}

func AddPgHost(hostVar string, nameVar string){
	InitDb()
	defer db.Close()
	result, err := db.Exec("insert into postgres_in_vault(host,dbname ) values ($1,$2)",hostVar,nameVar)
	if err != nil{
		log.Println(err)
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("successfully (%d row affected)\n", rowsAffected)
}

func HistoryAction() (*sql.Rows, error) {
	InitDb()
	defer db.Close()
	rows, err := db.Query("SELECT * FROM sshauth order by date desc")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return rows, err
}

func PgHistoryAction() (*sql.Rows, error) {
	InitDb()
	defer db.Close()
	rows, err := db.Query("SELECT * FROM auth_pg_logs order by date desc")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return rows, err
}

func UserActionHost(username string)(*sql.Rows, error){
	InitDb()
	defer db.Close()
	fmt.Println(username)
	rows, err := db.Query("select * from sshauth where username=$1",username)
	return rows, err
}

func AddHost(hostVar string){
	InitDb()
	defer db.Close()
	result, err := db.Exec("insert  into  sshost(host ) values ( $1)",hostVar)
	if err != nil{
		log.Println(err)
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("successfully (%d row affected)\n", rowsAffected)
}

func ListActivHost() (*sql.Rows, error) {
	InitDb()
	defer db.Close()
	rows, err := db.Query("SELECT distinct host FROM sshost")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return rows, err
}

func ListPgActiv() (*sql.Rows, error){
	InitDb()
	defer db.Close()
	rows, err := db.Query("SELECT distinct dbname FROM postgres_in_vault ORDER BY dbname " )
	if err != nil{
		log.Println(err)
		return nil, err
	}
	return rows, err
}

func AddPgRole(dbnameVar string ,urlVar string){
	InitDb()
	defer db.Close()
	result, err := db.Exec("insert  into  postgres_in_vault(host,dbname ) values ( $1,$2)",urlVar,dbnameVar)
	if err != nil{
		log.Println(err)
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("successfully (%d row affected)\n", rowsAffected)
}

func GetPgHost(dbnameVar string) (*sql.Rows, error){
	InitDb()
	defer db.Close()
	rows, err := db.Query("select distinct  host from postgres_in_vault where dbname=$1",dbnameVar)
	if err != nil{
		log.Println(err)
		return nil, err
	}
	return rows, err
}

func DeletePgDb(dbnameVar string){
	InitDb()
	defer db.Close()
	result, err := db.Exec("DELETE FROM postgres_in_vault WHERE dbname = $1",dbnameVar)
	if err != nil{
		log.Println(err)
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("successfully (%d row affected)\n", rowsAffected)
}