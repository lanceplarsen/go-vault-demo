package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/dimiro1/health"
	"github.com/dimiro1/health/db"
	"github.com/dimiro1/health/url"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"github.com/lanceplarsen/go-vault-demo/client"
	"github.com/lanceplarsen/go-vault-demo/config"
	"github.com/lanceplarsen/go-vault-demo/dao"
	"github.com/lanceplarsen/go-vault-demo/models"
	"github.com/lanceplarsen/go-vault-demo/service"
	_ "github.com/lib/pq"
)

var orderService = service.Order{}

func AllOrdersEndpoint(w http.ResponseWriter, r *http.Request) {
	orders, err := orderService.GetOrders()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	/*
	if len(orders) > 0 {
		respondWithJson(w, http.StatusOK, orders)
	} else {
		respondWithJson(w, http.StatusOK, map[string]string{"orders": "No orders"})
	}
	*/
	respondWithJson(w, http.StatusOK, orders)
}

func CreateOrderEndpoint(w http.ResponseWriter, r *http.Request) {
	var order models.Order

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&order); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	//Respond with the updated order
	order, err := orderService.CreateOrder(order)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusCreated, order)
}

func DeleteOrdersEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := orderService.DeleteOrders(); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusOK, map[string]string{"result": "success"})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJson(w, code, map[string]string{"error": msg})
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func main() {
	log.Println("Starting server initialization")

	//Get our config from the file
	var config = config.Config{}
	config.Read()

	//Server params
	var credential = client.Credential{
		Token:          config.Vault.Credential.Token,
		RoleID:         config.Vault.Credential.RoleID,
		SecretID:       config.Vault.Credential.SecretID,
		ServiceAccount: config.Vault.Credential.ServiceAccount,
	}

	var vault = client.Vault{
		Host:           config.Vault.Host,
		Port:           config.Vault.Port,
		Scheme:         config.Vault.Scheme,
		Authentication: config.Vault.Authentication,
		Role:           config.Vault.Role,
		Mount:          config.Vault.Mount,
		Namespace:      config.Vault.Namespace,
		Credential:     credential,
	}

	//Init it
	log.Println("Starting vault initialization")
	err := vault.Initialize()
	if err != nil {
		log.Fatal(err)
	}

	//Make sure we got a DB role
	log.Println("Starting DB initialization")
	if len(config.Vault.Database.Role) == 0 {
		log.Fatal("Could not get DB role from config.")
	}

	//See if we need to go get dyanmic DB creds
	if len(config.Database.Username) == 0 && len(config.Database.Password) == 0 {
		log.Printf("DB role: %s", config.Vault.Database.Role)
		secret, err := vault.GetSecret(fmt.Sprintf("%s/creds/%s", config.Vault.Database.Mount, config.Vault.Database.Role))
		if err != nil {
			log.Fatal(err)
		}
		//Update our configuration with the dynamic creds
		config.Database.Username = secret.Data["username"].(string)
		config.Database.Password = secret.Data["password"].(string)
		//Start our Goroutine Renewal for the DB creds
		go vault.RenewSecret(secret)
	}

	//DAO config
	var orderDao = dao.Order{
		Host:     config.Database.Host,
		Port:     config.Database.Port,
		Database: config.Database.Name,
		User:     config.Database.Username,
		Password: config.Database.Password,
	}

	//Check our DAO connection
	err = orderDao.Connect()
	if err != nil {
		log.Fatal(err)
	}

	//Get our TLS cert from Vault
	cert, err := vault.GetCertificate(fmt.Sprintf("%s/issue/%s", config.Vault.Pki.Mount, config.Vault.Pki.Role), config.Vault.Pki.CN)
	if err != nil {
		log.Fatal(err)
	}

	public := cert.Data["certificate"].(string)
	private := cert.Data["private_key"].(string)
	publicBytes := []byte(public)
	privateBytes := []byte(private)

	x509, err := tls.X509KeyPair(publicBytes, privateBytes)
	if err != nil {
		log.Fatal(err)
	}

	//Create service
	orderService.Vault = &vault
	orderService.Dao = &orderDao
	orderService.Encyrption.Key = config.Vault.Transit.Key
	orderService.Encyrption.Mount = config.Vault.Transit.Mount

	//Router
	r := mux.NewRouter()

	//API Routes
	r.HandleFunc("/api/orders", AllOrdersEndpoint).Methods("GET")
	r.HandleFunc("/api/orders", CreateOrderEndpoint).Methods("POST")
	r.HandleFunc("/api/orders", DeleteOrdersEndpoint).Methods("DELETE")

	//Health Check Routes
	h := health.NewHandler()
	conn := fmt.Sprintf("user=%s password=%s dbname=%s host=%s sslmode=disable", config.Database.Username, config.Database.Password, config.Database.Name, config.Database.Host)
	database, _ := sql.Open("postgres", conn)
	pg := db.NewPostgreSQLChecker(database)
	h.AddChecker("Postgres", pg)
	h.AddChecker("Vault", url.NewChecker(fmt.Sprintf("%s://%s:%s/v1/sys/health?perfstandbyok=true", config.Vault.Scheme, config.Vault.Host, config.Vault.Port)))
	r.Path("/health").Handler(h).Methods("GET")

	//CORS
	corsObj:=handlers.AllowedOrigins([]string{"*"})

	//Server config - http
	go func() {
		log.Println(fmt.Sprintf("Server is now accepting http requests on port %v", config.Server.Port))
		if err := http.ListenAndServe(fmt.Sprintf(":%v", config.Server.Port), handlers.CORS(corsObj)(r)); err != nil {
			log.Fatal(err)
		}
	}()

	//Server config - https
	go func() {
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{x509}}
		s := &http.Server{
			Addr:      ":8443",
			Handler:   r,
			TLSConfig: tlsConfig,
		}
		log.Println(fmt.Sprintf("Server is now accepting https requests on port 8443"))
		if err := s.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()

	//Catch SIGINT AND SIGTERM to gracefully tear down tokens and secrets
	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)
	sig := <-gracefulStop
	fmt.Printf("caught sig: %+v", sig)
	vault.Close()
	os.Exit(0)

}
