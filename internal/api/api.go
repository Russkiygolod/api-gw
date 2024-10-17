package api

import (
	"api-gw/internal/books"
	"api-gw/internal/domain"
	jwttoken "api-gw/internal/jwtToken"
	booksauthors "api-gw/pkg/models/booksAuthors"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"google.golang.org/grpc"
)

type ApiInterface interface {
}

// создаем логгер
var fileError, _ = os.OpenFile("log_api_error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
var logError = log.New(fileError, "ERROR:", log.LstdFlags|log.Lshortfile)

type API struct {
	r           *mux.Router // маршрутизатор запросов
	booksClient domain.ServiceBooksClient
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var ctx = context.Background()

func New(conn *grpc.ClientConn) *API {
	api := API{
		r:           mux.NewRouter(),
		booksClient: books.NewBooksClient(conn),
	}
	api.endpoints()
	api.authEndpoints()
	return &api
}

// Router возвращает маршрутизатор запросов.
func (api *API) Router() *mux.Router {
	return api.r
}

// Регистрация методов API в маршрутизаторе запросов.
func (api *API) endpoints() {
	postR := api.r.Methods(http.MethodPost, http.MethodGet, http.MethodPatch, http.MethodDelete).Subrouter()
	postR.Use(api.Middleware2())
	postR.HandleFunc("/books", api.createBooksHandler).Methods(http.MethodPost)
	postR.HandleFunc("/books", api.readBooksHandler).Methods(http.MethodGet)
	postR.HandleFunc("/books/{id}", api.updateBooksHandler).Methods(http.MethodPatch)
	postR.HandleFunc("/books/{id}", api.deleteBooksHandler).Methods(http.MethodDelete)
}

func (api *API) authEndpoints() {
	api.r.HandleFunc("/register", api.Register).Methods(http.MethodPost)
	api.r.HandleFunc("/login", api.Login).Methods(http.MethodPost)
}

// midlweare (проверка авторизации пользователя)
func (api *API) Middleware2() mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := r.Header.Get("Authorization")
			if len(tokenString) == 0 {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Missing Authorization Header"))
				return
			}
			Email, err := jwttoken.AuthMiddleware(tokenString)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Error verifying JWT token"))
				return
			}
			_, err = api.booksClient.PostChekAuth(ctx, &books.PostChekAuthReq{Email: Email})
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Authentication error!"))
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

// Обработчик HTTP-запросов на регистрацию пользователя
func (api *API) Register(w http.ResponseWriter, r *http.Request) {
	regReq := User{}
	err := json.NewDecoder(r.Body).Decode(&regReq)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if regReq.Email == "" || regReq.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("user registration error, email field or password field cannot be empty"))
		return
	}
	_, err = api.booksClient.PostRegistration(ctx, &books.PostRegistrationReq{Email: regReq.Email, Password: regReq.Password})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(grpc.ErrorDesc(err)))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Обработчик HTTP-запросов на вход в аккаунт
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	regReq := User{}
	err := json.NewDecoder(r.Body).Decode(&regReq)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Ищем пользователя в памяти приложения по электронной почте
	_, err = a.booksClient.PostChekAuth(ctx, &books.PostChekAuthReq{Email: regReq.Email})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("email not found"))
		return
	}
	// Если пользователь найден, но у него другой пароль, возвращаем ошибку
	userG, err := a.booksClient.PostLogin(ctx, &books.PostLoginReq{Email: regReq.Email, Password: regReq.Password})
	user := int(userG.Id)
	if user == 0 || err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("incorrect password"))
		return
	}
	// Генирируем и возвращаем токен
	token, err := jwttoken.GetToken(regReq.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error generating JWT token: " + err.Error()))
	} else {
		w.Header().Set("Authorization", "Bearer "+token)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token: " + token))
	}
}

// createBooksHandler создает книгу
func (api *API) createBooksHandler(w http.ResponseWriter, r *http.Request) {
	var B booksauthors.Book
	err := json.NewDecoder(r.Body).Decode(&B)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = api.booksClient.PostBooks(ctx, &books.PostBooksReq{
		Tittle:     &B.Book_title,
		AuthorName: &B.Author_name,
		Price:      uint64(B.Price),
	})
	if err != nil && grpc.ErrorDesc(err) == "empty fields are not allowed" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("empty fields are not allowed"))
		return
	} else if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// readBooksHandler читает книгу
func (api *API) readBooksHandler(w http.ResponseWriter, r *http.Request) {
	var B booksauthors.Book
	err := json.NewDecoder(r.Body).Decode(&B)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	BookIDG := uint64(B.Book_id)
	AuthorIDG := uint64(B.Author_id)

	book, err := api.booksClient.GetBooks(ctx, &books.GetBooksReq{
		Id:         &BookIDG,
		Tittle:     &B.Book_title,
		AuthorID:   &AuthorIDG,
		AuthorName: &B.Author_name,
	})
	var BookS []booksauthors.Book
	for _, val := range book.Books {
		BookS = append(BookS, booksauthors.Book{
			Book_id:     int(val.BookID),
			Book_title:  val.BookTitle,
			Price:       uint(val.Price),
			Author_name: val.AuthorName})
	}
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Отправка данных клиенту в формате JSON.
	err = json.NewEncoder(w).Encode(BookS)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// updateOrderHandler обновляет данные книги по ID
func (api *API) updateBooksHandler(w http.ResponseWriter, r *http.Request) {
	// Считывание параметра {id} из пути запроса.
	s := mux.Vars(r)["id"]
	id, err := strconv.Atoi(s)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var B booksauthors.Book
	err = json.NewDecoder(r.Body).Decode(&B)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	idG := uint64(id)
	AuthorIDG := uint64(B.Author_id)
	// Обновление данных в БД.
	_, err = api.booksClient.PatchBooks(ctx, &books.PatchBooksReq{
		Id:             &idG,
		Tittle:         &B.Book_title,
		AuthorID:       &AuthorIDG,
		AuthorName:     &B.Author_name,
		AuthorsOldName: &B.Authors_old_name,
		Price:          uint64(B.Price),
	})
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// deleteBooksHandler удаляет книгу по ID
func (api *API) deleteBooksHandler(w http.ResponseWriter, r *http.Request) {
	s := mux.Vars(r)["id"]
	id, err := strconv.Atoi(s)
	if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = api.booksClient.DelBooks(ctx, &books.DelBooksReq{BookID: uint64(id)})
	if grpc.ErrorDesc(err) == "the book does not exist" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("the book does not exist"))
		return
	} else if err != nil {
		logError.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		w.WriteHeader(http.StatusOK)
	}
}
