package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// в процессе доработки
func TestGetRequest(t *testing.T) {
	r, _ := http.NewRequest("POST", "/register", strings.NewReader(`{"emal":"asdf@mail.ru","password":"asdf"}`))
	w := httptest.NewRecorder()
	GetRequest(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []byte(`{"emal":"asdf@mail.ru","password":"asdf"}`), w.Body.Bytes())
}
func GetRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	myString := vars["mystring"]
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(myString))
}
