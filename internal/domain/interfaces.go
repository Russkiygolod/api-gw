package domain

import (
	"api-gw/internal/books"
)

//go:generate mockgen -source=interfaces.go -destination=mocks/interfaces_mock.go -package=mock
type ServiceBooksClient interface {
	books.BooksClient
}
