package booksauthors

type Book struct {
	Book_id          int    `json:"book_id"`
	Book_title       string `json:"book_title"`
	Author_id        int    `json:"author_id"`
	Author_name      string `json:"author_name"`
	Price            uint   `json:"price"`
	Authors_old_name string `json:"authors_old_name"`
}
