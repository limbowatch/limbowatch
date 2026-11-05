module example.com/t

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	example.com/local v0.0.0
)

replace example.com/local => ../local
