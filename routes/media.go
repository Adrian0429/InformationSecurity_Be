package routes

import (
	"github.com/Caknoooo/golang-clean_template/controller"
	"github.com/gin-gonic/gin"
)

func Media(route *gin.Engine, mediaController controller.MediaController) {
	routes := route.Group("/api/media")
	{
		routes.POST("", mediaController.Upload)
		routes.GET("/:id", mediaController.GetMedia)
	}
}
