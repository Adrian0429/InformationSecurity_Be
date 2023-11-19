package routes

import (
	"github.com/Caknoooo/golang-clean_template/controller"
	"github.com/Caknoooo/golang-clean_template/middleware"
	"github.com/Caknoooo/golang-clean_template/services"
	"github.com/Caknoooo/golang-clean_template/utils"
	"github.com/gin-gonic/gin"
)

func User(route *gin.Engine, userController controller.UserController, jwtService services.JWTService) {
	routes := route.Group("/api/user")
	{
		// User
		routes.POST("", userController.RegisterUser)
		routes.GET("", userController.GetAllUser)
		routes.POST("/login", userController.LoginUser)
		routes.DELETE("/", middleware.Authenticate(jwtService), userController.DeleteUser)
		routes.PATCH("/", middleware.Authenticate(jwtService), userController.UpdateUser)
		routes.GET("/me", middleware.Authenticate(jwtService), userController.MeUser)
		routes.POST("/upload/:method", middleware.Authenticate(jwtService), userController.Upload)
		routes.GET("/get/:path/:ownerid/:id/:method", middleware.Authenticate(jwtService), userController.GetMedia)
		routes.GET("/get/:path/KTP/:ownerid", middleware.Authenticate(jwtService), userController.GetKTP)
		routes.POST("/email", func(c *gin.Context) {
			utils.SimpleSendEmail()
		})

		routes.GET("/getAllMedia", middleware.Authenticate(jwtService), userController.GetAllMedia)
		// Admin
		routes.PATCH("/verify", middleware.Authenticate(jwtService), userController.UpdateStatusIsVerified)
	}

}
