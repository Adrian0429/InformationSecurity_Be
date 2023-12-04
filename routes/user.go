package routes

import (
	"github.com/Caknoooo/golang-clean_template/controller"
	"github.com/Caknoooo/golang-clean_template/middleware"
	"github.com/Caknoooo/golang-clean_template/services"
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
		routes.GET("/getbykey/:path/:ownerid/:id/:method", middleware.Authenticate(jwtService), userController.GetMediaWithKey)
		routes.GET("/get/:path/KTP/:ownerid", middleware.Authenticate(jwtService), userController.GetKTP)
		routes.POST("/send/Request/:ownerid", middleware.Authenticate(jwtService), userController.SendRequest)
		routes.POST("/send/Acceptance/:requestid", middleware.Authenticate(jwtService), userController.SendAcceptanceEmail)
		routes.GET("/getAllMedia", middleware.Authenticate(jwtService), userController.GetAllMedia)
		routes.POST("/verify", userController.VerifyFiles)
		// Admin
		//routes.PATCH("/verify", middleware.Authenticate(jwtService), userController.UpdateStatusIsVerified)
	}

}
