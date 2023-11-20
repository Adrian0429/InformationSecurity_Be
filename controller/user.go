package controller

import (
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Caknoooo/golang-clean_template/dto"
	"github.com/Caknoooo/golang-clean_template/entities"
	"github.com/Caknoooo/golang-clean_template/services"
	"github.com/Caknoooo/golang-clean_template/utils"
	"github.com/gin-gonic/gin"
)

type UserController interface {
	SendRequest(ctx *gin.Context)
	SendAcceptanceEmail(ctx *gin.Context)

	RegisterUser(ctx *gin.Context)
	GetAllUser(ctx *gin.Context)
	MeUser(ctx *gin.Context)
	UpdateStatusIsVerified(ctx *gin.Context)
	LoginUser(ctx *gin.Context)
	UpdateUser(ctx *gin.Context)
	DeleteUser(ctx *gin.Context)

	Upload(ctx *gin.Context)
	GetMedia(ctx *gin.Context)
	GetAllMedia(ctx *gin.Context)
	GetKTP(ctx *gin.Context)
}

type userController struct {
	jwtService  services.JWTService
	userService services.UserService
}

func NewUserController(us services.UserService, jwt services.JWTService) UserController {
	return &userController{
		jwtService:  jwt,
		userService: us,
	}
}

const PATH = "storage"

func (c *userController) RegisterUser(ctx *gin.Context) {
	var user dto.UserCreateRequest
	if err := ctx.ShouldBind(&user); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	file, err := ctx.FormFile("KTP")
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_FILE, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	user.KTP = file

	result, err := c.userService.RegisterUser(ctx.Request.Context(), user)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_REGISTER_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_REGISTER_USER, result)
	ctx.JSON(http.StatusOK, res)
}

func (c *userController) GetAllUser(ctx *gin.Context) {
	result, err := c.userService.GetAllUser(ctx.Request.Context())
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_LIST_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_GET_LIST_USER, result)
	ctx.JSON(http.StatusOK, res)
}

func (c *userController) UpdateStatusIsVerified(ctx *gin.Context) {
	token := ctx.MustGet("token").(string)
	adminId, err := c.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	var req dto.UpdateStatusIsVerifiedRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	result, err := c.userService.UpdateStatusIsVerified(ctx.Request.Context(), req, adminId)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_UPDATE_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_UPDATE_USER, result)
	ctx.JSON(http.StatusOK, res)
}

func (c *userController) MeUser(ctx *gin.Context) {
	token := ctx.MustGet("token").(string)
	userId, err := c.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	result, err := c.userService.GetUserById(ctx.Request.Context(), userId)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_GET_USER, result)
	ctx.JSON(http.StatusOK, res)
}

func (c *userController) LoginUser(ctx *gin.Context) {
	var req dto.UserLoginRequest
	if err := ctx.ShouldBind(&req); err != nil {
		response := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, response)
		return
	}

	res, err := c.userService.Verify(ctx.Request.Context(), req.Email, req.Password)
	if err != nil && !res {
		response := utils.BuildResponseFailed(dto.MESSAGE_FAILED_LOGIN, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, response)
		return
	}

	user, err := c.userService.GetUserByEmail(ctx.Request.Context(), req.Email)
	if err != nil {
		response := utils.BuildResponseFailed(dto.MESSAGE_FAILED_LOGIN, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, response)
		return
	}

	token := c.jwtService.GenerateToken(user.ID, user.Role)
	userResponse := entities.Authorization{
		Token: token,
		Role:  user.Role,
	}

	response := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_LOGIN, userResponse)
	ctx.JSON(http.StatusOK, response)
}

func (c *userController) UpdateUser(ctx *gin.Context) {
	var req dto.UserUpdateRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	token := ctx.MustGet("token").(string)
	userId, err := c.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	if err = c.userService.UpdateUser(ctx.Request.Context(), req, userId); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_UPDATE_USER, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_UPDATE_USER, nil)
	ctx.JSON(http.StatusOK, res)
}

func (c *userController) DeleteUser(ctx *gin.Context) {
	token := ctx.MustGet("token").(string)
	userID, err := c.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	if err = c.userService.DeleteUser(ctx.Request.Context(), userID); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_DELETE_USER, err.Error(), utils.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_DELETE_USER, nil)
	ctx.JSON(http.StatusOK, res)
}

func (c *userController) Upload(ctx *gin.Context) {
	token := ctx.MustGet("token").(string)
	method := ctx.Param("method")
	userId, err := c.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	file, err := ctx.FormFile("media")
	if err != nil {
		ctx.JSON(400, gin.H{
			"message": err.Error(),
		})
		return
	}

	aes, err := c.userService.GetAESNeeds(ctx.Request.Context(), userId)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	req := dto.MediaRequest{
		Media:  file,
		UserID: userId,
	}

	res, err := c.userService.Upload(ctx, req, aes, method)

	if err != nil {
		ctx.JSON(400, gin.H{
			"message": err.Error(),
		})
		return
	}
	ctx.JSON(200, gin.H{
		"message": "success",
		"data":    res,
	})

}

func (mc *userController) GetMedia(ctx *gin.Context) {
	path := ctx.Param("path")
	id := ctx.Param("id")
	OwnerUserId := ctx.Param("ownerid")
	method := ctx.Param("method")

	mediaPath := path + "/" + OwnerUserId + "/" + id

	_, err := os.Stat(mediaPath)
	if os.IsNotExist(err) {
		ctx.JSON(400, gin.H{
			"message": "media not found",
		})
		return
	}

	token := ctx.MustGet("token").(string)
	userId, err := mc.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	} else if userId != OwnerUserId {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_AUTHENTIFICATION, dto.MESSAGE_FAILED_AUTHENTIFICATION, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	aes, err := mc.userService.GetAESNeeds(ctx.Request.Context(), userId)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	decryptedData, TotalTime, err := utils.DecryptData(mediaPath, aes, method)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_DECRYPT, dto.MESSAGE_FAILED_DECRYPT, nil)
		ctx.AbortWithStatusJSON(http.StatusPreconditionFailed, res)
		return
	}

	// Determine the content type based on the file extension
	contentType := mime.TypeByExtension(filepath.Ext(mediaPath))
	if contentType == "" {
		contentType = "application/octet-stream" // Default to binary data if the content type is unknown
	}

	ctx.Header("Access-Control-Expose-Headers", "Time")
	ctx.Header("Time", TotalTime)
	ctx.Data(http.StatusOK, contentType, []byte(decryptedData))
}

func (mc *userController) GetKTP(ctx *gin.Context) {
	path := ctx.Param("path")
	filename := ctx.Param("ownerid")

	OwnerUserId := filename[:len(filename)-len(filepath.Ext(filename))]

	mediaPath := path + "/" + "KTP" + "/" + filename

	_, err := os.Stat(mediaPath)
	if os.IsNotExist(err) {
		ctx.JSON(400, gin.H{
			"message": "media not found",
		})
		return
	}

	token := ctx.MustGet("token").(string)
	userId, err := mc.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	} else if userId != OwnerUserId {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_AUTHENTIFICATION, dto.MESSAGE_FAILED_AUTHENTIFICATION, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	aes, err := mc.userService.GetAESNeeds(ctx.Request.Context(), userId)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	decryptedData, TotalTime, err := utils.DecryptData(mediaPath, aes, "AES")
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_DECRYPT, dto.MESSAGE_FAILED_DECRYPT, nil)
		ctx.AbortWithStatusJSON(http.StatusPreconditionFailed, res)
		return
	}

	// Determine the content type based on the file extension
	contentType := mime.TypeByExtension(filepath.Ext(mediaPath))
	if contentType == "" {
		contentType = "application/octet-stream" // Default to binary data if the content type is unknown
	}

	ctx.Header("Access-Control-Expose-Headers", "Time")
	ctx.Header("Time", TotalTime)
	ctx.Header("Content-Type", contentType)
	ctx.Writer.Write([]byte(decryptedData))
}

func (uc *userController) GetAllMedia(ctx *gin.Context) {
	result, err := uc.userService.GetAllMedia(ctx.Request.Context())

	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_LIST_MEDIA, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_GET_LIST_MEDIA, result)
	ctx.JSON(http.StatusOK, res)
}

func (uc *userController) SendRequest(ctx *gin.Context) {
	token := ctx.MustGet("token").(string)
	userID, err := uc.jwtService.GetUserIDByToken(token)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	requester, err := uc.userService.GetUserById(ctx.Request.Context(), userID)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	ownerId := ctx.Param("ownerid")
	owner, err := uc.userService.GetRequestInfo(ctx.Request.Context(), ownerId)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	utils.SendRequestEmail(owner, requester)
}

func (uc *userController) SendAcceptanceEmail(ctx *gin.Context) {
	requesterID := ctx.Param("requestid")
	ownerToken := ctx.MustGet("token").(string)

	ownerID, err := uc.jwtService.GetUserIDByToken(ownerToken)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER_TOKEN, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	ownerKeys, err := uc.userService.GetAESNeeds(ctx.Request.Context(), ownerID)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, dto.MESSAGE_FAILED_GET_SYMMETRIC_KEY, nil)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return
	}

	requester, err := uc.userService.GetUserById(ctx.Request.Context(), requesterID)
	if err != nil && requester.PublicKey != "" {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	keys, err := utils.EncryptRCA([]byte(ownerKeys.SymmetricKey), requester.PublicKey)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_ENCRYPT, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	iv, err := utils.EncryptRCA([]byte(ownerKeys.SymmetricKey), requester.PublicKey)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_ENCRYPT, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	var result dto.EncryptRequest
	result.IV = string(iv)
	result.SymmetricKey = string(keys)

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_GET_LIST_MEDIA, result)
	ctx.JSON(http.StatusOK, res)
	//utils.SendAcceptanceEmail(requester, string(keys), string(iv))
}
