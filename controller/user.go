package controller

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

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
	GetMediaWithKey(ctx *gin.Context)
	GetAllMedia(ctx *gin.Context)
	GetKTP(ctx *gin.Context)

	VerifyFiles(ctx *gin.Context)
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
	meUser := dto.MeUser{
		ID:        result.ID,
		Name:      result.Name,
		Email:     result.Email,
		PublicKey: result.PublicKey,
		Role:      result.Role,
		KTP:       result.KTP,
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_GET_USER, meUser)
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
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_DECRYPT, dto.MESSAGE_FAILED_DECRYPT, err)
		ctx.AbortWithStatusJSON(http.StatusPreconditionFailed, res)
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(mediaPath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	ctx.Header("Access-Control-Expose-Headers", "Time")
	ctx.Header("Time", TotalTime)
	ctx.Data(http.StatusOK, contentType, []byte(decryptedData))

}

func (mc *userController) GetMediaWithKey(ctx *gin.Context) {
	path := ctx.Param("path")
	id := ctx.Param("id")
	OwnerUserId := ctx.Param("ownerid")
	method := ctx.Param("method")
	key := ctx.GetHeader("key")
	iv := ctx.GetHeader("initial")
	mediaPath := path + "/" + OwnerUserId + "/" + id
	if key == "" || iv == "" {
		res := utils.BuildResponseFailed("no key or iv", "no key or iv", nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

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
	}

	requester, err := mc.userService.GetUserById(ctx.Request.Context(), userId)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_USER, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	decodedIV, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		fmt.Printf("Error decoding IV: %v\n", err)
		res := utils.BuildResponseFailed("decoding IV error", err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	decodedkey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		fmt.Printf("Error decoding key: %v\n", err)
		res := utils.BuildResponseFailed("decoding key error", err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	Deckeys, err, mes := utils.DecryptRCA([]byte(decodedkey), requester.PrivateKey)
	if err != nil {
		res := utils.BuildResponseFailed(mes, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	Deciv, err, mes := utils.DecryptRCA([]byte(decodedIV), requester.PrivateKey)
	if err != nil {
		res := utils.BuildResponseFailed(mes, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	var aes dto.EncryptRequest
	aes.IV = string(Deciv)
	aes.SymmetricKey = string(Deckeys)

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
	if err != nil {
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

	iv, err := utils.EncryptRCA([]byte(ownerKeys.IV), requester.PublicKey)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_ENCRYPT, err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	stringkey := base64.StdEncoding.EncodeToString([]byte(keys))
	stringiv := base64.StdEncoding.EncodeToString([]byte(iv))

	utils.SendAcceptanceEmail(requester, stringkey, stringiv)

}

func (uc *userController) VerifyFiles(ctx *gin.Context) {
	publicKey := ctx.Param("publicKey")
	file, err := ctx.FormFile("file")
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Error retrieving FormFile",
		})
		return
	}

	fileData, err := file.Open()
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Error opening file",
		})
		return
	}

	fileContent, err := ioutil.ReadAll(fileData)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Error reading file data",
		})
		return
	}

	signatureRegex := regexp.MustCompile(`/Author \(([^)]+)\) /Signature <([^>]+)>`)
	matches := signatureRegex.FindStringSubmatch(string(fileContent))
	var author, encryptedSignature string
	if len(matches) >= 3 {
		author = matches[1]
		encryptedSignature = matches[2]

	} else {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Error retrieving signature / The signature is not from us",
		})
		return
	}

	fileContent = signatureRegex.ReplaceAll(fileContent, []byte{})
	HashedPdf, err := utils.HashString(fileContent)
	byteOGSignature, err := base64.StdEncoding.DecodeString(encryptedSignature)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Error decoding signature",
		})
		return
	}

	err = utils.VerifyWithPublic([]byte(HashedPdf), byteOGSignature, publicKey)
	if err != nil {
		res := utils.BuildResponseFailed("error validating, the Digital Signature Didn't Match !!!", err.Error(), utils.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	result := dto.DigitalSignatureVerified{
		Name:      author,
		HashedPdf: HashedPdf,
	}

	res := utils.BuildResponseSuccess("Digital Signature Matched !!!", result)
	ctx.JSON(http.StatusOK, res)
}
