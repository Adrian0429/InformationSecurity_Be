package controller

import (
	"os"

	"github.com/Caknoooo/golang-clean_template/dto"
	"github.com/Caknoooo/golang-clean_template/services"
	"github.com/gin-gonic/gin"
)

type (
	MediaController interface {
		Upload(ctx *gin.Context)
		GetMedia(ctx *gin.Context)
	}

	mediaController struct {
		mediaService services.MediaService
	}
)

const PATH = "storage/"

func NewMediaController(ms services.MediaService) MediaController {
	return &mediaController{
		mediaService: ms,
	}
}

func (mc *mediaController) Upload(ctx *gin.Context) {
	file, err := ctx.FormFile("media")
	if err != nil {
		ctx.JSON(400, gin.H{
			"message": err.Error(),
		})
		return
	}

	req := dto.MediaRequest{
		Media: file,
	}

	res, err := mc.mediaService.Upload(ctx, req)

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

func (mc *mediaController) GetMedia(ctx *gin.Context) {
	id := ctx.Param("id")

	mediaPath := PATH + id

	_, err := os.Stat(mediaPath)
	if os.IsNotExist(err) {
		ctx.JSON(400, gin.H{
			"message": "image not found",
		})
		return
	}

	ctx.File(mediaPath)
}
