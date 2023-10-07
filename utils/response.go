package utils

type Response struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Error   any    `json:"error"`
	Data    any    `json:"data"`
}

type ResponseGetMedia struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}
type EmptyObj struct{}

func GetMediaSuccess(message string) ResponseGetMedia {
	res := ResponseGetMedia{
		Status:  true,
		Message: message,
	}
	return res
}
func BuildResponseSuccess(message string, data any) Response {
	res := Response{
		Status:  true,
		Message: message,
		Data:    data,
	}
	return res
}

func BuildResponseFailed(message string, err string, data any) Response {
	res := Response{
		Status:  false,
		Message: message,
		Error:   err,
		Data:    data,
	}
	return res
}
