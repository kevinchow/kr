package kr

import (
	"bufio"
	"os"
)

const NOTIFY_LOG_FILE_NAME = "krd-notify.log"

type Notifier struct {
	*os.File
}

func OpenNotifier() (n Notifier, err error) {
	filePath, err := KrDirFile(NOTIFY_LOG_FILE_NAME)
	if err != nil {
		return
	}
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return
	}
	n = Notifier{file}
	return
}

func (n Notifier) Notify(body []byte) (err error) {
	_, err = n.Write(body)
	if err != nil {
		return
	}
	err = n.Sync()
	return
}

type NotificationReader struct {
	*os.File
	lineReader *bufio.Reader
}

func OpenNotificationReader() (r NotificationReader, err error) {
	filePath, err := KrDirFile(NOTIFY_LOG_FILE_NAME)
	if err != nil {
		return
	}
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_APPEND|os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	r = NotificationReader{
		File:       file,
		lineReader: bufio.NewReader(file),
	}
	return
}

func (r NotificationReader) Read() (body []byte, err error) {
	return r.lineReader.ReadBytes('\n')
}
