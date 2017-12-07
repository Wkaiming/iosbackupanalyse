package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	backupPath string
	destPath   string
)

func init() {
	b := flag.String("b", "default backup path", "backup path")
	d := flag.String("d", "default dest path", "dest path")
	flag.Parse()
	backupPath = *b
	destPath = *d
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println(`commands:
	-b    backup file path .
	-d    file path  after analyse`)
		return
	}
	mbdbPath := filepath.Join(backupPath, "Manifest.mbdb")
	_, err := os.Stat(mbdbPath)
	if err != nil && os.IsNotExist(err) {
		fmt.Println(err)
		return
	}
	fp, err := os.OpenFile(mbdbPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer fp.Close()
	fp.Seek(6, 0)
	var domain, path string
	for {
		domain = ""
		path = ""
		//mbdb analyse
		for i := 0; i < 5; i++ {
			bys := make([]byte, 2)
			_, err := fp.Read(bys)
			if err == io.EOF && err != nil {
				return
			}
			if bys[0] != 0xFF && bys[1] != 0xFF {
				counts := uint16(bys[0])*0x100 + uint16(bys[1])
				if i == 0 || i == 1 {
					byss := make([]byte, counts)
					fp.Read(byss)
					if i == 0 {
						domain = string(byss)
					} else if i == 1 {
						path = string(byss)
					}
				} else {
					fp.Seek(int64(counts), os.SEEK_CUR)
				}
			}
		}
		fp.Seek(39, os.SEEK_CUR)
		by1 := make([]byte, 1)
		fp.Read(by1)
		if by1[0] != 0 {
			for k := 0; k < int(by1[0])*2; k++ {
				by3 := make([]byte, 2)
				fp.Read(by3)
				if by3[0] != 0xFF && by3[1] != 0xFF {
					counts := uint16(by3[0])*0x100 + uint16(by3[1])
					fp.Seek(int64(counts), os.SEEK_CUR)
				}
			}
		}
		copyFile(domain, path)
	}
	return
}

func sha1s(s string) string {
	r := sha1.Sum([]byte(s))
	return hex.EncodeToString(r[:])
}

func copyFile(domain, path string) {
	sha1 := sha1s(domain + "-" + path)
	dest := filepath.Join(destPath, domain, path)
	src := filepath.Join(backupPath, sha1)
	fmt.Println(src, "     ", dest)
	sha1Path := filepath.Join(backupPath, sha1)
	_, err := os.Stat(sha1Path)
	if err != nil {
		err = os.MkdirAll(dest, os.ModePerm)
		if err != nil {
			fmt.Println(err)
		}
		return
	}
	destP, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err == nil {
		srcP, err := os.Open(src)
		if err == nil {
			io.Copy(destP, srcP)
			srcP.Close()
		}
		destP.Close()
	}
	return
}
