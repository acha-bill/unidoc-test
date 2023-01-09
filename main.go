package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"image"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/unidoc/unipdf/v3/annotator"
	"github.com/unidoc/unipdf/v3/common/license"
	"github.com/unidoc/unipdf/v3/core"
	"github.com/unidoc/unipdf/v3/model"
)

var LicenseCustomerName = ""
var LicenseKey = ""

func LoadUniPDFLicense() error {
	if LicenseKey == "" {
		LicenseKey = os.Getenv("UNIPDF_LICENSE_KEY")
	}
	if LicenseCustomerName == "" {
		LicenseCustomerName = os.Getenv("UNIPDF_CUSTOMER_NAME")
	}
	// Replace \n string with new lines
	LicenseKey = strings.Replace(LicenseKey, `\n`, "\n", -1)

	err := license.SetLicenseKey(LicenseKey, LicenseCustomerName)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	if err := LoadUniPDFLicense(); err != nil {
		log.Fatalln(err)
	}
	if err := sign(); err != nil {
		log.Fatalln(err)
	}
}

type signatureHandler struct {
	sign func(hash string) ([]byte, error)
}

func newSignatureHandler(sign func(hash string) ([]byte, error)) *signatureHandler {
	return &signatureHandler{
		sign: sign,
	}
}

func (t *signatureHandler) IsApplicable(sig *model.PdfSignature) bool {
	return true
}

func (t *signatureHandler) Validate(sig *model.PdfSignature, digest model.Hasher) (model.SignatureValidationResult, error) {
	return model.SignatureValidationResult{
		IsSigned:   true,
		IsVerified: true,
	}, nil
}

func (t *signatureHandler) InitSignature(sig *model.PdfSignature) error {
	return nil
}

func (t *signatureHandler) NewDigest(sig *model.PdfSignature) (model.Hasher, error) {
	return sha512.New(), nil
}

func (t *signatureHandler) Sign(sig *model.PdfSignature, hasher model.Hasher) error {
	h := hasher.(hash.Hash)
	digest := hex.EncodeToString(h.Sum(nil))
	signature, err := t.sign(digest)
	if err != nil {
		return err
	}
	data := make([]byte, len(signature))
	copy(data, signature)
	sig.Contents = core.MakeHexString(string(data))
	return nil
}

func sign() error {
	f, err := os.Open("./input.pdf")
	if err != nil {
		return err
	}

	defer f.Close()

	pdfReader, err := model.NewPdfReader(f)
	if err != nil {
		return err
	}
	now := time.Now()
	handler := newSignatureHandler(func(hash string) ([]byte, error) {
		return nil, nil
	})
	signature := model.NewPdfSignature(handler)
	signature.SetDate(now, "")

	file, err := os.Open("./signature.png")
	if err != nil {
		return err
	}
	defer file.Close()
	sigImage, _, err := image.Decode(file)
	if err != nil {
		return err
	}
	imgEncoder := core.NewFlateEncoder()
	sigFieldOpts := annotator.NewSignatureFieldOpts()
	sigFieldOpts.Rect = []float64{10, 25, 110, 75}
	sigFieldOpts.WatermarkImage = sigImage
	sigFieldOpts.Encoder = imgEncoder

	sigField, err := annotator.NewSignatureField(signature, nil, sigFieldOpts)
	if err != nil {
		return err
	}
	sigField.T = core.MakeString("signature")

	pdfAppender, err := model.NewPdfAppender(pdfReader)
	if err != nil {
		return err
	}

	if err = pdfAppender.Sign(2, sigField); err != nil {
		return err
	}

	buffer := bytes.NewBuffer(nil)
	if err = pdfAppender.Write(buffer); err != nil {
		return err
	}

	outputFile, err := os.Create("./output.pdf")
	if err != nil {
		return fmt.Errorf("couldn't create output file: %s", err)
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, bytes.NewReader(buffer.Bytes()))
	if err != nil {
		return fmt.Errorf("couldn't copy document buffer to output file: %s", err)
	}

	return nil
}
