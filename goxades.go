package xades

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	xmldsigPrefix string = "dsig"
	Prefix        string = "xades"
	Namespace     string = "http://uri.etsi.org/01903/v1.3.2#"
)

const (
	SignedPropertiesTag          string = "SignedProperties"
	SignedSignaturePropertiesTag string = "SignedSignatureProperties"
	SigningTimeTag               string = "SigningTime"
	SigningCertificateTag        string = "SigningCertificate"
	SignaturePolicyIdentifierTag string = "SignaturePolicyIdentifier"
	SignaturePolicyIdTag         string = "SignaturePolicyId"
	SigPolicyIdTag               string = "SigPolicyId"

	CertTag                 string = "Cert"
	IssuerSerialTag         string = "IssuerSerial"
	CertDigestTag           string = "CertDigest"
	QualifyingPropertiesTag string = "QualifyingProperties"
)

const (
	signedPropertiesAttr string = "SignedProperties"
	targetAttr           string = "Target"
)

var digestAlgorithmIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
}

var signatureMethodIdentifiers = map[crypto.Hash]string{
	crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	crypto.SHA256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	crypto.SHA512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
}

type SignaturePolicy struct {
	Identifier  string //
	Description string //
	Qualifier   string
}

type SigningContext struct {
	DataContext       SignedDataContext
	PropertiesContext SignedPropertiesContext
	Canonicalizer     dsig.Canonicalizer
	Hash              crypto.Hash
	KeyStore          MemoryX509KeyStore
	SignaturePolicy   SignaturePolicy
}

type SignedDataContext struct {
	Canonicalizer dsig.Canonicalizer
	Hash          crypto.Hash
	ReferenceURI  string
	IsEnveloped   bool
}

type SignedPropertiesContext struct {
	Canonicalizer dsig.Canonicalizer
	Hash          crypto.Hash
	SigninigTime  time.Time
}

//MemoryX509KeyStore struct
type MemoryX509KeyStore struct {
	PrivateKey *rsa.PrivateKey
	Cert       *x509.Certificate
	CertBinary []byte
}

//GetKeyPair func
func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.PrivateKey, ks.CertBinary, nil
}

//DigestValue calculate hash for digest
func DigestValue(element *etree.Element, canonicalizer *dsig.Canonicalizer, hash crypto.Hash) (base64encoded string, err error) {

	canonical, err := (*canonicalizer).Canonicalize(element)
	if err != nil {
		return
	}

	_hash := hash.New()
	_, err = _hash.Write(canonical)
	if err != nil {
		return "", err
	}

	base64encoded = base64.StdEncoding.EncodeToString(_hash.Sum(nil))
	return
}

//SignatureValue calculate signature
func SignatureValue(element *etree.Element, canonicalizer *dsig.Canonicalizer, hash crypto.Hash, keyStore *MemoryX509KeyStore) (base64encoded string, err error) {

	canonical, err := (*canonicalizer).Canonicalize(element)
	if err != nil {
		return
	}

	ctx := &dsig.SigningContext{
		Hash:     hash,
		KeyStore: keyStore,
	}
	buffer, err := ctx.SignString(string(canonical))
	if err != nil {
		return
	}
	base64encoded = base64.StdEncoding.EncodeToString(buffer)
	return
}

//CreateSignature create filled signature element
func CreateSignature(signedData *etree.Element, ctx *SigningContext) (*etree.Element, error) {

	//DigestValue of signedData
	digestData, err := DigestValue(signedData, &ctx.DataContext.Canonicalizer, ctx.DataContext.Hash)
	if err != nil {
		return nil, err
	}

	signingTime := ctx.PropertiesContext.SigninigTime
	if signingTime.IsZero() {
		signingTime = time.Now()
	}
	//DigestValue of signedProperties
	signedProperties := createSignedProperties(&ctx.KeyStore, signingTime, ctx)
	unsignedProperties := createUnSignedProperties(&ctx.KeyStore, signingTime, ctx)
	qualifiedSignedProperties := createQualifiedSignedProperties(signedProperties)

	digestProperties, err := DigestValue(qualifiedSignedProperties, &ctx.PropertiesContext.Canonicalizer, ctx.PropertiesContext.Hash)
	if err != nil {
		return nil, err
	}

	//SignatureValue
	signedInfo := createSignedInfo(string(digestData), string(digestProperties), ctx)
	qualifiedSignedInfo := createQualifiedSignedInfo(signedInfo)

	if err != nil {
		return nil, err
	}
	signatureValueText, err := SignatureValue(qualifiedSignedInfo, &ctx.Canonicalizer, ctx.Hash, &ctx.KeyStore)
	if err != nil {
		return nil, err
	}

	signatureValue := createSignatureValue(signatureValueText)
	keyInfo := createKeyInfo(base64.StdEncoding.EncodeToString(ctx.KeyStore.CertBinary))
	object := createObject(signedProperties, unsignedProperties)

	signature := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureTag,
		Attr: []etree.Attr{
			{Key: "Id", Value: "Signature"},
			{Key: "xmlns:" + xmldsigPrefix, Value: dsig.Namespace},
			//{Space: "xmlns", Key: xmldsigPrefix, Value: dsig.Namespace},
		},
		Child: []etree.Token{signedInfo, signatureValue, keyInfo, object},
	}
	return &signature, nil
}

func createQualifiedSignedInfo(signedInfo *etree.Element) *etree.Element {
	qualifiedSignedInfo := signedInfo.Copy()
	qualifiedSignedInfo.Attr = append(qualifiedSignedInfo.Attr, etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: dsig.Namespace})
	return qualifiedSignedInfo
}
func createSignedInfo(digestValueDataText string, digestValuePropertiesText string, ctx *SigningContext) *etree.Element {

	var transformEnvSign etree.Element
	if ctx.DataContext.IsEnveloped {
		transformEnvSign = etree.Element{
			Space: xmldsigPrefix,
			Tag:   dsig.TransformTag,
			Attr: []etree.Attr{
				{Key: dsig.AlgorithmAttr, Value: dsig.EnvelopedSignatureAltorithmId.String()},
			},
		}
	}

	transformData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: ctx.DataContext.Canonicalizer.Algorithm().String()}, // "http://www.w3.org/2001/10/xml-exc-c14n#"},
		},
	}

	transformProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: ctx.PropertiesContext.Canonicalizer.Algorithm().String()}, // "http://www.w3.org/2001/10/xml-exc-c14n#"},
		},
	}

	transformsData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformsTag,
	}
	if ctx.DataContext.IsEnveloped {
		transformsData.AddChild(&transformEnvSign)
	}
	transformsData.AddChild(&transformData)

	digestMethodData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: digestAlgorithmIdentifiers[ctx.DataContext.Hash]},
		},
	}

	digestMethodProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: digestAlgorithmIdentifiers[ctx.PropertiesContext.Hash]},
		},
	}

	digestValueData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestValueTag,
	}
	digestValueData.SetText(digestValueDataText)

	transformsProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.TransformsTag,
		Child: []etree.Token{&transformProperties},
	}

	digestValueProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestValueTag,
	}
	digestValueProperties.SetText(digestValuePropertiesText)

	canonicalizationMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.CanonicalizationMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: ctx.Canonicalizer.Algorithm().String()},
		},
	}

	signatureMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: signatureMethodIdentifiers[ctx.Hash]},
		},
	}

	referenceData := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.ReferenceTag,
		Attr: []etree.Attr{
			{Key: dsig.URIAttr, Value: ctx.DataContext.ReferenceURI},
		},
		Child: []etree.Token{&transformsData, &digestMethodData, &digestValueData},
	}

	referenceProperties := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.ReferenceTag,
		Attr: []etree.Attr{
			{Key: dsig.URIAttr, Value: "#SignedProperties"},
			{Key: "Type", Value: "http://uri.etsi.org/01903#SignedProperties"},
		},
		Child: []etree.Token{&transformsProperties, &digestMethodProperties, &digestValueProperties},
	}

	signedInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignedInfoTag,
		Child: []etree.Token{&canonicalizationMethod, &signatureMethod, &referenceData, &referenceProperties},
	}

	return &signedInfo
}

func createSignatureValue(base64Signature string) *etree.Element {
	signatureValue := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.SignatureValueTag,
	}
	signatureValue.SetText(base64Signature)
	return &signatureValue
}

func createKeyInfo(base64Certificate string) *etree.Element {

	x509Cerificate := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.X509CertificateTag,
	}
	x509Cerificate.SetText(base64Certificate)

	x509Data := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.X509DataTag,
		Child: []etree.Token{&x509Cerificate},
	}
	keyInfo := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.KeyInfoTag,
		Child: []etree.Token{&x509Data},
	}
	return &keyInfo
}

func createObject(signedProperties *etree.Element, unsignedProperties *etree.Element) *etree.Element {

	qualifyingProperties := etree.Element{
		Space: Prefix,
		Tag:   QualifyingPropertiesTag,
		Attr: []etree.Attr{
			{Space: "xmlns", Key: Prefix, Value: Namespace},
			{Key: targetAttr, Value: "#Signature"},
		},
		Child: []etree.Token{signedProperties, unsignedProperties},
	}
	object := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "Object",
		Child: []etree.Token{&qualifyingProperties},
	}
	return &object
}

func createQualifiedSignedProperties(signedProperties *etree.Element) *etree.Element {
	qualifiedSignedProperties := signedProperties.Copy()
	qualifiedSignedProperties.Attr = append(
		signedProperties.Attr,
		etree.Attr{Space: "xmlns", Key: xmldsigPrefix, Value: dsig.Namespace},
		etree.Attr{Space: "xmlns", Key: Prefix, Value: Namespace},
	)

	return qualifiedSignedProperties
}

func createUnSignedProperties(keystore *MemoryX509KeyStore, signTime time.Time, ctx *SigningContext) *etree.Element {
	/*<xades:UnsignedProperties>
		<xades:UnsignedSignatureProperties>
		   <xades:SignatureTimeStamp Id="TS-13bfbebf-77b6-4f68-b851-6aa563230fe1">
			  <dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			  <xades:EncapsulatedTimeStamp Id="ETS-13bfbebf-77b6-4f68-b851-6aa563230fe1">MIAGCSqGSIb3DQEHAqCAMIILzwIBAzENMAsGCWCGSAFlAwQCATCBrQYLKoZIhvcNAQkQAQSggZ0EgZowgZcCAQEGCisGAQQB8zmCLAEwLzALBglghkgBZQMEAgEEIB1Y7y6UHdCKEG6bbbRIlV9EhRAMxQN06WIiO6m3DmpUAhA/sUAjR+U1BmAK5zgwtGWVGA8yMDIxMDEyMjE0NTQ0OFowAwIBAQIQfOAtYFboyf1gCuc4lhurQaEbMBkGCCsGAQUFBwEDBA0wCzAJBgcEAIGXXgEBoIIHdzCCB3MwggVboAMCAQICEHauOWbguj6lV4inIdKVB24wDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMSAwHgYDVQQDDBdJemVucGUuY29tIC0gREVTQVJST0xMTzAeFw0xNjA3MTUwOTA0MzNaFw0yMTA3MTUwOTA0MzNaMGYxCzAJBgNVBAYTAkVTMRQwEgYDVQQKDAtJWkVOUEUgUy5BLjEYMBYGA1UEYQwPVkFURVMtQTAxMzM3MjYwMScwJQYDVQQDDB50c2FkZXMuaXplbnBlLmNvbSAtIERFU0FSUk9MTE8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC66jO8d10jTn7JPA2sHxZqctIiA3av7ZneNmUCOeJ10f7HeWYw5hlYmQ+BeXXBrQWrTwmJHI+AxSKkrTlu6Swhhojs2jaCfugd8eWcwquBHIbFVolPrCtNUI9LcVJVPqDFkbiKTfvPXfbs6mNgyDP3yOIvcOJdBPXykDZnNbtHZDF0J2wlxQ1370l6BIxwyngvPjdy/IB7utK9ZphpjPXd1B5muEgdjoj/b3YTTpqmBPCnXimyQ3GGP0alMq4L2S0QX80Gu9v2pl7mDWkGRL3DBvqvntsexl6OZZH9eSzZMCqw0XUyMNNWUTbc9OskW512blagvU3PyqZT4zHqdTfmmC1n27duvnJ0hFZyZuX/07AMfx267PlyJ3lK6beibNVp/Qh3Lty/Hwb8kVN4IJ+w0h5NPFL5ID1CfXnXjwuvy1wRWfI4z1Isa3SlDX5sx4hB8d/Oj6dJoUYOaZ0cjvrh2X6Mcda4+W9NprUWSowUHlSAWzaBqmWmpQAP5KKJeNK1Biim4ZELHCh46Rd4hYp3Fqe2NXT93TpvWd6LKi04F6ILZel5pviMsHRwxMDos2VTZNh1/yz2DQb70tNPeoweb7PNyPrAbYfTmLdsevs3dumRtGcSdEZCveZl9rZrtnu2R4JufbLsGkFa+z1KlSbyFwaP0KkiLMPW2nCzuwbhQQIDAQABo4ICPDCCAjgwgbAGA1UdEgSBqDCBpYEPaW5mb0BpemVucGUuY29tpIGRMIGOMUcwRQYDVQQKDD5JWkVOUEUgUy5BLiAtIENJRiBBMDEzMzcyNjAtUk1lcmMuVml0b3JpYS1HYXN0ZWl6IFQxMDU1IEY2MiBTODFDMEEGA1UECQw6QXZkYSBkZWwgTWVkaXRlcnJhbmVvIEV0b3JiaWRlYSAxNCAtIDAxMDEwIFZpdG9yaWEtR2FzdGVpejAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFFnuNB8USbWoJpB9xu04DMUSXJ9HMB8GA1UdIwQYMBaAFLO6Zcf9Q8Xb/IfZ9X/DnjSb+2tNMDoGCCsGAQUFBwELBC4wLDAqBggrBgEFBQcwA4YeaHR0cDovL3RzYWRlcy5pemVucGUuY29tOjgwOTMvMIGmBgNVHSAEgZ4wgZswgZgGCSsGAQQB8zlnAzCBijAlBggrBgEFBQcCARYZaHR0cDovL3d3dy5pemVucGUuY29tL2NwczBhBggrBgEFBQcCAjBVGlNCZXJtZWVuIG11Z2FrIGV6YWd1dHpla28gd3d3Lml6ZW5wZS5jb20gTGltaXRhY2lvbmVzIGRlIGdhcmFudGlhcyBlbiB3d3cuaXplbnBlLmNvbTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsZGVzLml6ZW5wZS5jb20vY2dpLWJpbi9hcmwyMA0GCSqGSIb3DQEBCwUAA4ICAQACCLLIdGK6vuWBn8llZa+1ICvg6pJdhK0StaNx26a5rk5wLP4i2Wu/0OCq+rxR0K2T4Ql1TqVRLPs53jGQeDjw0IpC1kRBGuJsG6sMFMu1hDqx2wIP/FRVChfad8VTW+4p0c9rWEERhPzzgXmmzyhSyqKsMnSwDMpSjcl2cGFSh/cMMkwzkatYn0uVI+UikwK6+GeeNWyyRQEzEi6oQoXu10og+CSUl5lUyP2GGUhCYQimksIuW00eTV817gqIwRelv9MGZXC8mbacy2GMnNQq3aou5MTOLPrx5zI2jJYm4KTUNlmqWCj1xdC+7gB0mgWkXZTaaaIFfpU1YmGtFg1G9uBoaj8ezzyZSQwmG6U6vMUwBL0mK5UZq/nprkDhQFV7wQUgfeDAcLD+S11xU8Xs233bDdJ2+eLlc97PWyyueRypdGyWU/qKYiXfPUNdb6FW959mG23IcEdu043OQVcdEty3xByfGIVv9oyavNzXE22iVwwYNA783J6Eo13K2s4vHkc8VM2njKascL2p22MZ5aeahIn3g+shgVh5n5hsuYyV3GMxTRIERWpQKUF2sJpi8O7P9mz+2a7H1YrRGSpU2zuE46K8XD3ZhLYN9c41KaWU8xsqrLKYXel3rP3u3V0b7SP6vdncRoFoh85L9Guf6wycBYAZhwJXSA9WVirfGTGCA44wggOKAgEBMFkwRTELMAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMSAwHgYDVQQDDBdJemVucGUuY29tIC0gREVTQVJST0xMTwIQdq45ZuC6PqVXiKch0pUHbjALBglghkgBZQMEAgGgggEIMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjEwMTIyMTQ1NDQ4WjAvBgkqhkiG9w0BCQQxIgQg1+GZIqog6Czq9ULt9irdbkGlrBNf4xaHW9hJE9JvKQowgZoGCyqGSIb3DQEJEAIvMYGKMIGHMIGEMIGBBCBaOeDl+9TpSyUIodossJ1CQ7UYHK4/PZjPhopTsYpKBTBdMEmkRzBFMQswCQYDVQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xIDAeBgNVBAMMF0l6ZW5wZS5jb20gLSBERVNBUlJPTExPAhB2rjlm4Lo+pVeIpyHSlQduMA0GCSqGSIb3DQEBAQUABIICAI5WRsb2lOAKW73tdtWfp7ic0UHe41AeuS2DwklXl0+7vadEiVxJnM2VCw5TxAyhfNxgCUp2asY95Kk3IqYk+L6DPyPfTPpLSBL/u47ZiU4B0QMukSuwJAh/SMLuBvUEXo4LFJlXOa7fKVBMk930Ld+lDy6YppaUJ6quKlojAFpsexN6srT7xh6UCNp/Tj+9yF2uNMvjRBtSeOQdB366IG38oP+HW1DyfBBx+FGcx7pxjQh1yKFadPhR6awM3hbgvQauGyqnB+BdKEnj3hxW1JIDDj292HUCk5Ka6V5RVJ1fG4uY8lfoWoUYf4RYjvJCVgNU2xEf2+4kH3c6JWp1Xx9ZWsD24HVLh0oKEJ84+IjWff3vmgKVGILmtGQ3BziSS6Vnkb9xEo7a9tjXg9hMomG9O1qlKSswRjromqzsI5nd4Sn9WL5Y4ZERLmI+tduZhEZDDrsjiNS8NbhhjoaffTNaBs0ht8faszdTeHY7FP2Tu86zcp7wBsXZTLP3wYiqmCcTGnpDLla1rb4cvm2Pd/0654AmHJrF5BD2LLLIMUDmUpAro7QgOaoxdIRMd/die0jx2/HVuvKernap0uNQA3sl7rtYs8sXJSXpTNfLh+RlVksIB+WF04/bMeDnWD4W12KWcjN3GcJFu/khVlTYO+ejDNa9uej0DVlh/V2N0LOLAAAAAA==</xades:EncapsulatedTimeStamp>
		   </xades:SignatureTimeStamp>
		</xades:UnsignedSignatureProperties>
	</xades:UnsignedProperties>*/

	canonicalizationMethodTag := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "CanonicalizationMethod",
		Attr: []etree.Attr{
			{Key: "Algorithm", Value: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		},
	}
	encapsulatedTimeStampTag := etree.Element{
		Space: Prefix,
		Tag:   "EncapsulatedTimeStamp",
		Attr: []etree.Attr{
			{Key: "Id", Value: "EncapsulatedSignatureTimeStamp"},
		},
	}
	encapsulatedTimeStampTag.SetText("hash") //TODO

	signatureTimeStampTag := etree.Element{
		Space: Prefix,
		Tag:   "SignatureTimeStamp",
		Attr: []etree.Attr{
			{Key: "Id", Value: "SignatureTimeStamp"},
		},
		Child: []etree.Token{&canonicalizationMethodTag, &encapsulatedTimeStampTag},
	}

	unsignedSignaturePropertiesTag := etree.Element{
		Space: Prefix,
		Tag:   "UnsignedSignatureProperties",
		Child: []etree.Token{&signatureTimeStampTag},
	}

	unsignedPropertiesTag := etree.Element{
		Space: Prefix,
		Tag:   "UnsignedProperties",
		Child: []etree.Token{&unsignedSignaturePropertiesTag},
	}
	return &unsignedPropertiesTag
}

func createSignedProperties(keystore *MemoryX509KeyStore, signTime time.Time, ctx *SigningContext) *etree.Element {

	digestMethod := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestMethodTag,
		Attr: []etree.Attr{
			{Key: dsig.AlgorithmAttr, Value: digestAlgorithmIdentifiers[crypto.SHA1]},
		},
	}

	digestValue := etree.Element{
		Space: xmldsigPrefix,
		Tag:   dsig.DigestValueTag,
	}
	hash := sha1.Sum(keystore.CertBinary)
	digestValue.SetText(base64.StdEncoding.EncodeToString(hash[0:]))

	certDigest := etree.Element{
		Space: Prefix,
		Tag:   CertDigestTag,
		Child: []etree.Token{&digestMethod, &digestValue},
	}

	x509IssuerName := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "X509IssuerName",
	}
	x509IssuerName.SetText(keystore.Cert.Issuer.String())
	x509SerialNumber := etree.Element{
		Space: xmldsigPrefix,
		Tag:   "X509SerialNumber",
	}
	x509SerialNumber.SetText(keystore.Cert.SerialNumber.String())

	issuerSerial := etree.Element{
		Space: Prefix,
		Tag:   IssuerSerialTag,
		Child: []etree.Token{&x509IssuerName, &x509SerialNumber},
	}

	cert := etree.Element{
		Space: Prefix,
		Tag:   CertTag,
		Child: []etree.Token{&certDigest, &issuerSerial},
	}

	signingCertificate := etree.Element{
		Space: Prefix,
		Tag:   SigningCertificateTag,
		Child: []etree.Token{&cert},
	}

	sigPolicyIdIdentifierTag := etree.Element{
		Space: Prefix,
		Tag:   "Identifier",
	}
	sigPolicyIdIdentifierTag.SetText(ctx.SignaturePolicy.Identifier)
	sigPolicyIdDescriptionTag := etree.Element{
		Space: Prefix,
		Tag:   "Description",
	}
	sigPolicyIdDescriptionTag.SetText(ctx.SignaturePolicy.Description)

	sigPolicyIdTag := etree.Element{
		Space: Prefix,
		Tag:   SigPolicyIdTag,
		Child: []etree.Token{&sigPolicyIdIdentifierTag, &sigPolicyIdDescriptionTag},
	}

	sigPolicyHashMethodTag := etree.Element{
		Space: "dsig",
		Tag:   "DigestMethod",
	}
	sigPolicyHashMethodTag.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

	sigPolicyHashValueTag := etree.Element{
		Space: "dsig",
		Tag:   "DigestValue",
	}
	sigPolicyHashValueTag.SetText("hash") // TODO calc hash

	sigPolicyHashTag := etree.Element{
		Space: Prefix,
		Tag:   "SigPolicyHash",
		Child: []etree.Token{&sigPolicyHashMethodTag, &sigPolicyHashValueTag},
	}

	sigPolicyQualifierSPURITag := etree.Element{
		Space: Prefix,
		Tag:   "SPURI",
	}
	sigPolicyQualifierSPURITag.SetText(ctx.SignaturePolicy.Qualifier)

	sigPolicyQualifierTag := etree.Element{
		Space: Prefix,
		Tag:   "SigPolicyQualifier",
		Child: []etree.Token{&sigPolicyQualifierSPURITag},
	}

	sigPolicyQualifiersTag := etree.Element{
		Space: Prefix,
		Tag:   "SigPolicyQualifiers",
		Child: []etree.Token{&sigPolicyQualifierTag},
	}

	signaturePolicyIdTag := etree.Element{
		Space: Prefix,
		Tag:   SignaturePolicyIdTag,
		Child: []etree.Token{&sigPolicyIdTag, &sigPolicyHashTag, &sigPolicyQualifiersTag}, // TODO change ! add policyhash
	}

	signaturePolicyIdentifier := etree.Element{
		Space: Prefix,
		Tag:   SignaturePolicyIdentifierTag,
		Child: []etree.Token{&signaturePolicyIdTag},
	}

	signingTime := etree.Element{
		Space: Prefix,
		Tag:   SigningTimeTag,
	}
	signingTime.SetText(signTime.Format("2006-01-02T15:04:05Z"))

	var signedSignatureProperties etree.Element

	if ctx.SignaturePolicy.Identifier == "" {
		signedSignatureProperties = etree.Element{
			Space: Prefix,
			Tag:   SignedSignaturePropertiesTag,
			Child: []etree.Token{&signingTime, &signingCertificate},
		}
	} else {
		signedSignatureProperties = etree.Element{
			Space: Prefix,
			Tag:   SignedSignaturePropertiesTag,
			Child: []etree.Token{&signingTime, &signingCertificate, &signaturePolicyIdentifier},
		}
	}

	var signedProperties etree.Element

	if ctx.DataContext.ReferenceURI != "" {
		mimeTypeTag := etree.Element{
			Space: Prefix,
			Tag:   "MimeType",
		}
		mimeTypeTag.SetText("application/octet-stream")

		dataObjectFormatTag := etree.Element{
			Space: Prefix,
			Tag:   "DataObjectFormat",
			Attr: []etree.Attr{
				{Key: "ObjectReference", Value: ctx.DataContext.ReferenceURI},
			},
			Child: []etree.Token{&mimeTypeTag},
		}

		signedDataObjectPropertiesTag := etree.Element{
			Space: Prefix,
			Tag:   "SignedDataObjectProperties",
			Child: []etree.Token{&dataObjectFormatTag},
		}

		signedProperties = etree.Element{
			Space: Prefix,
			Tag:   SignedPropertiesTag,
			Attr: []etree.Attr{
				{Key: "Id", Value: "SignedProperties"},
			},
			Child: []etree.Token{&signedSignatureProperties, &signedDataObjectPropertiesTag},
		}
	} else {
		signedProperties = etree.Element{
			Space: Prefix,
			Tag:   SignedPropertiesTag,
			Attr: []etree.Attr{
				{Key: "Id", Value: "SignedProperties"},
			},
			Child: []etree.Token{&signedSignatureProperties},
		}
	}

	return &signedProperties
}
