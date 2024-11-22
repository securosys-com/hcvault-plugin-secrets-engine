/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.
*/

package helpers

// CONSTS
var UPDATE_POLICY_ON = []string{"Block", "UnBlock", "Modify"}

var SUPPORTED_KEY_TYPES = []string{"EC", "ED", "RSA", "DSA", "BLS", "AES", "ChaCha20", "Camellia", "TDEA"}
var SYMMETRIC_KEY_TYPES = []string{"AES", "Camellia", "ChaCha20", "TDEA"}
var ASYMMETRIC_KEY_TYPES = []string{"EC", "ED", "RSA", "DSA", "BLS"}

var RSA_CIPHER_LIST = []string{"RSA_PADDING_OAEP_WITH_SHA512", "RSA", "RSA_PADDING_OAEP_WITH_SHA224", "RSA_PADDING_OAEP_WITH_SHA256", "RSA_PADDING_OAEP_WITH_SHA1", "RSA_PADDING_OAEP", "RSA_PADDING_OAEP_WITH_SHA384", "RSA_NO_PADDING"}
var AES_CIPHER_LIST = []string{"AES_GCM", "AES_CTR", "AES_ECB", "AES_CBC_NO_PADDING", "AES"}
var CHACHA20_CIPHER_LIST = []string{"CHACHA20", "CHACHA20_AEAD"}
var CAMELIA_CIPHER_LIST = []string{"CAMELLIA", "CAMELLIA_CBC_NO_PADDING", "CAMELLIA_ECB"}
var TDEA_CIPHER_LIST = []string{"TDEA_CBC", "TDEA_ECB", "TDEA_CBC_NO_PADDING"}

var AES_WRAP_METHODS_LIST = []string{"AES_WRAP", "AES_WRAP_DSA", "AES_WRAP_EC", "AES_WRAP_ED", "AES_WRAP_RSA", "AES_WRAP_BLS", "AES_WRAP_PAD", "AES_WRAP_PAD_DSA", "AES_WRAP_PAD_EC", "AES_WRAP_PAD_ED", "AES_WRAP_PAD_RSA", "AES_WRAP_PAD_BLS"}
var RSA_WRAP_METHODS_LIST = []string{"RSA_WRAP_PAD", "RSA_WRAP_OAEP"}

var SUPPORTED_ENCRYPT_DECRYPT_KEYS = []string{"RSA", "AES", "CHACHA20", "CAMELLIA", "TDEA"}
var SUPPORTED_WRAP_KEYS = []string{"RSA", "AES"}
var SUPPORTED_SIGN_KEYS = []string{"EC", "ED", "RSA", "DSA", "BLS"}
var SUPPORTED_CERTIFICATE_SIGN_KEYS = []string{"RSA"}
var CERTIFICATE_RSA_SIGNATURE_LIST = []string{"SHA224_WITH_RSA", "SHA256_WITH_RSA", "SHA384_WITH_RSA", "SHA512_WITH_RSA"}

var EC_SIGNATURE_LIST = []string{"NONE_WITH_ECDSA", "SHA1_WITH_ECDSA", "SHA224_WITH_ECDSA", "SHA256_WITH_ECDSA", "SHA384_WITH_ECDSA", "SHA512_WITH_ECDSA", "SHA3224_WITH_ECDSA", "SHA3256_WITH_ECDSA", "SHA3384_WITH_ECDSA", "SHA3512_WITH_ECDSA", "KECCAK224_WITH_ECDSA", "KECCAK256_WITH_ECDSA", "KECCAK384_WITH_ECDSA", "KECCAK512_WITH_ECDSA"}
var ED_SIGNATURE_LIST = []string{"EDDSA"}
var RSA_SIGNATURE_LIST = []string{"SHA224_WITH_RSA_PSS", "SHA256_WITH_RSA_PSS", "SHA384_WITH_RSA_PSS", "SHA512_WITH_RSA_PSS", "NONE_WITH_RSA", "SHA224_WITH_RSA", "SHA256_WITH_RSA", "SHA384_WITH_RSA", "SHA512_WITH_RSA", "SHA1_WITH_RSA", "SHA1_WITH_RSA_PSS"}
var DSA_SIGNATURE_LIST = []string{"NONE_WITH_DSA", "SHA224_WITH_DSA", "SHA256_WITH_DSA", "SHA384_WITH_DSA", "SHA512_WITH_DSA", "SHA1_WITH_DSA"}
var BLS_SIGNATURE_LIST = []string{"BLS"}

var SUPPORTED_PAYLOAD_TYPE = []string{"UNSPECIFIED", "ISO_20022", "PDF", "BTC", "ETH"}
var SUPPORTED_TAG_LENGTH = []string{"0", "64", "96", "104", "112", "120", "128"}

var SUPPORTED_KEY_TYPE_NAME = []string{"aes128-gcm96", "aes256-gcm96", "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "chacha20-poly1305", "ed25519"}

var SUPPORTED_KEY_USAGE = []string{"DIGITAL_SIGNATURE", "CONTENT_COMMITMENT", "KEY_ENCIPHERMENT", "DATA_ENCIPHERMENT", "KEY_AGREEMENT", "KEY_CERT_SIGN", "CRL_SIGN", "ENCIPHER_ONLY", "DECIPHER_ONLY"}
var SUPPORTED_EXTENDED_KEY_USAGE = []string{"ANY_EXTENDED_KEY_USAGE", "SERVER_AUTH", "CLIENT_AUTH", "CODE_SIGNING", "EMAIL_PROTECTION", "TIME_STAMPING", "OCSP_SIGNING"}
var SUPPORTED_CERTIFICATE_ATTRIBUTES = []string{"commonName", "country", "stateOrProvinceName", "locality", "organizationName", "organizationUnitName", "email", "title", "surname", "givenName", "initials", "pseudonym", "generationQualifier"}

//END CONSTS
