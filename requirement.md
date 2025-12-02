Encryption-Decryption: We are using hybrid encryption in which that string that

is to be encrypted is encrypted using AES Key (AES algorithm) and then we encrypt it again with RSA Algorithm using Primary key. We get the stringified encryptedbase64iv and encryptedbase64 data in response. For decryption, we need encryptedbase64iv and encryptedbase64data First we decrypt the encryptedbase64iv using the Private Key (RSA Algorithm) and then we decrypt the encryptedbase64 data and the ivArraybuffer using the AES Key (AES Algorithm). In return we get the decrypted javascript object.

export async function hybridEncryption (plaintextData, rawPublicKey = enPu, rawAesKey-eAk) ( const rsaAlgorithm "SHA-256"); (name: "RSA QAEP", hash: const aesAlgorithm (name: "AES-CBC" 1

//import keys rawAeskey modifiedCaesarDecrypt (eAk) rawPublickey keyDecrypt (enRu) let importedaeskey await importAeskey (rawdesKey) let importedPublicKey = await import PublicKey (rawPublicKey)

return new Promise((resolve, reject) => { aesAlgorithm.iv = crypte.getRandomValues (new Uint8Array (16)).buffer; return Promise.all([ encryptUsingAesKey (aesAlgorithm, importedAeskey, encodeURIComponent (plaintextData)). encryptUsingPublicKey (rsaAlgorithm, importedPublicKey, aesAlgorithm.iv) 1).then(((encryptedDataArrayBuffer, encryptedlyArrayBuffer]) => { resolve (JSON.stringify(( encryptedDataBase64: arrayBufferToBase64String (encryptedDataArrayBuffer), encryptedIvBase64: arrayBufferToBase64String (encryptedIvArrayBuffer) 1)); }).catch((error) => ( throw Error("An error occured") 1);
})
}


The above function takes string that is to be encrypted as a parameter, it generates iv vector, then encrypts string data using AES algorithm and generates data array buffer. Then uses the iv vector data generated earlier and public key (rsa algorithm) to generate encryptedivbuffer array. Then the array buffers are converted into stringified encrypted data base64 and encryptediv base 64.

Below is the hybrid decryption function (encryption3.js file in the front-end)

export async function hybridDecryption (encobject, rawPrivateKey rawdesKey-eAk) ( enpr. const rsaalgorithm "SHA-256"); const aesAlgorithm I name: "BSA-QAEP", hash: (name: "AES-CBC" 1 Lawäeskey modifiedCaesarDecrypt (eak) rawPrivateKey-keyDecrypt (enPr) let importedAeskey await import@eskey (rawdesKey) let importedPrivatekey await import PrivateKey (rawPrivateKey)

return decryptUsingPrivateKey (rsaalgorithm, importedPrivateKey, encobject.encryptedIvBase64) then (ivArrayBuffer => ( aesalgorithm.iv ivArrayBuffer: return decryptUsingßeskey (acsAlgorithm, importedAeskey, encobject.encryptedDataBase64); then (plaintextDataArrayBuffer => { const textDecoder = new Text Decoder("はたよー 8")

const stringURI textDecoder.decode (plaintextDataArrayBuffer)

return JSON.parse(decodeURIComponent (stringURI)) )).catch((error) => { throw Error("An error occured") return null ))


The above function takes in the encrypted object(which is base64encrypteddata and base64encryptediv). It decrypts the encryptedbase64data using Private Key and then decrypts then encryptedbase64data using AES Algorithm. It then generates arraybuffer which is then decoded into plain javascript object.

Integration Service (IS)- We have a middleware server which receives all the reqöests before passing the request further to the back-end server. The role of integration-service is to decrypt the request body, check token for authentication.