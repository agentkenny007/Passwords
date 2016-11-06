angular.module('passwords', ['ionic, firebase'])

.run(function($ionicPlatform){
    $ionicPlatform.ready(function(){
        if (window.cordova && window.cordova.plugins.Keyboard){
            // Hide the accessory bar by default (remove this to show the accessory bar above the keyboard
            // for form inputs)
            cordova.plugins.Keyboard.hideKeyboardAccessoryBar(true);

            // Don't remove this line unless you know what you are doing. It stops the viewport
            // from snapping when text inputs are focused. Ionic handles this internally for
            // a much nicer keyboard experience.
            cordova.plugins.Keyboard.disableScroll(true);
        }
        if (window.StatusBar) StatusBar.styleDefault();
    });
})

.factory("$cipherFactory", function(){
    return {
        encrypt: function(message, password) { // to encrypt a password protected message with the purpose of storing it in a database
            // create a randomly generated 128 byte salt to use when we hash the supplied password
            var salt = forge.random.getBytesSync(128); // https://en.wikipedia.org/wiki/Salt_(cryptography)
            // create a salted key based upon the password string supplied
            var key = forge.pkcs5.pbkdf2(password, salt, 4, 16); // https://en.wikipedia.org/wiki/Cryptographic_hash_function
            // create an initialization vector of 16 random bytes
            var iv = forge.random.getBytesSync(16); // https://en.wikipedia.org/wiki/Initialization_vector
            // create a cypher (encryption algorithm) to encrypt our message
            var cipher = forge.cipher.createCipher('AES-CBC', key); // Advanced Encryption Standard algorithm using Cypher Block Chaining encryption mode
            cipher.start({ iv: iv }); // start encryption process using our init vector
            cipher.update(forge.util.createBuffer(message)); // generate encryption using a data buffer of the supplied message
            cipher.finish(); // complete encryption process
            // store our encrypted message as a Base64 encoded string
            var cipherText = forge.util.encode64(cipher.output.getBytes());
            // return an object with references to Base64 encoded strings of our encrypted message, salt, and init vector
            return { cipher_text: cipherText, salt: forge.util.encode64(salt), iv: forge.util.encode64(iv) };
        },
        decrypt: function(cipherText, password, salt, iv, options) { // to decrypt a password protected message returned from a database
            // create a salted key based upon the supplied password and the salt we stored
            var key = forge.pkcs5.pbkdf2(password, forge.util.decode64(salt), 4, 16);
            // create a decryption cypher to decrypt our message
            var decipher = forge.cipher.createDecipher('AES-CBC', key);
            decipher.start({ iv: forge.util.decode64(iv) }); // start decryption process using the init vector we stored (Base64 decoded)
            decipher.update(forge.util.createBuffer(forge.util.decode64(cipherText))); // generate decryption using a data buffer of our Base64 decoded encryption
            decipher.finish(); // complete decryption process
            // return a hex string of the decrypted message
            if (options !== undefined && options.hasOwnProperty("output") && options.output === "hex") // if output is specified as "hex"
                return decipher.output.toHex();
            // otherwise, return a string of the decrypted message
            else return decipher.output.toString();
        }
    };
    // Links that might make this code more illuminating:
    // https://www.thepolyglotdeveloper.com/2014/10/implement-aes-strength-encryption-javascript/
    // https://github.com/digitalbazaar/forge/tree/master/js
    // https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    // https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
    // https://en.wikipedia.org/wiki/Data_buffer
})
