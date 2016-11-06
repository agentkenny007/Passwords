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
        encrypt: function(message, password) {
            var salt = forge.random.getBytesSync(128);
            var key = forge.pkcs5.pbkdf2(password, salt, 4, 16);
            var iv = forge.random.getBytesSync(16);
            var cipher = forge.cipher.createCipher('AES-CBC', key);
            cipher.start({ iv: iv });
            cipher.update(forge.util.createBuffer(message));
            cipher.finish();
            var cipherText = forge.util.encode64(cipher.output.getBytes());
            return { cipher_text: cipherText, salt: forge.util.encode64(salt), iv: forge.util.encode64(iv) };
        },
        decrypt: function(cipherText, password, salt, iv, options) {
            var key = forge.pkcs5.pbkdf2(password, forge.util.decode64(salt), 4, 16);
            var decipher = forge.cipher.createDecipher('AES-CBC', key);
            decipher.start({ iv: forge.util.decode64(iv) });
            decipher.update(forge.util.createBuffer(forge.util.decode64(cipherText)));
            decipher.finish();
            if (options !== undefined && options.hasOwnProperty("output") && options.output === "hex")
                return decipher.output.toHex();
            else return decipher.output.toString();
        }
    };
})
