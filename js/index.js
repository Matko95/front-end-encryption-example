let loader      = document.getElementById("loader"),
    bobkey      = document.getElementById("bobkey"),
    johnkey     = document.getElementById("johnkey"),
    unencrypted = document.getElementById("unencrypted"),
    encrypted   = document.getElementById("encrypted"),
    final       = document.getElementById("final");

/** 
	Options for generating keys, we need to provide the number
	of bits for the keys, the larger the number the stronger 
	the keys are, but they become harder to generate, we need
	to provide a passphrase so we can later decrypt the keys.
**/
let keyOptions = {
	userIds: [{name: "Bob", email: "bob@lemon.email"}],
	numBits: 2048,
	passphrase: "bob-passphrase"
	//you would get the passphrase from an input field normally
};

let secondKeyOptions = {
	userIds: [{name: "John", email: "john@lemon.email"}],
	numBits: 2048,
	passphrase: "john-passphrase"
	//you would get the passphrase from an input field normally
}

let bob  = {},
    john = {},
    messageForJohn = "",
    email = {
			subject: "Hello John, I'm Bob!",
			body: "Foo!"
		};

/**
	Here we generate keys using the options provided above,
	we save the keys in local objects, but you would usually
	store them in a database, or some other permanent storage.
**/

openpgp.generateKey(keyOptions)
	.then((key) => {
		bob.privateKey = key.privateKeyArmored;
		bob.publicKey = key.publicKeyArmored;
		loader.innerHTML = "";
		bobkey.innerHTML = "Bob's keys generated";
		return Promise.resolve();
	})
	.then(() => {
		return openpgp.generateKey(secondKeyOptions)
	})
	.then(key => {
		john.privateKey = key.privateKeyArmored;
		john.publicKey = key.publicKeyArmored;
		johnkey.innerHTML = "John's keys generated";
		return Promise.resolve();
	})
	.then(() => {
		// Using John's public key, we encrypt the contents of the email.
		const options = {
			data: JSON.stringify(email),
			publicKeys:  openpgp.key.readArmored(john.publicKey).keys
		};
		unencrypted.innerHTML = "Plain text message : \r\n\r\n" + options.data;

		return openpgp.encrypt(options)
	})
	.then((cipherText)=>{
		// We get the cipherText which is the encrypted contents of the email.
		messageForJohn = cipherText.data;
		encrypted.innerHTML = "Encrypted message : \r\n\r\n" + messageForJohn;
		return Promise.resolve();		
	})
	.then(() => {
		/**
		   To decrypt the email, we now use John's private key, but before
		   we can actually use it, we need to decrypt it using the passphrase
		   we provided when we initialized the keys
	    **/
		let privateKey = openpgp.key.readArmored(john.privateKey).keys[0];

		if (privateKey.decrypt("john-passphrase")) {
			return openpgp.decrypt({
            			privateKey: privateKey,
            			message: openpgp.message.readArmored(messageForJohn)
            		}); 
		} 
		return Promise.reject('Wrong passphrase');
	})
	.then((decryptedData) => {
		// If all goes well we can now read the contents of Jonh's message :)
		final.innerHTML = "Decrypted message : \r\n\r\n" + decryptedData.data;
		console.log(JSON.parse(decryptedData.data));
	})
	.catch((err)=>{
		// In case something goes wrong
		console.error(err);
	})


