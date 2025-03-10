var fs = require('fs');
var SendSafely = require('@sendsafely/sendsafely');

var fileArray = [];
var fileUploadCount = 0;
var recipientAddedCount = 0;
var newPackageId;
var newServerSecret;
var newPackageCode;
var newKeyCode;

var filesToUpload = ["test1.txt", "test2.txt"];
var recipientsToAdd = ["user+one@example.com", "user+two@example.com", "user+three@example.com"];
var publicKeys = [];
var fileIds = [];

var privateKey = ""
var publicKeyId = "";
var files = [];
	
//var sendSafely = new SendSafely("https://demo.sendsafely.com", "exAPIkeyxyz", "exAPIsecretxyz");
var sendSafely = new SendSafely("https://ORGANIZATION_HOST", "API_KEY", "API_SECRET");

sendSafely.verifyCredentials(function(email) {
	initEvents();
    console.log("Connected to SendSafely as user " + email);
    getFiles();
});

function initEvents() {
	sendSafely.on('save.file',function(data) {
		var fileName = files.find(f=>{ return f.fileId === data.fileId }).fileId;
		fs.writeFile(fileName, data.file, (err) => {
			  if(err) {
				  throw err;
			  }
			  console.log('The file has been saved! ' + data.fileId);
		});		
	});
	
	sendSafely.on('sendsafely.error', function(error, errorMsg) {
	    console.log(error)
	});
}

function getFiles() {
    if (fileArray.length == filesToUpload.length) {
        step1();
    } else {
        console.log("Reading file " + filesToUpload[fileArray.length]);
        fs.readFile(filesToUpload[fileArray.length], function(err, data) {
            if (err) {
                throw err
            }
            var file = {
                size: data.length,
                name: filesToUpload[fileArray.length],
                data: data
            };
            fileArray.push(file);
            getFiles();
        })
    }
}

function step1() {
	console.log("Generate new key pair")
	sendSafely.generateKeyPair("Node example",false,function(privateKey, publicKey){
		console.log("New key pair generated");
		newPrivateKey = privateKey;
		newPublicKey = publicKey;
		publicKeyId = publicKey.id
		step2();
	});
}

function step2() {
    sendSafely.createPackage(function(packageId, serverSecret, packageCode, keyCode) {
        newPackageId = packageId;
        newServerSecret = serverSecret;
        newPackageCode = packageCode;
        newKeyCode = keyCode;
        console.log("Created new Package ID: " + packageId);
        console.log("KeyCode: " + keyCode);
        console.log("Server Secret: " + serverSecret);
        console.log("Package Code: " + packageCode);
        sendSafely.encryptAndUploadFiles(newPackageId, newKeyCode, newServerSecret, fileArray, "js", function(packageId,fileId, fileSize,fileName) {
            fileUploadCount++;
            fileIds.push(fileId);
            console.log("Upload Complete - File " + fileUploadCount + " - " + fileName);
            if (fileUploadCount == filesToUpload.length) {
                console.log("All Uploads Complete");
                step3();
            }
        })
    })
}

function step3() {
	console.log("Encrypting and Uploading Message");
    sendSafely.encryptAndUploadMessage(newPackageId, newKeyCode, newServerSecret, "This is a test package from Node.js", function(encryptedMessage) {
        console.log("Message Added");
        console.log("Adding Recipients");
        sendSafely.addRecipients(newPackageId, recipientsToAdd, undefined, function(finished) {
            console.log("Finalizing Package");
            sendSafely.finalizePackage(newPackageId, newPackageCode, newKeyCode, function(done) {
                console.log("Secure Link: " + done);
                step4();
            });
        });
    });
}

function step4() {
	console.log("Getting keycode");
	sendSafely.getKeycode(newPrivateKey,publicKeyId,newPackageId,function(keycode){
		console.log('Decrypted keycode from private key : ' + keycode);
		console.log('Keycode from package : ' + newKeyCode);
		step5();
	});
}

function step5() {
	sendSafely.packageInformation(newPackageId,function(res){
		files = res.files;
		for(var i = 0; i < res.files.length; i++) {
			var file = res.files[i];
			console.log('Downloading file ' + file.fileName);
			sendSafely.downloadFile(newPackageId,file.fileId,newKeyCode);
		}	
	});
}
