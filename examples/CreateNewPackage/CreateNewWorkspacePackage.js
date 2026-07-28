var fs = require('fs');
var SendSafely = require('@sendsafely/sendsafely');

var fileArray = [];
var fileUploadCount = 0;
var recipientAddedCount = 0;
var newPackageId;
var newServerSecret;
var newPackageCode;
var newKeyCode;
var newDirectoryId;
var workspaceURL = '/receive/?packageCode=';

var filesToUpload = ["test1.txt", "test2.txt"];
var recipientsToAdd = ["user+one@example.com", "user+two@example.com", "user+three@example.com"];
var publicKeys = [];
var fileIds = [];

var privateKey = ""
var publicKeyId = "";
var files = [];

// --- Authentication: choose ONE mode ------------------------------------------
// OAuth Bearer: set TOKEN to an access token (takes precedence when non-empty).
// HMAC API key: leave TOKEN empty and set API_KEY + API_SECRET.
// Values come from the environment when set, otherwise fill in the fallbacks manually.
var HOST = process.env.API_HOST || "https://123xyz.sendsafely.com";
var TOKEN = process.env.OAUTH_TOKEN || "";       // OAuth access token; non-empty => OAuth Bearer mode
var API_KEY = process.env.API_KEY || "API_KEY";          // used only when TOKEN is empty
var API_SECRET = process.env.API_SECRET || "API_SECRET"; // used only when TOKEN is empty

var sendSafely = TOKEN
    ? SendSafely.withBearerToken(HOST, TOKEN)
    : new SendSafely(HOST, API_KEY, API_SECRET);

// Register event handlers (incl. sendsafely.error) BEFORE the first call so auth
// failures during verifyCredentials (e.g. an expired token -> OAUTH_TOKEN_INVALID)
// are printed instead of being silently dropped.
initEvents();
sendSafely.verifyCredentials(function(email) {
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
        console.log('Error:', error, errorMsg || '');
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
    sendSafely.createWorkspace(function (packageId, serverSecret, packageCode, keyCode) {
        newPackageId = packageId;
        newServerSecret = serverSecret;
        newPackageCode = packageCode;
        newKeyCode = keyCode;
        console.log("Created new Package ID: " + packageId);
        console.log("KeyCode: " + keyCode);
        console.log("Server Secret: " + serverSecret);
        console.log("Package Code: " + packageCode);
        workspaceSecureLink = HOST + workspaceURL + newPackageCode + '#keycode=' + newKeyCode;
        console.info("Workspace link: " + workspaceSecureLink);
        sendSafely.packageInformation(newPackageId,function(res) {
            sendSafely.createSubdirectory(newPackageId, "Example Folder", res.rootDirectoryId, function (directory) {
                newDirectoryId = directory.responseJSON.directoryId;
                sendSafely.encryptAndUploadFilesToDirectory(newPackageId, newKeyCode, newServerSecret, fileArray, "js", newDirectoryId, function (packageId, fileId, fileSize, fileName) {
                    fileUploadCount++;
                    fileIds.push(fileId);
                    console.log("Upload Complete - File " + fileUploadCount + " - " + fileName);
                    if (fileUploadCount == filesToUpload.length) {
                        console.log("All Uploads Complete");
                        step2();
                    }
                })
            })
        })
    })
}

function step2() {
    sendSafely.getDirectory(newPackageId, newDirectoryId, 0, 0, null, null, function(data) {
        files = data.files;
        for(var i = 0; i < files.length; i++) {
            var file = files[i];
            console.log('Downloading file ' + file.fileName);
            sendSafely.downloadFileFromDirectory(newPackageId,newDirectoryId, file.fileId, newKeyCode);
        }

    });
}
