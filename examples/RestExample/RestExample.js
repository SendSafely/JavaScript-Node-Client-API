var SendSafely = require('@sendsafely/sendsafely');
var sendSafely = new SendSafely("https://ORGANIZATION_HOST", "API_KEY", "API_SECRET");

sendSafely.on('myrequest.error', function (error, errorMsg) {
    console.log('error event raised');
    console.log('error code: ' + error);
    console.log('error message: ' + errorMsg)
});

restExampleGetUserInformation();

function restExampleGetUserInformation() {
    const endpoint = "/user/";
    const httpMethod = "GET";
    const mimeType = "application/json";
    const requestData = null;
    const customErrorEventName = "myrequest.error";
    sendSafely.sendSignedRequest(endpoint, httpMethod, mimeType, requestData, (response) => {
        console.log('Success!');
        console.log(response);
    }, customErrorEventName);
}