
# Node.js SendSafely Sample Application

## Quickstart
Install the @sendsafely/sendsafely Node module 
```console
npm install
```

Update the SendSafely object in RestExample.js with your SendSafely organization hostname and a API Key and Secret.

```javascript
const sendSafely = new SendSafely("https://ORGANIZATION_HOST", "API_KEY", "API_SECRET");

const endpoint = "/user/"; 
const httpMethod = "GET";
const mimeType = "application/json";
const requestData = {}; // non JSONIFIED object
const customErrorEvent = "mycustom.error";

//Our Node SDK includes wrapper functions for various REST API endpoints to make it easier to perform common tasks from native code. 
// sendSignedRequest allows User to perform REST API operations for endpoints not yet migrated to Node SDK
// For a full list of REST API methods, please refer to: https://rest-api-docs.sendsafely.com/
sendSafely.sendSignedRequest(endpoint, httpMethod, mimeType, requestData, (data) => {
console.log('Success!');
console.log(data);
}, customErrorEventName);

// customErrorEvent will be raised when response property != SUCCESS
sendSafely.on(customErrorEventName, function (error, errorMsg) {
    console.log('error event raised');
    console.log('error code: ' + error);
    console.log('error message: ' + errorMsg)
});

```
*You can generate your own API_KEY and API_SECRET from the API Keys section of your Profile page when logged into your SendSafely portal.*

Run RestExample sample application using Node
```console
node RestExample.js
```

## Support
For support, please contact support@sendsafely.com. 