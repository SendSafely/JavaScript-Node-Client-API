
# SendSafely JavaScript API for Node.js

The SendSafely JavaScript API for Node.js lets you integrate SendSafely secure data transfer capabilities directly into your Node.js application. 

## Quickstart
The example below shows you how to install the package and use it as a CommonJS module.

Install with npm
```console
npm install @sendsafely/sendsafely
```

Include the SendSafely class to start making your API calls.

```javascript
var SendSafely = require('@sendsafely/sendsafely');
//var sendSafely = new SendSafely("https://demo.sendsafely.com", "exAPIkeyxyz", "exAPIsecretxyz");
var sendSafely = new SendSafely("https://ORGANIZATION_HOST", "API_KEY", "API_SECRET");

sendSafely.verifyCredentials(function(email)  {
	console.log("Connected to SendSafely as user "  +  email);
});

```

*You will need to generate your own API_KEY and API_SECRET from the API Keys section of your Profile page when logged into your SendSafely portal.*

## Examples
Please refer to our [Developer Website](https://sendsafely.github.io) to familiarize yourself with the core SendSafely API and common operations. 

## Support
For support, please contact support@sendsafely.com. 


