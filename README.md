
# SendSafely JavaScript API for Node.js

The SendSafely JavaScript API for Node.js lets you integrate SendSafely secure data transfer capabilities directly into your Node.js application. 

## Requirements

- **Node.js**: v18 or higher *(required starting from SDK v2.0.0)*

Please ensure you upgrade to Node v18 to take advantage of the latest features and maintain compatibility with our SDK v2.0.0 and later.

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
Please refer to our [Developer Website](https://sendsafely.github.io) to familiarize yourself with the core SendSafely API and common operations. See our [examples](https://github.com/SendSafely/JavaScript-Node-Client-API/tree/master/examples/CreateNewPackage) in GitHub for working examples of how to use the SendSafely JavaScript API for Node.js.  

## Support
For support, please contact support@sendsafely.com. 


