
# SendSafely JavaScript API for Node.js

The SendSafely JavaScript API for Node.js lets you integrate SendSafely secure data transfer capabilities directly into your Node.js application. 

## Requirements

- **Node.js**: v24.5.0 or higher

Please ensure you are on Node v24.5.0 or later to maintain compatibility with the SDK. If your application runs behind a corporate proxy, see [Proxy configuration](#proxy-configuration) below.

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

## Proxy configuration

The SDK uses the Node.js built-in `fetch` for all HTTP requests. By default Node does not read the `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables, so to route SDK traffic through a corporate proxy you need to opt in. Start your application with proxy support enabled:

```console
NODE_USE_ENV_PROXY=1 node app.js
```

or pass the equivalent flag:

```console
node --use-env-proxy app.js
```

With this enabled, Node honors `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` for the SDK's requests. This support is available in Node v24.5.0 and later.

If you are upgrading from an earlier SDK version, note that previous releases picked up these proxy variables automatically. Starting with this release you must enable the setting above.

## Examples
Please refer to our [Developer Website](https://sendsafely.github.io) to familiarize yourself with the core SendSafely API and common operations. See our [examples](https://github.com/SendSafely/JavaScript-Node-Client-API/tree/master/examples/CreateNewPackage) in GitHub for working examples of how to use the SendSafely JavaScript API for Node.js.  

## Support
For support, please contact support@sendsafely.com. 


