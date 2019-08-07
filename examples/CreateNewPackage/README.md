
# Node.js SendSafely Sample Application

CreateNewPackage.js is a sample application demonstrating core SendSafely secure data transfer capabilities using the Sendsafely JavaScript API for Node.js. 

## Quickstart
Install the @sendsafely/sendsafely Node module 
```console
npm install
```

Update the SendSafely object in CreateNewPackage.js with your SendSafely organization hostname and a API Key and Secret.

```javascript
//var sendSafely = new SendSafely("https://demo.sendsafely.com", "exAPIkeyxyz", "exAPIsecretxyz");
var sendSafely = new SendSafely("https://ORGANIZATION_HOST", "API_KEY", "API_SECRET");
```

*You can generate your own API_KEY and API_SECRET from the API Keys section of your Profile page when logged into your SendSafely portal.* 

## Support
For support, please contact support@sendsafely.com. 