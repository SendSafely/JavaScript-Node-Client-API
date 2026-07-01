// Type definitions for @sendsafely/sendsafely
// Project: https://github.com/SendSafely/JavaScript-Node-Client-API
//
// This declaration mirrors the runtime public surface of SendSafely.js. The
// surface is enumerated from the `this.x =` assignments in the constructor
// PLUS the `on`/`unbind`/`isBound` methods that EventHandler injects onto each
// instance at runtime and are therefore absent from the constructor body and
// the JSDoc.
//
// v1 policy (intentionally loose):
// adding a `types` field flips every TS consumer from inferred-`any` to
// checked, with NO opt-out (a consumer's own `declare module` shim does NOT
// override package-bundled types — verified). To avoid breaking builds on
// `npm update`, ALL parameters are typed `any` for v1 — including constructor
// params, so patterns like `new SendSafely(process.env.SS_HOST, ...)` (which
// pass `string | undefined`) keep compiling under `strict`. Callbacks are
// `(...args: any[]) => void`. Return types are kept accurate (they cannot
// reject consumer input). Precision can be tightened in a later minor version.

export = SendSafely;

declare class SendSafely {
  // apiSecret is positionally required: pass the secret, or `null` for the
  // anonymous path (the constructor selects AnonymousRequest only when
  // apiSecret === null; omitting it falls through to a broken SignedRequest).
  constructor(url: any, apiKey: any, apiSecret: any, requestAPI?: any);

  // --- Event API: injected onto the instance by EventHandler at runtime ---
  // (not present in the constructor body)
  on(event: any, callback: (...args: any[]) => void): number;
  unbind(event: any, id?: any): void;
  isBound(event: any): void;

  // --- Data properties (constructor-assigned) ---
  async: any;
  NETWORK_ERROR: any;
  NOT_INITIALIZED_ERROR: any;
  apiKeyId: any;
  apiKeySecret: any;
  systemName: any;
  serverWorkerURI: any;
  keyGeneratorURI: any;
  uploadAPI: any;
  url: any;
  requestAPI: any;
  wrapperRequest: any;
  eventHandler: any;
  executor: any;
  request: any;

  // --- Methods (constructor-assigned, in source order) ---
  verifyVersion(api_identifier: any, finished: (...args: any[]) => void): void;
  parseLinks(text: any): any;
  versionUpdated(host: any, versionInfo: any, finished: (...args: any[]) => void): void;
  verifyCredentials(finished: (...args: any[]) => void): void;
  getUserInformation(finished: (...args: any[]) => void, customErrorEvent?: any): void;
  deleteFile(packageId: any, fileId: any, finished: (...args: any[]) => void): void;
  deleteFileWithDirectory(packageId: any, fileId: any, directoryId: any, finished: (...args: any[]) => void): void;
  removeRecipient(packageId: any, recipientId: any, finished: (...args: any[]) => void): void;
  enterpriseInfo(finished: (...args: any[]) => void): void;
  addRecipient(packageId: any, email: any, keyCode: any, finished: (...args: any[]) => void): void;
  addRecipientWithSMS(packageId: any, email: any, keycode: any, phonenumber: any, countryCode: any, finished: (...args: any[]) => void): void;
  addRecipients(packageId: any, emails: any, keycode: any, finished: (...args: any[]) => void, customEvent?: any): void;
  addRecipientPhonenumber(packageId: any, recipientId: any, phonenumber: any, countryCode: any, finished: (...args: any[]) => void): void;
  uploadKeycode(packageId: any, publicKeys: any, keyCode: any, callback: (...args: any[]) => void): void;
  getPublicKeys(packageId: any, callback: (...args: any[]) => void): void;
  finalizePackage(packageId: any, packageCode: any, keyCode: any, finished: (...args: any[]) => void): void;
  finalizeUndisclosedPackage(packageId: any, packageCode: any, keyCode: any, password: any, finished: (...args: any[]) => void): void;
  shouldNotifyRecipients(): boolean;
  saveMessage(packageId: any, message: any, finished: (...args: any[]) => void): void;
  deleteTempPackage(packageId: any, finished: (...args: any[]) => void): void;
  deletePackage(packageId: any, finished: (...args: any[]) => void): void;
  renameDirectory(packageId: any, directoryId: any, directoryName: any, finished: (...args: any[]) => void): void;
  getDirectory(packageId: any, directoryId: any, directoryIndex: any, fileIndex: any, sortField: any, sortOrder: any, finished: (...args: any[]) => void): void;
  deleteDirectory(packageId: any, directoryId: any, finished: (...args: any[]) => void): void;
  packageInformation(packageId: any, finished: (...args: any[]) => void): void;
  packageInformationFromLink(link: any, finished: (...args: any[]) => void): void;
  getActivePackages(rowIndex: any, finished: (...args: any[]) => void): void;
  getReceivedPackages(rowIndex: any, finished: (...args: any[]) => void): void;
  getArchivedPackages(rowIndex: any, finished: (...args: any[]) => void): void;
  getActivityLog(packageId: any, rowIndex: any, finished: (...args: any[]) => void): void;
  getRecipient(packageId: any, recipientId: any, finished: (...args: any[]) => void): void;
  getFileInformation(packageId: any, directoryId: any, fileId: any, finished: (...args: any[]) => void): void;
  updateRecipientRole(packageId: any, recipientId: any, roleName: any, finished: (...args: any[]) => void): void;
  updatePackage(packageId: any, data: any, finished: (...args: any[]) => void): void;
  updateFile(packageId: any, fileId: any, fileName: any, finished: (...args: any[]) => void): void;
  encryptAndUploadMessage(packageId: any, keyCode: any, serverSecret: any, message: any, finished: (...args: any[]) => void): void;
  encryptAndUploadFiles(packageId: any, keyCode: any, serverSecret: any, files: any, uploadType: any, finished: (...args: any[]) => void): void;
  encryptAndUploadFilesToDirectory(packageId: any, keyCode: any, serverSecret: any, files: any, uploadType: any, directoryId: any, finished: (...args: any[]) => void): void;
  getKeycode(privateKey: any, publicKeyId: any, packageId: any, callback: (...args: any[]) => void): void;
  generateKeyPair(description: any, visible: any, callback: (...args: any[]) => void): void;
  generateRsaKeyPair(description: any, callback: (...args: any[]) => void): void;
  removePublicKey(publicKeyId: any, callback: (...args: any[]) => void): void;
  downloadFile(packageId: any, fileId: any, keyCode: any, config: any): void;
  downloadFileFromDirectory(packageId: any, directoryId: any, fileId: any, keyCode: any, config: any): void;
  createDirectory(packageId: any, directoryName: any, finished: (...args: any[]) => void): void;
  createSubdirectory(packageId: any, directoryName: any, directoryId: any, finished: (...args: any[]) => void): void;
  updateDirectory(packageId: any, sourceDirectoryId: any, targetDirectoryId: any, finished: (...args: any[]) => void): void;
  copyFile(sourcePackageId: any, sourceFileId: any, sourceServerSecret: any, sourceKeycode: any, targetPackageId: any, targetDirectoryId: any, targetServerSecret: any, targetKeycode: any, finished: (...args: any[]) => void): void;
  hasOngoingUploads(): boolean;
  createPackage(finished: (...args: any[]) => void): void;
  createWorkspace(finished: (...args: any[]) => void): void;
  encryptMessage(packageId: any, keyCode: any, serverSecret: any, message: any, finished: (...args: any[]) => void): void;
  decryptMessage(packageId: any, keyCode: any, serverSecret: any, ciphertext: any, finished: (...args: any[]) => void): void;
  getPackageMessage(packageId: any, packageCode: any, keyCode: any, finished: (...args: any[]) => void): void;
  checkAPIInitialized(): void;
  syncKeycodes(privateKey: any, publicKeyId: any, callback: (...args: any[]) => void): void;
  sendFeedback(log: any, stacktrace: any, systemInfo: any): void;
  sendSignedRequest(endpoint: any, HTTPMethod: any, mimeType: any, requestData: any, successCallback: (...args: any[]) => void, customErrorEvent?: any): void;
}

declare namespace SendSafely {
  // Static properties / methods (the SendSafely.X = assignments)
  const SDK_VERSION: any;
  const SDK_VERSION_HEADER: any;
  const SDK_VERSION_VALUE: any;
  const CLIENT_VERSION_HEADER: any;
  function setClientVersion(v: any): void;

  // Public sub-constructor. At runtime this is a factory that returns a full
  // SendSafely instance (`new SendSafely(url, dropzoneId, null)`)
  // with two members added, so it is declared as extending SendSafely rather
  // than as a standalone/empty class.
  class SendSafelyDropzone extends SendSafely {
    constructor(url: any, dropzoneId: any);
    // Added by the SendSafelyDropzone factory:
    notifyRecipients: any;
    setUnconfirmedSender(email: any): void;
    // Set by setUnconfirmedSender(); consumed when building a request.
    unconfirmedSender?: any;
  }
}
