import 'core-js/es6/promise';
import 'core-js/fn/function/bind';
import 'core-js/fn/object/assign';
import 'core-js/fn/array/find';
import 'core-js/fn/array/some';
import 'core-js/fn/array/is-array';
import 'core-js/fn/array/splice';
import { BigInteger } from 'jsbn';
import SHA256 from 'crypto-js/sha256';
import base64Js from 'base64-js';

// Declare the ES6 features we're using

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

let nopLogger = {
    debug(){},
    info(){},
    warn(){},
    error(){}
};

const NONE = 0;
const ERROR = 1;
const WARN = 2;
const INFO = 3;
const DEBUG = 4;

let logger;
let level;

class Log {
    static get NONE() {return NONE};
    static get ERROR() {return ERROR};
    static get WARN() {return WARN};
    static get INFO() {return INFO};
    static get DEBUG() {return DEBUG};
    
    static reset(){
        level = INFO;
        logger = nopLogger;
    }
    
    static get level(){
        return level;
    }
    static set level(value){
        if (NONE <= value && value <= DEBUG){
            level = value;
        }
        else {
            throw new Error("Invalid log level");
        }
    }
    
    static get logger(){
        return logger;
    }
    static set logger(value){
        if (!value.debug && value.info) {
            // just to stay backwards compat. can remove in 2.0
            value.debug = value.info;
        }

        if (value.debug && value.info && value.warn && value.error){
            logger = value;
        }
        else {
            throw new Error("Invalid logger");
        }
    }
    
    static debug(...args){
        if (level >= DEBUG){
            logger.debug.apply(logger, Array.from(args));
        }
    }
    static info(...args){
        if (level >= INFO){
            logger.info.apply(logger, Array.from(args));
        }
    }
    static warn(...args){
        if (level >= WARN){
            logger.warn.apply(logger, Array.from(args));
        }
    }
    static error(...args){
        if (level >= ERROR){
            logger.error.apply(logger, Array.from(args));
        }
    }
}

Log.reset();

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

const timer = {
    setInterval: function (cb, duration) {
        return setInterval(cb, duration);
    },
    clearInterval: function (handle) {
        return clearInterval(handle);
    }
};

let testing = false;
let request = null;

class Global {

    static _testing() {
        testing = true;
    }

    static get location() {
        if (!testing) {
            return location;
        }
    }

    static get localStorage() {
        if (!testing) {
            return localStorage;
        }
    }

    static get sessionStorage() {
        if (!testing) {
            return sessionStorage;
        }
    }

    static setXMLHttpRequest(newRequest) {
        request = newRequest;
    }

    static get XMLHttpRequest() {
        if (!testing) {
            return request || XMLHttpRequest;
        }
    }

    static get timer() {
        if (!testing) {
            return timer;
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class WebStorageStateStore {
    constructor({prefix = "oidc.", store = Global.localStorage} = {}) {
        this._store = store;
        this._prefix = prefix;
    }

    set(key, value) {
        Log.debug("WebStorageStateStore.set", key);

        key = this._prefix + key;

        this._store.setItem(key, value);
        
        return Promise.resolve();
    }

    get(key) {
        Log.debug("WebStorageStateStore.get", key);

        key = this._prefix + key;

        let item = this._store.getItem(key);
        
        return Promise.resolve(item);
    }

    remove(key) {
        Log.debug("WebStorageStateStore.remove", key);

        key = this._prefix + key;

        let item = this._store.getItem(key);
        this._store.removeItem(key);
        
        return Promise.resolve(item);
    }

    getAllKeys() {
        Log.debug("WebStorageStateStore.getAllKeys");

        var keys = [];

        for (let index = 0; index < this._store.length; index++) {
            let key = this._store.key(index);
            
            if (key.indexOf(this._prefix) === 0) {
                keys.push(key.substr(this._prefix.length));
            }
        }
        
        return Promise.resolve(keys);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class JsonService {
    constructor(XMLHttpRequestCtor = Global.XMLHttpRequest) {
        this._XMLHttpRequest = XMLHttpRequestCtor;
    }
    
    getJson(url, token) {
        Log.debug("JsonService.getJson", url);
        
        if (!url){
            Log.error("No url passed");
            throw new Error("url");
        }
        
        return new Promise((resolve, reject) => {
            
            var req = new this._XMLHttpRequest();
            req.open('GET', url);

            req.onload = function() {
                Log.debug("HTTP response received, status", req.status);
                
                if (req.status === 200) {
                    try {
                        resolve(JSON.parse(req.responseText));
                    }
                    catch (e) {
                        Log.error("Error parsing JSON response", e.message);
                        reject(e);
                    }
                }
                else {
                    reject(Error(req.statusText + " (" + req.status + ")"));
                }
            };

            req.onerror = function() {
                Log.error("network error");
                reject(Error("Network Error"));
            };
            
            if (token) {
                Log.debug("token passed, setting Authorization header");
                req.setRequestHeader("Authorization", "Bearer " + token);
            }

            req.send();
        });
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const OidcMetadataUrlPath = '.well-known/openid-configuration';

class MetadataService {
    constructor(settings, JsonServiceCtor = JsonService) {
        if (!settings) {
            Log.error("No settings passed to MetadataService");
            throw new Error("settings");
        }

        this._settings = settings;
        this._jsonService = new JsonServiceCtor();
    }

    get metadataUrl() {
        if (!this._metadataUrl) {
            if (this._settings.metadataUrl) {
                this._metadataUrl = this._settings.metadataUrl;
            }
            else {
                this._metadataUrl = this._settings.authority;

                if (this._metadataUrl && this._metadataUrl.indexOf(OidcMetadataUrlPath) < 0) {
                    if (this._metadataUrl[this._metadataUrl.length - 1] !== '/') {
                        this._metadataUrl += '/';
                    }
                    this._metadataUrl += OidcMetadataUrlPath;
                }
            }
        }

        return this._metadataUrl;
    }

    getMetadata() {
        Log.debug("MetadataService.getMetadata");

        if (this._settings.metadata) {
            Log.debug("Returning metadata from settings");
            return Promise.resolve(this._settings.metadata);
        }

        if (!this.metadataUrl) {
            Log.error("No authority or metadataUrl configured on settings");
            return Promise.reject(new Error("No authority or metadataUrl configured on settings"));
        }

        Log.debug("getting metadata from", this.metadataUrl);

        return this._jsonService.getJson(this.metadataUrl)
            .then(metadata => {
                Log.debug("json received");
                this._settings.metadata = metadata;
                return metadata;
            });
    }
    
    getIssuer() {
        Log.debug("MetadataService.getIssuer");
        return this._getMetadataProperty("issuer");
    }

    getAuthorizationEndpoint() {
        Log.debug("MetadataService.getAuthorizationEndpoint");
        return this._getMetadataProperty("authorization_endpoint");
    }

    getUserInfoEndpoint() {
        Log.debug("MetadataService.getUserInfoEndpoint");
        return this._getMetadataProperty("userinfo_endpoint");
    }

    getTokenEndpoint() {
        Log.debug("MetadataService.getTokenEndpoint");
        return this._getMetadataProperty("token_endpoint", true);
    }
    
    getCheckSessionIframe() {
        Log.debug("MetadataService.getCheckSessionIframe");
        return this._getMetadataProperty("check_session_iframe", true);
    }

    getEndSessionEndpoint() {
        Log.debug("MetadataService.getEndSessionEndpoint");
        return this._getMetadataProperty("end_session_endpoint", true);
    }

    getRevocationEndpoint() {
        Log.debug("MetadataService.getRevocationEndpoint");
        return this._getMetadataProperty("revocation_endpoint", true);
    }

    _getMetadataProperty(name, optional=false) {
        Log.debug("MetadataService._getMetadataProperty", name);

        return this.getMetadata().then(metadata => {
            Log.debug("metadata recieved");

            if (metadata[name] === undefined) {

                if (optional === true) {
                    Log.warn("Metadata does not contain optional property " + name);
                    return undefined;
                }
                else {
                    Log.error("Metadata does not contain property " + name);
                    throw new Error("Metadata does not contain property " + name);
                }
            }

            return metadata[name];
        });
    }

    getSigningKeys() {
        Log.debug("MetadataService.getSigningKeys");

        if (this._settings.signingKeys) {
            Log.debug("Returning signingKeys from settings");
            return Promise.resolve(this._settings.signingKeys);
        }

        return this._getMetadataProperty("jwks_uri").then(jwks_uri => {
            Log.debug("jwks_uri received", jwks_uri);

            return this._jsonService.getJson(jwks_uri).then(keySet => {
                Log.debug("key set received", keySet);

                if (!keySet.keys) {
                    Log.error("Missing keys on keyset");
                    throw new Error("Missing keys on keyset");
                }

                this._settings.signingKeys = keySet.keys;
                return this._settings.signingKeys;
            });
        });
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class UserInfoService {
    constructor(settings, JsonServiceCtor = JsonService, MetadataServiceCtor = MetadataService) {
        if (!settings) {
            Log.error("No settings passed to UserInfoService");
            throw new Error("settings");
        }

        this._settings = settings;
        this._jsonService = new JsonServiceCtor();
        this._metadataService = new MetadataServiceCtor(this._settings);
    }

    getClaims(token) {
        Log.debug("UserInfoService.getClaims");

        if (!token) {
            Log.error("No token passed");
            return Promise.reject(new Error("A token is required"));
        }

        return this._metadataService.getUserInfoEndpoint().then(url => {
            Log.debug("received userinfo url", url);

            return this._jsonService.getJson(url, token).then(claims => {
                Log.debug("claims received", claims);
                return claims;
            });
        });
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class ErrorResponse extends Error {
    constructor({error, error_description, error_uri, state}={}
    ) {
         if (!error){
            Log.error("No error passed to ErrorResponse");
            throw new Error("error");
        }
        
        super(error_description || error);
        
        this.name = "ErrorResponse"; 
        
        this.error = error;
        this.error_description = error_description;
        this.error_uri = error_uri;
        
        this.state = state;
    }
}

/*
Based on the work of Auth0
https://github.com/auth0/idtoken-verifier
https://github.com/auth0/idtoken-verifier/blob/master/LICENSE
Which is based on the work of Tom Wu
http://www-cs-students.stanford.edu/~tjw/jsbn/
http://www-cs-students.stanford.edu/~tjw/jsbn/LICENSE
*/


if (typeof btoa === 'undefined') {
  global.btoa = function (str) {
    return new Buffer(str).toString('base64');
  };
}

if (typeof atob === 'undefined') {
  global.atob = function (b64Encoded) {
    return new Buffer(b64Encoded, 'base64').toString();
  };
}

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad = "=";

const Base64 = {
  hexToBase64(h) {
    var i;
    var c;
    var ret = "";
    for(i = 0; i+3 <= h.length; i+=3) {
      c = parseInt(h.substring(i,i+3),16);
      ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
    }
    if(i+1 == h.length) {
      c = parseInt(h.substring(i,i+1),16);
      ret += b64map.charAt(c << 2);
    }
    else if(i+2 == h.length) {
      c = parseInt(h.substring(i,i+2),16);
      ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
    }
    if (b64pad) while((ret.length & 3) > 0) ret += b64pad;
    return ret;
  },

  padding(str) {
    var mod = (str.length % 4);
    var pad = 4 - mod;

    if (mod === 0) {
      return str;
    }

    return str + (new Array(1 + pad)).join('=');
  },

  byteArrayToString(array) {
    var result = "";
    for (var i = 0; i < array.length; i++) {
      result += String.fromCharCode(array[i]);
    }
    return result;
  },


  stringToByteArray(str) {
    var arr = new Array(str.length);
    for (var a = 0; a < str.length; a++) {
      arr[a] = str.charCodeAt(a);
    }
    return arr;
  },

  byteArrayToHex(raw) {
    var HEX = '';

    for (var i = 0; i < raw.length; i++) {
      var _hex = raw[i].toString(16);
      HEX += (_hex.length === 2 ? _hex : '0' + _hex);
    }

    return HEX;
  },

  encodeString(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
      return String.fromCharCode('0x' + p1);
    }))
    .replace(/\+/g, '-') // Convert '+' to '-'
    .replace(/\//g, '_'); // Convert '/' to '_';
  },

  decodeToString(str) {
    str = Base64.padding(str)
      .replace(/-/g, '+') // Convert '-' to '+'
      .replace(/_/g, '/'); // Convert '_' to '/'

    return decodeURIComponent(atob(str).split('').map(function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
  },

  decodeToHEX(str) {
    return Base64.byteArrayToHex(base64Js.toByteArray(Base64.padding(str)));
  },

  base64ToBase64Url(s) {
    s = s.replace(/=/g, "");
    s = s.replace(/\+/g, "-");
    s = s.replace(/\//g, "_");
    return s;
  },

  urlDecode(str) {
    str = str.replace(/-/g, '+') // Convert '-' to '+'
      .replace(/_/g, '/') // Convert '_' to '/'
      .replace(/\s/g, ' '); // Convert '\s' to ' '

    return atob(str);
  }
};


var DigestInfoHead = {
  sha1: '3021300906052b0e03021a05000414',
  sha224: '302d300d06096086480165030402040500041c',
  sha256: '3031300d060960864801650304020105000420',
  sha384: '3041300d060960864801650304020205000430',
  sha512: '3051300d060960864801650304020305000440',
  md2: '3020300c06082a864886f70d020205000410',
  md5: '3020300c06082a864886f70d020505000410',
  ripemd160: '3021300906052b2403020105000414'
};

var DigestAlgs = {
  sha256: SHA256,
};

function RSAVerifier(modulus, exp) {
  this.n = null;
  this.e = 0;

  if (modulus != null && exp != null && modulus.length > 0 && exp.length > 0) {
    this.n = new BigInteger(modulus, 16);
    this.e = parseInt(exp, 16);
  } else {
    throw new Error('Invalid key data');
  }
}

function getAlgorithmFromDigest(hDigestInfo) {
  for (var algName in DigestInfoHead) {
    var head = DigestInfoHead[algName];
    var len = head.length;

    if (hDigestInfo.substring(0, len) === head) {
      return {
        alg: algName,
        hash: hDigestInfo.substring(len)
      };
    }
  }
  return [];
}


RSAVerifier.prototype.verify = function (msg, encsig) {
  encsig = Base64.decodeToHEX(encsig);
  encsig = encsig.replace(/[^0-9a-f]|[\s\n]]/ig, '');

  var sig = new BigInteger(encsig, 16);

  if (sig.bitLength() > this.n.bitLength()) {
    throw new Error('Signature does not match with the key modulus.');
  }

  var decryptedSig = sig.modPowInt(this.e, this.n);
  var digest = decryptedSig.toString(16).replace(/^1f+00/, '');
  var digestInfo = getAlgorithmFromDigest(digest);

  if (digestInfo.length === 0) {
    return false;
  }

  if (!DigestAlgs.hasOwnProperty(digestInfo.alg)) {
    throw new Error('Hashing algorithm is not supported.');
  }

  var msgHash = DigestAlgs[digestInfo.alg](msg).toString();
  return (digestInfo.hash === msgHash);
};


const AllowedSigningAlgs = ['RS256'];


const jws = {
  JWS: {
    parse: function(token) {
      var parts = token.split('.');
      var header;
      var payload;

      // This diverges from Auth0's implementation, which throws rather than
      // returning undefined
      if (parts.length !== 3) {
        return undefined;
      }

      try {
        header = JSON.parse(Base64.urlDecode(parts[0]));
        payload = JSON.parse(Base64.urlDecode(parts[1]));
      } catch (e) {
        return new Error('Token header or payload is not valid JSON');
      }

      return {
        headerObj: header,
        payloadObj: payload,
      };
    },
    verify: function(jwt, key, allowedSigningAlgs = []) {
      allowedSigningAlgs.forEach((alg) => {
        if (AllowedSigningAlgs.indexOf(alg) === -1) {
          throw new Error('Invalid signing algorithm: ' + alg);
        }
      });
      var verify = new RSAVerifier(key.n, key.e);
      var parts = jwt.split('.');

      var headerAndPayload = [parts[0], parts[1]].join('.');
      var verified = verify.verify(headerAndPayload, parts[2]);
      return verified;
    },
  },
};

const KeyUtil = {
  /**
   * Returns decoded keys in Hex format for use in crypto functions.
   * Supports modulus/exponent-style keys.
   *
   * @param {object} key the security key
   * @returns
   */
  getKey(key) {
    if (key.kty === 'RSA') {
      return {
        e: Base64.decodeToHEX(key.e),
        n: Base64.decodeToHEX(key.n),
      };
    }

    return null;
  },
};


const X509 = {
    getPublicKeyFromCertPEM: function() {
      throw new Error('Not implemented. Use the full oidc-client library if you need support for X509.');
    },
};

const crypto = {
  Util: {
    hashString: function(value, alg) {
      var hashFunc = DigestAlgs[alg];
      return hashFunc(value).toString();
    },
  }
};

function hextob64u(s) {
  if (s.length % 2 == 1) {
    s = '0' + s;
  }
  return Base64.base64ToBase64Url(Base64.hexToBase64(s));
}

var cryptoLib = {
  jws,
  KeyUtil,
  X509,
  crypto,
  hextob64u,
};

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const { jws: jws$1, KeyUtil: KeyUtil$1, X509: X509$1, crypto: crypto$1, hextob64u: hextob64u$1, AllowedSigningAlgs: AllowedSigningAlgs$1 } = cryptoLib;


class JoseUtil {

    static parseJwt(jwt) {
        Log.debug("JoseUtil.parseJwt");
        try {
            var token = jws$1.JWS.parse(jwt);
            return {
                header: token.headerObj,
                payload: token.payloadObj
            }
        }
        catch (e) {
            Log.error(e);
        }
    }

    static validateJwt(jwt, key, issuer, audience, clockSkew, now) {
        Log.debug("JoseUtil.validateJwt");

        try {
            if (key.kty === "RSA") {
                if (key.e && key.n) {
                    key = KeyUtil$1.getKey(key);
                }
                else if (key.x5c && key.x5c.length) {
                    key = KeyUtil$1.getKey(X509$1.getPublicKeyFromCertPEM(key.x5c[0]));
                }
                else {
                    Log.error("RSA key missing key material", key);
                    return Promise.reject(new Error("RSA key missing key material"));
                }
            }
            else if (key.kty === "EC") {
                if (key.crv && key.x && key.y) {
                    key = KeyUtil$1.getKey(key);
                }
                else {
                    Log.error("EC key missing key material", key);
                    return Promise.reject(new Error("EC key missing key material"));
                }
            }
            else {
                Log.error("Unsupported key type", key && key.kty);
                return Promise.reject(new Error("Unsupported key type: " + key && key.kty));
            }

            return JoseUtil._validateJwt(jwt, key, issuer, audience, clockSkew, now);
        }
        catch (e) {
            Log.error(e && e.message || e);
            return Promise.reject("JWT validation failed");
        }
    }

    static _validateJwt(jwt, key, issuer, audience, clockSkew, now) {
        Log.debug("JoseUtil._validateJwt");

        if (!clockSkew) {
            clockSkew = 0;
        }

        if (!now) {
            now = parseInt(Date.now() / 1000);
        }

        var payload = JoseUtil.parseJwt(jwt).payload;

        if (!payload.iss) {
            Log.error("issuer was not provided");
            return Promise.reject(new Error("issuer was not provided"));
        }
        if (payload.iss !== issuer) {
            Log.error("Invalid issuer in token", payload.iss);
            return Promise.reject(new Error("Invalid issuer in token: " + payload.iss));
        }

        if (!payload.aud) {
            Log.error("aud was not provided");
            return Promise.reject(new Error("aud was not provided"));
        }
        var validAudience = payload.aud === audience || (Array.isArray(payload.aud) && payload.aud.indexOf(audience) >= 0);
        if (!validAudience) {
            Log.error("Invalid audience in token", payload.aud);
            return Promise.reject(new Error("Invalid audience in token: " + payload.aud));
        }

        var lowerNow = now + clockSkew;
        var upperNow = now - clockSkew;

        if (!payload.iat) {
            Log.error("iat was not provided");
            return Promise.reject(new Error("iat was not provided"));
        }
        if (lowerNow < payload.iat) {
            Log.error("iat is in the future", payload.iat);
            return Promise.reject(new Error("iat is in the future: " + payload.iat));
        }

        if (payload.nbf && lowerNow < payload.nbf) {
            Log.error("nbf is in the future", payload.nbf);
            return Promise.reject(new Error("nbf is in the future: " + payload.nbf));
        }

        if (!payload.exp) {
            Log.error("exp was not provided");
            return Promise.reject(new Error("exp was not provided"));
        }
        if (payload.exp < upperNow) {
            Log.error("exp is in the past", payload.exp);
            return Promise.reject(new Error("exp is in the past:" + payload.exp));
        }

        try {
            if (!jws$1.JWS.verify(jwt, key, AllowedSigningAlgs$1)) {
                Log.error("signature validation failed");
                return Promise.reject(new Error("signature validation failed"));
            }
        }
        catch (e) {
            Log.error(e && e.message || e);
            return Promise.reject(new Error("signature validation failed"));
        }

        return Promise.resolve();
    }

    static hashString(value, alg) {
        Log.debug("JoseUtil.hashString", value, alg);
        try {
            return crypto$1.Util.hashString(value, alg);
        }
        catch (e) {
            Log.error(e);
        }
    }

    static hexToBase64Url(value) {
        Log.debug("JoseUtil.hexToBase64Url", value);
        try {
            return hextob64u$1(value);
        }
        catch (e) {
            Log.error(e);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const ProtocolClaims = ["nonce", "at_hash", "iat", "nbf", "exp", "aud", "iss", "c_hash"];

class ResponseValidator {

    constructor(settings, MetadataServiceCtor = MetadataService, UserInfoServiceCtor = UserInfoService, joseUtil = JoseUtil) {
        if (!settings) {
            Log.error("No settings passed to ResponseValidator");
            throw new Error("settings");
        }

        this._settings = settings;
        this._metadataService = new MetadataServiceCtor(this._settings);
        this._userInfoService = new UserInfoServiceCtor(this._settings);
        this._joseUtil = joseUtil;
    }

    validateSigninResponse(state, response) {
        Log.debug("ResponseValidator.validateSigninResponse");

        return this._processSigninParams(state, response).then(response => {
            Log.debug("state processed");
            return this._validateTokens(state, response).then(response => {
                Log.debug("tokens validated");
                return this._processClaims(response).then(response => {
                    Log.debug("claims processed");
                    return response;
                });
            });
        });
    }

    validateSignoutResponse(state, response) {
        Log.debug("ResponseValidator.validateSignoutResponse");

        if (state.id !== response.state) {
            Log.error("State does not match");
            return Promise.reject(new Error("State does not match"));
        }

        // now that we know the state matches, take the stored data
        // and set it into the response so callers can get their state
        // this is important for both success & error outcomes
        Log.debug("state validated");
        response.state = state.data;

        if (response.error) {
            Log.warn("Response was error", response.error);
            return Promise.reject(new ErrorResponse(response));
        }

        return Promise.resolve(response);
    }

    _processSigninParams(state, response) {
        Log.debug("ResponseValidator._processSigninParams");

        if (state.id !== response.state) {
            Log.error("State does not match");
            return Promise.reject(new Error("State does not match"));
        }
        
        if (!state.client_id) {
            Log.error("No client_id on state");
            return Promise.reject(new Error("No client_id on state"));
        }
        
        if (!state.authority) {
            Log.error("No authority on state");
            return Promise.reject(new Error("No authority on state"));
        }
        
        // this allows the authority to be loaded from the signin state
        if (!this._settings.authority) {
            this._settings.authority = state.authority;
        }
        // ensure we're using the correct authority if the authority is not loaded from signin state
        else if (this._settings.authority && this._settings.authority !== state.authority) {
            Log.error("authority mismatch on settings vs. signin state");
            return Promise.reject(new Error("authority mismatch on settings vs. signin state"));
        }
        // this allows the client_id to be loaded from the signin state
        if (!this._settings.client_id) {
            this._settings.client_id = state.client_id;
        }
        // ensure we're using the correct client_id if the client_id is not loaded from signin state
        else if (this._settings.client_id && this._settings.client_id !== state.client_id) {
            Log.error("client_id mismatch on settings vs. signin state");
            return Promise.reject(new Error("client_id mismatch on settings vs. signin state"));
        }
        
        // now that we know the state matches, take the stored data
        // and set it into the response so callers can get their state
        // this is important for both success & error outcomes
        Log.debug("state validated");
        response.state = state.data;

        if (response.error) {
            Log.warn("Response was error", response.error);
            return Promise.reject(new ErrorResponse(response));
        }

        if (state.nonce && !response.id_token) {
            Log.error("Expecting id_token in response");
            return Promise.reject(new Error("No id_token in response"));
        }

        if (!state.nonce && response.id_token) {
            Log.error("Not expecting id_token in response");
            return Promise.reject(new Error("Unexpected id_token in response"));
        }

        return Promise.resolve(response);
    }

    _processClaims(response) {
        Log.debug("ResponseValidator._processClaims");

        if (response.isOpenIdConnect) {
            Log.debug("response is OIDC, processing claims");

            response.profile = this._filterProtocolClaims(response.profile);

            if (this._settings.loadUserInfo && response.access_token) {
                Log.debug("loading user info");

                return this._userInfoService.getClaims(response.access_token).then(claims => {
                    Log.debug("user info claims received from user info endpoint");

                    if (claims.sub !== response.profile.sub) {
                        Log.error("sub from user info endpoint does not match sub in access_token");
                        return Promise.reject(new Error("sub from user info endpoint does not match sub in access_token"));
                    }

                    response.profile = this._mergeClaims(response.profile, claims);
                    Log.debug("user info claims received, updated profile:", response.profile);

                    return response;
                });
            }
            else {
                Log.debug("not loading user info");
            }
        }
        else {
            Log.debug("response is not OIDC, not processing claims");
        }

        return Promise.resolve(response);
    }

    _mergeClaims(claims1, claims2) {
        var result = Object.assign({}, claims1);

        for (let name in claims2) {
            var values = claims2[name];
            if (!Array.isArray(values)) {
                values = [values];
            }

            for (let value of values) {
                if (!result[name]) {
                    result[name] = value;
                }
                else if (Array.isArray(result[name])) {
                    if (result[name].indexOf(value) < 0) {
                        result[name].push(value);
                    }
                }
                else if (result[name] !== value) {
                    result[name] = [result[name], value];
                }
            }
        }

        return result;
    }

    _filterProtocolClaims(claims) {
        Log.debug("ResponseValidator._filterProtocolClaims, incoming claims:", claims);

        var result = Object.assign({}, claims);

        if (this._settings._filterProtocolClaims) {
            ProtocolClaims.forEach(type => {
                delete result[type];
            });

            Log.debug("protocol claims filtered", result);
        }
        else {
            Log.debug("protocol claims not filtered");
        }

        return result;
    }

    _validateTokens(state, response) {
        Log.debug("ResponseValidator._validateTokens");

        if (response.id_token) {

            if (response.access_token) {
                Log.debug("Validating id_token and access_token");
                return this._validateIdTokenAndAccessToken(state, response);
            }

            Log.debug("Validating id_token");
            return this._validateIdToken(state, response);
        }

        Log.debug("No id_token to validate");
        return Promise.resolve(response);
    }

    _validateIdTokenAndAccessToken(state, response) {
        Log.debug("ResponseValidator._validateIdTokenAndAccessToken");

        return this._validateIdToken(state, response).then(response => {
            return this._validateAccessToken(response);
        });
    }

    _validateIdToken(state, response) {
        Log.debug("ResponseValidator._validateIdToken");

        if (!state.nonce) {
            Log.error("No nonce on state");
            return Promise.reject(new Error("No nonce on state"));
        }
        
        let jwt = this._joseUtil.parseJwt(response.id_token);
        if (!jwt || !jwt.header || !jwt.payload) {
            Log.error("Failed to parse id_token", jwt);
            return Promise.reject(new Error("Failed to parse id_token"));
        }

        if (state.nonce !== jwt.payload.nonce) {
            Log.error("Invalid nonce in id_token");
            return Promise.reject(new Error("Invalid nonce in id_token"));
        }

        var kid = jwt.header.kid;

        return this._metadataService.getIssuer().then(issuer => {
            Log.debug("Received issuer");

            return this._metadataService.getSigningKeys().then(keys => {
                if (!keys) {
                    Log.error("No signing keys from metadata");
                    return Promise.reject(new Error("No signing keys from metadata"));
                }

                Log.debug("Received signing keys");
                let key;
                if (!kid) {
                    keys = this._filterByAlg(keys, jwt.header.alg);

                    if (keys.length > 1) {
                        Log.error("No kid found in id_token and more than one key found in metadata");
                        return Promise.reject(new Error("No kid found in id_token and more than one key found in metadata"));
                    } 
                    else {
                        // kid is mandatory only when there are multiple keys in the referenced JWK Set document
                        // see http://openid.net/specs/openid-connect-core-1_0.html#Signing
                        key = keys[0];
                    }
                }
                else {
                    key = keys.filter(key => {
                        return key.kid === kid;
                    })[0];
                }

                if (!key) {
                    Log.error("No key matching kid or alg found in signing keys");
                    return Promise.reject(new Error("No key matching kid or alg found in signing keys"));
                }

                let audience = state.client_id;
                
                let clockSkewInSeconds = this._settings.clockSkew;
                Log.debug("Validaing JWT; using clock skew (in seconds) of: ", clockSkewInSeconds);

                return this._joseUtil.validateJwt(response.id_token, key, issuer, audience, clockSkewInSeconds).then(()=>{
                    Log.debug("JWT validation successful");
                    
                    if (!jwt.payload.sub) {
                        Log.error("No sub present in id_token");
                        return Promise.reject(new Error("No sub present in id_token"));
                    }

                    response.profile = jwt.payload;
                    
                    return response;
                });
            });
        });
    }

    _filterByAlg(keys, alg){
        Log.debug("ResponseValidator._filterByAlg", alg);

        var kty = null;
        if (alg.startsWith("RS")) {
            kty = "RSA";
        }
        else if (alg.startsWith("PS")) {
            kty = "PS";
        }
        else if (alg.startsWith("ES")) {
            kty = "EC";
        }
        else {
            Log.debug("alg not supported: ", alg);
            return [];
        }
        
        Log.debug("Looking for keys that match kty: ", kty);

        keys = keys.filter(key => {
            return key.kty === kty;
        });

        Log.debug("Number of keys that match kty: ", kty, keys.length);

        return keys;
    }

    _validateAccessToken(response) {
        Log.debug("ResponseValidator._validateAccessToken");

        if (!response.profile) {
            Log.error("No profile loaded from id_token");
            return Promise.reject(new Error("No profile loaded from id_token"));
        }

        if (!response.profile.at_hash) {
            Log.error("No at_hash in id_token");
            return Promise.reject(new Error("No at_hash in id_token"));
        }

        if (!response.id_token) {
            Log.error("No id_token");
            return Promise.reject(new Error("No id_token"));
        }

        let jwt = this._joseUtil.parseJwt(response.id_token);
        if (!jwt || !jwt.header) {
            Log.error("Failed to parse id_token", jwt);
            return Promise.reject(new Error("Failed to parse id_token"));
        }

        var hashAlg = jwt.header.alg;
        if (!hashAlg || hashAlg.length !== 5) {
            Log.error("Unsupported alg:", hashAlg);
            return Promise.reject(new Error("Unsupported alg: " + hashAlg));
        }

        var hashBits = hashAlg.substr(2, 3);
        if (!hashBits) {
            Log.error("Unsupported alg:", hashAlg, hashBits);
            return Promise.reject(new Error("Unsupported alg: " + hashAlg));
        }

        hashBits = parseInt(hashBits);
        if (hashBits !== 256 && hashBits !== 384 && hashBits !== 512) {
            Log.error("Unsupported alg:", hashAlg, hashBits);
            return Promise.reject(new Error("Unsupported alg: " + hashAlg));
        }

        let sha = "sha" + hashBits;
        var hash = this._joseUtil.hashString(response.access_token, sha);
        if (!hash) {
            Log.error("access_token hash failed:", sha);
            return Promise.reject(new Error("Failed to validate at_hash"));
        }

        var left = hash.substr(0, hash.length / 2);
        var left_b64u = this._joseUtil.hexToBase64Url(left);
        if (left_b64u !== response.profile.at_hash) {
            Log.error("Failed to validate at_hash", left_b64u, response.profile.at_hash);
            return Promise.reject(new Error("Failed to validate at_hash"));
        }

        return Promise.resolve(response);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const OidcMetadataUrlPath$1 = '.well-known/openid-configuration';

const DefaultResponseType = "id_token";
const DefaultScope = "openid";
const DefaultStaleStateAge = 60 * 5; // seconds
const DefaultClockSkewInSeconds = 60 * 5;

class OidcClientSettings {
    constructor({
        // metadata related
        authority, metadataUrl, metadata, signingKeys,
        // client related
        client_id, client_secret, response_type = DefaultResponseType, scope = DefaultScope,
        redirect_uri, post_logout_redirect_uri,
        // optional protocol
        prompt, display, max_age, ui_locales, acr_values, resource,
        // behavior flags
        filterProtocolClaims = true, loadUserInfo = true,
        staleStateAge = DefaultStaleStateAge, clockSkew = DefaultClockSkewInSeconds,
        // other behavior
        stateStore = new WebStorageStateStore(),
        ResponseValidatorCtor = ResponseValidator,
        MetadataServiceCtor = MetadataService,
        // extra query params
        extraQueryParams = {}
    } = {}) {

        this._authority = authority;
        this._metadataUrl = metadataUrl;
        this._metadata = metadata;
        this._signingKeys = signingKeys;

        this._client_id = client_id;
        this._client_secret = client_secret;
        this._response_type = response_type;
        this._scope = scope;
        this._redirect_uri = redirect_uri;
        this._post_logout_redirect_uri = post_logout_redirect_uri;

        this._prompt = prompt;
        this._display = display;
        this._max_age = max_age;
        this._ui_locales = ui_locales;
        this._acr_values = acr_values;
        this._resource = resource;

        this._filterProtocolClaims = !!filterProtocolClaims;
        this._loadUserInfo = !!loadUserInfo;
        this._staleStateAge = staleStateAge;
        this._clockSkew = clockSkew;

        this._stateStore = stateStore;
        this._validator = new ResponseValidatorCtor(this);
        this._metadataService = new MetadataServiceCtor(this);

        this._extraQueryParams = typeof extraQueryParams === 'object' ? extraQueryParams : {};
    }

    // client config
    get client_id() {
        return this._client_id;
    }
    set client_id(value) {
        if (!this._client_id) {
            // one-time set only
            this._client_id = value;
        }
        else {
            Log.error("client_id has already been assigned.");
            throw new Error("client_id has already been assigned.")
        }
    }
    get client_secret() {
        return this._client_secret;
    }
    get response_type() {
        return this._response_type;
    }
    get scope() {
        return this._scope;
    }
    get redirect_uri() {
        return this._redirect_uri;
    }
    get post_logout_redirect_uri() {
        return this._post_logout_redirect_uri;
    }


    // optional protocol params
    get prompt() {
        return this._prompt;
    }
    get display() {
        return this._display;
    }
    get max_age() {
        return this._max_age;
    }
    get ui_locales() {
        return this._ui_locales;
    }
    get acr_values() {
        return this._acr_values;
    }
    get resource() {
        return this._resource;
    }


    // metadata
    get authority() {
        return this._authority;
    }
    set authority(value) {
        if (!this._authority) {
            // one-time set only
            this._authority = value;
        }
        else {
            Log.error("authority has already been assigned.");
            throw new Error("authority has already been assigned.")
        }
    }
    get metadataUrl() {
        if (!this._metadataUrl) {
            this._metadataUrl = this.authority;

            if (this._metadataUrl && this._metadataUrl.indexOf(OidcMetadataUrlPath$1) < 0) {
                if (this._metadataUrl[this._metadataUrl.length - 1] !== '/') {
                    this._metadataUrl += '/';
                }
                this._metadataUrl += OidcMetadataUrlPath$1;
            }
        }

        return this._metadataUrl;
    }

    // settable/cachable metadata values
    get metadata() {
        return this._metadata;
    }
    set metadata(value) {
        this._metadata = value;
    }

    get signingKeys() {
        return this._signingKeys;
    }
    set signingKeys(value) {
        this._signingKeys = value;
    }

    // behavior flags
    get filterProtocolClaims() {
        return this._filterProtocolClaims;
    }
    get loadUserInfo() {
        return this._loadUserInfo;
    }
    get staleStateAge() {
        return this._staleStateAge;
    }
    get clockSkew() {
        return this._clockSkew;
    }

    get stateStore() {
        return this._stateStore;
    }
    get validator() {
        return this._validator;
    }
    get metadataService() {
        return this._metadataService;
    }

    // extra query params
    get extraQueryParams() {
        return this._extraQueryParams;
    }
    set extraQueryParams(value) {
        if (typeof value === 'object'){
            this._extraQueryParams = value;
        } else {
            this._extraQueryParams = {};
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class UrlUtility {
    static addQueryParam(url, name, value) {
        if (url.indexOf('?') < 0) {
            url += "?";
        }

        if (url[url.length - 1] !== "?") {
            url += "&";
        }

        url += encodeURIComponent(name);
        url += "=";
        url += encodeURIComponent(value);

        return url;
    }

    static parseUrlFragment(value, delimiter = "#", global = Global) {
        Log.debug("UrlUtility.parseUrlFragment");

        if (typeof value !== 'string'){
            value = global.location.href;
        }

        var idx = value.lastIndexOf(delimiter);
        if (idx >= 0) {
            value = value.substr(idx + 1);
        }

        var params = {},
            regex = /([^&=]+)=([^&]*)/g,
            m;

        var counter = 0;
        while (m = regex.exec(value)) {
            params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
            if (counter++ > 50) {
                Log.error("response exceeded expected number of parameters", value);
                return {
                    error: "Response exceeded expected number of parameters"
                };
            }
        }

        for (var prop in params) {
            return params;
        }
        
        return {};
    }
}

// NOTICE: the code in this file originally developed by Microsoft
// original source: https://github.com/AzureAD/azure-activedirectory-library-for-js/blob/master/lib/adal.js#L1029
//----------------------------------------------------------------------
// AdalJS v1.0.8
// @preserve Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

function random() {
    var guidHolder = 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx';
    var hex = '0123456789abcdef';
    var r = 0;
    var guidResponse = "";
    for (var i = 0; i < guidHolder.length; i++) {
        if (guidHolder[i] !== '-' && guidHolder[i] !== '4') {
            // each x and y needs to be random
            r = Math.random() * 16 | 0;
        }

        if (guidHolder[i] === 'x') {
            guidResponse += hex[r];
        } else if (guidHolder[i] === 'y') {
            // clock-seq-and-reserved first hex is filtered and remaining hex values are random
            r &= 0x3; // bit and with 0011 to set pos 2 to zero ?0??
            r |= 0x8; // set pos 3 to 1 as 1???
            guidResponse += hex[r];
        } else {
            guidResponse += guidHolder[i];
        }
    }
    return guidResponse;
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class State {
    constructor({id, data, created} = {}) {
        this._id = id || random();
        this._data = data;

        if (typeof created === 'number' && created > 0) {
            this._created = created;
        }
        else {
            this._created = parseInt(Date.now() / 1000);
        }
    }

    get id() {
        return this._id;
    }
    get data() {
        return this._data;
    }
    get created() {
        return this._created;
    }

    toStorageString() {
        Log.debug("State.toStorageString");
        return JSON.stringify({
            id: this.id,
            data: this.data,
            created: this.created
        });
    }
    
    static fromStorageString(storageString) {
        Log.debug("State.fromStorageString");
        return new State(JSON.parse(storageString));
    }

    static clearStaleState(storage, age) {
        Log.debug("State.clearStaleState");

        var cutoff = Date.now() / 1000 - age;

        return storage.getAllKeys().then(keys => {
            Log.debug("got keys", keys);

            var promises = [];
            for (let key of keys) {
                var p = storage.get(key).then(item => {
                    let remove = false;

                    if (item) {
                        try {
                            var state = State.fromStorageString(item);

                            Log.debug("got item from key: ", key, state.created);

                            if (state.created <= cutoff) {
                                remove = true;
                            }
                        }
                        catch (e) {
                            Log.error("Error parsing state for key", key, e.message);
                            remove = true;
                        }
                    }
                    else {
                        Log.debug("no item in storage for key: ", key);
                        remove = true;
                    }

                    if (remove) {
                        Log.debug("removed item for key: ", key);
                        return storage.remove(key);
                    }
                });

                promises.push(p);
            }

            Log.debug("waiting on promise count:", promises.length);
            return Promise.all(promises);
        });
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class SigninState extends State {
    constructor({nonce, authority, client_id} = {}) {
        super(arguments[0]);
        
        if (nonce === true) {
            this._nonce = random();
        }
        else if (nonce) {
            this._nonce = nonce;
        }
        
        this._authority = authority;
        this._client_id = client_id;
    }

    get nonce() {
        return this._nonce;
    }
    get authority() {
        return this._authority;
    }
    get client_id() {
        return this._client_id;
    }
    
    toStorageString() {
        Log.debug("SigninState.toStorageString");
        return JSON.stringify({
            id: this.id,
            data: this.data,
            created: this.created,
            nonce: this.nonce,
            authority: this.authority,
            client_id: this.client_id
        });
    }

    static fromStorageString(storageString) {
        Log.debug("SigninState.fromStorageString");
        var data = JSON.parse(storageString);
        return new SigninState(data);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class SigninRequest {
    constructor({
        // mandatory
        url, client_id, redirect_uri, response_type, scope, authority,
        // optional
        data, prompt, display, max_age, ui_locales, id_token_hint, login_hint, acr_values, resource,
        request, request_uri, extraQueryParams,
    }) {
        if (!url) {
            Log.error("No url passed to SigninRequest");
            throw new Error("url");
        }
        if (!client_id) {
            Log.error("No client_id passed to SigninRequest");
            throw new Error("client_id");
        }
        if (!redirect_uri) {
            Log.error("No redirect_uri passed to SigninRequest");
            throw new Error("redirect_uri");
        }
        if (!response_type) {
            Log.error("No response_type passed to SigninRequest");
            throw new Error("response_type");
        }
        if (!scope) {
            Log.error("No scope passed to SigninRequest");
            throw new Error("scope");
        }
        if (!authority) {
            Log.error("No authority passed to SigninRequest");
            throw new Error("authority");
        }

        let oidc = SigninRequest.isOidc(response_type);
        this.state = new SigninState({ nonce: oidc, data, client_id, authority });

        url = UrlUtility.addQueryParam(url, "client_id", client_id);
        url = UrlUtility.addQueryParam(url, "redirect_uri", redirect_uri);
        url = UrlUtility.addQueryParam(url, "response_type", response_type);
        url = UrlUtility.addQueryParam(url, "scope", scope);
        
        url = UrlUtility.addQueryParam(url, "state", this.state.id);
        if (oidc) {
            url = UrlUtility.addQueryParam(url, "nonce", this.state.nonce);
        }

        var optional = { prompt, display, max_age, ui_locales, id_token_hint, login_hint, acr_values, resource, request, request_uri };
        for(let key in optional){
            if (optional[key]) {
                url = UrlUtility.addQueryParam(url, key, optional[key]);
            }
        }

        for(let key in extraQueryParams){
            url = UrlUtility.addQueryParam(url, key, extraQueryParams[key]);
        }

        this.url = url;
    }

    static isOidc(response_type) {
        var result = response_type.split(/\s+/g).filter(function(item) {
            return item === "id_token";
        });
        return !!(result[0]);
    }
    
    static isOAuth(response_type) {
        var result = response_type.split(/\s+/g).filter(function(item) {
            return item === "token";
        });
        return !!(result[0]);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const OidcScope = "openid";

class SigninResponse {
    constructor(url) {

        var values = UrlUtility.parseUrlFragment(url, "#");

        this.error = values.error;
        this.error_description = values.error_description;
        this.error_uri = values.error_uri;
        
        this.state = values.state;
        this.id_token = values.id_token;
        this.session_state = values.session_state;
        this.access_token = values.access_token;
        this.token_type = values.token_type;
        this.scope = values.scope;
        this.profile = undefined; // will be set from ResponseValidator

        let expires_in = parseInt(values.expires_in);
        if (typeof expires_in === 'number' && expires_in > 0) {
            let now = parseInt(Date.now() / 1000);
            this.expires_at = now + expires_in;
        }
    }

    get expires_in() {
        if (this.expires_at) {
            let now = parseInt(Date.now() / 1000);
            return this.expires_at - now;
        }
        return undefined;
    }

    get expired() {
        let expires_in = this.expires_in;
        if (expires_in !== undefined) {
            return expires_in <= 0;
        }
        return undefined;
    }

    get scopes() {
        return (this.scope || "").split(" ");
    }
    
    get isOpenIdConnect() {
        return this.scopes.indexOf(OidcScope) >= 0 || !!this.id_token;
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class SignoutRequest {
    constructor({url, id_token_hint, post_logout_redirect_uri, data}) {
        if (!url) {
            Log.error("No url passed to SignoutRequest");
            throw new Error("url");
        }

        if (id_token_hint) {
            url = UrlUtility.addQueryParam(url, "id_token_hint", id_token_hint);
        }
        
        if (post_logout_redirect_uri) {
            url = UrlUtility.addQueryParam(url, "post_logout_redirect_uri", post_logout_redirect_uri);
            
            if (data) {
                this.state = new State({ data });
                
                url = UrlUtility.addQueryParam(url, "state", this.state.id);
            }
        }
        
        this.url = url;
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class SignoutResponse {
    constructor(url) {

        var values = UrlUtility.parseUrlFragment(url, "?");

        this.error = values.error;
        this.error_description = values.error_description;
        this.error_uri = values.error_uri;

        this.state = values.state;
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class OidcClient {
    constructor(settings = {}) {
        if (settings instanceof OidcClientSettings) {
            this._settings = settings;
        }
        else {
            this._settings = new OidcClientSettings(settings);
        }
    }

    get _stateStore() {
        return this.settings.stateStore;
    }
    get _validator() {
        return this.settings.validator;
    }
    get _metadataService() {
        return this.settings.metadataService;
    }

    get settings() {
        return this._settings;
    }
    get metadataService() {
        return this._metadataService;
    }

    createSigninRequest({
        response_type, scope, redirect_uri, 
        // data was meant to be the place a caller could indicate the data to
        // have round tripped, but people were getting confused, so i added state (since that matches the spec) 
        // and so now if data is not passed, but state is then state will be used
        data, state, prompt, display, max_age, ui_locales, id_token_hint, login_hint, acr_values,
        resource, request, request_uri, extraQueryParams } = {},
        stateStore
    ) {
        Log.debug("OidcClient.createSigninRequest");

        let client_id = this._settings.client_id;
        response_type = response_type || this._settings.response_type;
        scope = scope || this._settings.scope;
        redirect_uri = redirect_uri || this._settings.redirect_uri;

        // id_token_hint, login_hint aren't allowed on _settings
        prompt = prompt || this._settings.prompt;
        display = display || this._settings.display;
        max_age = max_age || this._settings.max_age;
        ui_locales = ui_locales || this._settings.ui_locales;
        acr_values = acr_values || this._settings.acr_values;
        resource = resource || this._settings.resource;
        extraQueryParams = extraQueryParams || this._settings.extraQueryParams;
        
        let authority = this._settings.authority;

        return this._metadataService.getAuthorizationEndpoint().then(url => {
            Log.debug("Received authorization endpoint", url);

            let signinRequest = new SigninRequest({
                url,
                client_id,
                redirect_uri,
                response_type,
                scope,
                data: data || state,
                authority,
                prompt, display, max_age, ui_locales, id_token_hint, login_hint, acr_values,
                resource, request, request_uri, extraQueryParams,
            });

            var signinState = signinRequest.state;
            stateStore = stateStore || this._stateStore;

            return stateStore.set(signinState.id, signinState.toStorageString()).then(() => {
                return signinRequest;
            });
        });
    }

    processSigninResponse(url, stateStore) {
        Log.debug("OidcClient.processSigninResponse");

        var response = new SigninResponse(url);

        if (!response.state) {
            Log.error("No state in response");
            return Promise.reject(new Error("No state in response"));
        }

        stateStore = stateStore || this._stateStore;

        return stateStore.remove(response.state).then(storedStateString => {
            if (!storedStateString) {
                Log.error("No matching state found in storage");
                throw new Error("No matching state found in storage");
            }

            let state = SigninState.fromStorageString(storedStateString);

            Log.debug("Received state from storage; validating response");
            return this._validator.validateSigninResponse(state, response);
        });
    }

    createSignoutRequest({id_token_hint, data, state, post_logout_redirect_uri} = {},
        stateStore
    ) {
        Log.debug("OidcClient.createSignoutRequest");

        post_logout_redirect_uri = post_logout_redirect_uri || this._settings.post_logout_redirect_uri;

        return this._metadataService.getEndSessionEndpoint().then(url => {
            if (!url) {
                Log.error("No end session endpoint url returned");
                throw new Error("no end session endpoint");
            }

            Log.debug("Received end session endpoint", url);

            let request = new SignoutRequest({
                url,
                id_token_hint,
                post_logout_redirect_uri,
                data: data || state
            });

            var signoutState = request.state;
            if (signoutState) {
                Log.debug("Signout request has state to persist");

                stateStore = stateStore || this._stateStore;
                stateStore.set(signoutState.id, signoutState.toStorageString());
            }

            return request;
        });
    }

    processSignoutResponse(url, stateStore) {
        Log.debug("OidcClient.processSignoutResponse");

        var response = new SignoutResponse(url);
        if (!response.state) {
            Log.debug("No state in response");

            if (response.error) {
                Log.warn("Response was error", response.error);
                return Promise.reject(new ErrorResponse(response));
            }

            return Promise.resolve(response);
        }

        var stateKey = response.state;

        stateStore = stateStore || this._stateStore;

        return stateStore.remove(stateKey).then(storedStateString => {
            if (!storedStateString) {
                Log.error("No matching state found in storage");
                throw new Error("No matching state found in storage");
            }

            let state = State.fromStorageString(storedStateString);

            Log.debug("Received state from storage; validating response");
            return this._validator.validateSignoutResponse(state, response);
        });
    }

    clearStaleState(stateStore) {
        Log.debug("OidcClient.clearStaleState");

        stateStore = stateStore || this._stateStore;

        return State.clearStaleState(stateStore, this.settings.staleStateAge);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class InMemoryWebStorage{
    constructor(){
        this._data = {};
    }
    
    getItem(key) {
        Log.debug("InMemoryWebStorage.getItem", key);
        return this._data[key];
    }
    
    setItem(key, value){
        Log.debug("InMemoryWebStorage.setItem", key);
        this._data[key] = value;
    }   
    
    removeItem(key){
        Log.debug("InMemoryWebStorage.removeItem", key);
        delete this._data[key];
    }
    
    get length() {
        return Object.getOwnPropertyNames(this._data).length;
    }
    
    key(index) {
        return Object.getOwnPropertyNames(this._data)[index];
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class RedirectNavigator {
    
    prepare() {
        return Promise.resolve(this);
    }

    navigate(params) {
        Log.debug("RedirectNavigator.navigate");
        
        if (!params || !params.url) {
            Log.error("No url provided");
            return Promise.reject(new Error("No url provided"));
        }

        window.location = params.url;
        
        return Promise.resolve();
    }

    get url() {
        Log.debug("RedirectNavigator.url");
        return window.location.href;
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const CheckForPopupClosedInterval = 500;
const DefaultPopupFeatures = 'location=no,toolbar=no,width=500,height=500,left=100,top=100;';
//const DefaultPopupFeatures = 'location=no,toolbar=no,width=500,height=500,left=100,top=100;resizable=yes';

const DefaultPopupTarget = "_blank";

class PopupWindow {

    constructor(params) {
        Log.debug("PopupWindow.ctor");

        this._promise = new Promise((resolve, reject) => {
            this._resolve = resolve;
            this._reject = reject;
        });

        let target = params.popupWindowTarget || DefaultPopupTarget;
        let features = params.popupWindowFeatures || DefaultPopupFeatures;

        this._popup = window.open('', target, features);
        if (this._popup) {
            Log.debug("popup successfully created");
            this._checkForPopupClosedTimer = window.setInterval(this._checkForPopupClosed.bind(this), CheckForPopupClosedInterval);
        }
    }

    get promise() {
        return this._promise;
    }

    navigate(params) {
        Log.debug("PopupWindow.navigate");

        if (!this._popup) {
            this._error("Error opening popup window");
        }
        else if (!params || !params.url) {
            this._error("No url provided");
        }
        else {
            Log.debug("Setting URL in popup");

            this._id = params.id;
            if (this._id) {
                window["popupCallback_" + params.id] = this._callback.bind(this);
            }

            this._popup.focus();
            this._popup.window.location = params.url;
        }

        return this.promise;
    }

    _success(data) {
        this._cleanup();

        Log.debug("Successful response from popup window");
        this._resolve(data);
    }
    _error(message) {
        this._cleanup();

        Log.error(message);
        this._reject(new Error(message));
    }

    close() {
        this._cleanup(false);
    }

    _cleanup(keepOpen) {
        Log.debug("PopupWindow._cleanup");

        window.clearInterval(this._checkForPopupClosedTimer);
        this._checkForPopupClosedTimer = null;

        delete window["popupCallback_" + this._id];

        if (this._popup && !keepOpen) {
            this._popup.close();
        }
        this._popup = null;
    }

    _checkForPopupClosed() {
        Log.debug("PopupWindow._checkForPopupClosed");

        if (!this._popup || this._popup.closed) {
            this._error("Popup window closed");
        }
    }

    _callback(url, keepOpen) {
        Log.debug("PopupWindow._callback");

        this._cleanup(keepOpen);

        if (url) {
            this._success({ url: url });
        }
        else {
            this._error("Invalid response from popup");
        }
    }

    static notifyOpener(url, keepOpen, delimiter) {
        Log.debug("PopupWindow.notifyOpener");

        if (window.opener) {
            url = url || window.location.href;
            if (url) {

                var data = UrlUtility.parseUrlFragment(url, delimiter);
                
                if (data.state) {
                    var name = "popupCallback_" + data.state;
                    var callback = window.opener[name]; 
                    if (callback) {
                        Log.debug("passing url message to opener");
                        callback(url, keepOpen);
                    }
                    else {
                        Log.warn("no matching callback found on opener");
                    }
                }
                else {
                    Log.warn("no state found in response url");
                }
            }
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class PopupNavigator {
    
    prepare(params) {
        let popup = new PopupWindow(params);
        return Promise.resolve(popup);
    }
    
    callback(url, keepOpen, delimiter) {
        Log.debug("PopupNavigator.callback");

        try {
            PopupWindow.notifyOpener(url, keepOpen, delimiter);
            return Promise.resolve();
        }
        catch (e) {
            return Promise.reject(e);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const DefaultTimeout = 10000;

class IFrameWindow {

    constructor(params) {
        Log.debug("IFrameWindow.ctor");

        this._promise = new Promise((resolve, reject) => {
            this._resolve = resolve;
            this._reject = reject;
        });

        this._boundMessageEvent = this._message.bind(this);
        window.addEventListener("message", this._boundMessageEvent, false);
        
        this._frame = window.document.createElement("iframe");

        // shotgun approach
        this._frame.style.visibility = "hidden";
        this._frame.style.position = "absolute";
        this._frame.style.display = "none";
        this._frame.style.width = 0;
        this._frame.style.height = 0;
        
        window.document.body.appendChild(this._frame);
    }

    navigate(params) {
        Log.debug("IFrameWindow.navigate");

        if (!params || !params.url) {
            this._error("No url provided");
        }
        else {
            let timeout = params.silentRequestTimeout || DefaultTimeout;
            Log.debug("Using timeout of:", timeout);
            this._timer = window.setTimeout(this._timeout.bind(this), timeout);
            this._frame.src = params.url;
        }
        
        return this.promise;
    }

    get promise() {
        return this._promise;
    }

    _success(data) {
        this._cleanup();

        Log.debug("Successful response from frame window");
        this._resolve(data);
    }
    _error(message) {
        this._cleanup();

        Log.error(message);
        this._reject(new Error(message));
    }

    close() {
        this._cleanup();
    }

    _cleanup() {
        if (this._frame) {
            Log.debug("IFrameWindow._cleanup");

            window.removeEventListener("message", this._boundMessageEvent, false);
            window.clearTimeout(this._timer);
            window.document.body.removeChild(this._frame);

            this._timer = null;
            this._frame = null;
            this._boundMessageEvent = null;
        }
    }

    _timeout() {
        Log.debug("IFrameWindow._timeout");
        this._error("Frame window timed out");
    }

    _message(e) {
        Log.debug("IFrameWindow._message");

        if (this._timer &&
            e.origin === this._origin &&
            e.source === this._frame.contentWindow
        ) {
            let url = e.data;
            if (url) {
                this._success({ url: url });
            }
            else {
                this._error("Invalid response from frame");
            }
        }
    }

    get _origin() {
        return location.protocol + "//" + location.host;
    }

    static notifyParent(url) {
        Log.debug("IFrameWindow.notifyParent");

        if (window.parent && window !== window.parent) {
            url = url || window.location.href;
            if (url) {
                Log.debug("posting url message to parent");
                window.parent.postMessage(url, location.protocol + "//" + location.host);
            }
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class IFrameNavigator {

    prepare(params) {
        let frame = new IFrameWindow(params);
        return Promise.resolve(frame);
    }

    callback(url) {
        Log.debug("IFrameNavigator.callback");

        try {
            IFrameWindow.notifyParent(url);
            return Promise.resolve();
        }
        catch (e) {
            return Promise.reject(e);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const DefaultAccessTokenExpiringNotificationTime = 60;
const DefaultCheckSessionInterval = 2000;

class UserManagerSettings extends OidcClientSettings {
    constructor({
        popup_redirect_uri,
        popup_post_logout_redirect_uri,
        popupWindowFeatures,
        popupWindowTarget,
        silent_redirect_uri,
        silentRequestTimeout,
        automaticSilentRenew = false,
        includeIdTokenInSilentRenew = true,
        monitorSession = true,
        checkSessionInterval = DefaultCheckSessionInterval,
        revokeAccessTokenOnSignout = false,
        accessTokenExpiringNotificationTime = DefaultAccessTokenExpiringNotificationTime,
        redirectNavigator = new RedirectNavigator(),
        popupNavigator = new PopupNavigator(),
        iframeNavigator = new IFrameNavigator(),
        userStore = new WebStorageStateStore({ store: Global.sessionStorage })
    } = {}) {
        super(arguments[0]);

        this._popup_redirect_uri = popup_redirect_uri;
        this._popup_post_logout_redirect_uri = popup_post_logout_redirect_uri;
        this._popupWindowFeatures = popupWindowFeatures;
        this._popupWindowTarget = popupWindowTarget;
        
        this._silent_redirect_uri = silent_redirect_uri;
        this._silentRequestTimeout = silentRequestTimeout;
        this._automaticSilentRenew = !!automaticSilentRenew;
        this._includeIdTokenInSilentRenew = includeIdTokenInSilentRenew;
        this._accessTokenExpiringNotificationTime = accessTokenExpiringNotificationTime;

        this._monitorSession = monitorSession;
        this._checkSessionInterval = checkSessionInterval;
        this._revokeAccessTokenOnSignout = revokeAccessTokenOnSignout;

        this._redirectNavigator = redirectNavigator;
        this._popupNavigator = popupNavigator;
        this._iframeNavigator = iframeNavigator;
        
        this._userStore = userStore;
    }

    get popup_redirect_uri() {
        return this._popup_redirect_uri;
    }
    get popup_post_logout_redirect_uri() {
        return this._popup_post_logout_redirect_uri;
    }
    get popupWindowFeatures() {
        return this._popupWindowFeatures;
    }
    get popupWindowTarget() {
        return this._popupWindowTarget;
    }

    get silent_redirect_uri() {
        return this._silent_redirect_uri;
    }
     get silentRequestTimeout() {
        return this._silentRequestTimeout;
    }
    get automaticSilentRenew() {
        return !!(this.silent_redirect_uri && this._automaticSilentRenew);
    }
    get includeIdTokenInSilentRenew() {
        return this._includeIdTokenInSilentRenew;
    }
    get accessTokenExpiringNotificationTime() {
        return this._accessTokenExpiringNotificationTime;
    }

    get monitorSession() {
        return this._monitorSession;
    }
    get checkSessionInterval() {
        return this._checkSessionInterval;
    }
    get revokeAccessTokenOnSignout() {
        return this._revokeAccessTokenOnSignout;
    }

    get redirectNavigator() {
        return this._redirectNavigator;
    }
    get popupNavigator() {
        return this._popupNavigator;
    }
    get iframeNavigator() {
        return this._iframeNavigator;
    }
    
    get userStore() {
        return this._userStore;
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class User {
    constructor({id_token, session_state, access_token, token_type, scope, profile, expires_at, state}) {
        this.id_token = id_token;
        this.session_state = session_state;
        this.access_token = access_token;
        this.token_type = token_type;
        this.scope = scope;
        this.profile = profile;
        this.expires_at = expires_at;
        this.state = state;
    }

    get expires_in() {
        if (this.expires_at) {
            let now = parseInt(Date.now() / 1000);
            return this.expires_at - now;
        }
        return undefined;
    }

    get expired() {
        let expires_in = this.expires_in;
        if (expires_in !== undefined) {
            return expires_in <= 0;
        }
        return undefined;
    }

    get scopes() {
        return (this.scope || "").split(" ");
    }

    toStorageString() {
        Log.debug("User.toStorageString");
        return JSON.stringify({
            id_token: this.id_token,
            session_state: this.session_state,
            access_token: this.access_token,
            token_type: this.token_type,
            scope: this.scope,
            profile: this.profile,
            expires_at: this.expires_at
        });
    }

    static fromStorageString(storageString) {
        Log.debug("User.fromStorageString");
        return new User(JSON.parse(storageString));
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class Event {

    constructor(name) {
        this._name = name;
        this._callbacks = [];
    }

    addHandler(cb) {
        this._callbacks.push(cb);
    }

    removeHandler(cb) {
        var idx = this._callbacks.findIndex(item => item === cb);
        if (idx >= 0) {
            this._callbacks.splice(idx, 1);
        }
    }

    raise(...params) {
        Log.debug("Raising event: " + this._name);
        for (var cb of this._callbacks) {
            cb(...params);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const TimerDuration = 5; // seconds

class Timer extends Event {

    constructor(name, timer = Global.timer) {
        super(name);
        this._timer = timer;
        this._nowFunc = () => Date.now() / 1000;
    }

    get now() {
        return parseInt(this._nowFunc());
    }

    init(duration) {
        this.cancel();

        if (duration <= 0) {
            duration = 1;
        }
        duration = parseInt(duration);

        Log.debug("Timer.init timer " + this._name + " for duration:", duration);
        this._expiration = this.now + duration;

        // we're using a fairly short timer and then checking the expiration in the 
        // callback to handle scenarios where the browser device sleeps, and then 
        // the timers end up getting delayed.
        var timerDuration = TimerDuration;
        if (duration < timerDuration) {
            timerDuration = duration;
        }
        this._timerHandle = this._timer.setInterval(this._callback.bind(this), timerDuration * 1000);
    }

    cancel() {
        if (this._timerHandle) {
            Log.debug("Timer.cancel: ", this._name);
            this._timer.clearInterval(this._timerHandle);
            this._timerHandle = null;
        }
    }

    _callback() {
        var diff = this._expiration - this.now;
        Log.debug("Timer._callback; " + this._name + " timer expires in:", diff);

        if (this._expiration <= this.now) {
            this.cancel();
            super.raise();
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const DefaultAccessTokenExpiringNotificationTime$1 = 60; // seconds

class AccessTokenEvents {

    constructor({
        accessTokenExpiringNotificationTime = DefaultAccessTokenExpiringNotificationTime$1,
        accessTokenExpiringTimer = new Timer("Access token expiring"),
        accessTokenExpiredTimer = new Timer("Access token expired")
    } = {}) {
        this._accessTokenExpiringNotificationTime = accessTokenExpiringNotificationTime;

        this._accessTokenExpiring = accessTokenExpiringTimer;
        this._accessTokenExpired = accessTokenExpiredTimer;
    }

    load(container) {
        Log.debug("AccessTokenEvents.load");
        
        this._cancelTimers();

        // only register events if there's an access token where we care about expiration
        if (container.access_token) {
            let duration = container.expires_in;
            Log.debug("access token present, remaining duration:", duration);

            if (duration > 0) {
                // only register expiring if we still have time
                let expiring = duration - this._accessTokenExpiringNotificationTime;
                if (expiring <= 0){
                    expiring = 1;
                }
                Log.debug("registering expiring timer in:", expiring);
                this._accessTokenExpiring.init(expiring);
            }

            // always register expired. if it's negative, it will still fire
            let expired = duration + 1;
            Log.debug("registering expired timer in:", expired);
            this._accessTokenExpired.init(expired);
        }
    }

    unload() {
        Log.debug("AccessTokenEvents.unload");
        this._cancelTimers();
    }
    
    _cancelTimers(){
        Log.debug("canceling existing access token timers");
        this._accessTokenExpiring.cancel();
        this._accessTokenExpired.cancel();
    }

    addAccessTokenExpiring(cb) {
        this._accessTokenExpiring.addHandler(cb);
    }
    removeAccessTokenExpiring(cb) {
        this._accessTokenExpiring.removeHandler(cb);
    }

    addAccessTokenExpired(cb) {
        this._accessTokenExpired.addHandler(cb);
    }
    removeAccessTokenExpired(cb) {
        this._accessTokenExpired.removeHandler(cb);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class UserManagerEvents extends AccessTokenEvents {

    constructor(settings) {
        super(settings);
        this._userLoaded = new Event("User loaded");
        this._userUnloaded = new Event("User unloaded");
        this._silentRenewError = new Event("Silent renew error");
        this._userSignedOut = new Event("User signed out");
        this._userSessionChanged = new Event("User session changed");
    }

    load(user, raiseEvent=true) {
        Log.debug("UserManagerEvents.load");
        super.load(user);
        if (raiseEvent) {
            this._userLoaded.raise(user);
        }
    }
    unload() {
        Log.debug("UserManagerEvents.unload");
        super.unload();
        this._userUnloaded.raise();
    }

    addUserLoaded(cb) {
        this._userLoaded.addHandler(cb);
    }
    removeUserLoaded(cb) {
        this._userLoaded.removeHandler(cb);
    }
    
    addUserUnloaded(cb) {
        this._userUnloaded.addHandler(cb);
    }
    removeUserUnloaded(cb) {
        this._userUnloaded.removeHandler(cb);
    }

    addSilentRenewError(cb) {
        this._silentRenewError.addHandler(cb);
    }
    removeSilentRenewError(cb) {
        this._silentRenewError.removeHandler(cb);
    }
    _raiseSilentRenewError(e) {
        Log.debug("UserManagerEvents._raiseSilentRenewError", e.message);
        this._silentRenewError.raise(e);
    }

    addUserSignedOut(cb) {
        this._userSignedOut.addHandler(cb);
    }
    removeUserSignedOut(cb) {
        this._userSignedOut.removeHandler(cb);
    }
    _raiseUserSignedOut(e) {
        Log.debug("UserManagerEvents._raiseUserSignedOut");
        this._userSignedOut.raise(e);
    }

    addUserSessionChanged(cb) {
        this._userSessionChanged.addHandler(cb);
    }
    removeUserSessionChanged(cb) {
        this._userSessionChanged.removeHandler(cb);
    }
    _raiseUserSessionChanged(e) {
        Log.debug("UserManagerEvents._raiseUserSessionChanged");
        this._userSessionChanged.raise(e);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class SilentRenewService {

    constructor(userManager) {
        this._userManager = userManager;
    }

    start() {
        if (!this._callback) {
            this._callback = this._tokenExpiring.bind(this);
            this._userManager.events.addAccessTokenExpiring(this._callback);
            
            // this will trigger loading of the user so the expiring events can be initialized
            this._userManager.getUser().then(user=>{
                // deliberate nop
            }).catch(err=>{
                // catch to suppress errors since we're in a ctor
                Log.error("Error from getUser:", err.message);
            });
        }
    }

    stop() {
        if (this._callback) {
            this._userManager.events.removeAccessTokenExpiring(this._callback);
            delete this._callback;
        }
    }

    _tokenExpiring() {
        Log.debug("SilentRenewService automatically renewing access token");
        
        this._userManager.signinSilent().then(user => {
            Log.debug("Silent token renewal successful");
        }, err => {
            Log.error("Error from signinSilent:", err.message);
            this._userManager.events._raiseSilentRenewError(err);
        });
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const DefaultInterval = 2000;

class CheckSessionIFrame {
    constructor(callback, client_id, url, interval) {
        this._callback = callback;
        this._client_id = client_id;
        this._url = url;
        this._interval = interval || DefaultInterval;

        var idx = url.indexOf("/", url.indexOf("//") + 2);
        this._frame_origin = url.substr(0, idx);

        this._frame = window.document.createElement("iframe");

        // shotgun approach
        this._frame.style.visibility = "hidden";
        this._frame.style.position = "absolute";
        this._frame.style.display = "none";
        this._frame.style.width = 0;
        this._frame.style.height = 0;

        this._frame.src = url;
    }
    load() {
        return new Promise((resolve) => {
            this._frame.onload = () => {
                resolve();
            };

            window.document.body.appendChild(this._frame);
            this._boundMessageEvent = this._message.bind(this);
            window.addEventListener("message", this._boundMessageEvent, false);
        });
    }
    _message(e) {
        if (e.origin === this._frame_origin &&
            e.source === this._frame.contentWindow
        ) {
            if (e.data === "error") {
                Log.error("error message from check session op iframe");
                this.stop();
            }
            else if (e.data === "changed") {
                Log.debug("changed message from check session op iframe");
                this.stop();
                this._callback();
            }
            else {
                Log.debug(e.data + " message from check session op iframe");
            }
        }
    }
    start(session_state) {
        if (this._session_state !== session_state) {
            Log.debug("CheckSessionIFrame.start");

            this.stop();

            this._session_state = session_state;

            this._timer = window.setInterval(() => {
                this._frame.contentWindow.postMessage(this._client_id + " " + this._session_state, this._frame_origin);
            }, this._interval);
        }
    }

    stop() {
        Log.debug("CheckSessionIFrame.stop");

        this._session_state = null;

        if (this._timer) {
            window.clearInterval(this._timer);
            this._timer = null;
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class SessionMonitor {

    constructor(userManager, CheckSessionIFrameCtor = CheckSessionIFrame) {
        if (!userManager) {
            Log.error("No user manager passed to SessionMonitor");
            throw new Error("userManager");
        }

        this._userManager = userManager;
        this._CheckSessionIFrameCtor = CheckSessionIFrameCtor;

        this._userManager.events.addUserLoaded(this._start.bind(this));
        this._userManager.events.addUserUnloaded(this._stop.bind(this));

        this._userManager.getUser().then(user => {
            if (user) {
                this._start(user);
            }
        }).catch(err => {
            // catch to suppress errors since we're in a ctor
            Log.error("SessionMonitor ctor; error from getUser:", err.message);
        });
    }

    get _settings() {
        return this._userManager.settings;
    }
    get _metadataService() {
        return this._userManager.metadataService;
    }
    get _client_id() {
        return this._settings.client_id;
    }
    get _checkSessionInterval() {
        return this._settings.checkSessionInterval;
    }

    _start(user) {
        let session_state = user.session_state;

        if (session_state) {
            this._sub = user.profile.sub;
            this._sid = user.profile.sid;
            Log.debug("SessionMonitor._start; session_state:", session_state, ", sub:", this._sub);

            if (!this._checkSessionIFrame) {
                this._metadataService.getCheckSessionIframe().then(url => {
                    if (url) {
                        Log.debug("Initializing check session iframe");

                        let client_id = this._client_id;
                        let interval = this._checkSessionInterval;

                        this._checkSessionIFrame = new this._CheckSessionIFrameCtor(this._callback.bind(this), client_id, url, interval);
                        this._checkSessionIFrame.load().then(() => {
                            this._checkSessionIFrame.start(session_state);
                        });
                    }
                    else {
                        Log.warn("No check session iframe found in the metadata");
                    }
                }).catch(err => {
                    // catch to suppress errors since we're in non-promise callback
                    Log.error("Error from getCheckSessionIframe:", err.message);
                });
            }
            else {
                this._checkSessionIFrame.start(session_state);
            }
        }
    }

    _stop() {
        Log.debug("SessionMonitor._stop");

        this._sub = null;
        this._sid = null;

        if (this._checkSessionIFrame) {
            this._checkSessionIFrame.stop();
        }
    }

    _callback() {
        Log.debug("SessionMonitor._callback");

        this._userManager.querySessionStatus().then(session => {
            var raiseUserSignedOutEvent = true;

            if (session) {
                if (session.sub === this._sub) {
                    raiseUserSignedOutEvent = false;
                    this._checkSessionIFrame.start(session.session_state);

                    if (session.sid === this._sid) {
                        Log.debug("Same sub still logged in at OP, restarting check session iframe; session_state:", session.session_state);
                    }
                    else {
                        Log.debug("Same sub still logged in at OP, session state has changed, restarting check session iframe; session_state:", session.session_state);
                        this._userManager.events._raiseUserSessionChanged();
                    }
                }
                else {
                    Log.debug("Different subject signed into OP:", session.sub);
                }
            }
            else {
                Log.debug("Subject no longer signed into OP");
            }

            if (raiseUserSignedOutEvent) {
                Log.debug("SessionMonitor._callback; raising signed out event");
                this._userManager.events._raiseUserSignedOut();
            }
        }).catch(err => {
            Log.debug("Error calling queryCurrentSigninSession; raising signed out event", err.message);
            this._userManager.events._raiseUserSignedOut();
        });
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const AccessTokenTypeHint = "access_token";

class TokenRevocationClient {
    constructor(settings, XMLHttpRequestCtor = Global.XMLHttpRequest, MetadataServiceCtor = MetadataService) {
        if (!settings) {
            Log.error("No settings provided");
            throw new Error("No settings provided.");
        }
        
        this._settings = settings;
        this._XMLHttpRequestCtor = XMLHttpRequestCtor;
        this._metadataService = new MetadataServiceCtor(this._settings);
    }

    revoke(accessToken, required) {
        Log.debug("TokenRevocationClient.revoke");

        if (!accessToken) {
            Log.error("No accessToken provided");
            throw new Error("No accessToken provided.");
        }

        return this._metadataService.getRevocationEndpoint().then(url => {
            if (!url) {
                if (required) {
                    Log.error("Revocation not supported");
                    throw new Error("Revocation not supported");
                }

                // not required, so don't error and just return
                return;
            }

            var client_id = this._settings.client_id;
            var client_secret = this._settings.client_secret;
            return this._revoke(url, client_id, client_secret, accessToken);
        });
    }

    _revoke(url, client_id, client_secret, accessToken) {
        Log.debug("Calling revocation endpoint");

        return new Promise((resolve, reject) => {

            var xhr = new this._XMLHttpRequestCtor();
            xhr.open("POST", url);
            
            xhr.onload = () => {
                Log.debug("HTTP response received, status", xhr.status);
                
                if (xhr.status === 200) {
                    resolve();
                }
                else {
                    reject(Error(xhr.statusText + " (" + xhr.status + ")"));
                }
            };

            var body = "client_id=" + encodeURIComponent(client_id); 
            if (client_secret) {
                body += "&client_secret=" + encodeURIComponent(client_secret);
            }
            body += "&token_type_hint=" + encodeURIComponent(AccessTokenTypeHint);
            body += "&token=" + encodeURIComponent(accessToken);
            
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.send(body);
        });
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class UserManager extends OidcClient {
    constructor(settings = {},
        SilentRenewServiceCtor = SilentRenewService,
        SessionMonitorCtor = SessionMonitor,
        TokenRevocationClientCtor = TokenRevocationClient
    ) {

        if (!(settings instanceof UserManagerSettings)) {
            settings = new UserManagerSettings(settings);
        }
        super(settings);

        this._events = new UserManagerEvents(settings);
        this._silentRenewService = new SilentRenewServiceCtor(this);
        
        // order is important for the following properties; these services depend upon the events.
        if (this.settings.automaticSilentRenew) {
            Log.debug("automaticSilentRenew is configured, setting up silent renew");
            this.startSilentRenew();
        }

        if (this.settings.monitorSession) {
            Log.debug("monitorSession is configured, setting up session monitor");
            this._sessionMonitor = new SessionMonitorCtor(this);
        }

        this._tokenRevocationClient = new TokenRevocationClientCtor(this._settings);
    }

    get _redirectNavigator() {
        return this.settings.redirectNavigator;
    }
    get _popupNavigator() {
        return this.settings.popupNavigator;
    }
    get _iframeNavigator() {
        return this.settings.iframeNavigator;
    }
    get _userStore() {
        return this.settings.userStore;
    }

    get events() {
        return this._events;
    }

    getUser() {
        Log.debug("UserManager.getUser");

        return this._loadUser().then(user => {
            if (user) {
                Log.info("user loaded");

                this._events.load(user, false);

                return user;
            }
            else {
                Log.info("user not found in storage");
                return null;
            }
        });
    }

    removeUser() {
        Log.debug("UserManager.removeUser");

        return this.storeUser(null).then(() => {
            Log.info("user removed from storage");
            this._events.unload();
        });
    }

    signinRedirect(args) {
        Log.debug("UserManager.signinRedirect");
        return this._signinStart(args, this._redirectNavigator).then(()=>{
            Log.info("signinRedirect successful");
        });
    }
    signinRedirectCallback(url) {
        Log.debug("UserManager.signinRedirectCallback");
        return this._signinEnd(url || this._redirectNavigator.url).then(user => {
            if (user) {
                if (user.profile && user.profile.sub) {
                    Log.info("signinRedirectCallback successful, signed in sub: ", user.profile.sub);
                }
                else {
                    Log.info("signinRedirectCallback successful");
                }
            }

            return user;
        });
    }
    
    signinPopup(args = {}) {
        Log.debug("UserManager.signinPopup");

        let url = args.redirect_uri || this.settings.popup_redirect_uri || this.settings.redirect_uri;
        if (!url) {
            Log.error("No popup_redirect_uri or redirect_uri configured");
            return Promise.reject(new Error("No popup_redirect_uri or redirect_uri configured"));
        }

        args.redirect_uri = url;
        args.display = "popup";

        return this._signin(args, this._popupNavigator, {
            startUrl: url,
            popupWindowFeatures: args.popupWindowFeatures || this.settings.popupWindowFeatures,
            popupWindowTarget: args.popupWindowTarget || this.settings.popupWindowTarget
        }).then(user => {
            if (user) {
                if (user.profile && user.profile.sub) {
                    Log.info("signinPopup successful, signed in sub: ", user.profile.sub);
                }
                else {
                    Log.info("signinPopup successful");
                }
            }

            return user;
        });
    }
    signinPopupCallback(url) {
        Log.debug("UserManager.signinPopupCallback");
        return this._signinCallback(url, this._popupNavigator).then(user => {
            if (user) {
                if (user.profile && user.profile.sub) {
                    Log.info("signinPopupCallback successful, signed in sub: ", user.profile.sub);
                }
                else {
                    Log.info("signinPopupCallback successful");
                }
            }

            return user;
        });
    }

    signinSilent(args = {}) {
        Log.debug("UserManager.signinSilent");

        let url = args.redirect_uri || this.settings.silent_redirect_uri;
        if (!url) {
            Log.error("No silent_redirect_uri configured");
            return Promise.reject(new Error("No silent_redirect_uri configured"));
        }

        args.redirect_uri = url;
        args.prompt = "none";

        let setIdToken;
        if (args.id_token_hint || !this.settings.includeIdTokenInSilentRenew) {
            setIdToken = Promise.resolve();
        }
        else {
            setIdToken = this._loadUser().then(user => {
                args.id_token_hint = user && user.id_token;
            });
        }

        return setIdToken.then(() => {
            return this._signin(args, this._iframeNavigator, {
                startUrl: url,
                silentRequestTimeout: args.silentRequestTimeout || this.settings.silentRequestTimeout
            });
        }).then(user => {
            if (user) {
                if (user.profile && user.profile.sub) {
                    Log.info("signinSilent successful, signed in sub: ", user.profile.sub);
                }
                else {
                    Log.info("signinSilent successful");
                }
            }

            return user;
        });
    }
    signinSilentCallback(url) {
        Log.debug("UserManager.signinSilentCallback");
        return this._signinCallback(url, this._iframeNavigator).then(user => {
            if (user) {
                if (user.profile && user.profile.sub) {
                    Log.info("signinSilentCallback successful, signed in sub: ", user.profile.sub);
                }
                else {
                    Log.info("signinSilentCallback successful");
                }
            }

            return user;
        });
    }

    querySessionStatus(args = {}) {
        Log.debug("UserManager.querySessionStatus");

        let url = args.redirect_uri || this.settings.silent_redirect_uri;
        if (!url) {
            Log.error("No silent_redirect_uri configured");
            return Promise.reject(new Error("No silent_redirect_uri configured"));
        }

        args.redirect_uri = url;
        args.prompt = "none";
        args.response_type = "id_token";
        args.scope = "openid";

        return this._signinStart(args, this._iframeNavigator, {
            startUrl: url,
            silentRequestTimeout: args.silentRequestTimeout || this.settings.silentRequestTimeout
        }).then(navResponse => {
            return this.processSigninResponse(navResponse.url).then(signinResponse => {
                Log.debug("got signin response");

                if (signinResponse.session_state && signinResponse.profile.sub && signinResponse.profile.sid) {
                    Log.info("querySessionStatus success for sub: ",  signinResponse.profile.sub);
                    return {
                        session_state: signinResponse.session_state,
                        sub: signinResponse.profile.sub,
                        sid: signinResponse.profile.sid
                    };
                }
                else {
                    Log.info("querySessionStatus successful, user not authenticated");
                }
            });
        });
    }

    _signin(args, navigator, navigatorParams = {}) {
        Log.debug("_signin");
        return this._signinStart(args, navigator, navigatorParams).then(navResponse => {
            return this._signinEnd(navResponse.url);
        });
    }
    _signinStart(args, navigator, navigatorParams = {}) {
        Log.debug("_signinStart");

        return navigator.prepare(navigatorParams).then(handle => {
            Log.debug("got navigator window handle");

            return this.createSigninRequest(args).then(signinRequest => {
                Log.debug("got signin request");

                navigatorParams.url = signinRequest.url;
                navigatorParams.id = signinRequest.state.id;
                
                return handle.navigate(navigatorParams);
            }).catch(err => {
                if (handle.close) {
                    Log.debug("Error after preparing navigator, closing navigator window");
                    handle.close();
                }
                throw err;
            });
        });
    }
    _signinEnd(url) {
        Log.debug("_signinEnd");

        return this.processSigninResponse(url).then(signinResponse => {
            Log.debug("got signin response");

            let user = new User(signinResponse);

            return this.storeUser(user).then(() => {
                Log.debug("user stored");

                this._events.load(user);

                return user;
            });
        });
    }
    _signinCallback(url, navigator) {
        Log.debug("_signinCallback");
        return navigator.callback(url);
    }

    signoutRedirect(args = {}) {
        Log.debug("UserManager.signoutRedirect");
        let postLogoutRedirectUri = args.post_logout_redirect_uri || this.settings.post_logout_redirect_uri;
        if (postLogoutRedirectUri){
            args.post_logout_redirect_uri = postLogoutRedirectUri;
        }
        return this._signoutStart(args, this._redirectNavigator).then(()=>{
            Log.info("signoutRedirect successful");
        });
    }
    signoutRedirectCallback(url) {
        Log.debug("UserManager.signoutRedirectCallback");
        return this._signoutEnd(url || this._redirectNavigator.url).then(response=>{
            Log.info("signoutRedirectCallback successful");
            return response;
        });
    }

    signoutPopup(args = {}) {
        Log.debug("UserManager.signinPopup");

        let url = args.post_logout_redirect_uri || this.settings.popup_post_logout_redirect_uri || this.settings.post_logout_redirect_uri;
        args.post_logout_redirect_uri = url;
        args.display = "popup";
        if (args.post_logout_redirect_uri){
            // we're putting a dummy entry in here because we 
            // need a unique id from the state for notification
            // to the parent window, which is necessary if we
            // plan to return back to the client after signout
            // and so we can close the popup after signout
            args.state = args.state || {};
        }

        return this._signout(args, this._popupNavigator, {
            startUrl: url,
            popupWindowFeatures: args.popupWindowFeatures || this.settings.popupWindowFeatures,
            popupWindowTarget: args.popupWindowTarget || this.settings.popupWindowTarget
        }).then(() => {
            Log.info("signoutPopup successful");
        });
    }
    signoutPopupCallback(url, keepOpen) {
        if (typeof(keepOpen) === 'undefined' && typeof(url) === 'boolean') {
            url = null;
            keepOpen = true;
        }
        Log.debug("UserManager.signoutPopupCallback");
        let delimiter = '?';
        return this._popupNavigator.callback(url, keepOpen, delimiter).then(() => {
            Log.info("signoutPopupCallback successful");
        });
    }

    _signout(args, navigator, navigatorParams = {}) {
        Log.debug("_signout");
        return this._signoutStart(args, navigator, navigatorParams).then(navResponse => {
            return this._signoutEnd(navResponse.url);
        });
    }
    _signoutStart(args = {}, navigator, navigatorParams = {}) {
        Log.debug("_signoutStart");

        return navigator.prepare(navigatorParams).then(handle => {
            Log.debug("got navigator window handle");

            return this._loadUser().then(user => {
                Log.debug("loaded current user from storage");

                var revokePromise = this._settings.revokeAccessTokenOnSignout ? this._revokeInternal(user) : Promise.resolve();
                return revokePromise.then(() => {

                    var id_token = args.id_token_hint || user && user.id_token;
                    if (id_token) {
                        Log.debug("Setting id_token into signout request");
                        args.id_token_hint = id_token;
                    }

                    return this.removeUser().then(() => {
                        Log.debug("user removed, creating signout request");

                        return this.createSignoutRequest(args).then(signoutRequest => {
                            Log.debug("got signout request");

                            navigatorParams.url = signoutRequest.url;
                            if (signoutRequest.state) {
                                navigatorParams.id = signoutRequest.state.id;
                            }
                            return handle.navigate(navigatorParams);
                        });
                    });
                });
            }).catch(err => {
                if (handle.close) {
                    Log.debug("Error after preparing navigator, closing navigator window");
                    handle.close();
                }
                throw err;
            });
        });
    }
    _signoutEnd(url) {
        Log.debug("_signoutEnd");

        return this.processSignoutResponse(url).then(signoutResponse => {
            Log.debug("got signout response");

            return signoutResponse;
        });
    }

    revokeAccessToken() {
        Log.debug("UserManager.revokeAccessToken");

        return this._loadUser().then(user => {
            return this._revokeInternal(user, true).then(success => {
                if (success) {
                    Log.debug("removing token properties from user and re-storing");

                    user.access_token = null;
                    user.expires_at = null;
                    user.token_type = null;

                    return this.storeUser(user).then(() => {
                        Log.debug("user stored");
                        this._events.load(user);
                    });
                }
            });
        }).then(()=>{
            Log.info("access token revoked successfully");
        });
    }

    _revokeInternal(user, required) {
        Log.debug("checking if token revocation is necessary");

        var access_token = user && user.access_token;

        // check for JWT vs. reference token
        if (!access_token || access_token.indexOf('.') >= 0) {
            Log.debug("no need to revoke due to no user, token, or JWT format");
            return Promise.resolve(false);
        }

        return this._tokenRevocationClient.revoke(access_token, required).then(() => true);
    }

    startSilentRenew() {
        this._silentRenewService.start();
    }

    stopSilentRenew() {
        this._silentRenewService.stop();
    }

    get _userStoreKey() {
        return `user:${this.settings.authority}:${this.settings.client_id}`;
    }

    _loadUser() {
        Log.debug("_loadUser");

        return this._userStore.get(this._userStoreKey).then(storageString => {
            if (storageString) {
                Log.debug("user storageString loaded");
                return User.fromStorageString(storageString);
            }

            Log.debug("no user storageString");
            return null;
        });
    }

    storeUser(user) {
        if (user) {
            Log.debug("storeUser storing user");

            var storageString = user.toStorageString();
            return this._userStore.set(this._userStoreKey, storageString);
        }
        else {
            Log.debug("storeUser removing user storage");
            return this._userStore.remove(this._userStoreKey);
        }
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

const DefaultPopupFeatures$1 = 'location=no,toolbar=no,zoom=no';
const DefaultPopupTarget$1 = "_blank";

class CordovaPopupWindow {

    constructor(params) {
        Log.debug("CordovaPopupWindow.ctor");

        this._promise = new Promise((resolve, reject) => {
            this._resolve = resolve;
            this._reject = reject;
        });

        this.features = params.popupWindowFeatures || DefaultPopupFeatures$1;
        this.target = params.popupWindowTarget || DefaultPopupTarget$1;
        
        this.redirect_uri = params.startUrl;
        Log.debug("redirect_uri: " + this.redirect_uri);
    }

    _isInAppBrowserInstalled(cordovaMetadata) {
        return ["cordova-plugin-inappbrowser", "cordova-plugin-inappbrowser.inappbrowser", "org.apache.cordova.inappbrowser"].some(function (name) {
            return cordovaMetadata.hasOwnProperty(name)
        })
    }
    
    navigate(params) {
        Log.debug("CordovaPopupWindow.navigate");

        if (!params || !params.url) {
            this._error("No url provided");
        } else {
            if (!window.cordova) {
                return this._error("cordova is undefined")
            }
            
            var cordovaMetadata = window.cordova.require("cordova/plugin_list").metadata;
            if (this._isInAppBrowserInstalled(cordovaMetadata) === false) {
                return this._error("InAppBrowser plugin not found")
            }
            this._popup = cordova.InAppBrowser.open(params.url, this.target, this.features);
            if (this._popup) {
                Log.debug("popup successfully created");
                
                this._exitCallbackEvent = this._exitCallback.bind(this); 
                this._loadStartCallbackEvent = this._loadStartCallback.bind(this);
                
                this._popup.addEventListener("exit", this._exitCallbackEvent, false);
                this._popup.addEventListener("loadstart", this._loadStartCallbackEvent, false);
            } else {
                this._error("Error opening popup window");
            }
        }
        return this.promise;
    }

    get promise() {
        return this._promise;
    }

    _loadStartCallback(event) {
        if (event.url.indexOf(this.redirect_uri) === 0) {
            this._success({ url: event.url });
        }    
    }
    _exitCallback(message) {
        this._error(message);    
    }
    
    _success(data) {
        this._cleanup();

        Log.debug("Successful response from cordova popup window");
        this._resolve(data);
    }
    _error(message) {
        this._cleanup();

        Log.error(message);
        this._reject(new Error(message));
    }

    close() {
        this._cleanup();
    }

    _cleanup() {
        Log.debug("CordovaPopupWindow._cleanup");

        if (this._popup){
            this._popup.removeEventListener("exit", this._exitCallbackEvent, false);
            this._popup.removeEventListener("loadstart", this._loadStartCallbackEvent, false);
            this._popup.close();
        }
        this._popup = null;
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class CordovaPopupNavigator {
    
    prepare(params) {
        let popup = new CordovaPopupWindow(params);
        return Promise.resolve(popup);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

class CordovaIFrameNavigator {
    
    prepare(params) {
        params.popupWindowFeatures = 'hidden=yes';
        let popup = new CordovaPopupWindow(params);
        return Promise.resolve(popup);
    }
}

// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.

var index = {
    Log,
    OidcClient,
    OidcClientSettings,
    WebStorageStateStore,
    InMemoryWebStorage,
    UserManager,
    AccessTokenEvents,
    MetadataService,
    CordovaPopupNavigator,
    CordovaIFrameNavigator,
    CheckSessionIFrame,
    TokenRevocationClient,
    SessionMonitor,
    Global
};

export default index;
export { Log, OidcClient, OidcClientSettings, WebStorageStateStore, InMemoryWebStorage, UserManager, AccessTokenEvents, MetadataService, CordovaPopupNavigator, CordovaIFrameNavigator, CheckSessionIFrame, TokenRevocationClient, SessionMonitor, Global };
