import "@babel/polyfill";
import fetch from 'node-fetch';
import jwt  from 'jsonwebtoken';  
import jwkToPem from 'jwk-to-pem';

let pems = {};

const AWS_ACCOUNT_ID = process.env.AWS_ACCOUNT_ID;
const APIS_USERPOOL = JSON.parse(process.env.APIS_USERPOOL);

const authenticate = async (rawCookie, ISS) => {
  const cookies = parseCookies(rawCookie);
  const { id_token, access_token } = cookies;

  if (!id_token || !access_token){
    return false;
  }

  const decodedJwt = jwt.decode(access_token, {complete: true});
  if (!decodedJwt) {
      console.log("cognito token not valid or expired");
      return false;
  }

  //Fail if token is not from your UserPool
  if (decodedJwt.payload.iss !== ISS) {
      console.error("invalid issuer");
      return false;
  }

  //Reject the jwt if it's not an 'Access Token'
  if (decodedJwt.payload.token_use !== 'access') {
      console.error("not an access token");
      return false;
  }

  //Get the kid from the token and retrieve corresponding PEM
  const kid = decodedJwt.header.kid;
  if (!pems[ISS]){
    pems[ISS] = await getPems(ISS);
  } else {
    console.log('pems cached!')
  }

  const pem = pems[ISS][kid];
  if (!pem) {
      console.error('failed to fetch public keys from cognito');
      return false;
  }

  //Verify the signature of the JWT token to ensure it's really coming from your User Pool
  let decodedId;
  try {
    const result = jwt.verify(access_token, pem, { issuer: ISS });
    console.log(result);
    
    if (!result.username){
      return false;
    }
    
    decodedId = jwt.decode(id_token, {complete: true});
  } catch (e){
    console.log(e);
    return false;
  }
  
  console.log(decodedId);

  return decodedId.payload;
};

const parseCookies = (cookie) => {
  const parsedCookie = {};
    cookie.split(';')
    .forEach(c => {
      const parts = c.split('=');
      if (parts.length === 2){
        parsedCookie[parts[0].trim()] = parts[1].trim();
      }
    });
  return parsedCookie;
}

const getPems = async (iss) => {
  const pem = {};

  const resp = await fetch(`${iss}/.well-known/jwks.json`);
  const respJson = await resp.json();

  const { keys } = respJson;
  
  if (!keys){
    return pem;
  }
  
  for(let i = 0; i < keys.length; i++) {
      //Convert each key to PEM
      let key_id = keys[i].kid;
      let modulus = keys[i].n;
      let exponent = keys[i].e;
      let key_type = keys[i].kty;
      let jwk = { kty: key_type, n: modulus, e: exponent};
      pem[key_id] = jwkToPem(jwk);
  }

  return pem;
}

const forbidden = {
  "isAuthorized": false,
  "context": {}
};

const asyncHandler = async (event, context) => {
  if (!event || !event.headers || !event.headers.cookie || !event.requestContext){
    return forbidden;
  }

  const { accountId, apiId } = event.requestContext;

  if (accountId !== AWS_ACCOUNT_ID){
    return forbidden;
  }

  if (!APIS_USERPOOL[apiId]){
    return forbidden;
  }

  const REGION = process.env.COGNITO_REGION;
  const USERPOOLID = APIS_USERPOOL[apiId];
  const ISS = `https://cognito-idp.${REGION}.amazonaws.com/${USERPOOLID}`;

  const authed = await authenticate(event.headers.cookie, ISS);

  return {
    "isAuthorized": authed !== false,
    "context": authed !== false ? authed : {}
  };
}

export default { asyncHandler };