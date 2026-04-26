export const DEBUG_MODE = true;

const PROD_ORIGIN = 'https://carto.jaetill.com';
const DEV_ORIGIN  = 'http://localhost:5173';

const origin = import.meta.env.DEV ? DEV_ORIGIN : PROD_ORIGIN;

export const COGNITO = {
  region:      'us-east-2',
  userPoolId:  'us-east-2_xneeJzaDJ',
  domain:      'just.jaetill.com',
  clientId:    '3r633l045s8fse9v1ebubk8re6',
  redirectUri: `${origin}/callback.html`,
  logoutUri:   `${origin}/`,
  scopes:      ['openid', 'email', 'profile', 'aws.cognito.signin.user.admin'],
};
