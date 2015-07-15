/**
 * Login With Google for Mobile Applications
 * *** PLEASE READ ***
 *
 * This is an extension of Parse's OAuth 2.0 for Web Apps Login With GitHub example.
 *
 * For this code to work you need to already have an authentication code from your app's user. To
 * get one follow the processes below from Google's website
 *
 * Android:	https://developers.google.com/+/mobile/android/sign-in
 * iOS:		https://developers.google.com/+/mobile/ios/sign-in
 *
 * Once the authentication code is available, all that needs to be done is to call
 * the 'accessGoogleUser' Cloud function from within the Mobile app with the parameters:
 * 		code: authentication code
 *		email(optional): this is Google's Account username. They're indexed by email and can be assigned to the new user
 *
 *	The output of this Cloud code function should be the Parse User's session token associated with the Google login
 *
 *	NOTE: The Parse TokenStorage class in the database has the following fields:
 *			user - Pointer to the ParseUser
 *			access_token - the active authentication code
 *			accountId - the Google user's ID (non-email)
 *
 *	Key functions:
 *		accessGoogleUser
 *		getGoogleAccessToken
 *		upsertGoogleUser
 *		newGoogleUser
 */
 
 /*
 1. Create a project on the Google Developer Console
 2. Go to the 'Credentials' tab and click 'Create new Client ID' 
 3. Make a Client ID for a Web application
	a. For the Authorized Redirect URI you can put 'http://localhost:8080/oauth2callback'
	b. For the Authorized JavaScript Origins I have 'http://localhost:8080' and the Website you can use with Parse hosting i.e. 'https://[YOUR_APP].parseapp.com/'
 4. Use the information from this Client ID for the information below 
 */
 
var googleClientId = 'your client id';	//The client ID obtained from the Google Developers Console, follow the steps above
var googleClientSecret = 'your client secret';												//The client secret obtained from the Google Developers Console, follow the steps above

var googleValidateEndpoint = 'https://www.googleapis.com/oauth2/v1/userinfo';	//this is the only verification link you need to verify the user's Google Access Token

var googleRedirectEndpoint = 'https://google.com/login/oauth/authorize?';	//not used (handled client side)
var googleUserEndpoint = 'https://api.google.com/user';						//not used (Google has HTTP requests for the user profile using their User ID but they're not necessary here, and this isn't the right address)


/**
 * In the Data Browser, set the Class Permissions for these 2 classes to
 *   disallow public access for Get/Find/Create/Update/Delete operations.
 * Only the master key should be able to query or write to these classes.
 */
var TokenRequest = Parse.Object.extend("TokenRequest");
var TokenStorage = Parse.Object.extend("TokenStorage");

/**
 * Create a Parse ACL which prohibits public access.  This will be used
 *   in several places throughout the application, to explicitly protect
 *   Parse User, TokenRequest, and TokenStorage objects.
 */
var restrictedAcl = new Parse.ACL();
restrictedAcl.setPublicReadAccess(false);
restrictedAcl.setPublicWriteAccess(false);

/**
 * Load needed modules.
 */
var express = require('express');
var querystring = require('querystring');
var _ = require('underscore');
var Buffer = require('buffer').Buffer;

/**
 * Create an express application instance
 */
var app = express();

/**
 * Global app configuration section
 */
app.set('views', 'cloud/views');  // Specify the folder to find templates
app.set('view engine', 'ejs');    // Set the template engine
app.use(express.bodyParser());    // Middleware for reading request body


/**
 * OAuth Callback route.
 *
 * This is intended to be accessed via redirect from Google.  The request
 *   will be validated against a previously stored TokenRequest and against
 *   another Google endpoint, and if valid, a User will be created and/or
 *   updated with details from Google.  A page will be rendered which will
 *   'become' the user on the client-side and redirect to the /main page.
 */
Parse.Cloud.define('accessGoogleUser', function(req, res) {
  var data = req.params;
  var token;
  /**
   * Validate that code and state have been passed in as query parameters.
   * Render an error page if this is invalid.
   */
  if (!(data && data.code)) {
    res.error('Invalid auth response received.');
    return;
  }
  token = data.code;
  Parse.Cloud.useMasterKey();
  Parse.Promise.as().then(function() {
    // Validate & Exchange the code parameter for an access token from Google
    return getGoogleAccessToken(data.code);
  }).then(function(httpResponse) {
    var userData = httpResponse.data;
    if (userData && userData.id) {
      return upsertGoogleUser(token, userData, data.email);
    } else {
      return Parse.Promise.error("Unable to parse Google data");
    }
  }).then(function(user) {
    /**
     * Send back the session token in the response to be used with 'become/becomeInBackground' functions
     */
    res.success(user.getSessionToken());
  }, function(error) {
    /**
     * If the error is an object error (e.g. from a Parse function) convert it
     *   to a string for display to the user.
     */
    if (error && error.code && error.error) {
      error = error.code + ' ' + error.error;
    }
    res.error(JSON.stringify(error));
  });

});

/**
 * This function is called when Google redirects the user back after
 *   authorization.  It calls back to Google to validate and exchange the code
 *   for an access token.
 */
var getGoogleAccessToken = function(code) {
  var body = querystring.stringify({
    access_token: code
  });
  return Parse.Cloud.httpRequest({
    url: googleValidateEndpoint + '?access_token=' + code
  });
}

/**
 * This function checks to see if this Google user has logged in before.
 * If the user is found, update the accessToken (if necessary) and return
 *   the users session token.  If not found, return the newGoogleUser promise.
 */
var upsertGoogleUser = function(accessToken, googleData, emailId) {
  var query = new Parse.Query(TokenStorage);
  query.equalTo('accountId', googleData.id);
  //query.ascending('createdAt');
  // Check if this googleId has previously logged in, using the master key
  return query.first({ useMasterKey: true }).then(function(tokenData) {
    // If not, create a new user.
    if (!tokenData) {
      return newGoogleUser(accessToken, googleData, emailId);
    }
    // If found, fetch the user.
    var user = tokenData.get('user');
    return user.fetch({ useMasterKey: true }).then(function(user) {
      // Update the access_token if it is different.
      if (accessToken !== tokenData.get('access_token')) {
        tokenData.set('access_token', accessToken);
      }
      /**
       * This save will not use an API request if the token was not changed.
       * e.g. when a new user is created and upsert is called again.
       */
      return tokenData.save(null, { useMasterKey: true });
    }).then(function(obj) {
      // Return the user object.
      return Parse.Promise.as(user);
    });
  });
}

/**
 * This function creates a Parse User with a random login and password, and
 *   associates it with an object in the TokenStorage class.
 * Once completed, this will return upsertGoogleUser.  This is done to protect
 *   against a race condition:  In the rare event where 2 new users are created
 *   at the same time, only the first one will actually get used.
 */
var newGoogleUser = function(accessToken, googleData, email) {
  var user = new Parse.User();
  // Generate a random username and password.
  var username = new Buffer(24);
  var password = new Buffer(24);
  _.times(24, function(i) {
    username.set(i, _.random(0, 255));
    password.set(i, _.random(0, 255));
  });
  var name = googleData.name;
  name = name.split(" ");
  var firstName = name[0];
  if(name.length > 1)
	var lastName = name[name.length-1];
  user.set("username", username.toString('base64'));
  user.set("password", password.toString('base64'));
  user.set("email", email);
  user.set("first_name", firstName);
  user.set("last_name", lastName);
  user.set("account_type", 'g');
  // Sign up the new User
  return user.signUp().then(function(user) {
    // create a new TokenStorage object to store the user+Google association.
    var ts = new TokenStorage();
    ts.set('user', user);
    ts.set('accountId', googleData.id);
    ts.set('access_token', accessToken);
    ts.setACL(restrictedAcl);
    // Use the master key because TokenStorage objects should be protected.
    return ts.save(null, { useMasterKey: true });
  }).then(function(tokenStorage) {
    return upsertGoogleUser(accessToken, googleData);
  });
}


/**
 * This function calls the googleUserEndpoint to get the user details for the
 * provided access token, returning the promise from the httpRequest.
 * UNUSED: Android
 */
var getGoogleUserDetails = function(accessToken) {
  return Parse.Cloud.httpRequest({
    method: 'GET',
    url: googleUserEndpoint,
    params: { access_token: accessToken },
    headers: {
      'User-Agent': 'Parse.com Cloud Code'
    }
  });
}


/**
 * Google specific details, including application id and secret
 */

/**
 * Logged in route.
 *
 * JavaScript will validate login and call a Cloud function to get the users
 *   Google details using the stored access token.
 */
app.get('/main', function(req, res) {
  res.render('main', {});
});

/**
 * Attach the express app to Cloud Code to process the inbound request.
 */
app.listen();

/**
 * Main route.
 *
 * When called, render the login.ejs view
 */
app.get('/', function(req, res) {
  res.render('login', {});
});

/**
 * Login with Google route.
 *
 * When called, generate a request token and redirect the browser to Google.
 */
app.get('/authorize', function(req, res) {

  var tokenRequest = new TokenRequest();
  // Secure the object against public access.
  tokenRequest.setACL(restrictedAcl);
  /**
   * Save this request in a Parse Object for validation when Google responds
   * Use the master key because this class is protected
   */
  tokenRequest.save(null, { useMasterKey: true }).then(function(obj) {
    /**
     * Redirect the browser to Google for authorization.
     * This uses the objectId of the new TokenRequest as the 'state'
     *   variable in the Google redirect.
     */
    res.redirect(
      googleRedirectEndpoint + querystring.stringify({
        client_id: googleClientId,
        state: obj.id
      })
    );
  }, function(error) {
    // If there's an error storing the request, render the error page.
    res.render('error', { errorMessage: 'Failed to save auth request.'});
  });

});
