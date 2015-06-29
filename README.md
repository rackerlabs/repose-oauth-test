# Repose OAuth2.0 Filter Test

The steps below that are Alpha labeled coincide with those in [RFC 6749 OAuth 2.0 dated October 2012](http://tools.ietf.org/html/rfc6749), section 4.1. Authorization Code Grant.

The steps below that are Numeric labeled as well as the **NOTE**s are steps that will need to be part of the Repose OAuth 2.0 filter.

This particular example uses the [GitHub API](https://developer.github.com/v3/) to perform [GitHub OAuth](https://developer.github.com/v3/oauth/)

In the scenario below the following substitutions were made:

| RFC 6749 Name        | Scenario Name |
|:---------------------|:--------------|
| Resource Owner       | User          |
| Client               | Browser       |
| User-Agent           | Repose        |
| Authorization Server | OAuth Service |

![Repose OAuth 2.0 filter sequence](/doc/ReposeOAuth20SequenceBasic.png)

## A. Client Identifier
 - A User using a Browser Requests a Resource from Repose in front of an Origin Service.
 - Repose returns a redirect to the Browser to the OAuth Service with the Origin Service's
    - ID
    - Requested Scope
    - State (UUID)
    - Redirect Return URI

ex. `https://www.github.com/login/oauth/authorize?client_id=<CLIENT_ID>&scope=user:email,read:public_key&redirect_uri=https://oauth-test.openrepose.org/callback&state=<AN_UNGUESSABLE_RANDOM_STRING>`

## B. User authenticates
 - The User reviews the OAuth Service's Authorization page and accepts/rejects the request.

## C. Authorization Code
 - The OAuth Service returns a redirect to the Browser to the Repose Redirect Return URI with the:
    - Code
    - State
 - The Browser hits the Repose Redirect Return URI.

**NOTE**: Before continuing, Repose must ensure the received State matches the one it provided in the original redirect.

## D. Authorization Code
 - Repose Requests a Token from the OAuth Service with the Origin Service's (POST)
    - ID
    - Secret
    - Code
    - Return URI

ex. `https://github.com/login/oauth/access_token?client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&code=<CODE>&redirect_uri=https://oauth-test.openrepose.org/callback`

## E. Access Token
 - The OAuth Service returns with:
    - Token
    - Authorized Scope

ex. `{"access_token":"<ACCESS_TOKEN>","token_type":"bearer","scope":"read:public_key,user:email"}`

**NOTE**: Before continuing, Repose must ensure all required scope permissions were actually authorized.

## 1. Resource Request with Access Token
 - Repose Requests the original Resource from the Origin Service.

ex. `https://api.github.com/user/emails?access_token=<ACCESS_TOKEN>`

ex. `https://api.github.com/user/keys?access_token=<ACCESS_TOKEN>`

## 2. Original Request serviced
 - Repose Returns the originally requested Resource to the User.
