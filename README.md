Custom buildpack: OIDC Validator
=======================

This is a [Heroku buildpack](http://devcenter.heroku.com/articles/buildpacks).

Usage
-----

Example usage:

    $ heroku buildpacks:add --index 2 "https://github.com/vishvananda/heroku-buildpack-oidc-validator"

    $ git push heroku main
    ...
    -----> Validate Buildpack app detected
    -----> Attempting to rewrite Procfile
           Added validate to web command:
           web: ./validate ./start.sh

The buildpack will detect that your app has a `Procfile` in the root and
rewrite the web process to run the validate proxy before executing your app.

How does the validator work?
----------------------------

The validator will detect an openid connect bearer token in the request. If the
request contains a token, it will validate the token and add a header in the
request to the underlying app based on the subject contained in the token.

Customizing the validation
--------------------------

To customize how the validation works, you can set the following env vars on
the app:

- `VALIDATOR_REJECT_UNMATCHED`: if true, this will reject any request that
  fails validation with a 401
- `VALIDATOR_SUB_HEADER`: this is the key used for the header that will
    contain the validated subject name.
- `VALIDATOR_ID_HEADER`: this is the key used for the header representing the
  connection id.

The validator looks for environment variables in the following format for valid
connections. These env variables will be removed from the environment of the
child app.
- `CONN_.*_ID`: this is used as the value of `VALIDATOR_ID_HEADER`
  token. For each matching id value, the values below are interpreted
- `CONN_.*_ISS`: this regex is used to validate the issuer or the
  token
- `CONN_.*_AUD`: the token must contain at least one audience that
  matches this regex
- `CONN_.*_SUB`: this is used to validate the subject of the regex.
  The may contain one match group. The value from this match
  group or the whole sub is used as the value for `VAL_SUBJECT_HEADER`.


