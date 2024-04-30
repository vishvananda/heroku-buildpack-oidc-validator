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

- `VALIDATOR_HEADER_NAME`: this is the key used for the header that will
    contain the validated subject name.
- `VALIDATOR_ISSUER_REGEX`: this regex is used to validate the issuer or the
  token
- `VALIDATOR_AUDIENCE_REGEX`: the token must contain at least one audience that
  matches this regex
- `VALIDATOR_SUBJECT_REGEX`: this is used to validate the subject of the regex.
  The regex must contain exactly one match group. The value from this match
  group is used as the value in the header.


