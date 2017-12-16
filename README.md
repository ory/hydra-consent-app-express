# hydra-consent-app-express

This is an exemplary consent application that implements ORY Hydra's consent flow. It uses NodeJS and express.

A consent application is responsible for:

* Authenticating users (signing a user in)
* Authorizing an application ("Would you like to give application X access to your email address?")

You can use this demo for a rough guide on how to implement the consent flow using NodeJS. The only important source file is [this](https://github.com/ory/hydra-consent-app-express/blob/master/routes/index.js), everything else was created using `express init .`.

If you are using Auth0, check out [hydra-auth0-consent-sdk](https://github.com/ory/hydra-auth0-consent-sdk)

A go implementation of the consent app is at [hydra-consent-app-go](https://github.com/ory/hydra-consent-app-go)
