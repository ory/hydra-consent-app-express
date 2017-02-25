const express = require('express')
const Hydra = require('hydra-js')
const path = require('path')
const router = express.Router()

// Instantiating a hydra config. If you provide no config, the hydra-js library will try to figure them out
// from the environment variables, such as HYDRA_CLIENT_ID, HYDRA_CLIENT_SECRET, and HYDRA_URL.
const hydra = new Hydra()

// A simple error helper
const catcher = (w) => (error) => {
  console.error(error)
  w.render('error', { error })
  w.status(500)
  return Promise.reject(error)
}

// This is a mock object for the user. Usually, you would fetch this from, for example, mysql, or mongodb, or somewhere else.
// The data is arbitrary, but will require a unique user id.
const user = {
  email: 'dan@acme.com',
  password: 'secret',

  email_verified: true,
  user_id: 'user:12345:dandean',
  name: 'Dan Dean',
  nickname: 'Danny',
}

// This get's executed when we want to tell hydra that the user is authenticated and that he authorized the application
const resolveConsent = (r, w, challenge, scopes = []) => {
  const { email, email_verified, user_id: subject, name, nickname } = user
  const data = {}

  // Sometimes the body parser doesn't return an array, so let's fix that.
  if (!Array.isArray(scopes)) {
    scopes = [scopes]
  }

  // This is the openid 'profile' scope which should include some user profile data. (optional)
  if (scopes.indexOf('profile') >= 0) {
    data.name = name
    data.nickname = nickname
  }

  // This is to fulfill the openid 'email' scope which returns the user's email address. (optional)
  if (scopes.indexOf('email') >= 0) {
    data.email = email
    data.email_verified = email_verified
  }

  // Make sure that the consent challenge is valid
  hydra.verifyConsentChallenge(challenge).then(({ challenge: decoded }) => {
    // Create the consent response
    return hydra.generateConsentResponse(r.query.challenge, subject, scopes, {}, data).then(({ consent }) => {

      // Redirect back to hydra
      w.redirect(decoded.redir + '&consent=' + consent)
    })
  }).catch(catcher(w))
}

router.get('/consent', (r, w) => {
  // This endpoint is hit when hydra initiates the consent flow  
  
  if (!r.session.isAuthenticated) {
    // The user is not authenticated yet, so redirect him to the log in page
    return w.redirect('/login?error=Please+log+in&challenge=' + r.query.challenge)
  } else if (r.query.error) {
    // An error occurred (at hydra)
    return w.render('error', { error: { name: r.query.error, message: r.query.error_description } })
  }

  // Ok, the user is authenticated! Let's show the consent screen!
  hydra.verifyConsentChallenge(r.query.challenge).then(({ challenge }) => {
    // challenge contains informations such as requested scopes, client id, ...
    
    // Here you could, for example, allow clients to force a user's consent. Since you're able to
    // say which scopes a client can request in hydra, you could allow this for a few highly priviledged clients!
    // 
    // if (challenge.scp.find((s) => s === 'force-consent')) {
    //   resolveConsent(r, w, r.query.challenge, challenge.scp)
    //   return Promise.resolve()
    // }

    // render the consent screen
    w.render('consent', { scopes: challenge.scp })
    return Promise.resolve()
  }).catch(catcher(w))
})

router.post('/consent', (r, w) => {
  if (!r.session.isAuthenticated) {
    return w.redirect('/login?error=Please+log+in&challenge=' + r.body.challenge)
  }

  resolveConsent(r, w, r.query.challenge, r.body.allowed_scopes)
})

router.get('/login', (r, w) => {
  w.render('login', { error: r.query.error, user, challenge: r.query.challenge })
})

router.post('/login', (r, w) => {
  const form = r.body
  if (form.email !== user.email || form.password !== user.password) {
    w.redirect('/login?error=Wrong+credentials+provided&challenge=' + form.challenge)
  }

  r.session.isAuthenticated = true
  console.log(r.session)
  w.redirect('/consent?challenge=' + r.body.challenge)
})

router.get('/', (r, w) => w.send('This is an exemplary consent app for Hydra. Please read the hydra docs on how to use this router.'))

module.exports = router
