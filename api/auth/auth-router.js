const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body
  const { role_name } = req
  const hash = bcrypt.hashSync(password, 8)
  User.add({ username, password: hash, role_name })
    .then(newUser => {
      res.status(201).json(newUser)
    })
    .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
 if (bcrypt.compareSync(req.body.password, req.user.password)) {
  const token = buildToken(req.user)
  res.json({
    message: `${req.user.username} is back`,
    token,
  })
 } else {
  next({ status: 401, message: 'Invalid credentials' })
 }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    role_name:user.role_name,
    username: user.username,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
