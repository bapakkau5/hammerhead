var express = require('express');
var router = express.Router();
var hammerhead = require('../hammerhead')

router.get('/', function (req, res, next) {
  hammerhead.protect(req, res, function () {
    res.render('index', { title: 'Express' });
  })
});

router.get('/config', function (req, res, next) {
  res.send(hammerhead.viewconfig());
})

router.get('/bans', function (req, res, next) {
  res.send(hammerhead.getbans());
})

router.get('/vuln/:exp', function (req, res) {
  res.send("The answer is :" + eval(req.params.exp));
});

module.exports = router;
