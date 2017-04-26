var express = require('express');
var router = express.Router();
var hammerhead = require('../hammerhead')

router.get('/', function (req, res, next) {
  hammerhead.protect(req, res, function () {
    res.render('index', { title: 'Express' });
  })
});

router.get('/monitor', function (req, res, next) {
  res.render('monit', { ips: JSON.stringify(hammerhead.getips()), blacklist: JSON.stringify(hammerhead.getblacklist()) });
})

router.get('/bl', function (req, res, next) {
  res.send(hammerhead.getblacklist());
})

module.exports = router;
