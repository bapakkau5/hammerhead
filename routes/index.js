var express = require('express');
var router = express.Router();
var hammerhead = require('../hammerhead')

hammerhead.setConfig({ whitelist: ['127.0.0.1'] });

router.get('/', function (req, res, next) {
  hammerhead.protect(req, res, function () {
    res.render('index', { title: 'Express-HH-Get' });
  })
});

router.post('/', function (req, res, next) {
  hammerhead.protect(req, res, function () {
    res.render('index', { title: 'Express-HH-Post' });
  })
});

router.get('/monitor', function (req, res, next) {
  res.render('monit', { ips: hammerhead.getIPs(), lists: JSON.stringify(hammerhead.getLists()) });
})

module.exports = router;
