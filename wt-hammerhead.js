'use latest';
import express from 'express';
import { fromExpress } from 'webtask-tools';
import bodyParser from 'body-parser';
const app = express();
const bluebird = require('bluebird');
const options = {
    request_limit: 5,
    ban_threshold: 3,
    epoch_limit: 10,
    block_undetected: true,
    action: 429,
    message: 'Blocked by HammerHead',
    duration: 60,
    blacklist: [],
    whitelist: [],
    log: true
};
const getIP = (req) => {
    var ip_address =  req.headers['x-forwarded-for'] || 
     req.connection.remoteAddress || 
     req.socket.remoteAddress ||
     req.connection.socket.remoteAddress;
    
    if (!ip_address)
        return null;
    if (ip_address == '::1')
        return '127.0.0.1';

    return ip_address;
};
var IPS = {}, BANS = {};
const kick = (req, res, ip) => {
  
    if (options.log) 
      console.info('[+HH+] REQUEST FROM ' + ip + ' REJECTED AT ' + (new Date()));
    
    if (typeof options.action === 'number') {
        res.status(options.action);
        res.send(options.message);
    }
};
const protect = (req, res, next) => {
        
        var ip = getIP(req);
        
        if(BANS[ip])
              return kick(req, res, ip);
              
        let expire = ip => new Promise(r => setTimeout(() =>{
          delete BANS[ip];
          r;
          }, IPS[ip].ban_duration * 1000));
        
        let ipUndetected = (ip) => { return !ip && options.block_undetected };
        let isBlackListedIP = (ip) => { return options.blacklist.length > 0 && options.blacklist.indexOf(ip) >= 0 };
        let isWhiteListedIP = (ip) => { return options.whitelist.length > 0 && options.whitelist.indexOf(ip) >= 0 };

        if (ipUndetected(ip) || isBlackListedIP(ip)) {
            kick(req, res, ip);
        }
        else if (isWhiteListedIP(ip))
            next();
        else {
            var exists = IPS[ip];
            if (exists) {
                IPS[ip].requests++;
                if (IPS[ip].requests % options.request_limit === 0) {
                    var ban_duration = exists.epochs < options.ban_threshold ? (options.duration * (exists.epochs + 1)) : options.ban_threshold * options.duration * Math.pow(2, (exists.epochs - options.ban_threshold + 1));
                   console.log('[+HH+] IP BANNED : ', ip);
                    
                    IPS[ip].epochs++;
                    IPS[ip].ban_duration = ban_duration;
                    IPS[ip].ban_time = new Date();

                    if (IPS[ip].epochs == options.epoch_limit)
                        options.blacklist.push(ip);
                    
                    if(!BANS[ip])
                          BANS[ip] = ip;
                          
                    expire(ip);
                    
                    kick(req, res, ip);
                    
                }
                else
                    next();
            }
            else {
                IPS[ip] = { requests: 1, epochs: 0, ban_duration: 0, ban_time: null };
                next();
            }
        }
    };
app.use(bodyParser.json());

app.get('/', (req, res) => {
  const HTML = renderView({
    title: 'HammerHead ON WT',
    body: '<h1>Protected Page</h1>'
  });
  
  protect(req, res,() =>{
    res.set('Content-Type', 'text/html');
    res.status(200).send(HTML);
  });
  
});
module.exports = fromExpress(app);

function renderView(locals) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>${locals.title}</title>
    </head>
    <body>
      ${locals.body}
    </body>
    </html>
  `;
}