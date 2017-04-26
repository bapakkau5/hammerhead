var ip_util = require('ip');
var env = require('./env');
const banTokenStore = (process.env.r_remote == 'true') ? require('redis').createClient({ port: process.env.r_port, host: process.env.r_host, auth_pass: process.env.r_pass, tls: { servername: process.env.r_host } }) : require('redis').createClient();

var options = {
    request_limit: 1000,
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

var state = {
    reverseproxychecked: false,
    reverseproxy: false
};

var IPS = {};

function getRemoteIP(req) {
    return req.headers['x-real-ip'] ? req.headers['x-real-ip'] : req.headers['x-forwarded-for'];
}

function getIP(req) {
    if (!state.reverseproxychecked) {
        console.log("[+] CHECKING FOR A REVERSE PROXY.")
        var nginxHeader = req.headers['x-nginx-proxy'];
        var isNginxForwarded = (nginxHeader == null || nginxHeader == 'false') ? false : true;
        if (isNginxForwarded) {
            console.log("[+] REVERSE PROXY DETECTED.");
            state.reverseproxy = true;
        }
        else
            console.log("[+] NO REVERSE PROXY. EXPRESS HANDLES CLIENT CONNECTIONS.")
        state.reverseproxychecked = true;
    }
    var ip_address = null;
    if (state.reverseproxy)
        ip_address = getRemoteIP(req);
    else
        ip_address = req.connection.remoteAddress;

    if (!ip_address)
        return null;
    if (ip_address == '::1')
        return '127.0.0.1';
    if (ip_util.isV6Format(ip_address) && ~ip_address.indexOf('::ffff'))
        ip_address = ip_address.split('::ffff:')[1];

    return ip_address;

}

function kick(req, res, ip) {
    if (options.log) console.log('[HH] REQUEST FROM ' + ip + ' REJECTED AT ' + (new Date()));
    else if (typeof options.action === 'number') {
        res.status(options.action);
        res.send(options.message);
    }
}

module.exports = {

    getips: function () {
        return IPS;
    },

    getblacklist: function () {
        return options.blacklist;
    },

    protect: function (req, res, next) {
        var ip = getIP(req);

        let ipUndetected = (ip) => { return !ip && ip in options.block_undetected }
        let isBlackListedIP = (ip) => { return options.blacklist.length > 0 && options.blacklist.indexOf(ip) >= 0 }
        let isWhiteListedIP = (ip) => { return options.whitelist.length > 0 && options.whitelist.indexOf(ip) >= 0 }

        if (ipUndetected(ip) || isBlackListedIP(ip)) {
            res.status(429)
            req.connection.end()
        }
        else if (isWhiteListedIP(ip))
            next();
        else {
            var exists = IPS[ip];
            if (exists) {
                banTokenStore.exists(ip, (err, reply) => {
                    if (reply == 1)
                        kick(req, res, ip)
                    else {

                        IPS[ip].requests++;

                        if (IPS[ip].requests % options.request_limit == 0) {
                            var ban_duration = exists.epochs < options.ban_threshold ? (options.duration * (exists.epochs + 1)) : options.ban_threshold * options.duration * Math.pow(2, (exists.epochs - options.ban_threshold))
                            banTokenStore.set(ip, "BANNED: " + new Date())
                            banTokenStore.expire(ip, ban_duration);
                            console.log('[HH] IP BANNED : ', ip);
                            IPS[ip].epochs++;
                            IPS[ip].ban_duration = ban_duration;
                            IPS[ip].ban_time = new Date();
                            if (IPS[ip].epochs == options.epoch_limit)
                                options.blacklist.push(ip);
                            kick(req, res, ip)
                        }
                        else
                            next();
                    }
                })
            }
            else {
                IPS[ip] = { requests: 1, epochs: 0, ban_duration: 0, ban_time: null };
                next();
            }
        }
    }
}
