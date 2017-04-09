var ip_util = require('ip');

var options = {
    limit: 10,
    refresh: 5,
    block_undetected: false,
    action: 'close',
    message: 'Blocked by HammerHead',
    duration: 120,
    blacklist: null,
    whitelist: null,
    log: true,
    callback: null
};

var state = {
    reverseproxychecked: false,
    reverseproxy: false
};

var BANS = {};
var IPS = {};

function getRemoteIP(req) {
    return req.headers['x-real-ip'];
}

function getIP(req) {
    if (!state.reverseproxychecked) {
        console.log("[+] CHECKING IF NGINX IS THE REVERSE PROXY.")
        var nginxHeader = req.headers['x-nginx-proxy'];
        var isNginxForwarded = (nginxHeader == null || nginxHeader == 'false') ? false : true;
        if (isNginxForwarded) {
            console.log("[+] NGINX DETECTED.");
            state.reverseproxy = true;
        }
        else
            console.log("[+] EXPRESS HANDLES CLIENT CONNECTIONS.")
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

function ban(req, res, ip) {
    if (options.log) console.log('[HH] REQUEST FROM ' + ip + ' REJECTED AT ' + (new Date()));
    if (options.action == 'close')
        req.connection.end();
    else if (typeof options.action === 'number') {
        res.status(options.action);
        return res.send(options.message);
    }
    else
        return res.status(403);
    if (options.callback && typeof options.callback === 'function') options.callback(ip);
}

function BotIPS() {
    for (var k in IPS) {
        if (IPS[k].counter === 1) delete IPS[k];
        else IPS[k].counter--;
    }

    setTimeout(function () {
        BotIPS();
    }, options.refresh);
}

function BotBANS() {
    for (var k in BANS) {
        if (BANS[k] === 1) delete BANS[k];
        else BANS[k]--;
    }

    console.log(BANS, IPS)

    setTimeout(function () {
        BotBANS();
    }, 1000);
}

module.exports = {

    optionsure: function (options) {
        options = Object.assign(options, options);
        options.refresh *= 1000;
        BotBANS();
        BotIPS();
    },

    viewoptions: function () {
        return options;
    },

    getbans: function () {
        return BANS;
    },

    protect: function (req, res, next) {
        var ip = getIP(req);

        req.ddos = {
            blacklist: function () {
                options.blacklist[ip] = true;
                ban(req, res, ip);
            },
            removeFromBlacklist: function () {
                delete options.blacklist[ip];
            },
            ban: function () {
                BANS[ip] = options.duration;
                ban(req, res, ip);
            }
        };

        if (!ip && options.block_undetected)
            req.ddos.ban();
        else if (options.blacklist && ip in options.blacklist)
            req.ddos.ban();
        else if (options.whitelist && ip in options.whitelist)
            next();
        else if (ip in BANS)
            req.ddos.ban();
        else {
            var data = IPS[ip];
            if (data) {
                if (IPS[ip].counter == options.limit - 1) {
                    BANS[ip] = options.duration;
                    ban(req, res, ip);
                } else {
                    IPS[ip].counter++;
                    next();
                }
            } else {
                IPS[ip] = { counter: 1 };
                next();
            }
        }
    }
}
