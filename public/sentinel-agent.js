/*!
 * SentinelGlobe Browser Shield v1.0
 * Include with:
 * <script src="https://your-sentinel-host/sentinel-agent.js" data-site="example.com" defer></script>
 *
 * This is a client-side detection layer. It reports tampering, injected scripts,
 * clickjacking, form hijacking and known-bad resources to the SentinelGlobe
 * control plane. It is not a substitute for server-side WAF/firewall rules.
 */
(function () {
  'use strict';
  if (window.SentinelShield) return;

  var script = document.currentScript;
  var src = script && script.src ? script.src : '';
  var endpoint = (script && script.getAttribute('data-endpoint')) || (src ? new URL(src).origin + '/api/agent/beacon' : '');
  var site = (script && script.getAttribute('data-site')) || location.hostname;
  var mode = (script && script.getAttribute('data-mode')) || 'protect';
  var blockedDomains = [];
  var reported = {};
  var queue = [];
  var flushTimer = null;

  function absolute(url) {
    try {
      return new URL(url, location.href).href;
    } catch (error) {
      return String(url || '');
    }
  }

  function hostOf(url) {
    try {
      return new URL(url, location.href).hostname.toLowerCase();
    } catch (error) {
      return '';
    }
  }

  function isBlocked(url) {
    var host = hostOf(url);
    if (!host) return false;
    for (var i = 0; i < blockedDomains.length; i += 1) {
      var domain = String(blockedDomains[i] || '').toLowerCase().replace(/^\*\./, '');
      if (domain && (host === domain || host.endsWith('.' + domain))) return true;
    }
    return false;
  }

  function isHighConfidenceBad(url) {
    return /coinhive|cryptonight|coin-hive|webmine|minero\.cc|crypto-loot|coinimp|jsecoin|deepMiner|reconnectwifi|browsermine/i.test(
      String(url || ''),
    );
  }

  function send(payload, sync) {
    var body = JSON.stringify(payload);
    if (sync && navigator.sendBeacon) {
      try {
        navigator.sendBeacon(endpoint, new Blob([body], { type: 'text/plain;charset=UTF-8' }));
        return;
      } catch (error) {
        /* fall through */
      }
    }
    try {
      fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        keepalive: true,
        mode: 'cors',
        credentials: 'omit',
      }).catch(function () {});
    } catch (error) {
      /* ignore */
    }
  }

  function report(type, detail, severity, extra) {
    if (!endpoint) return;
    var key = type + '|' + detail;
    if (reported[key]) return;
    reported[key] = Date.now();
    var payload = {
      site: site,
      type: type,
      detail: String(detail || '').slice(0, 500),
      url: location.href,
      severity: severity || 'ELEVATED',
      referrer: document.referrer || '',
      ua: navigator.userAgent,
      at: new Date().toISOString(),
    };
    if (extra) {
      for (var name in extra) {
        if (Object.prototype.hasOwnProperty.call(extra, name)) payload[name] = extra[name];
      }
    }
    queue.push(payload);
    if (!flushTimer) {
      flushTimer = window.setTimeout(function () {
        flushTimer = null;
        var batch = queue.splice(0, queue.length);
        for (var i = 0; i < batch.length; i += 1) send(batch[i], false);
      }, 250);
    }
  }

  function removeResource(element, reason, url) {
    if (!element || !element.parentNode) return;
    if (mode === 'protect') {
      element.parentNode.removeChild(element);
      report('blocked-resource', reason + ' ' + absolute(url), 'HIGH', { removed: true });
    } else {
      report('suspicious-resource', reason + ' ' + absolute(url), 'ELEVATED', { removed: false });
    }
  }

  function inspectElement(element) {
    if (!element || element.nodeType !== 1) return;
    var tag = String(element.tagName || '').toLowerCase();
    if (tag !== 'script' && tag !== 'iframe' && tag !== 'link') return;
    var url = element.getAttribute('src') || element.getAttribute('href') || '';
    if (!url) return;
    var absoluteUrl = absolute(url);
    if (isBlocked(absoluteUrl) || isHighConfidenceBad(absoluteUrl)) {
      removeResource(element, 'Known malicious domain or miner:', absoluteUrl);
      return;
    }
    if (location.protocol === 'https:' && /^http:\/\//i.test(absoluteUrl)) {
      report('mixed-content', 'Insecure resource on HTTPS page: ' + absoluteUrl, 'ELEVATED');
    }
  }

  function inspectForm(form) {
    if (!form || !form.getAttribute) return;
    var action = form.getAttribute('action') || '';
    if (!action) return;
    var actionHost = hostOf(action);
    if (!actionHost) return;
    if (actionHost !== location.hostname && !isBlocked(action)) {
      report('form-hijack', 'Form submits to external host: ' + actionHost, 'HIGH', {
        formAction: absolute(action),
      });
    }
  }

  function scan(root) {
    if (!root || !root.querySelectorAll) return;
    var nodes = root.querySelectorAll('script[src],iframe[src],link[href],form[action]');
    for (var i = 0; i < nodes.length; i += 1) {
      var node = nodes[i];
      if (node.tagName && node.tagName.toLowerCase() === 'form') inspectForm(node);
      else inspectElement(node);
    }
  }

  function bootConfig() {
    if (!endpoint) return;
    try {
      fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site: site,
          type: 'agent-online',
          detail: 'Browser shield loaded on ' + location.hostname,
          url: location.href,
          severity: 'CLEAN',
        }),
        mode: 'cors',
        credentials: 'omit',
      })
        .then(function (response) {
          return response.ok ? response.json() : null;
        })
        .then(function (payload) {
          if (payload && Array.isArray(payload.blockedDomains)) {
            blockedDomains = payload.blockedDomains;
            scan(document);
          }
        })
        .catch(function () {});
    } catch (error) {
      /* ignore */
    }
  }

  window.SentinelShield = {
    version: '1.0.0',
    report: report,
    scan: scan,
    blockedDomains: function () {
      return blockedDomains.slice();
    },
    site: site,
  };

  if (window.top !== window.self) {
    report('clickjacking', 'Page is framed by ' + (document.referrer || 'an unknown origin'), 'HIGH');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      scan(document);
      bootConfig();
    });
  } else {
    scan(document);
    bootConfig();
  }

  if (window.MutationObserver) {
    var observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i += 1) {
        var mutation = mutations[i];
        if (mutation.type === 'attributes' && mutation.target && mutation.target.tagName) {
          var tag = mutation.target.tagName.toLowerCase();
          if (tag === 'form') inspectForm(mutation.target);
          else inspectElement(mutation.target);
        }
        for (var j = 0; j < mutation.addedNodes.length; j += 1) {
          var node = mutation.addedNodes[j];
          if (node.nodeType === 1) {
            inspectElement(node);
            if (node.querySelectorAll) scan(node);
          }
        }
      }
    });
    observer.observe(document.documentElement || document, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src', 'href', 'action'],
    });
  }

  window.addEventListener('error', function (event) {
    if (event && event.message && /blocked|csp|refused/i.test(String(event.message))) {
      report('client-error', String(event.message), 'ELEVATED');
    }
  });

  window.addEventListener('securitypolicyviolation', function (event) {
    report(
      'csp-violation',
      (event.violatedDirective || 'CSP') + ' blocked ' + (event.blockedURI || 'a resource'),
      'ELEVATED',
    );
  });

  window.addEventListener('pagehide', function () {
    var pending = queue.splice(0, queue.length);
    for (var i = 0; i < pending.length; i += 1) send(pending[i], true);
  });
})();
