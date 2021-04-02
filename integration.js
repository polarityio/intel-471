"use strict";

const request = require("request");
const config = require("./config/config");
const async = require("async");
const fs = require("fs");

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === "string" && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === "string" && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === "string" && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === "string" && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === "string" && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === "boolean") {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug(entities);

  entities.forEach(entity => {
    let requestOptions = {
      method: "GET",
      uri: `${options.url}/v1/search`,
      auth: {
        user: options.userName,
        pass: options.apiKey
      },
      json: true
    };

    if (entity.type != 'cve') {
      requestOptions.qs = {ioc: `${entity.value}`}
    } else if (entity.type === 'cve') {
      requestOptions.qs = {cveReport: `${entity.value}`}
    } else {
      return;
    }

    Logger.trace({ uri: requestOptions }, "Request URI");

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        if (error) {
          return done(error);
        }

        Logger.trace(requestOptions);
        Logger.trace(
          { body, statusCode: res ? res.statusCode : "N/A" },
          "Result of Lookup"
        );

        let result = {};

        if (res.statusCode === 200) {
          result = {
            entity,
            body
          };
        } else if (res.statusCode === 404 || res.statusCode === 202) {
          result = {
            entity,
            body: null
          };
        } else {
          let error = {
            err: body,
            detail: `${body.error}: ${body.message}`
          };
          if (res.statusCode === 401) {
            error = {
              err: 'Unauthorized',
              detail: 'Request had Authorization header but token was missing or invalid. Please ensure your API token is valid.'
            };
          } else if (res.statusCode === 403) {
            error = {
              err: 'Access Denied',
              detail: 'Not enough access permissions.'
            };
          } else if (res.statusCode === 404) {
            error = {
              err: 'Not Found',
              detail: 'Requested item doesn’t exist or not enough access permissions.'
            };
          } else if (res.statusCode === 429) {
            error = {
              err: 'Too Many Requests',
              detail: 'Daily number of requests exceeds limit. Check Retry-After header to get information about request delay.'
            };
          } else if (Math.round(res.statusCode / 10) * 10 === 500) {
            error = {
              err: 'Server Error',
              detail: 'Something went wrong on our End (Intel471 API)'
            };
          }

          return done(error);
        }

        done(null, result);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, "Error");
      cb(err);
      return;
    }

    results.forEach(({ body, entity }) => {
      if (body === null || _isMiss(body)) {
        lookupResults.push({
          entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity,
          data: {
            summary: [],
            details: body
          }
        });
      }
    });

    Logger.debug({ lookupResults }, "Results");
    cb(null, lookupResults);
  });
}

const _isMiss = (body) => {
  const noValidReturnValues = !(
    (Array.isArray(body.indicators) && body.indicators.length > 0) ||
    (Array.isArray(body.cveReports) && body.cveReports.length > 0) ||
    (Array.isArray(body.spotReports) && body.spotReports.length > 0) ||
    (Array.isArray(body.iocs) && body.iocs.length > 0) ||
    (Array.isArray(body.events) && body.events.length > 0) ||
    (Array.isArray(body.reports) && body.reports.length > 0) ||
    (Array.isArray(body.posts) && body.posts.length > 0) ||
    (Array.isArray(body.entities) && body.entities.length > 0) ||
    (Array.isArray(body.nidsList) && body.nids.length > 0) ||
    (Array.isArray(body.privateMessages) && body.privateMessages.length > 0) ||
    (Array.isArray(body.yaras) && body.yaras.length > 0) ||
    (Array.isArray(body.malwareReports) && body.malwareReports.length > 0) ||
    (Array.isArray(body.actors) && body.actors.length > 0)
  );

  return !body || noValidReturnValues
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== "string" ||
    (typeof options[optionName].value === "string" &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(
    errors,
    options,
    "userName",
    "You must provide a valid Intel 471 Username"
  );
  validateStringOption(
    errors,
    options,
    "apiKey",
    "You must provide a valid Intel 471 API Key"
  );

  callback(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
