import { IncomingMessage, ServerResponse } from "http";

interface HelmetOptions {
  contentSecurityPolicy?: any;
  dnsPrefetchControl?: any;
  expectCt?: any;
  frameguard?: any;
  hidePoweredBy?: any;
  hsts?: any;
  ieNoOpen?: any;
  noSniff?: any;
  permittedCrossDomainPolicies?: any;
  referrerPolicy?: any;
  xssFilter?: any;
}

interface MiddlewareFunction {
  (req: IncomingMessage, res: ServerResponse, next: () => void): void;
}

const DEFAULT_MIDDLEWARE = [
  "dnsPrefetchControl",
  "frameguard",
  "hidePoweredBy",
  "hsts",
  "ieNoOpen",
  "noSniff",
  "xssFilter",
];

type MiddlewareName =
  | "contentSecurityPolicy"
  | "dnsPrefetchControl"
  | "expectCt"
  | "frameguard"
  | "hidePoweredBy"
  | "hsts"
  | "ieNoOpen"
  | "noSniff"
  | "permittedCrossDomainPolicies"
  | "referrerPolicy"
  | "xssFilter";

const middlewares: MiddlewareName[] = [
  "contentSecurityPolicy",
  "dnsPrefetchControl",
  "expectCt",
  "frameguard",
  "hidePoweredBy",
  "hsts",
  "ieNoOpen",
  "noSniff",
  "permittedCrossDomainPolicies",
  "referrerPolicy",
  "xssFilter",
];

function helmet(options: Readonly<HelmetOptions> = {}) {
  if (options.constructor.name === "IncomingMessage") {
    throw new Error(
      "It appears you have done something like `app.use(helmet)`, but it should be `app.use(helmet())`."
    );
  }

  const stack: MiddlewareFunction[] = middlewares.reduce(function (
    result,
    middlewareName
  ) {
    const middleware = helmet[middlewareName];
    let middlewareOptions = options[middlewareName];
    const isDefault = DEFAULT_MIDDLEWARE.indexOf(middlewareName) !== -1;

    if (middlewareOptions === false) {
      return result;
    } else if (middlewareOptions === true) {
      middlewareOptions = {};
    }

    if (middlewareOptions != null) {
      return result.concat(middleware(middlewareOptions));
    } else if (isDefault) {
      return result.concat(middleware({}));
    }
    return result;
  },
  []);

  return function helmet(
    req: IncomingMessage,
    res: ServerResponse,
    next: (...args: unknown[]) => void
  ) {
    let index = 0;

    function internalNext(...args: unknown[]) {
      if (args.length > 0) {
        next(...args);
        return;
      }

      const middleware = stack[index];
      if (!middleware) {
        return next();
      }

      index++;

      middleware(req, res, internalNext);
    }

    internalNext();
  };
}

helmet.contentSecurityPolicy = require("helmet-csp");
helmet.dnsPrefetchControl = require("dns-prefetch-control");
helmet.expectCt = require("expect-ct");
helmet.frameguard = require("frameguard");
helmet.hidePoweredBy = require("hide-powered-by");
helmet.hsts = require("hsts");
helmet.ieNoOpen = require("ienoopen");
helmet.noSniff = require("dont-sniff-mimetype");
helmet.permittedCrossDomainPolicies = require("helmet-crossdomain");
helmet.referrerPolicy = require("referrer-policy");
helmet.xssFilter = require("x-xss-protection");

export = helmet;
