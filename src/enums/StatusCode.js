const statuses = {
  OK: { code: 200, name: 'Ok' },
  CREATED: { code: 201, name: 'Created' },
  ACCEPTED: { code: 202, name: 'Accepted' },
  NO_CONTENT: { code: 204, name: 'No Content' },
  BAD_REQUEST: { code: 400, name: 'Bad Request' },
  DENIED: { code: 401, name: 'Denied' },
  FORBIDDEN: { code: 403, name: 'Forbidden' },
  NOT_FOUND: { code: 404, name: 'Not Found' },
  UNSUPPORTED_MEDIA: { code: 415, name: 'Unsupported Media' },
  SERVER_ERROR: { code: 500, name: 'Server Error' },
  getStatusByCode(code) {
    const keys = Object.keys(this);
    const foundKey = keys.find((key) => this[key].code === code);
    if (!foundKey) {
      throw new Error(`'${code}' is not a valid status code`);
    }

    return this[foundKey];
  },
  getStatusByName(name) {
    const keys = Object.keys(this);
    const foundKey = keys.find((key) => this[key].name.toLowerCase() === name.toLowerCase());
    if (!foundKey) {
      throw new Error(`'${name}' is not a valid status name`);
    }

    return this[foundKey];
  },
  getSuccessfulStatusCodes() {
    const successfulCodes = Object.values(this)
      .filter((status) => status.code >= 200 && status.code < 300);
    return successfulCodes.map((status) => status.code);
  },
  getErrorCodes() {
    const unsuccessfulCodes = Object.values(this)
      .filter((status) => status.code >= 400);
    return unsuccessfulCodes.map((status) => status.code);
  },
};

Object.entries(statuses).forEach(([k, v]) => {
  if (typeof v === 'function') {
    Object.defineProperty(statuses, k, { enumerable: false });
  }
});

/**
 * Status Code Enumeration representing different HTTP response codes
 * @readonly
 * @enum {Object<string, Object<string, string|number>>}
 * @property {Object<string, string|number>} StatusCode.OK Status Code for Ok 200
 * @property {Object<string, string|number>} StatusCode.CREATED Status Code for Created 201
 * @property {Object<string, string|number>} StatusCode.ACCEPTED Status Code for Accepted 202
 * @property {Object<string, string|number>} StatusCode.NO_CONTENT Status Code for No Content 204
 * @property {Object<string, string|number>} StatusCode.BAD_REQUEST Status Code for Bad Request 400
 * @property {Object<string, string|number>} StatusCode.DENIED Status Code for Denied 401
 * @property {Object<string, string|number>} StatusCode.FORBIDDEN Status Code for Forbidden 403
 * @property {Object<string, string|number>} StatusCode.NOT_FOUND Status Code for Not Found 404
 * @property {Object<string, string|number>} StatusCode.UNSUPPORTED_MEDIA Status Code for
 * Unsupported Media 415
 * @property {Object<string, string|number>} StatusCode.SERVER_ERROR Status Code for Server Error
 * 500
 */
const StatusCode = new Proxy(Object.freeze(statuses), {
  get: (target, prop) => {
    if (Reflect.has(target, prop)) {
      return target[prop];
    }
    throw new Error(`'${prop}' is not a valid status code`);
  },
});

module.exports = StatusCode;
