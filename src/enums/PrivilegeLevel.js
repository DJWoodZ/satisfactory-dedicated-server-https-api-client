/**
 * Privilege Level Enumeration representing different privilege levels granted by an authentication
 * token
 * @readonly
 * @enum {Object<string, string>}
 * @property {string} PrivilegeLevel.NotAuthenticated Not authenticated
 * @property {string} PrivilegeLevel.Client Authenticated with Client privileges
 * @property {string} PrivilegeLevel.Administrator Authenticated with Admin privileges
 * @property {string} PrivilegeLevel.InitialAdmin Authenticated as Initial Admin with privileges to
 * claim the server
 * @property {string} PrivilegeLevel.APIToken Authenticated as Third Party Application
 */
const PrivilegeLevel = new Proxy(Object.freeze({
  NotAuthenticated: 'NotAuthenticated',
  Client: 'Client',
  Administrator: 'Administrator',
  InitialAdmin: 'InitialAdmin',
  APIToken: 'APIToken',
}), {
  get: (target, prop) => {
    if (Reflect.has(target, prop)) {
      return target[prop];
    }
    throw new Error(`'${prop}' is not a valid privilege level`);
  },
});

module.exports = PrivilegeLevel;
