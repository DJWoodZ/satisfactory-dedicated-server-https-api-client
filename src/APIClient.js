const nodeHttps = require('https');

const PrivilegeLevel = require('./enums/PrivilegeLevel');
const StatusCode = require('./enums/StatusCode');
const { deepMerge } = require('./utils');

const API_PATH = '/api/v1';

/**
 * An API client for interacting with the Dedicated Server HTTPS API.
 */
class APIClient {
  /**
   * Constructs a new instance of the Dedicated Server API client
   * @param {Object} options Configuration options for the API client
   * @param {string} [options.address='127.0.0.1'] The address of the Dedicated Server
   * @param {number} [options.port=7777] The port number of the Dedicated Server
   * @param {string} [options.authenticationToken] The authentication token to be set for requests
   * @param {Object} [options.https={request:{timeout:30000}}] Options for HTTPS functions
   * @param {Object} [options.https.request={timeout:30000}] Options for HTTPS request @see {@link https://nodejs.org/api/https.html#httpsrequestoptions-callback}
   */
  constructor({
    address = '127.0.0.1',
    port = 7777,
    authenticationToken,
    https = {},
  } = {}) {
    this.address = address;
    this.port = port;
    this.https = deepMerge({}, {
      request: {
        timeout: 30000,
      },
    }, https);
    this.authenticationToken = authenticationToken;
  }

  /**
     * Constructs and returns HTTP request options object for API requests
     * @private
     * @param {string} method The HTTP method to use (e.g., 'POST', 'GET')
     * @param {number} contentLength The length of the request body content in bytes
     * @param {string} [authenticationToken] Optional bearer token for authentication
     * @param {string} [boundary] Optional boundary used in multipart/form-data requests
     * @returns {Object} An object containing HTTP request options with headers and authorization
     * token (if provided)
     */
  #getRequestOptions(method, contentLength, authenticationToken, boundary) {
    const options = deepMerge({}, (this?.https?.request || {}), {
      hostname: this.address,
      port: this.port,
      path: API_PATH,
      method,
      headers: {
        'Content-Type': boundary ? `multipart/form-data; boundary=${boundary}` : 'application/json',
        'Content-Length': contentLength,
      },
    });

    if (authenticationToken) {
      if (typeof authenticationToken === 'string' && authenticationToken.length > 0) {
        options.headers.Authorization = `Bearer ${authenticationToken}`;
      } else {
        throw new Error('Bearer token invalid');
      }
    }

    return options;
  }

  /**
     * Sends a request to the Dedicated Server using HTTPS
     * @private
     * @param {string} method The HTTP method to use (e.g., 'GET', 'POST')
     * @param {Buffer|Object} data The data to be sent in the request body. If it's a Buffer,
     * it will be treated as a multipart/form-data payload; otherwise, it will be serialized as JSON
     * @param {string} [authenticationToken] Optional bearer token for authentication
     * @param {string} [boundary] Optional boundary used in multipart/form-data requests
     * @returns {Promise<Object|Buffer>} A promise that resolves to the response object (if JSON) or
     * the raw response buffer (if binary)
     */
  #getRequest(method, data, authenticationToken, boundary) {
    return new Promise((resolve, reject) => {
      const payload = Buffer.isBuffer(data) ? data : JSON.stringify(data);
      const dataLen = payload.length;

      const options = this.#getRequestOptions(
        method,
        dataLen,
        authenticationToken,
        boundary,
      );

      const req = nodeHttps.request(options, (res) => {
        const chunks = [];

        res.on('data', (chunk) => {
          chunks.push(chunk);
        });

        res.on('end', () => {
          const buffer = Buffer.concat(chunks);

          const resp = {
            status: StatusCode.getStatusByCode(res.statusCode),
          };

          if (res.headers?.['content-type'] === 'application/octet-stream') {
            resolve(buffer);
          } else if (res.headers?.['content-type']?.startsWith('application/json')) {
            const body = JSON.parse(buffer.toString());

            if (body?.data) {
              resp.data = body.data;
            }
            if (body?.errorCode) {
              resp.errorCode = body.errorCode;
            }
            if (body?.errorMessage) {
              resp.errorMessage = body.errorMessage;
            }
            if (body?.errorData) {
              resp.errorData = body.errorData;
            }

            if (StatusCode.getSuccessfulStatusCodes().includes(res.statusCode) && !resp.errorCode
                && !resp.errorMessage && !resp.errorData) {
              resolve(resp);
            } else {
              reject(new Error(JSON.stringify(resp)));
            }
          } else if (StatusCode.getSuccessfulStatusCodes().includes(res.statusCode)) {
            resolve(resp);
          } else {
            reject(new Error('Unexpected response'));
          }
        });
      });

      req.on('error', (e) => {
        req.destroy();
        reject(e);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timeout'));
      });

      req.write(payload);
      req.end();
    });
  }

  /**
     * Parses a given authentication token and returns its privilege level
     * @param {string} authenticationToken The authentication token string to parse
     * @returns {PrivilegeLevel} The privilege level of the authenticated user
     * @throws {Error} If the provided token is not valid or if it does not contain a
     * valid privilege level
     */
  static getAuthenticationTokenPrivilegeLevel(authenticationToken) {
    if (typeof authenticationToken === 'string' && authenticationToken.length > 0) {
      try {
        const payload = JSON.parse(atob(authenticationToken.split('.')[0]));
        if (payload?.pl && PrivilegeLevel[payload.pl]) {
          return PrivilegeLevel[payload.pl];
        }
      } catch {
        throw new Error('Bearer token invalid');
      }
    }

    throw new Error('Bearer token invalid');
  }

  /**
     * Retrieves the server and CA certificates from a remote server via HTTPS
     * @param {Object} [options] Optional parameters for the request
     * @param {string} [options.address='127.0.0.1'] The address of the remote server
     * @param {number} [options.port=7777] The port number of the remote server
     * @param {Object} [options.https={request:{timeout:30000}}] Options for HTTPS functions
     * @param {Object} [options.https.request={timeout:30000}] Options for HTTPS request @see {@link https://nodejs.org/api/https.html#httpsrequestoptions-callback}
     * @returns {Promise<{server: {cert: Object, pem: string}}>} A promise that resolves with the
     * server certificate or rejects with an error
     * @returns {Promise<{server: {cert: Object, pem: string}, ca: {cert: Object, pem: string}}>} A
     * promise that resolves with the server and CA certificates or rejects with an error
     */
  static getCertificates({
    address = '127.0.0.1',
    port = 7777,
    https = {},
  } = {}) {
    const httpsOpts = deepMerge({}, {
      request: {
        timeout: 30000,
      },
    }, https);

    const options = deepMerge({}, (httpsOpts?.request || {}), {
      hostname: address,
      port,
      path: API_PATH,
      method: 'GET',
    });

    return new Promise((resolve, reject) => {
      const req = nodeHttps.request(options, (res) => {
        res.on('data', () => {
          const serverCert = res.socket.getPeerCertificate();
          const caCert = res.socket.getPeerCertificate(true).issuerCertificate;

          if (serverCert) {
            // Get the subject and issuer subject from the certificate
            const certPemBody = serverCert.raw.toString('base64');
            const issuerPemBody = caCert ? caCert.raw.toString('base64') : null;

            const serverPem = `-----BEGIN CERTIFICATE-----\n${certPemBody.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
            let ca;

            // Save the CA certificate (if available)
            if (issuerPemBody && !serverCert.raw.equals(caCert.raw)) {
              ca = {
                cert: caCert,
                pem: `-----BEGIN CERTIFICATE-----\n${issuerPemBody.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`,
              };
            }

            resolve({
              server: {
                cert: serverCert,
                pem: serverPem,
              },
              ca,
            });
          } else {
            reject(new Error('No certificate found.'));
          }
        });
      });

      req.on('error', (e) => {
        req.destroy();
        reject(e);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timeout'));
      });

      req.end();
    });
  }

  /**
     * Sets the API Client's authentication token
     * @param {string} authenticationToken The authentication token to be set
     * @throws {Error} Throws an error if the authenticationToken is not undefined, null or a string
     */
  setAPIClientAuthenticationToken(authenticationToken) {
    if (authenticationToken !== undefined && authenticationToken !== null && typeof authenticationToken !== 'string') {
      throw new Error('Invalid authentication token provided');
    }
    this.authenticationToken = authenticationToken;
  }

  /**
     * Sends a health check request to the dedicated server
     * @param {string} [clientCustomData=''] Defaults to an empty string if not provided
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the clientCustomData is not a string
     */
  healthCheck(clientCustomData = '') {
    if (typeof clientCustomData !== 'string') {
      throw new Error('clientCustomData must be a string');
    }

    const data = {
      function: 'HealthCheck',
      data: {
        clientCustomData,
      },
    };

    return this.#getRequest('POST', data);
  }

  /**
     * Verifies the authentication token currently set for the API Client
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     */
  verifyAuthenticationToken() {
    const data = {
      function: 'VerifyAuthenticationToken',
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Performs a passwordless login
     * @param {PrivilegeLevel} minimumPrivilegeLevel The minimum required privilege level requested
     * for the login
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the minimumPrivilegeLevel is not specified or if it's not
     * a string
     */
  passwordlessLogin(minimumPrivilegeLevel) {
    if (minimumPrivilegeLevel === undefined || minimumPrivilegeLevel === null) {
      throw new Error('minimumPrivilegeLevel must be specified');
    }
    if (typeof minimumPrivilegeLevel !== 'string') {
      throw new Error('minimumPrivilegeLevel must be a string');
    }

    const data = {
      function: 'PasswordlessLogin',
      data: {
        MinimumPrivilegeLevel: minimumPrivilegeLevel,
      },
    };

    return this.#getRequest('POST', data);
  }

  /**
     * Performs a password login
     * @param {PrivilegeLevel} minimumPrivilegeLevel The minimum required privilege level requested
     * for the login
     * @param {string} password The password used for authentication
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the minimumPrivilegeLevel is not specified or if it's not
     * a string
     * @throws {Error} Throws an error if the password is not specified or if it's not a string
     */
  passwordLogin(minimumPrivilegeLevel, password) {
    if (minimumPrivilegeLevel === undefined || minimumPrivilegeLevel === null) {
      throw new Error('minimumPrivilegeLevel must be specified');
    }
    if (typeof minimumPrivilegeLevel !== 'string') {
      throw new Error('minimumPrivilegeLevel must be a string');
    }
    if (password === undefined || password === null) {
      throw new Error('password must be specified');
    }
    if (typeof password !== 'string') {
      throw new Error('password must be a string');
    }

    const data = {
      function: 'PasswordLogin',
      data: {
        MinimumPrivilegeLevel: minimumPrivilegeLevel,
        Password: password,
      },
    };

    return this.#getRequest('POST', data);
  }

  /**
     * Queries the state of the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     */
  queryServerState() {
    const data = {
      function: 'QueryServerState',
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Gets the options for the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     */
  getServerOptions() {
    const data = {
      function: 'GetServerOptions',
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Gets the advanced game settings for the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     */
  getAdvancedGameSettings() {
    const data = {
      function: 'GetAdvancedGameSettings',
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Applies the advanced game settings to the server
     * @param {Object} appliedAdvancedGameSettings,
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the appliedAdvancedGameSettings is not specified or if
     * it's not an object
     */
  applyAdvancedGameSettings(appliedAdvancedGameSettings) {
    if (appliedAdvancedGameSettings === undefined || appliedAdvancedGameSettings === null) {
      throw new Error('appliedAdvancedGameSettings must be specified');
    }
    if (typeof appliedAdvancedGameSettings !== 'object' || !Object.prototype.isPrototypeOf.call(Object.getPrototypeOf(appliedAdvancedGameSettings), Object)) {
      throw new Error('appliedAdvancedGameSettings must be an object');
    }

    const data = {
      function: 'ApplyAdvancedGameSettings',
      data: {
        AppliedAdvancedGameSettings: appliedAdvancedGameSettings,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Stakes a claim on the server
     * @param {string} serverName the name to set for the server
     * @param {string} adminPassword the admin password to set for the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the serverName is not specified or if it's not a string
     * @throws {Error} Throws an error if the adminPassword is not specified or if it's not a string
     */
  claimServer(serverName, adminPassword) {
    if (serverName === undefined || serverName === null) {
      throw new Error('serverName must be specified');
    }
    if (typeof serverName !== 'string') {
      throw new Error('serverName must be a string');
    }
    if (adminPassword === undefined || adminPassword === null) {
      throw new Error('adminPassword must be specified');
    }
    if (typeof adminPassword !== 'string') {
      throw new Error('adminPassword must be a string');
    }

    const data = {
      function: 'ClaimServer',
      data: {
        ServerName: serverName,
        AdminPassword: adminPassword,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Renames the server
     * @param {string} serverName the name to set for the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the serverName is not specified or if it's not a string
     */
  renameServer(serverName) {
    if (serverName === undefined || serverName === null) {
      throw new Error('serverName must be specified');
    }
    if (typeof serverName !== 'string') {
      throw new Error('serverName must be a string');
    }

    const data = {
      function: 'RenameServer',
      data: {
        ServerName: serverName,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Sets the client password for the server
     * @param {string} password the client password to set for the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the password is not specified or if it's not a string
     */
  setClientPassword(password) {
    if (password === undefined || password === null) {
      throw new Error('password must be specified');
    }
    if (typeof password !== 'string') {
      throw new Error('password must be a string');
    }

    const data = {
      function: 'SetClientPassword',
      data: {
        Password: password,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Sets the admin password for the server
     * @param {string} password the admin password to set for the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the password is not specified or if it's not a string
     */
  setAdminPassword(password) {
    if (password === undefined || password === null) {
      throw new Error('password must be specified');
    }
    if (typeof password !== 'string') {
      throw new Error('password must be a string');
    }

    const data = {
      function: 'SetAdminPassword',
      data: {
        Password: password,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Sets the session to auto load on the server
     * @param {string} sessionName the name of the session to load automatically when the server
     * starts
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the sessionName is not specified or if it's not a string
     */
  setAutoLoadSessionName(sessionName) {
    if (sessionName === undefined || sessionName === null) {
      throw new Error('sessionName must be specified');
    }
    if (typeof sessionName !== 'string') {
      throw new Error('sessionName must be a string');
    }

    const data = {
      function: 'SetAutoLoadSessionName',
      data: {
        SessionName: sessionName,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Runs a command on the server
     * @param {string} command the command to run on the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the command is not specified or if it's not a string
     */
  runCommand(command) {
    if (command === undefined || command === null) {
      throw new Error('command must be specified');
    }
    if (typeof command !== 'string') {
      throw new Error('command must be a string');
    }

    const data = {
      function: 'RunCommand',
      data: {
        Command: command,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Requests the server to shut down
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     */
  shutdown() {
    const data = {
      function: 'Shutdown',
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Applies new server options to the server
     * @param {Object<string, string>} updatedServerOptions the new server options to apply to the
     * server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the updatedServerOptions is not specified or if it's not
     * an object
     */
  applyServerOptions(updatedServerOptions) {
    if (updatedServerOptions === undefined || updatedServerOptions === null) {
      throw new Error('updatedServerOptions must be specified');
    }
    if (typeof updatedServerOptions !== 'object' || !Object.prototype.isPrototypeOf.call(Object.getPrototypeOf(updatedServerOptions), Object)) {
      throw new Error('updatedServerOptions must be an object');
    }

    const data = {
      function: 'ApplyServerOptions',
      data: {
        UpdatedServerOptions: updatedServerOptions,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Creates a new game on the server
     * @param {Object} newGameData Data for creating a new game.
     * @param {string} newGameData.SessionName The name of the session to create.
     * @param {string} [newGameData.MapName] Path name to the Map Package to use as a map.
     * @param {string} [newGameData.StartingLocation] Name of the starting location.
     * @param {boolean} [newGameData.SkipOnboarding] Whenever the Onboarding should be skipped.
     * @param {Object<string, string>} [newGameData.AdvancedGameSettings] Advanced game settings.
     * @param {Object<string, string>} [newGameData.CustomOptionsOnlyForModding] Custom options.
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the newGameData is not specified or if it's not an object
     */
  createNewGame(newGameData) {
    if (newGameData === undefined || newGameData === null) {
      throw new Error('newGameData must be specified');
    }
    if (typeof newGameData !== 'object' || !Object.prototype.isPrototypeOf.call(Object.getPrototypeOf(newGameData), Object)) {
      throw new Error('newGameData must be an object');
    }

    const data = {
      function: 'CreateNewGame',
      data: {
        NewGameData: newGameData,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Saves the game on the server using the provided name
     * @param {string} saveName the name to use for the save
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the saveName is not specified or if it's not a string
     */
  saveGame(saveName) {
    if (saveName === undefined || saveName === null) {
      throw new Error('saveName must be specified');
    }
    if (typeof saveName !== 'string') {
      throw new Error('saveName must be a string');
    }

    const data = {
      function: 'SaveGame',
      data: {
        SaveName: saveName,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Delete a save file from the server
     * @param {string} saveName the name of the save file to delete
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the saveName is not specified or if it's not a string
     */
  deleteSaveFile(saveName) {
    if (saveName === undefined || saveName === null) {
      throw new Error('saveName must be specified');
    }
    if (typeof saveName !== 'string') {
      throw new Error('saveName must be a string');
    }

    const data = {
      function: 'DeleteSaveFile',
      data: {
        SaveName: saveName,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Deletes all save files from the server belonging to the given session name
     * @param {string} sessionName the name of the session to delete all saves for
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the sessionName is not specified or if it's not a string
     */
  deleteSaveSession(sessionName) {
    if (sessionName === undefined || sessionName === null) {
      throw new Error('sessionName must be specified');
    }
    if (typeof sessionName !== 'string') {
      throw new Error('sessionName must be a string');
    }

    const data = {
      function: 'DeleteSaveSession',
      data: {
        SessionName: sessionName,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Enumerates all sessions on the server
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     */
  enumerateSessions() {
    const data = {
      function: 'EnumerateSessions',
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Loads a save game file on the Server with the given name
     * @param {string} saveName the name of the save file to load
     * @param {boolean} [enableAdvancedGameSettings] Whether to enable advanced game settings
     * (default is false)
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the saveName is not specified or if it's not a string
     * @throws {Error} Throws an error if the enableAdvancedGameSettings is not a boolean
     */
  loadGame(saveName, enableAdvancedGameSettings = false) {
    if (saveName === undefined || saveName === null) {
      throw new Error('saveName must be specified');
    }
    if (typeof saveName !== 'string') {
      throw new Error('saveName must be a string');
    }
    if (typeof enableAdvancedGameSettings !== 'boolean') {
      throw new Error('enableAdvancedGameSettings must be a boolean');
    }

    const data = {
      function: 'LoadGame',
      data: {
        SaveName: saveName,
        EnableAdvancedGameSettings: enableAdvancedGameSettings,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }

  /**
     * Upload a save game file to the server using the given and name
     * @param {Buffer} buffer the buffer to upload from
     * @param {string} saveName the name of the save file to create on the server
     * @param {boolean} [loadSaveGame] whether to load the uploaded save game (default is false)
     * @param {boolean} [enableAdvancedGameSettings] whether to enable advanced game settings
     * (default is false)
     * @returns {Promise<*>} Returns a Promise that resolves with the response from the server
     * @throws {Error} Throws an error if the loadSaveGame is not a boolean
     * @throws {Error} Throws an error if the enableAdvancedGameSettings is not a boolean
     */
  uploadSaveGame(buffer, saveName, loadSaveGame = false, enableAdvancedGameSettings = false) {
    if (typeof loadSaveGame !== 'boolean') {
      throw new Error('loadSaveGame must be a boolean');
    }
    if (typeof enableAdvancedGameSettings !== 'boolean') {
      throw new Error('enableAdvancedGameSettings must be a boolean');
    }

    const data = {
      function: 'UploadSaveGame',
      data: {
        SaveName: saveName,
        LoadSaveGame: loadSaveGame,
        EnableAdvancedGameSettings: enableAdvancedGameSettings,
      },
    };

    const date = new Date();
    const boundary = `${date.getTime()}${Math.random().toString(16).slice(2)}`;

    const multipart = Buffer.concat([
      Buffer.from(`--${boundary}\r\n`),
      Buffer.from('Content-Disposition: form-data; name="data"\r\n'),
      Buffer.from('Content-Type: application/json\r\n\r\n'),
      Buffer.from(`${JSON.stringify(data)}\r\n`),
      Buffer.from(`--${boundary}\r\n`),
      Buffer.from(`Content-Disposition: form-data; name="saveGameFile"; filename="${saveName}.sav"\r\n`),
      Buffer.from('Content-Type: application/octet-stream\r\n\r\n'),
      buffer,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);

    return this.#getRequest('POST', multipart, this.authenticationToken, boundary);
  }

  /**
     * Downloads a save game with the given name from the server
     * @param {string} saveName the name of the save game to download
     * @returns {Promise<Buffer>} a promise that resolves to the buffer of the downloaded save game
     * file
     * @throws {Error} Throws an error if the saveName is not specified or if it's not a string
     */
  downloadSaveGame(saveName) {
    if (saveName === undefined || saveName === null) {
      throw new Error('saveName must be specified');
    }
    if (typeof saveName !== 'string') {
      throw new Error('saveName must be a string');
    }

    const data = {
      function: 'DownloadSaveGame',
      data: {
        SaveName: saveName,
      },
    };

    return this.#getRequest('POST', data, this.authenticationToken);
  }
}

module.exports = APIClient;
