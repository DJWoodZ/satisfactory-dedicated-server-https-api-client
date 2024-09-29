import https from 'https';
import APIClient from '../src/APIClient';

const createSuccessfulHTTPSRequestMock = () => {
  const responseData = { test: true };
  const statusCode = 200;
  const writeMock = jest.fn();

  const requestSpy = jest.spyOn(https, 'request').mockImplementation((options, callback) => {
    const req = {
      end: jest.fn(),
      write: writeMock,
      destroy: jest.fn(),
      on: jest.fn(),
    };
    const res = {
      statusCode,
      headers: {
        'content-type': 'application/json',
      },
      setEncoding: jest.fn(),
      on: jest.fn((event, handler) => {
        if (event === 'data') {
          handler(Buffer.from(`{ "data": ${JSON.stringify(responseData)} }`));
        } else if (event === 'end') {
          handler();
        }
      }),
    };
    callback(res);
    return req;
  });

  return {
    writeMock,
    requestSpy,
  };
};

afterEach(() => {
  jest.resetAllMocks();
});

describe('APIClient()', () => {
  let client;

  beforeEach(() => {
    client = new APIClient();
  });

  afterEach(() => {
    client = null;
  });

  it('should have default values for properties', () => {
    expect(client.address).toBe('127.0.0.1');
    expect(client.port).toBe(7777);
    expect(client.authenticationToken).toBeUndefined();
    expect(client.https).toEqual({ request: { timeout: 30000 } });
  });

  it('should accept custom values for properties', () => {
    const address = '192.168.0.1';
    const port = 8080;
    const rejectUnauthorized = true;
    const checkServerIdentity = jest.fn();
    const ca = ['cert'];
    const timeout = 5000;
    const authenticationToken = 'abc123';

    client = new APIClient({
      address,
      port,
      authenticationToken,
      https: {
        request: {
          rejectUnauthorized,
          checkServerIdentity,
          ca,
          timeout,
        },
      },
    });

    expect(client.address).toBe(address);
    expect(client.port).toBe(port);
    expect(client.authenticationToken).toBe(authenticationToken);
    expect(client.https.request.rejectUnauthorized).toBe(rejectUnauthorized);
    expect(client.https.request.checkServerIdentity).toEqual(checkServerIdentity);
    expect(client.https.request.ca).toEqual(ca);
    expect(client.https.request.timeout).toBe(timeout);
  });
});

describe('APIClient.getAuthenticationTokenPrivilegeLevel', () => {
  it('should return the privilege level for a valid token', () => {
    const APITokenPl = btoa('{\n\t"pl": "APIToken"\n}');
    const authToken = `${APITokenPl}.SOME_TOKEN`;
    expect(APIClient.getAuthenticationTokenPrivilegeLevel(authToken)).toBe('APIToken');
  });

  it('should throw an error for a missing token', () => {
    expect(() => APIClient.getAuthenticationTokenPrivilegeLevel()).toThrowError('Bearer token invalid');
  });

  it('should throw an error for an empty token', () => {
    expect(() => APIClient.getAuthenticationTokenPrivilegeLevel('')).toThrowError('Bearer token invalid');
  });

  it('should throw an error for a malformed token', () => {
    const authToken = 'MALFORMED.SOME_TOKEN';
    expect(() => APIClient.getAuthenticationTokenPrivilegeLevel(authToken)).toThrowError('Bearer token invalid');
  });

  it('should throw an error for an unrecognized privilege level', () => {
    const InvalidTokenPl = btoa('{\n\t"pl": "InvalidToken"\n}');
    const authToken = `${InvalidTokenPl}.SOME_TOKEN`;
    expect(() => APIClient.getAuthenticationTokenPrivilegeLevel(authToken)).toThrowError('Bearer token invalid');
  });
});

describe('APIClient.getCertificates', () => {
  const mockGetPeerServerCertificateResponse = {
    raw: Buffer.from('certificate-data'),
  };

  const mockGetPeerCACertificateResponse = {
    raw: Buffer.from('issuer-certificate-data'),
  };

  const mockHTTPSRequest = (response1, response2, timeout, error) => {
    jest.spyOn(https, 'request').mockImplementation((options, callback) => {
      const req = {
        end: jest.fn(),
        write: jest.fn(),
        destroy: jest.fn(),
        on: jest.fn((event, handler) => {
          if (event === 'timeout' && timeout) {
            handler();
          } else if (event === 'error' && error) {
            handler(new Error('Mock error'));
          }
        }),
      };

      const res = {
        statusCode: 200,
        headers: {},
        setEncoding: jest.fn(),
        on: jest.fn((event, handler) => {
          if (!timeout) {
            if (event === 'data') {
              handler();
            } else if (event === 'end') {
              handler();
            }
          }
        }),
        socket: {
          getPeerCertificate: jest.fn((fullChain) => (fullChain
            ? {
              issuerCertificate: response2,
            } : response1)),
          destroy: jest.fn(),
          end: jest.fn(),
          write: jest.fn(),
        },
      };

      if (!timeout && !error) {
        callback(res);
      }

      return req;
    });
  };

  it('should handle successful request with server certificate and issuer certificate', async () => {
    mockHTTPSRequest(mockGetPeerServerCertificateResponse, mockGetPeerCACertificateResponse);

    const result = await APIClient.getCertificates({
      address: '127.0.0.1',
      port: 7777,
      rejectUnauthorized: true,
    });

    expect(result).toEqual({
      server: {
        cert: mockGetPeerServerCertificateResponse,
        pem: `-----BEGIN CERTIFICATE-----\n${mockGetPeerServerCertificateResponse.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`,
      },
      ca: {
        cert: mockGetPeerCACertificateResponse,
        pem: `-----BEGIN CERTIFICATE-----\n${mockGetPeerCACertificateResponse.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`,
      },
    });
  });

  it('should handle successful request with server certificate only', async () => {
    mockHTTPSRequest(mockGetPeerServerCertificateResponse, undefined);

    const result = await APIClient.getCertificates({
      address: '127.0.0.1',
      port: 7777,
      rejectUnauthorized: true,
    });

    expect(result).toEqual({
      server: {
        cert: mockGetPeerServerCertificateResponse,
        pem: `-----BEGIN CERTIFICATE-----\n${mockGetPeerServerCertificateResponse.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`,
      },
    });
  });

  it('should handle unsuccessful request due to no certificate found', async () => {
    mockHTTPSRequest(undefined, undefined);

    await expect(APIClient.getCertificates({
      address: '127.0.0.1',
      port: 7777,
      rejectUnauthorized: true,
    })).rejects.toThrowError('No certificate found.');
  });

  it('should handle unsuccessful request due to error', async () => {
    mockHTTPSRequest(undefined, undefined, false, true);

    await expect(APIClient.getCertificates({ address: '127.0.0.1', port: 7777 })).rejects.toThrowError('Mock error');
  });

  it('should handle unsuccessful request due to timeout', async () => {
    mockHTTPSRequest(undefined, undefined, true);

    await expect(APIClient.getCertificates({ address: '127.0.0.1', port: 7777 })).rejects.toThrowError('Timeout');
  });
});

describe('APIClient.setAPIClientAuthenticationToken', () => {
  let client;

  beforeEach(() => {
    client = new APIClient();
  });

  afterEach(() => {
    client.setAPIClientAuthenticationToken(null);
  });

  it('should set the authentication token', () => {
    const authToken = 'abc123';
    client.setAPIClientAuthenticationToken(authToken);
    expect(client.authenticationToken).toBe(authToken);
  });

  it('should handle undefined input for authentication token', () => {
    client.setAPIClientAuthenticationToken(undefined);
    expect(client.authenticationToken).toBeUndefined();
  });

  it('should clear the authentication token if no argument is passed', () => {
    client.setAPIClientAuthenticationToken('xyz789');
    client.setAPIClientAuthenticationToken();
    expect(client.authenticationToken).toBeUndefined();
  });

  it('should handle empty string as the authentication token', () => {
    const authToken = '';
    client.setAPIClientAuthenticationToken(authToken);
    expect(client.authenticationToken).toBe(authToken);
  });

  it('should handle null as the authentication token', () => {
    const authToken = null;
    client.setAPIClientAuthenticationToken(authToken);
    expect(client.authenticationToken).toBe(authToken);
  });

  it('should throw error if the argument is not a string or a valid type for authentication token', () => {
    const invalidAuthTokens = [true, false, {}, [], 12345];
    invalidAuthTokens.forEach((token) => {
      expect(() => client.setAPIClientAuthenticationToken(token)).toThrow('Invalid authentication token provided');
    });
  });

  it('should cover all possible paths with a valid token', () => {
    const authToken = 'abc123';
    client.setAPIClientAuthenticationToken(authToken);
    expect(client.authenticationToken).toBe(authToken);

    client.setAPIClientAuthenticationToken();
    expect(client.authenticationToken).toBeUndefined();

    client.setAPIClientAuthenticationToken(null);
    expect(client.authenticationToken).toBeNull();

    client.setAPIClientAuthenticationToken(undefined);
    expect(client.authenticationToken).toBeUndefined();

    client.setAPIClientAuthenticationToken('xyz789');
    expect(client.authenticationToken).toBe('xyz789');
  });
});

describe('APIClient.healthCheck', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with clientCustomData', () => {
    const clientCustomData = 'Custom Data';
    const response = apiClient.healthCheck(clientCustomData);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"HealthCheck","data":{"clientCustomData":"${clientCustomData}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should send a POST request with the correct data when provided without clientCustomData', () => {
    const response = apiClient.healthCheck();

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith('{"function":"HealthCheck","data":{"clientCustomData":""}}');
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the clientCustomData is not a string', () => {
    expect(() => apiClient.healthCheck(123)).toThrowError('clientCustomData must be a string');
  });
});

describe('APIClient.verifyAuthenticationToken', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data', () => {
    const response = apiClient.verifyAuthenticationToken();

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith('{"function":"VerifyAuthenticationToken"}');
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });
});

describe('APIClient.passwordlessLogin', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with minimumPrivilegeLevel', () => {
    const minimumPrivilegeLevel = 'Minimum Privilege Level';
    const response = apiClient.passwordlessLogin(minimumPrivilegeLevel);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"PasswordlessLogin","data":{"MinimumPrivilegeLevel":"${minimumPrivilegeLevel}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the minimumPrivilegeLevel is not specified', () => {
    expect(() => apiClient.passwordlessLogin()).toThrowError('minimumPrivilegeLevel must be specified');
    expect(() => apiClient.passwordlessLogin(null)).toThrowError('minimumPrivilegeLevel must be specified');
  });

  it('should throw an error if the minimumPrivilegeLevel is not a string', () => {
    expect(() => apiClient.passwordlessLogin(123)).toThrowError('minimumPrivilegeLevel must be a string');
  });
});

describe('APIClient.passwordLogin', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with minimumPrivilegeLevel and password', () => {
    const minimumPrivilegeLevel = 'Minimum Privilege Level';
    const password = 'password';
    const response = apiClient.passwordLogin(minimumPrivilegeLevel, password);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"PasswordLogin","data":{"MinimumPrivilegeLevel":"${minimumPrivilegeLevel}","Password":"${password}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the minimumPrivilegeLevel is not specified', () => {
    expect(() => apiClient.passwordLogin()).toThrowError('minimumPrivilegeLevel must be specified');
    expect(() => apiClient.passwordLogin(null)).toThrowError('minimumPrivilegeLevel must be specified');
  });

  it('should throw an error if the minimumPrivilegeLevel is not a string', () => {
    expect(() => apiClient.passwordLogin(123)).toThrowError('minimumPrivilegeLevel must be a string');
  });

  it('should throw an error if the password is not specified', () => {
    const minimumPrivilegeLevel = 'Minimum Privilege Level';
    expect(() => apiClient.passwordLogin(minimumPrivilegeLevel)).toThrowError('password must be specified');
    expect(() => apiClient.passwordLogin(minimumPrivilegeLevel, null)).toThrowError('password must be specified');
  });

  it('should throw an error if the password is not a string', () => {
    const minimumPrivilegeLevel = 'Minimum Privilege Level';
    expect(() => apiClient.passwordLogin(minimumPrivilegeLevel, 123)).toThrowError('password must be a string');
  });
});

describe('APIClient.queryServerState', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data', () => {
    const response = apiClient.queryServerState();

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith('{"function":"QueryServerState"}');
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });
});

describe('APIClient.getServerOptions', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data', () => {
    const response = apiClient.getServerOptions();

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith('{"function":"GetServerOptions"}');
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });
});

describe('APIClient.getAdvancedGameSettings', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data', () => {
    const response = apiClient.getAdvancedGameSettings();

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith('{"function":"GetAdvancedGameSettings"}');
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });
});

describe('APIClient.applyAdvancedGameSettings', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with appliedAdvancedGameSettings', () => {
    const appliedAdvancedGameSettings = { setting: 'value' };
    const response = apiClient.applyAdvancedGameSettings(appliedAdvancedGameSettings);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"ApplyAdvancedGameSettings","data":{"AppliedAdvancedGameSettings":${JSON.stringify(appliedAdvancedGameSettings)}}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the appliedAdvancedGameSettings is not specified', () => {
    expect(() => apiClient.applyAdvancedGameSettings()).toThrowError('appliedAdvancedGameSettings must be specified');
    expect(() => apiClient.applyAdvancedGameSettings(null)).toThrowError('appliedAdvancedGameSettings must be specified');
  });

  it('should throw an error if the appliedAdvancedGameSettings is not an object', () => {
    expect(() => apiClient.applyAdvancedGameSettings(123)).toThrowError('appliedAdvancedGameSettings must be an object');
  });
});

describe('APIClient.claimServer', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with minimumPrivilegeLevel and password', () => {
    const serverName = 'Server Name';
    const adminPassword = 'Admin Password';
    const response = apiClient.claimServer(serverName, adminPassword);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"ClaimServer","data":{"ServerName":"${serverName}","AdminPassword":"${adminPassword}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the serverName is not specified', () => {
    expect(() => apiClient.claimServer()).toThrowError('serverName must be specified');
    expect(() => apiClient.claimServer(null)).toThrowError('serverName must be specified');
  });

  it('should throw an error if the serverName is not a string', () => {
    expect(() => apiClient.claimServer(123)).toThrowError('serverName must be a string');
  });

  it('should throw an error if the adminPassword is not specified', () => {
    const serverName = 'Server Name';
    expect(() => apiClient.claimServer(serverName)).toThrowError('adminPassword must be specified');
    expect(() => apiClient.claimServer(serverName, null)).toThrowError('adminPassword must be specified');
  });

  it('should throw an error if the adminPassword is not a string', () => {
    const serverName = 'Server Name';
    expect(() => apiClient.claimServer(serverName, 123)).toThrowError('adminPassword must be a string');
  });
});

describe('APIClient.renameServer', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with minimumPrivilegeLevel', () => {
    const serverName = 'ServerName';
    const response = apiClient.renameServer(serverName);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"RenameServer","data":{"ServerName":"${serverName}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the serverName is not specified', () => {
    expect(() => apiClient.renameServer()).toThrowError('serverName must be specified');
    expect(() => apiClient.renameServer(null)).toThrowError('serverName must be specified');
  });

  it('should throw an error if the serverName is not a string', () => {
    expect(() => apiClient.renameServer(123)).toThrowError('serverName must be a string');
  });
});

describe('APIClient.setClientPassword', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with password', () => {
    const password = 'Client Password';
    const response = apiClient.setClientPassword(password);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"SetClientPassword","data":{"Password":"${password}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the password is not specified', () => {
    expect(() => apiClient.setClientPassword()).toThrowError('password must be specified');
    expect(() => apiClient.setClientPassword(null)).toThrowError('password must be specified');
  });

  it('should throw an error if the password is not a string', () => {
    expect(() => apiClient.setClientPassword(123)).toThrowError('password must be a string');
  });
});

describe('APIClient.setAdminPassword', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with password', () => {
    const password = 'Admin Password';
    const response = apiClient.setAdminPassword(password);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"SetAdminPassword","data":{"Password":"${password}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the password is not specified', () => {
    expect(() => apiClient.setAdminPassword()).toThrowError('password must be specified');
    expect(() => apiClient.setAdminPassword(null)).toThrowError('password must be specified');
  });

  it('should throw an error if the password is not a string', () => {
    expect(() => apiClient.setAdminPassword(123)).toThrowError('password must be a string');
  });
});

describe('APIClient.setAutoLoadSessionName', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with sessionName', () => {
    const sessionName = 'Session Name';
    const response = apiClient.setAutoLoadSessionName(sessionName);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"SetAutoLoadSessionName","data":{"SessionName":"${sessionName}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the sessionName is not specified', () => {
    expect(() => apiClient.setAutoLoadSessionName()).toThrowError('sessionName must be specified');
    expect(() => apiClient.setAutoLoadSessionName(null)).toThrowError('sessionName must be specified');
  });

  it('should throw an error if the sessionName is not a string', () => {
    expect(() => apiClient.setAutoLoadSessionName(123)).toThrowError('sessionName must be a string');
  });
});

describe('APIClient.runCommand', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with command', () => {
    const command = 'command';
    const response = apiClient.runCommand(command);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"RunCommand","data":{"Command":"${command}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the command is not specified', () => {
    expect(() => apiClient.runCommand()).toThrowError('command must be specified');
    expect(() => apiClient.runCommand(null)).toThrowError('command must be specified');
  });

  it('should throw an error if the command is not a string', () => {
    expect(() => apiClient.runCommand(123)).toThrowError('command must be a string');
  });
});

describe('APIClient.shutdown', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data', () => {
    const response = apiClient.shutdown();

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith('{"function":"Shutdown"}');
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });
});

describe('APIClient.applyServerOptions', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with updatedServerOptions', () => {
    const updatedServerOptions = { option: 'value' };
    const response = apiClient.applyServerOptions(updatedServerOptions);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"ApplyServerOptions","data":{"UpdatedServerOptions":${JSON.stringify(updatedServerOptions)}}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the updatedServerOptions is not specified', () => {
    expect(() => apiClient.applyServerOptions()).toThrowError('updatedServerOptions must be specified');
    expect(() => apiClient.applyServerOptions(null)).toThrowError('updatedServerOptions must be specified');
  });

  it('should throw an error if the updatedServerOptions is not an object', () => {
    expect(() => apiClient.applyServerOptions(123)).toThrowError('updatedServerOptions must be an object');
  });
});

describe('APIClient.createNewGame', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with newGameData', () => {
    const newGameData = { data: 'value' };
    const response = apiClient.createNewGame(newGameData);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"CreateNewGame","data":{"NewGameData":${JSON.stringify(newGameData)}}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the newGameData is not specified', () => {
    expect(() => apiClient.createNewGame()).toThrowError('newGameData must be specified');
    expect(() => apiClient.createNewGame(null)).toThrowError('newGameData must be specified');
  });

  it('should throw an error if the newGameData is not an object', () => {
    expect(() => apiClient.createNewGame(123)).toThrowError('newGameData must be an object');
  });
});

describe('APIClient.saveGame', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with saveName', () => {
    const saveName = 'Save Name';
    const response = apiClient.saveGame(saveName);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"SaveGame","data":{"SaveName":"${saveName}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the saveName is not specified', () => {
    expect(() => apiClient.saveGame()).toThrowError('saveName must be specified');
    expect(() => apiClient.saveGame(null)).toThrowError('saveName must be specified');
  });

  it('should throw an error if the saveName is not a string', () => {
    expect(() => apiClient.saveGame(123)).toThrowError('saveName must be a string');
  });
});

describe('APIClient.deleteSaveFile', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with saveName', () => {
    const saveName = 'Save Name';
    const response = apiClient.deleteSaveFile(saveName);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"DeleteSaveFile","data":{"SaveName":"${saveName}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the saveName is not specified', () => {
    expect(() => apiClient.deleteSaveFile()).toThrowError('saveName must be specified');
    expect(() => apiClient.deleteSaveFile(null)).toThrowError('saveName must be specified');
  });

  it('should throw an error if the saveName is not a string', () => {
    expect(() => apiClient.deleteSaveFile(123)).toThrowError('saveName must be a string');
  });
});

describe('APIClient.deleteSaveSession', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with sessionName', () => {
    const sessionName = 'Session Name';
    const response = apiClient.deleteSaveSession(sessionName);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"DeleteSaveSession","data":{"SessionName":"${sessionName}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the sessionName is not specified', () => {
    expect(() => apiClient.deleteSaveSession()).toThrowError('sessionName must be specified');
    expect(() => apiClient.deleteSaveSession(null)).toThrowError('sessionName must be specified');
  });

  it('should throw an error if the sessionName is not a string', () => {
    expect(() => apiClient.deleteSaveSession(123)).toThrowError('sessionName must be a string');
  });
});

describe('APIClient.enumerateSessions', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data', () => {
    const response = apiClient.enumerateSessions();

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith('{"function":"EnumerateSessions"}');
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });
});

describe('APIClient.loadGame', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with saveName and enableAdvancedGameSettings', () => {
    const saveName = 'Save Name';
    const enableAdvancedGameSettings = true;
    const response = apiClient.loadGame(saveName, enableAdvancedGameSettings);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"LoadGame","data":{"SaveName":"${saveName}","EnableAdvancedGameSettings":${enableAdvancedGameSettings}}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the saveName is not specified', () => {
    expect(() => apiClient.loadGame()).toThrowError('saveName must be specified');
    expect(() => apiClient.loadGame(null)).toThrowError('saveName must be specified');
  });

  it('should throw an error if the saveName is not a string', () => {
    expect(() => apiClient.loadGame(123)).toThrowError('saveName must be a string');
  });

  it('should throw an error if the enableAdvancedGameSettings is not a boolean', () => {
    const saveName = 'Save Name';
    const enableAdvancedGameSettings = 'true';
    expect(() => apiClient.loadGame(saveName, enableAdvancedGameSettings)).toThrowError('enableAdvancedGameSettings must be a boolean');
  });
});

describe('APIClient.uploadSaveGame', () => {
  let apiClient;
  let writeMock;
  let requestSpy;

  beforeEach(() => {
    const mock = createSuccessfulHTTPSRequestMock();
    writeMock = mock.writeMock;
    requestSpy = mock.requestSpy;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data', () => {
    const saveGameData = 'Save Game Data';
    const buffer = Buffer.from(saveGameData);
    const saveName = 'Save Name';
    const loadSaveGame = true;
    const enableAdvancedGameSettings = true;

    const response = apiClient.uploadSaveGame(
      buffer,
      saveName,
      loadSaveGame,
      enableAdvancedGameSettings,
    );

    expect(writeMock).toHaveBeenCalledTimes(1);

    const payload = writeMock.mock.calls[0][0].toString();
    const contentType = requestSpy.mock.calls[0][0].headers['Content-Type'];

    const match = /boundary=([^;]+)/.exec(contentType);
    const boundary = match[1];

    expect(boundary.length > 1).toBeTruthy();

    expect(payload).toEqual(`--${boundary}\r\n`
    + 'Content-Disposition: form-data; name="data"\r\n'
    + 'Content-Type: application/json\r\n'
    + '\r\n'
    + `{"function":"UploadSaveGame","data":{"SaveName":"${saveName}","LoadSaveGame":${loadSaveGame},"EnableAdvancedGameSettings":${enableAdvancedGameSettings}}}\r\n`
    + `--${boundary}\r\n`
    + `Content-Disposition: form-data; name="saveGameFile"; filename="${saveName}.sav"\r\n`
    + 'Content-Type: application/octet-stream\r\n'
    + '\r\n'
    + `${saveGameData}\r\n`
    + `--${boundary}--\r\n`);

    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the loadSaveGame is not a boolean', () => {
    const saveGameData = 'Save Game';
    const buffer = Buffer.from(saveGameData);
    const saveName = 'Save Name';
    const loadSaveGame = 123;

    expect(() => apiClient.uploadSaveGame(
      buffer,
      saveName,
      loadSaveGame,
    )).toThrowError('loadSaveGame must be a boolean');
  });

  it('should throw an error if the enableAdvancedGameSettings is not a boolean', () => {
    const saveGameData = 'Save Game';
    const buffer = Buffer.from(saveGameData);
    const saveName = 'Save Name';
    const loadSaveGame = undefined;
    const enableAdvancedGameSettings = '123';

    expect(() => apiClient.uploadSaveGame(
      buffer,
      saveName,
      loadSaveGame,
      enableAdvancedGameSettings,
    )).toThrowError('enableAdvancedGameSettings must be a boolean');
  });
});

describe('APIClient.downloadSaveGame', () => {
  let apiClient;
  let writeMock;

  beforeEach(() => {
    writeMock = createSuccessfulHTTPSRequestMock().writeMock;
    apiClient = new APIClient();
  });

  afterEach(() => {
    writeMock = null;
  });

  it('should send a POST request with the correct data when provided with saveName', () => {
    const saveName = 'Save Name';
    const response = apiClient.downloadSaveGame(saveName);

    expect(writeMock).toHaveBeenCalledTimes(1);
    expect(writeMock).toHaveBeenCalledWith(`{"function":"DownloadSaveGame","data":{"SaveName":"${saveName}"}}`);
    expect(response).resolves.toEqual({ data: { test: true }, status: { code: 200, name: 'Ok' } });
  });

  it('should throw an error if the saveName is not specified', () => {
    expect(() => apiClient.downloadSaveGame()).toThrowError('saveName must be specified');
    expect(() => apiClient.downloadSaveGame(null)).toThrowError('saveName must be specified');
  });

  it('should throw an error if the saveName is not a string', () => {
    expect(() => apiClient.downloadSaveGame(123)).toThrowError('saveName must be a string');
  });
});
