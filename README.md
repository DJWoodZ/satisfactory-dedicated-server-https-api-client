Satisfactory Dedicated Server HTTPS API Client
==============================================

A low-level, zero dependency Node.js client library for the HTTPS API of the [Satisfactory Dedicated Server](https://satisfactory.fandom.com/wiki/Dedicated_servers).

Installation
------------

```
npm i @djwoodz/satisfactory-dedicated-server-https-api-client
```

Example Usage
-------------

```js
// import module
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');
```

```js
// create apiClient
const apiClient = new APIClient({
  address: '127.0.0.1',
  port: 7777,
  https: {
    request: {
      rejectUnauthorized: false, // accepts any CA, not secure
    },
  },
});
```

```js
// health check using await
const { data } = await apiClient.healthCheck();
console.log(data);
```

```js
// health check using .then()
apiClient.healthCheck()
  .then((data) => {
    console.log(data);
  });
```

APIClient Constructor Options
--------------------------

Name | Type | Default | Description
----|------|---------|-------------
address | string | '127.0.0.1' | The address of the Dedicated Server
port | number | 7777 | The port number of the Dedicated Server
https | object | { request: { timeout:30000 } } | Options for HTTPS functions
authenticationToken | string | | The authentication token to be set for requests

APIClient Functions
-------------------

### API Functions <a id="APIFunctions"></a>

These map to the 'API Functions' in the DedicatedServerAPIDocs.md file (available under the 'CommunityResources' directory of the installed Satisfactory game):

| Method Signature | Description |
| --- | --- |
| [healthCheck(clientCustomData?: string) → {Promise.&lt;*&gt;}](#healthCheck) | Performs a health check on the server |
| [verifyAuthenticationToken() → {Promise.&lt;*&gt;}](#verifyAuthenticationToken) | Verifies the authentication token currently set for the API Client |
| [passwordlessLogin(minimumPrivilegeLevel: PrivilegeLevel) → {Promise.&lt;*&gt;}](#passwordlessLogin) | Performs a passwordless login |
| [passwordLogin(minimumPrivilegeLevel: PrivilegeLevel, password: string) → {Promise.&lt;*&gt;}](#passwordLogin) | Performs a password-based login |
| [queryServerState() → {Promise.&lt;*&gt;}](#queryServerState) | Queries the state of the server |
| [getServerOptions() → {Promise.&lt;*&gt;}](#getServerOptions) | Gets the options for the server |
| [getAdvancedGameSettings() → {Promise.&lt;*&gt;}](#getAdvancedGameSettings) | Gets the advanced game settings for the server |
| [applyAdvancedGameSettings(appliedAdvancedGameSettings: object) → {Promise.&lt;*&gt;}](#applyAdvancedGameSettings) | Applies the provided advanced game settings to the server |
| [claimServer(serverName: string, adminPassword: string) → {Promise.&lt;*&gt;}](#claimServer) | Stakes a claim on the server |
| [renameServer(serverName: string) → {Promise.&lt;*&gt;}](#renameServer) | Renames the server |
| [setClientPassword(password: string) → {Promise.&lt;*&gt;}](#setClientPassword) | Sets the client password for the server |
| [setAdminPassword(password: string) → {Promise.&lt;*&gt;}](#setAdminPassword) | Sets the admin password for the server |
| [setAutoLoadSessionName(sessionName: string) → {Promise.&lt;*&gt;}](#setAutoLoadSessionName) | Sets the session name to automatically load when joining the server |
| [runCommand(command: string) → {Promise.&lt;*&gt;}](#runCommand) | Runs a command on the server |
| [shutdown() → {Promise.&lt;*&gt;}](#shutdown) | Requests the server to shut down |
| [applyServerOptions(updatedServerOptions: object.&lt;string, string&gt;) → {Promise.&lt;*&gt;}](#applyServerOptions) | Applies new server options to the server |
| [createNewGame(newGameData: object) → {Promise.&lt;*&gt;}](#createNewGame) | Creates a new game on the server |
| [saveGame(saveName: string) → {Promise.&lt;*&gt;}](#saveGame) | Saves the game on the server using the provided name |
| [deleteSaveFile(saveName: string) → {Promise.&lt;*&gt;}](#deleteSaveFile) | Deletes a save file from the server |
| [deleteSaveSession(sessionName: string) → {Promise.&lt;*&gt;}](#deleteSaveSession) | Deletes all save files from the server belonging to the given session name |
| [enumerateSessions() → {Promise.&lt;*&gt;}](#enumerateSessions) | Enumerates all sessions on the server |
| [loadGame(saveName: string, enableAdvancedGameSettings?: boolean) → {Promise.&lt;*&gt;}](#loadGame) | Loads a save game with the given name from the server |
| [uploadSaveGame(buffer: Buffer, saveName: string, loadSaveGame?: boolean, enableAdvancedGameSettings?: boolean) → {Promise.&lt;*&gt;}](#uploadSaveGame) | Upload a save game file to the server using the given and name |
| [downloadSaveGame(saveName: string) → {Promise.&lt;Buffer&gt;}](#downloadSaveGame) | Downloads a save game with the given name from the server |

### Other Functions <a id="OtherFunctions"></a>

The client also has several other functions:

| Method Signature | Description |
| --- | --- |
| [setAPIClientAuthenticationToken(authenticationToken: string)](#setAPIClientAuthenticationToken) | Sets the API Client's authentication token |
| [(static) getAuthenticationTokenPrivilegeLevel(authenticationToken: string) → {PrivilegeLevel}](#getAuthenticationTokenPrivilegeLevel) | Parses a given authentication token and returns its privilege level |
| [(static) getCertificates(options?) → {Promise.&lt;object&gt;}](#getCertificates) | Retrieves the server and CA certificates from a remote server via HTTPS |

### Enumerations

#### PrivilegeLevel

Privilege Level Enumeration representing different privilege levels granted by an authentication token.

| Enumerator | Description |
| --- | --- |
| PrivilegeLevel.NotAuthenticated | Not authenticated |
| PrivilegeLevel.Client | Authenticated with Client privileges |
| PrivilegeLevel.Administrator | Authenticated with Admin privileges |
| PrivilegeLevel.InitialAdmin | Authenticated as Initial Admin with privileges to claim the server |
| PrivilegeLevel.APIToken | Authenticated as Third Party Application |

#### StatusCode

Status Code Enumeration representing different HTTP response codes.

| Enumerator | Description |
| --- | --- |
| StatusCode.OK | Status Code for Ok 200 |
| StatusCode.CREATED | Status Code for Created 201 |
| StatusCode.ACCEPTED | Status Code for Accepted 202 |
| StatusCode.NO_CONTENT | Status Code for No Content 204 |
| StatusCode.BAD_REQUEST | Status Code for Bad Request 400 |
| StatusCode.DENIED | Status Code for Denied 401 |
| StatusCode.FORBIDDEN | Status Code for Forbidden 403 |
| StatusCode.NOT_FOUND | Status Code for Not Found 404 |
| StatusCode.UNSUPPORTED_MEDIA | Status Code for Unsupported Media 415 |
| StatusCode.SERVER_ERROR | Status Code for Server Error 500 |

Basic Examples
--------------

### Health Check <a id="healthCheck"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.healthCheck());
};

main();
```

[Back to API Functions](#APIFunctions)

### Query Server State <a id="queryServerState"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.queryServerState());
};

main();
```

[Back to API Functions](#APIFunctions)

### Verify Authentication Token <a id="verifyAuthenticationToken"></a>

```js
const { APIClient, StatusCode } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  const { status } = await apiClient.verifyAuthenticationToken();

  if (status === StatusCode.NO_CONTENT) {
    console.log('The authentication token is valid.');
  } else {
    console.error('The authentication token is invalid.');
  }
};

main();
```

[Back to API Functions](#APIFunctions)

### Passwordless Login <a id="passwordlessLogin"></a>

```js
const { APIClient, StatusCode } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  // Client passwordless login (when Client password is not set)
  const { status, data } = await apiClient.passwordlessLogin(PrivilegeLevel.Client);

  if (status === StatusCode.OK && data?.authenticationToken) {
    // update the API Client to use the authentication token
    apiClient.setAPIClientAuthenticationToken(data.authenticationToken);

    // check the authentication token is valid
    if (apiClient.verifyAuthenticationToken(data.authenticationToken)) {
      // perform operation permissable at Client privilege level
      console.log(await apiClient.queryServerState());
    }
  }
};

main();
```

[Back to API Functions](#APIFunctions)

### Password Login <a id="passwordLogin"></a>

```js
const { APIClient, StatusCode } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  // Client password login (when Client password is set)
  const { status, data } = await apiClient.passwordLogin(PrivilegeLevel.Client, 'My Client Password');

  if (status === StatusCode.OK && data?.authenticationToken) {
    // update the API Client to use the authentication token
    apiClient.setAPIClientAuthenticationToken(data.authenticationToken);

    // check the authentication token is valid
    if (apiClient.verifyAuthenticationToken(data.authenticationToken)) {
      // perform operation permissable at Client privilege level
      console.log(await apiClient.queryServerState());
    }
  }
};

main();
```

[Back to API Functions](#APIFunctions)

### Get Server Options <a id="getServerOptions"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.getServerOptions());
};

main();
```

[Back to API Functions](#APIFunctions)

### Get Advanced Game Settings <a id="getAdvancedGameSettings"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.getAdvancedGameSettings());
};

main();
```

[Back to API Functions](#APIFunctions)

### Apply Advanced Game Settings <a id="applyAdvancedGameSettings"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.applyAdvancedGameSettings({
    'FG.PlayerRules.GodMode': true,
    'FG.PlayerRules.FlightMode': true,
  }));
};

main();
```

[Back to API Functions](#APIFunctions)

### Rename Server <a id="renameServer"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.renameServer('My Server'));
};

main();
```

[Back to API Functions](#APIFunctions)

### Set Client Password <a id="setClientPassword"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.setClientPassword('My Client Password'));
};

main();
```

[Back to API Functions](#APIFunctions)

### Set Admin Password <a id="setAdminPassword"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.setAdminPassword('My Admin Password'));
};

main();
```

[Back to API Functions](#APIFunctions)

### Set Auto Load Session Name <a id="setAutoLoadSessionName"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.setAutoLoadSessionName('My Session'));

  console.log((await apiClient.queryServerState()).data.serverGameState.autoLoadSessionName);
};

main();
```

[Back to API Functions](#APIFunctions)

### Run Command <a id="runCommand"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.runCommand('FG.NetworkQuality'));
};

main();
```
[Back to API Functions](#APIFunctions)

### Shutdown <a id="shutdown"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.shutdown());
};

main();
```

[Back to API Functions](#APIFunctions)

### Apply Server Options <a id="applyServerOptions"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.applyServerOptions({ 'FG.AutosaveInterval': '600' }));
};

main();
```

[Back to API Functions](#APIFunctions)

### Create New Game <a id="createNewGame"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.createNewGame({
    SessionName: 'My Session',
  }));
};

main();
```

[Back to API Functions](#APIFunctions)

### Save Game <a id="saveGame"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.saveGame('My Save'));
};

main();
```

[Back to API Functions](#APIFunctions)

### Delete Save File <a id="deleteSaveFile"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.deleteSaveFile('My Save'));
};

main();
```

[Back to API Functions](#APIFunctions)

### Delete Save Session <a id="deleteSaveSession"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.deleteSaveSession('My Session'));
};

main();
```

[Back to API Functions](#APIFunctions)

### Enumerate Sessions <a id="enumerateSessions"></a>

Here is an example of how you can iterate all save names against all sessions:

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  const { data } = await apiClient.enumerateSessions();
  const { currentSessionIndex } = data;
  data.sessions.forEach((session, index) => {
    console.log(`Session: ${session.sessionName}${(index === currentSessionIndex ? ' (Current)' : '')}`);
    session.saveHeaders.forEach(({ saveName }) => {
      console.log(`  Save Name: ${saveName}`);
    });
  });
};

main();
```

Example output:

```
Session: My Session (Current)
  Save Name: My Save
```

[Back to API Functions](#APIFunctions)

### Load Game <a id="loadGame"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  console.log(await apiClient.loadGame('My Save'));
};

main();
```

[Back to API Functions](#APIFunctions)

### Upload Save Game <a id="uploadSaveGame"></a>

```js
const fs = require('fs');
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  try {
    const buffer = fs.readFileSync('My Save 1.sav');
    console.log(await apiClient.uploadSaveGame(buffer, 'My Save 1', true));
  } catch (error) {
    console.error('Error reading the file:', error);
  }
};

main();
```

[Back to API Functions](#APIFunctions)

### Download Save Game <a id="downloadSaveGame"></a>

```js
const fs = require('fs');
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  try {
    const buffer = await apiClient.downloadSaveGame('My Save 2');
    fs.writeFileSync('My Save 2.sav', buffer);
    console.log('Buffer written to file successfully!');
  } catch (error) {
    console.error('Error writing to file', error);
  }
};

main();
```

[Back to API Functions](#APIFunctions)

### Set API Client Authentication Token <a id="setAPIClientAuthenticationToken"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const authenticationToken = 'some API token';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    authenticationToken,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  apiClient.setAPIClientAuthenticationToken('some other token');
};

main();
```

[Back to Other Functions](#OtherFunctions)

### Get Authentication Token Privilege Level <a id="getAuthenticationTokenPrivilegeLevel"></a>

```js
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

console.log(APIClient.getAuthenticationTokenPrivilegeLevel('some API token'));
```

[Back to Other Functions](#OtherFunctions)

Advanced Examples
-----------------

### Claim Server <a id="claimServer"></a>

Here is an example of how to claim a new server (set server name and admin password), set the client password and generate an API Token:

```js
const { APIClient, StatusCode, PrivilegeLevel } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const serverName = 'My Server';
const adminPassword = 'My Admin Password';
const clientPassword = 'My Client Password';

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });

  try {
    // passwordless login
    {
      const {
        status,
        data,
      } = await apiClient.passwordlessLogin(PrivilegeLevel.InitialAdmin);

      // check passwordlessLogin returned the 'Ok' status code
      if (status === StatusCode.OK) {
        // get the initial authentication token
        const authenticationToken = data?.authenticationToken;
        if (authenticationToken) {
          // check the token is an InitialAdmin token
          const privilegeLevel = APIClient.getAuthenticationTokenPrivilegeLevel(authenticationToken);
          if (privilegeLevel === PrivilegeLevel.InitialAdmin) {
            console.log(`${PrivilegeLevel.InitialAdmin} token obtained.`);

            // update the API Client to use the InitialAdmin authentication token
            apiClient.setAPIClientAuthenticationToken(authenticationToken);
          } else {
            throw new Error(`authentication token was not ${PrivilegeLevel.InitialAdmin}: ${privilegeLevel}.`);
          }
        } else {
          throw new Error('passwordlessLogin did not return an authentication token.');
        }
      } else {
        throw new Error(`passwordlessLogin status code was: ${status?.code}.`);
      }
    }

    // claim the server
    {
      const {
        status,
        data,
      } = await apiClient.claimServer(serverName, adminPassword);

      // check claimServer returned the 'Ok' status code
      if (status === StatusCode.OK) {
        // get the authentication token
        const authenticationToken = data?.authenticationToken;

        if (authenticationToken) {
          // check the token is an Administrator token
          const privilegeLevel = APIClient.getAuthenticationTokenPrivilegeLevel(authenticationToken);
          if (privilegeLevel === PrivilegeLevel.Administrator) {
            console.log(`Server claimed (named and admin password set). ${PrivilegeLevel.Administrator} token obtained.`);

            // update the API Client to use the Administrator authentication token
            apiClient.setAPIClientAuthenticationToken(authenticationToken);
          } else {
            throw new Error(`authentication token was not ${PrivilegeLevel.Administrator}: ${privilegeLevel}.`);
          }
        } else {
          throw new Error('claimServer did not return an authentication token.');
        }
      } else {
        throw new Error(`claimServer status code was: ${status?.code}.`);
      }
    }

    // set the client password
    {
      const {
        status,
      } = await apiClient.setClientPassword(clientPassword);

      // check setClientPassword returned the 'No Content' status code
      if (status === StatusCode.NO_CONTENT) {
        console.log('Client password set.');
      } else {
        throw new Error('Client password was not set.');
      }
    }

    // Generate API token
    {
      const {
        status,
        data,
      } = await apiClient.runCommand('server.GenerateAPIToken');

      // check runCommand returned the 'Ok' status code and had a result
      if (status === StatusCode.OK && data?.commandResult) {
        console.log(`server.GenerateAPIToken command result: ${data?.commandResult}`);
      } else {
        throw new Error('server.GenerateAPIToken command failed');
      }
    }
  } catch (error) {
    console.error(`An error occurred: ${error.message}`);
  }
};

main();
```

[Back to API Functions](#APIFunctions)

### Get Certificates <a id="getCertificates"></a>

`APIClient.getCertificates()` is a static utility function that can obtain the certificate(s) from the server.

Here is an example of how you might use it:

```js
const fs = require('fs');
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;

const main = async () => {
  const { server, ca } = await APIClient.getCertificates({
    address,
    port,
    https: {
      request: {
        rejectUnauthorized: false, // accepts any CA, not secure
      },
    },
  });
  if (server?.pem) {
    try {
      console.log(`Server cert fingerprint512: ${server.cert?.fingerprint512}`);
      fs.writeFileSync('serverCert.pem', server.pem);
      console.log('Written server certificate to file successfully!');
    } catch (error) {
      console.error('Error writing to file', error);
    }
  }
  if (ca?.pem) {
    try {
      console.log(`CA cert fingerprint512: ${ca.cert?.fingerprint512}`);
      fs.writeFileSync('caCert.pem', ca.pem);
      console.log('Written CA certificate to file successfully!');
    } catch (error) {
      console.error('Error writing to file', error);
    }
  }
};

main();
```

Then, instead of setting `rejectUnauthorized: false`, you can use the results from `getCertificates()` with the `ca` and `checkServerIdentity` options when creating a new `APIClient`. The latter is handy for Dedicated Servers that use self-signed certificates.

For example, you can check the host and certificate fingerprint like this:

```js
const fs = require('fs');
const { APIClient } = require('@djwoodz/satisfactory-dedicated-server-https-api-client');

const address = '127.0.0.1';
const port = 7777;
const fingerprint512 = 'some fingerprint';
const ca = fs.readFileSync('serverCert.pem');

const checkServerIdentity = (host, cert) => {
  if (host !== address || cert?.fingerprint512 !== fingerprint512) {
    throw new Error('Server identity check failed');
  }
};

const main = async () => {
  const apiClient = new APIClient({
    address,
    port,
    https: {
      request: {
        ca,
        checkServerIdentity,
      },
    },
  });

  console.log(await apiClient.healthCheck());
};

main();
```

[Back to Other Functions](#OtherFunctions)