<!-- cspell:words adfs -->

# auth-vir

Auth made easy and secure via JWT cookies, CSRF tokens, and password hashing helpers. ESM and browser friendly.

-   Reference docs: https://electrovir.github.io/auth-vir
-   Clone and run the demo: https://github.com/electrovir/auth-vir/blob/dev/packages/demo

# Install

```sh
npm i auth-vir
```

# Usage

## Easy usage

For the easiest usage, construct and use `BackendAuthClient` on your server and `FrontendAuthClient` in your frontend.

## Password hashing

-   Hash a user created password:
    <!-- example-link: ./src/examples/password-hash.example.ts -->

    ```TypeScript
    import {hashPassword} from 'auth-vir';

    /** When a user creates or resets their password, hash it before storing it in your database. */

    const hashedPassword = await hashPassword('user input password');
    /** Store `hashedPassword` in your database. */
    ```

-   Compare a stored password hash for login checking:
    <!-- example-link: ./src/examples/password-compare.example.ts -->

    ```TypeScript
    import {doesPasswordMatchHash} from 'auth-vir';

    if (
        !(await doesPasswordMatchHash({
            hash: 'hash from database',
            password: 'user input password for login',
        }))
    ) {
        throw new Error('Login failure.');
    }
    ```

## Session auth

### Host / server / backend side

Use this on your host / server / backend to authenticate client / frontend requests.

1. Expose the [`AuthHeaderName.CsrfToken`](https://electrovir.github.io/auth-vir/variables/AuthHeaderName.html) (or just `'csrf-token'`) header via CORS headers with either of the following options:
    1. Set `customHeaders: [AuthHeaderName.CsrfToken]` in `implementApi` from [`@rest-vir/host`](https://www.npmjs.com/package/@rest-vir/host).
    2. Set the header `Access-Control-Allow-Headers` to (at least) `AuthHeaderName.CsrfToken`.
2. Set the `Access-Control-Allow-Origin` header (it cannot be `*`) and properly implement CORS headers and responses.
3. Generate JWT signing and encryption keys with one of the following:
    - Run `npx auth-vir`: the generated keys will be printed to your console.
    - Run [`await generateNewJwtKeys()`](https://electrovir.github.io/auth-vir/functions/generateNewJwtKeys.html) (imported from this package) in your code.
4. Securely store the generated keys in a secret place. Do not commit them. They should not be shared with anyone or any other host, client, or service.
5. In your application code, load the string keys from step 1 into [`parseJwtKeys`](https://electrovir.github.io/auth-vir/functions/parseUserJwt.html): `await parseJwtKeys(stringKeys)`.
6. Use the output of [`parseJwtKeys`](https://electrovir.github.io/auth-vir/functions/parseUserJwt.html) in all auth functionality:
    - [`generateSuccessfulLoginHeaders`](https://electrovir.github.io/auth-vir/functions/generateSuccessfulLoginHeaders.html): after a user successfully logs in, run this function and attach the output headers to the `Response` object.
    - [`extractUserIdFromRequestHeaders`](https://electrovir.github.io/auth-vir/functions/extractUserIdFromRequestHeaders.html): to verify an authenticated user `Request` object (make sure to properly attach all auth in the client by following the below [Client / frontend side](#client--frontend-side) guide).

Here's a full example of how to use all host / server / backend side auth functionality:

<!-- example-link: ./src/examples/full-backend.example.ts -->

```TypeScript
import {type ClientRequest, type ServerResponse} from 'node:http';
import {
    AuthCookie,
    doesPasswordMatchHash,
    extractUserIdFromRequestHeaders,
    generateNewJwtKeys,
    generateSuccessfulLoginHeaders,
    hashPassword,
    parseJwtKeys,
    type CookieParams,
    type CreateJwtParams,
    type CsrfHeaderNameOption,
} from 'auth-vir';

type MyUserId = string;

/**
 * The CSRF header prefix for this app. Either `csrfHeaderPrefix` or `csrfHeaderName` must be
 * provided to all CSRF-related functions.
 */
const csrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'my-app',
};

/**
 * Use this for a /login endpoint.
 *
 * This verifies a user's login credentials and generate the auth cookie and CSRF token.
 */
export async function handleLogin(
    userRequestData: Readonly<{username: string; password: string}>,
    response: ServerResponse,
) {
    const user = findUserInDatabaseByUsername(userRequestData.username);

    if (
        !(await doesPasswordMatchHash({
            hash: user.hashedPassword,
            password: userRequestData.password,
        }))
    ) {
        throw new Error('Credentials mismatch.');
    }

    const authHeaders = await generateSuccessfulLoginHeaders(user.id, cookieParams);
    Object.entries(authHeaders).forEach(
        ([
            key,
            value,
        ]) => {
            response.setHeader(key, value);
        },
    );
}

/**
 * Use this for a /sign-up endpoint.
 *
 * This creates a new user, stores their securely hashed password in the database, and generates the
 * auth cookie and CSRF token.
 */
export async function createUser(
    userRequestData: Readonly<{username: string; password: string}>,
    response: ServerResponse,
) {
    const newUser = await createUserInDatabase(userRequestData);

    const authHeaders = await generateSuccessfulLoginHeaders(newUser.id, cookieParams);
    Object.entries(authHeaders).forEach(
        ([
            key,
            value,
        ]) => {
            response.setHeader(key, value);
        },
    );
}

/**
 * Use this all endpoints that require an authenticated user.
 *
 * This loads the current user from their auth cookie and CSRF token.
 */
export async function getAuthenticatedUser(request: ClientRequest) {
    const userId = (
        await extractUserIdFromRequestHeaders<MyUserId>({
            headers: request.getHeaders(),
            jwtParams,
            csrfHeaderNameOption: csrfOption,
            cookieName: AuthCookie.Auth,
        })
    )?.userId;
    const user = userId ? findUserInDatabaseById(userId) : undefined;

    if (!userId || !user) {
        throw new Error('Unauthorized.');
    }

    return user;
}

/**
 * # ===========
 *
 * Helpers
 *
 * # ===========
 */

async function loadSecretJwtKeys() {
    /**
     * This should load your saved JWT keys from a non-committed config file or a secrets manager
     * (like AWS Secrets Manager).
     */
    return await generateNewJwtKeys();
}

const jwtParams: Readonly<CreateJwtParams> = {
    audience: 'server context',
    jwtDuration: {
        hours: 2,
    },
    issuer: 'server login',
    jwtKeys: await parseJwtKeys(await loadSecretJwtKeys()),
};

const cookieParams: CookieParams = {
    cookieDuration: {
        hours: 2,
    },
    hostOrigin: 'https://your-backend-origin.example.com',
    jwtParams,
};

function findUserInDatabaseByUsername(username: string) {
    /** This should connect to your database and find a user matching the given username. */

    return {
        /** This should be retrieved from your database. */
        id: 'some id',
        username,
        /** This should be retrieved from your database. */
        hashedPassword: 'hash retrieved from database',
    };
}

function findUserInDatabaseById(userId: MyUserId):
    | undefined
    | {
          id: MyUserId;
          username: string;
      } {
    /** This should connect to your database and find a user matching the given user id. */

    return {
        id: userId,
        /** This should be retrieved from your database. */
        username: 'some username',
    };
}

async function createUserInDatabase(
    userRequestData: Readonly<{username: string; password: string}>,
) {
    const hashedPassword = await hashPassword(userRequestData.password);

    if (!hashedPassword) {
        throw new Error('Password too long.');
    }

    /**
     * Store the new username and hashedPassword in your database and return the new user id.
     *
     * @example
     *
     *     // using the Prisma ORM:
     *     return (
     *         await prismaClient.user.create({
     *             data: {
     *                 username: userRequestData.username,
     *                 hashedPassword,
     *             },
     *             select: {
     *                 id: true,
     *             },
     *         })
     *     ).id;
     */

    return {
        id: 'some new id',
    };
}
```

### Client / frontend side

Use this on your client / frontend for storing and sending session authorization.

1. Send a login fetch request to your host / server / backend with `{credentials: 'include'}` set on the request.
2. Pass the `Response` from step 1 into [`handleAuthResponse`](https://electrovir.github.io/auth-vir/functions/handleAuthResponse.html).
3. In all subsequent fetch requests to the host / server / backend, set `{credentials: 'include'}` and include `{headers: {[AuthHeaderName.CsrfToken]: (await getCurrentCsrfToken()).csrfToken}}`.

Here's a full example of how to use all the client / frontend side auth functionality:

<!-- example-link: ./src/examples/full-frontend.example.ts -->

```TypeScript
import {HttpStatus} from '@augment-vir/common';
import {type CsrfHeaderNameOption, getCurrentCsrfToken, resolveCsrfHeaderName} from 'auth-vir';

/**
 * The CSRF header prefix for this app. Either `csrfHeaderPrefix` or `csrfHeaderName` must be
 * provided to all CSRF-related functions.
 */
const csrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'my-app',
};

/** Call this when the user logs in for the first time this session. */
export async function sendLoginRequest(
    userLoginData: {username: string; password: string},
    loginUrl: string,
) {
    if (getCurrentCsrfToken()) {
        throw new Error('Already logged in.');
    }

    const response = await fetch(loginUrl, {
        method: 'post',
        body: JSON.stringify(userLoginData),
        credentials: 'include',
    });

    /** The CSRF token cookie is automatically stored by the browser from the Set-Cookie header. */

    return response;
}

/** Call this when the user needs to send any authenticated request after already having logged in. */
export async function sendAuthenticatedRequest(
    requestUrl: string,
    requestInit: Omit<RequestInit, 'headers'> = {},
    headers: Record<string, string> = {},
) {
    const csrfToken = getCurrentCsrfToken();

    if (!csrfToken) {
        throw new Error('Not authenticated.');
    }

    const response = await fetch(requestUrl, {
        ...requestInit,
        credentials: 'include',
        headers: {
            ...headers,
            [resolveCsrfHeaderName(csrfOption)]: csrfToken,
        },
    });

    if (response.status === HttpStatus.Unauthorized) {
        throw new Error('User no longer logged in.');
    } else {
        return response;
    }
}

/**
 * Call this when the user explicitly clicks a "log out" button. The backend clears the auth and
 * CSRF cookies via Set-Cookie headers.
 */
export async function logout(logoutUrl: string) {
    await sendAuthenticatedRequest(logoutUrl, {
        method: 'post',
    });
}
```

## SAML sign-in (Node.js only)

Verify `SAMLResponse` messages from an enterprise SAML identity provider (for example ADFS, Entra ID, or Okta), including IdP-initiated sign-in. These exports use Node.js APIs, so they are kept out of the main (browser friendly) entry point and are imported from `auth-vir/dist/saml/index.js`. See the TSDoc comments on each export for full details.

-   `parseIdpMetadata`: read the IdP's entity ID, sign-in URL, and signing certificates from its metadata XML.
-   `generateSpMetadata`: generate your SP metadata XML for the IdP admin to import.
-   `verifySamlResponse`: verify a posted `SAMLResponse` and get the signed profile (NameID and attributes) or a typed failure reason.

```TypeScript
import {verifySamlResponse} from 'auth-vir/dist/saml/index.js';

const result = await verifySamlResponse({
    /** Usually the output of `parseIdpMetadata`, stored per organization. */
    idp: {
        entityId: 'http://adfs.example.com/adfs/services/trust',
        signingCertificates: ['-----BEGIN CERTIFICATE-----...'],
    },
    spEntityId: 'https://app.example.com/sso/saml/metadata',
    acsUrl: 'https://app.example.com/sso/saml/acs/example-org',
    samlResponse: requestBody.SAMLResponse,
    /** Back this with a database table that has a unique assertion ID column. */
    replayStore: {
        async markAssertionUsed({assertionId, expiresAt}) {
            return await insertIfNotExists({assertionId, expiresAt});
        },
    },
});

if (result.success) {
    /** `result.profile.nameId` and `result.profile.attributes` are safe to trust. */
} else {
    /** Log `result.reason` and `result.detail`, but do not show them to the user. */
}
```

# Requirements

All of these configurations must be set for the auth exports in this package to function properly:

-   Expose the [`AuthHeaderName.CsrfToken`](https://electrovir.github.io/auth-vir/variables/AuthHeaderName.html) (or just `'csrf-token'`) header via CORS headers with either of the following options:
    1.  Set `customHeaders: [AuthHeaderName.CsrfToken]` in `implementApi` from [`@rest-vir/host`](https://www.npmjs.com/package/@rest-vir/host).
    2.  Set the header `Access-Control-Allow-Headers` to (at least) `AuthHeaderName.CsrfToken`.
-   Set `credentials: include` in all fetch requests on the client that need to use or set the auth cookie.
-   Server CORS should set `Access-Control-Allow-Origin` (it cannot be `*`).
