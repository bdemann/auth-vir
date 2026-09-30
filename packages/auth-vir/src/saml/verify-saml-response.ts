import {
    extractErrorMessage,
    type MaybePromise,
    type PartialWithUndefined,
    wrapInTry,
} from '@augment-vir/common';
import {SAML, SamlStatusError, ValidateInResponseTo} from '@node-saml/node-saml';
import {type Element} from '@xmldom/xmldom';
import {
    type AnyDuration,
    convertDuration,
    createUtcFullDate,
    type FullDate,
    getNowInUtcTimezone,
    toTimestamp,
    type UtcTimezone,
} from 'date-vir';
import {
    getAttribute,
    getChildElements,
    getElementText,
    getOnlyChildElement,
    isXmlElement,
    parseStrictXml,
    SamlNamespace,
} from './saml-xml.js';

/**
 * The stored settings for an organization's SAML identity provider (IdP), usually obtained from
 * `parseIdpMetadata`.
 *
 * @category SAML
 */
export type SamlIdpSettings = Readonly<{
    /** The IdP's entity ID. Assertions whose `Issuer` does not match this exactly are rejected. */
    entityId: string;
    /**
     * PEM encoded X.509 certificates that the IdP signs with. A signature from any one of these is
     * accepted, so both the old and new certificate can be stored during a certificate rollover.
     */
    signingCertificates: ReadonlyArray<string>;
}>;

/**
 * Records which assertion IDs have already been used, to prevent a captured `SAMLResponse` from
 * being replayed. For IdP-initiated sign-in (no `InResponseTo`) this is the only replay defense.
 *
 * @category SAML
 */
export type SamlAssertionReplayStore = Readonly<{
    /**
     * Atomically record that an assertion ID has been used. Must return `false` if the ID was
     * already recorded (and `true` otherwise). The record only needs to be kept until `expiresAt`
     * (the assertion's `NotOnOrAfter` plus the allowed clock skew); after that the assertion is
     * rejected as expired anyway.
     *
     * This is only called after every other check has passed, so forged messages can never use up a
     * legitimate assertion ID.
     */
    markAssertionUsed(
        params: Readonly<{assertionId: string; expiresAt: FullDate<UtcTimezone>}>,
    ): MaybePromise<boolean>;
}>;

/**
 * Default allowed clock skew between the SP and the IdP for SAML timestamp checks.
 *
 * @category SAML
 * @default {minutes: 2}
 */
export const defaultSamlClockSkew: Readonly<AnyDuration> = {
    minutes: 2,
};

/**
 * The largest clock skew that {@link verifySamlResponse} will accept.
 *
 * @category SAML
 * @default {minutes: 5}
 */
export const maxSamlClockSkew: Readonly<AnyDuration> = {
    minutes: 5,
};

/**
 * Params for {@link verifySamlResponse}.
 *
 * @category SAML
 */
export type VerifySamlResponseParams = Readonly<{
    idp: SamlIdpSettings;
    /** Our own SP entity ID. Assertions whose `Audience` does not include this are rejected. */
    spEntityId: string;
    /**
     * Our own Assertion Consumer Service URL (the URL the `SAMLResponse` was posted to). Bearer
     * assertions whose `Recipient` does not match this are rejected.
     */
    acsUrl: string;
    /** The base64 encoded `SAMLResponse` form field, exactly as it was posted. */
    samlResponse: string;
    replayStore: SamlAssertionReplayStore;
}> &
    Readonly<
        PartialWithUndefined<{
            /**
             * Allowed clock skew for `NotBefore` and `NotOnOrAfter` checks. Capped at
             * {@link maxSamlClockSkew}.
             *
             * @default defaultSamlClockSkew
             */
            clockSkew: Readonly<AnyDuration>;
        }>
    >;

/**
 * A SAML assertion that passed every check in {@link verifySamlResponse}. Every value here was read
 * from the signed part of the message.
 *
 * @category SAML
 */
export type VerifiedSamlProfile = {
    /** The subject's `NameID`. With the email NameID format, this is the user's email address. */
    nameId: string;
    nameIdFormat: string | undefined;
    assertionId: string;
    /** The earlier of the Conditions and bearer SubjectConfirmationData `NotOnOrAfter` times. */
    notOnOrAfter: FullDate<UtcTimezone>;
    sessionIndex: string | undefined;
    /**
     * Every attribute in the assertion, keyed by the attribute's `Name`. Values are always arrays,
     * even when the IdP sent only one value.
     */
    attributes: Record<string, string[]>;
};

/**
 * Why {@link verifySamlResponse} rejected a message.
 *
 * @category SAML
 */
export enum SamlVerifyFailureReason {
    /** The message could not be parsed or is missing required SAML elements. */
    Malformed = 'malformed',
    /**
     * The assertion is not signed by any of the IdP's certificates, or the signed content was
     * altered or moved (signature wrapping).
     */
    InvalidSignature = 'invalid-signature',
    /** The IdP responded with an error status instead of an assertion. */
    IdpStatusError = 'idp-status-error',
    WrongIssuer = 'wrong-issuer',
    WrongAudience = 'wrong-audience',
    WrongRecipient = 'wrong-recipient',
    Expired = 'expired',
    NotYetValid = 'not-yet-valid',
    /** The replay store reported that this assertion ID was already used. */
    Replayed = 'replayed',
}

/**
 * Output of {@link verifySamlResponse}.
 *
 * @category SAML
 */
export type VerifySamlResponseResult =
    | {
          success: true;
          profile: VerifiedSamlProfile;
      }
    | {
          success: false;
          reason: SamlVerifyFailureReason;
          /** Human-readable detail for logs. Do not show this to the end user. */
          detail: string;
      };

class SamlVerifyError extends Error {
    public override readonly name = 'SamlVerifyError';
    constructor(
        public readonly reason: SamlVerifyFailureReason,
        message: string,
    ) {
        super(message);
    }
}

const bearerConfirmationMethod = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

/**
 * Verify a `SAMLResponse` posted by an IdP and extract the signed profile. Supports IdP-initiated
 * sign-in (no `InResponseTo`).
 *
 * The assertion itself must be signed; a signature on only the outer `Response` is not accepted.
 * Encrypted assertions are not supported.
 *
 * Rejections are returned as a typed failure. This only throws for invalid params or when the
 * replay store throws.
 *
 * @category SAML
 */
export async function verifySamlResponse(
    params: VerifySamlResponseParams,
): Promise<VerifySamlResponseResult> {
    const requestedClockSkewMs = wrapInTry(
        () => {
            return convertDuration(params.clockSkew || defaultSamlClockSkew, {
                milliseconds: true,
            }).milliseconds;
        },
        {
            handleError: (error) => {
                throw new TypeError('SAML clock skew is not a valid duration.', {
                    cause: error,
                });
            },
        },
    );

    if (!params.idp.signingCertificates.length) {
        throw new TypeError('At least one IdP signing certificate is required.');
    } else if (!params.idp.entityId) {
        throw new TypeError('An IdP entity ID is required.');
    } else if (!params.spEntityId) {
        throw new TypeError('An SP entity ID is required.');
    } else if (!params.acsUrl) {
        throw new TypeError('An ACS URL is required.');
    } else if (requestedClockSkewMs < 0) {
        throw new TypeError('SAML clock skew cannot be negative.');
    }

    const clockSkewMs = Math.min(
        requestedClockSkewMs,
        convertDuration(maxSamlClockSkew, {
            milliseconds: true,
        }).milliseconds,
    );

    try {
        const assertionXml = await getSignedAssertionXml(params);
        const profile = readVerifiedAssertion({
            assertionXml,
            params,
            clockSkewMs,
            nowMs: toTimestamp(getNowInUtcTimezone()),
        });

        if (
            !(await params.replayStore.markAssertionUsed({
                assertionId: profile.assertionId,
                expiresAt: createUtcFullDate(toTimestamp(profile.notOnOrAfter) + clockSkewMs),
            }))
        ) {
            throw new SamlVerifyError(
                SamlVerifyFailureReason.Replayed,
                `Assertion '${profile.assertionId}' was already used.`,
            );
        }

        return {
            success: true,
            profile,
        };
    } catch (error) {
        if (error instanceof SamlVerifyError) {
            return {
                success: false,
                reason: error.reason,
                detail: error.message,
            };
        }
        throw error;
    }
}

/**
 * Uses node-saml to check the signature and return only the XML that the signature covers. All
 * other checks happen in {@link readVerifiedAssertion} so that they read only signed content.
 */
async function getSignedAssertionXml(params: VerifySamlResponseParams): Promise<string> {
    const saml = new SAML({
        idpCert: [...params.idp.signingCertificates],
        issuer: params.spEntityId,
        callbackUrl: params.acsUrl,
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: false,
        validateInResponseTo: ValidateInResponseTo.never,
        /** These checks are done in `readVerifiedAssertion` instead. */
        audience: false,
        acceptedClockSkewMs: -1,
    });

    try {
        const {profile} = await saml.validatePostResponseAsync({
            SAMLResponse: params.samlResponse,
        });

        const assertionXml = profile?.getAssertionXml?.();

        if (!assertionXml) {
            throw new SamlVerifyError(
                SamlVerifyFailureReason.Malformed,
                'SAML response did not contain a sign-in assertion.',
            );
        }

        return assertionXml;
    } catch (error) {
        if (error instanceof SamlVerifyError) {
            throw error;
        }

        const message = extractErrorMessage(error);

        if (error instanceof SamlStatusError) {
            throw new SamlVerifyError(SamlVerifyFailureReason.IdpStatusError, message);
        } else if (/signature/i.test(message)) {
            throw new SamlVerifyError(SamlVerifyFailureReason.InvalidSignature, message);
        } else {
            throw new SamlVerifyError(SamlVerifyFailureReason.Malformed, message);
        }
    }
}

function readVerifiedAssertion({
    assertionXml,
    params,
    clockSkewMs,
    nowMs,
}: Readonly<{
    assertionXml: string;
    params: VerifySamlResponseParams;
    clockSkewMs: number;
    nowMs: number;
}>): VerifiedSamlProfile {
    const assertion = wrapInTry(() => parseStrictXml(assertionXml), {
        handleError: (error) => {
            throw new SamlVerifyError(
                SamlVerifyFailureReason.Malformed,
                extractErrorMessage(error),
            );
        },
    });
    if (!isXmlElement(assertion, SamlNamespace.Assertion, 'Assertion')) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.Malformed,
            'Signed content is not a SAML 2.0 Assertion.',
        );
    }

    const assertionId = getAttribute(assertion, 'ID');
    if (!assertionId) {
        throw new SamlVerifyError(SamlVerifyFailureReason.Malformed, 'Assertion has no ID.');
    }

    const issuer = requireChild(assertion, SamlNamespace.Assertion, 'Issuer');
    const issuerText = getElementText(issuer);
    if (issuerText !== params.idp.entityId) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.WrongIssuer,
            `Expected issuer '${params.idp.entityId}' but got '${issuerText}'.`,
        );
    }

    const conditions = requireChild(assertion, SamlNamespace.Assertion, 'Conditions');
    const conditionsNotOnOrAfterMs = checkTimeWindow({
        element: conditions,
        nowMs,
        clockSkewMs,
    });
    checkAudience(conditions, params.spEntityId);

    const subject = requireChild(assertion, SamlNamespace.Assertion, 'Subject');
    const subjectNotOnOrAfterMs = checkBearerConfirmation({
        subject,
        acsUrl: params.acsUrl,
        nowMs,
        clockSkewMs,
    });

    const nameId = requireChild(subject, SamlNamespace.Assertion, 'NameID');
    const nameIdText = getElementText(nameId);
    if (!nameIdText) {
        throw new SamlVerifyError(SamlVerifyFailureReason.Malformed, 'NameID is empty.');
    }

    const authnStatement = getChild(assertion, SamlNamespace.Assertion, 'AuthnStatement');

    return {
        nameId: nameIdText,
        nameIdFormat: getAttribute(nameId, 'Format'),
        assertionId,
        notOnOrAfter: createUtcFullDate(
            Math.min(subjectNotOnOrAfterMs, conditionsNotOnOrAfterMs ?? Infinity),
        ),
        sessionIndex: authnStatement ? getAttribute(authnStatement, 'SessionIndex') : undefined,
        attributes: readAttributes(assertion),
    };
}

/** Wraps {@link getOnlyChildElement} so that duplicate elements become a typed failure. */
function getChild(
    parent: Readonly<Element>,
    namespace: SamlNamespace,
    localName: string,
): Element | undefined {
    try {
        return getOnlyChildElement(parent, namespace, localName);
    } catch (error) {
        throw new SamlVerifyError(SamlVerifyFailureReason.Malformed, extractErrorMessage(error));
    }
}

function requireChild(
    parent: Readonly<Element>,
    namespace: SamlNamespace,
    localName: string,
): Element {
    const child = getChild(parent, namespace, localName);
    if (!child) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.Malformed,
            `Missing '${localName}' element.`,
        );
    }
    return child;
}

function parseSamlTime(element: Readonly<Element>, attributeName: string): number | undefined {
    const value = getAttribute(element, attributeName);
    if (value == undefined) {
        return undefined;
    }

    const timestamp = Date.parse(value);
    if (Number.isNaN(timestamp)) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.Malformed,
            `Invalid ${attributeName} time: '${value}'.`,
        );
    }
    return timestamp;
}

/**
 * Checks `NotBefore` and `NotOnOrAfter` on the given element.
 *
 * @returns The `NotOnOrAfter` timestamp, if present.
 */
function checkTimeWindow({
    element,
    nowMs,
    clockSkewMs,
}: Readonly<{
    element: Readonly<Element>;
    nowMs: number;
    clockSkewMs: number;
}>): number | undefined {
    const notBeforeMs = parseSamlTime(element, 'NotBefore');
    const notOnOrAfterMs = parseSamlTime(element, 'NotOnOrAfter');

    if (notOnOrAfterMs != undefined && nowMs - clockSkewMs >= notOnOrAfterMs) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.Expired,
            `'${element.localName}' expired at ${getAttribute(element, 'NotOnOrAfter')}.`,
        );
    } else if (notBeforeMs != undefined && nowMs + clockSkewMs < notBeforeMs) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.NotYetValid,
            `'${element.localName}' is not valid until ${getAttribute(element, 'NotBefore')}.`,
        );
    } else {
        return notOnOrAfterMs;
    }
}

/** Every `AudienceRestriction` must include our SP entity ID (SAML core 2.5.1.4). */
function checkAudience(conditions: Readonly<Element>, spEntityId: string) {
    const restrictions = getChildElements(
        conditions,
        SamlNamespace.Assertion,
        'AudienceRestriction',
    );

    if (!restrictions.length) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.WrongAudience,
            'Assertion has no AudienceRestriction.',
        );
    }

    restrictions.forEach((restriction) => {
        const audiences = getChildElements(restriction, SamlNamespace.Assertion, 'Audience').map(
            (audience) => getElementText(audience),
        );

        if (!audiences.includes(spEntityId)) {
            throw new SamlVerifyError(
                SamlVerifyFailureReason.WrongAudience,
                `Expected audience '${spEntityId}' but got '${audiences.join("', '")}'.`,
            );
        }
    });
}

/**
 * Requires a bearer `SubjectConfirmation` that is currently valid and addressed to our ACS URL
 * (SAML profiles 4.1.4.2).
 *
 * @returns The confirmation's `NotOnOrAfter` timestamp.
 */
function checkBearerConfirmation({
    subject,
    acsUrl,
    nowMs,
    clockSkewMs,
}: Readonly<{
    subject: Readonly<Element>;
    acsUrl: string;
    nowMs: number;
    clockSkewMs: number;
}>): number {
    const bearerConfirmations = getChildElements(
        subject,
        SamlNamespace.Assertion,
        'SubjectConfirmation',
    ).filter((confirmation) => getAttribute(confirmation, 'Method') === bearerConfirmationMethod);

    if (!bearerConfirmations.length) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.Malformed,
            'Assertion has no bearer SubjectConfirmation.',
        );
    }

    const errors: SamlVerifyError[] = [];

    for (const confirmation of bearerConfirmations) {
        try {
            return checkSubjectConfirmationData({
                confirmation,
                acsUrl,
                nowMs,
                clockSkewMs,
            });
        } catch (error) {
            if (error instanceof SamlVerifyError) {
                errors.push(error);
            } else {
                throw error;
            }
        }
    }

    /** Report the first confirmation's failure since most IdPs only send one. */
    throw (
        errors[0] ??
        new SamlVerifyError(
            SamlVerifyFailureReason.Malformed,
            'No bearer SubjectConfirmation was valid.',
        )
    );
}

function checkSubjectConfirmationData({
    confirmation,
    acsUrl,
    nowMs,
    clockSkewMs,
}: Readonly<{
    confirmation: Readonly<Element>;
    acsUrl: string;
    nowMs: number;
    clockSkewMs: number;
}>): number {
    const data = requireChild(confirmation, SamlNamespace.Assertion, 'SubjectConfirmationData');

    const recipient = getAttribute(data, 'Recipient');
    if (recipient !== acsUrl) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.WrongRecipient,
            `Expected recipient '${acsUrl}' but got '${recipient ?? ''}'.`,
        );
    }

    const notOnOrAfterMs = checkTimeWindow({
        element: data,
        nowMs,
        clockSkewMs,
    });
    if (notOnOrAfterMs == undefined) {
        throw new SamlVerifyError(
            SamlVerifyFailureReason.Malformed,
            'Bearer SubjectConfirmationData has no NotOnOrAfter.',
        );
    }

    return notOnOrAfterMs;
}

function readAttributes(assertion: Readonly<Element>): Record<string, string[]> {
    /** A Map avoids treating attribute names such as `__proto__` as object keys. */
    const attributes = new Map<string, string[]>();

    getChildElements(assertion, SamlNamespace.Assertion, 'AttributeStatement').forEach(
        (statement) => {
            getChildElements(statement, SamlNamespace.Assertion, 'Attribute').forEach(
                (attribute) => {
                    const name = getAttribute(attribute, 'Name');
                    if (!name) {
                        throw new SamlVerifyError(
                            SamlVerifyFailureReason.Malformed,
                            'Attribute has no Name.',
                        );
                    }

                    const values = getChildElements(
                        attribute,
                        SamlNamespace.Assertion,
                        'AttributeValue',
                    ).map((value) => getElementText(value));

                    attributes.set(name, [
                        ...(attributes.get(name) || []),
                        ...values,
                    ]);
                },
            );
        },
    );

    return Object.fromEntries(attributes);
}
