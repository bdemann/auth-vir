import {
    type AnyDuration,
    calculateRelativeDate,
    type FullDate,
    getNowInUtcTimezone,
    toUtcIsoString,
    type UtcTimezone,
} from 'date-vir';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {SignedXml} from 'xml-crypto';
import {samlTestFilesDirPath} from '../file-paths.mock.js';

export type MockIdpKeyPair = Readonly<{
    privateKey: string;
    certificate: string;
}>;

function readMockKeyPair(name: string): MockIdpKeyPair {
    return {
        privateKey: readFileSync(join(samlTestFilesDirPath, `${name}.key.pem`), 'utf8'),
        certificate: readFileSync(join(samlTestFilesDirPath, `${name}.cert.pem`), 'utf8'),
    };
}

/** Throwaway key pairs generated only for these tests. Never trust them anywhere else. */
export const mockIdpKeys = {
    current: readMockKeyPair('idp-current'),
    rolledOver: readMockKeyPair('idp-rolled-over'),
    unknown: readMockKeyPair('idp-unknown'),
} satisfies Record<string, MockIdpKeyPair>;

export const mockSaml = {
    idpEntityId: 'http://adfs.example.com/adfs/services/trust',
    spEntityId: 'https://app.example.com/sso/saml/metadata',
    acsUrl: 'https://app.example.com/sso/saml/acs/example-org',
    nameId: 'user@example.com',
};

export type MockSamlResponseParams = Partial<{
    assertionId: string;
    issuer: string;
    audiences: ReadonlyArray<string>;
    recipient: string;
    nameId: string;
    /** Defaults to one minute ago. */
    notBefore: FullDate<UtcTimezone>;
    /** Defaults to five minutes from now. */
    notOnOrAfter: FullDate<UtcTimezone>;
    /** The bearer SubjectConfirmationData's NotOnOrAfter. Defaults to `notOnOrAfter`. */
    subjectNotOnOrAfter: FullDate<UtcTimezone>;
    attributes: Readonly<Record<string, ReadonlyArray<string>>>;
    /** Which element(s) to sign. */
    signedElements: 'assertion' | 'response' | 'both' | 'none';
    signingKey: MockIdpKeyPair;
}>;

export function fromNow(duration: Readonly<AnyDuration>): FullDate<UtcTimezone> {
    return calculateRelativeDate(getNowInUtcTimezone(), duration);
}

function escapeXml(value: string): string {
    return value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
}

const signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const exclusiveC14n = 'http://www.w3.org/2001/10/xml-exc-c14n#';

function signElement(
    xml: string,
    localName: 'Assertion' | 'Response',
    signingKey: MockIdpKeyPair,
): string {
    const elementXpath = `//*[local-name(.)='${localName}']`;
    const signedXml = new SignedXml({
        privateKey: signingKey.privateKey,
        /** Embeds the signer's certificate in KeyInfo, like ADFS does. It must never be trusted. */
        publicCert: signingKey.certificate,
        signatureAlgorithm,
        canonicalizationAlgorithm: exclusiveC14n,
    });
    signedXml.addReference({
        xpath: elementXpath,
        transforms: [
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            exclusiveC14n,
        ],
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    });
    signedXml.computeSignature(xml, {
        prefix: 'ds',
        location: {
            /** The schema requires the Signature right after the element's Issuer. */
            reference: `${elementXpath}/*[local-name(.)='Issuer']`,
            action: 'after',
        },
    });

    return signedXml.getSignedXml();
}

/** Builds the XML of an ADFS-style SAML response, before base64 encoding. */
export function createMockSamlResponseXml(params: MockSamlResponseParams = {}): string {
    const assertionId = params.assertionId || `_${crypto.randomUUID()}`;
    const issuer = escapeXml(params.issuer ?? mockSaml.idpEntityId);
    const notBefore = toUtcIsoString(
        params.notBefore ||
            fromNow({
                minutes: -1,
            }),
    );
    const notOnOrAfter = toUtcIsoString(
        params.notOnOrAfter ||
            fromNow({
                minutes: 5,
            }),
    );
    const subjectNotOnOrAfter = params.subjectNotOnOrAfter
        ? toUtcIsoString(params.subjectNotOnOrAfter)
        : notOnOrAfter;
    const issueInstant = toUtcIsoString(getNowInUtcTimezone());
    const recipient = escapeXml(params.recipient ?? mockSaml.acsUrl);
    const audiences = (params.audiences || [mockSaml.spEntityId])
        .map((audience) => `<saml:Audience>${escapeXml(audience)}</saml:Audience>`)
        .join('');
    const attributes = Object.entries(
        params.attributes || {
            role: ['admin'],
        },
    )
        .map(
            ([
                name,
                values,
            ]) => {
                return `<saml:Attribute Name="${escapeXml(name)}">${values
                    .map(
                        (value) => `<saml:AttributeValue>${escapeXml(value)}</saml:AttributeValue>`,
                    )
                    .join('')}</saml:Attribute>`;
            },
        )
        .join('');

    const xml = [
        `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_${crypto.randomUUID()}" Version="2.0" IssueInstant="${issueInstant}" Destination="${recipient}">`,
        `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${issuer}</saml:Issuer>`,
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>',
        `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${escapeXml(assertionId)}" IssueInstant="${issueInstant}" Version="2.0">`,
        `<saml:Issuer>${issuer}</saml:Issuer>`,
        '<saml:Subject>',
        `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${escapeXml(params.nameId ?? mockSaml.nameId)}</saml:NameID>`,
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">',
        `<saml:SubjectConfirmationData NotOnOrAfter="${subjectNotOnOrAfter}" Recipient="${recipient}"/>`,
        '</saml:SubjectConfirmation>',
        '</saml:Subject>',
        `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">`,
        `<saml:AudienceRestriction>${audiences}</saml:AudienceRestriction>`,
        '</saml:Conditions>',
        `<saml:AttributeStatement>${attributes}</saml:AttributeStatement>`,
        `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${escapeXml(assertionId)}">`,
        '<saml:AuthnContext><saml:AuthnContextClassRef>urn:federation:authentication:windows</saml:AuthnContextClassRef></saml:AuthnContext>',
        '</saml:AuthnStatement>',
        '</saml:Assertion>',
        '</samlp:Response>',
    ].join('');

    const signedElements = params.signedElements || 'assertion';
    const signingKey = params.signingKey || mockIdpKeys.current;

    const withAssertionSignature =
        signedElements === 'assertion' || signedElements === 'both'
            ? signElement(xml, 'Assertion', signingKey)
            : xml;

    return signedElements === 'response' || signedElements === 'both'
        ? signElement(withAssertionSignature, 'Response', signingKey)
        : withAssertionSignature;
}

export function encodeSamlResponse(xml: string): string {
    return Buffer.from(xml, 'utf8').toString('base64');
}

export function createMockSamlResponse(params: MockSamlResponseParams = {}): string {
    return encodeSamlResponse(createMockSamlResponseXml(params));
}

/** A replay store backed by an in-memory Set, matching the contract a database table would have. */
export function createMockReplayStore() {
    const usedAssertionIds = new Set<string>();

    return {
        usedAssertionIds,
        markAssertionUsed({assertionId}: Readonly<{assertionId: string}>) {
            if (usedAssertionIds.has(assertionId)) {
                return false;
            }
            usedAssertionIds.add(assertionId);
            return true;
        },
    };
}
