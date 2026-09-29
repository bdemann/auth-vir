import {removeDuplicates, type PartialWithUndefined} from '@augment-vir/common';
import {generateServiceProviderMetadata} from '@node-saml/node-saml';
import {type Element} from '@xmldom/xmldom';
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
 * The parts of an IdP's SAML metadata needed to accept sign-ins from it. Output of
 * {@link parseIdpMetadata}.
 *
 * @category SAML
 */
export type ParsedIdpMetadata = {
    entityId: string;
    /**
     * The IdP's `SingleSignOnService` location. The HTTP-Redirect binding is preferred, then
     * HTTP-POST.
     */
    ssoUrl: string;
    /** Every signing certificate listed in the metadata, PEM encoded. */
    signingCertificates: string[];
};

const ssoBindingPreference = [
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
];

/**
 * Parse an IdP's SAML metadata XML (such as ADFS's `FederationMetadata.xml`). Throws an `Error`
 * with a human-readable message if the metadata is invalid.
 *
 * The metadata's own signature is not checked: the admin who pastes it in is trusted to have
 * obtained it from the right place.
 *
 * @category SAML
 */
export function parseIdpMetadata(metadataXml: string): ParsedIdpMetadata {
    const entityDescriptor = parseStrictXml(metadataXml);

    if (!isXmlElement(entityDescriptor, SamlNamespace.Metadata, 'EntityDescriptor')) {
        throw new Error('Metadata root element must be a SAML 2.0 EntityDescriptor.');
    }

    const entityId = getAttribute(entityDescriptor, 'entityID');
    if (!entityId) {
        throw new Error('Metadata EntityDescriptor has no entityID.');
    }

    const idpDescriptor = getOnlyChildElement(
        entityDescriptor,
        SamlNamespace.Metadata,
        'IDPSSODescriptor',
    );
    if (!idpDescriptor) {
        throw new Error('Metadata has no IDPSSODescriptor.');
    }

    const signingCertificates = readSigningCertificates(idpDescriptor);
    if (!signingCertificates.length) {
        throw new Error('Metadata has no signing certificates.');
    }

    return {
        entityId,
        ssoUrl: readSsoUrl(idpDescriptor),
        signingCertificates,
    };
}

function readSsoUrl(idpDescriptor: Readonly<Element>): string {
    const services = getChildElements(idpDescriptor, SamlNamespace.Metadata, 'SingleSignOnService');

    for (const binding of ssoBindingPreference) {
        const location = services
            .filter((service) => getAttribute(service, 'Binding') === binding)
            .map((service) => getAttribute(service, 'Location'))
            .find((serviceLocation) => serviceLocation);

        if (location) {
            return location;
        }
    }

    throw new Error('Metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService.');
}

function readSigningCertificates(idpDescriptor: Readonly<Element>): string[] {
    const certificates = getChildElements(idpDescriptor, SamlNamespace.Metadata, 'KeyDescriptor')
        /** A KeyDescriptor without a `use` is usable for both signing and encryption. */
        .filter((keyDescriptor) => (getAttribute(keyDescriptor, 'use') ?? 'signing') === 'signing')
        .flatMap((keyDescriptor) => {
            return getChildElements(keyDescriptor, SamlNamespace.XmlDsig, 'KeyInfo');
        })
        .flatMap((keyInfo) => getChildElements(keyInfo, SamlNamespace.XmlDsig, 'X509Data'))
        .flatMap((x509Data) => getChildElements(x509Data, SamlNamespace.XmlDsig, 'X509Certificate'))
        .map((certificate) => toPemCertificate(getElementText(certificate)));

    return removeDuplicates(certificates);
}

function toPemCertificate(base64Certificate: string): string {
    const base64 = base64Certificate.replaceAll(/\s/g, '');

    if (!base64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
        throw new Error('Metadata contains an X509Certificate that is not valid base64.');
    }

    const lines = base64.match(/.{1,64}/g) || [];

    return [
        '-----BEGIN CERTIFICATE-----',
        ...lines,
        '-----END CERTIFICATE-----',
    ].join('\n');
}

/**
 * Params for {@link generateSpMetadata}.
 *
 * @category SAML
 */
export type GenerateSpMetadataParams = Readonly<{
    /** Our SP entity ID. Must match `spEntityId` given to `verifySamlResponse`. */
    entityId: string;
    /** Our Assertion Consumer Service URL. Must match `acsUrl` given to `verifySamlResponse`. */
    acsUrl: string;
}> &
    Readonly<
        PartialWithUndefined<{
            /**
             * The NameID format to request from the IdP.
             *
             * @default 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
             */
            nameIdFormat: string;
        }>
    >;

/**
 * Generate our SP metadata XML, for an IdP admin to import. It declares that assertions must be
 * signed and that our requests are not signed.
 *
 * @category SAML
 */
export function generateSpMetadata(params: GenerateSpMetadataParams): string {
    return generateServiceProviderMetadata({
        issuer: params.entityId,
        callbackUrl: params.acsUrl,
        wantAssertionsSigned: true,
        identifierFormat:
            params.nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    });
}
