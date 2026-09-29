import {assert, assertWrap} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {DOMParser, MIME_TYPE} from '@xmldom/xmldom';
import {generateSpMetadata, parseIdpMetadata} from './saml-metadata.js';
import {createMockReplayStore, createMockSamlResponse, mockIdpKeys, mockSaml} from './saml.mock.js';
import {verifySamlResponse} from './verify-saml-response.js';

const metadataNamespace = 'urn:oasis:names:tc:SAML:2.0:metadata';

function toBase64Body(pem: string): string {
    return pem.replaceAll(/-----(BEGIN|END) CERTIFICATE-----/g, '').replaceAll(/\s/g, '');
}

function normalizePem(pem: string): string {
    return pem.replaceAll('\r\n', '\n').trim();
}

function keyDescriptor(use: string | undefined, pem: string): string {
    const useAttribute = use ? ` use="${use}"` : '';

    return [
        `<KeyDescriptor${useAttribute}>`,
        '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>',
        toBase64Body(pem),
        '</X509Certificate></X509Data></KeyInfo>',
        '</KeyDescriptor>',
    ].join('');
}

/** Shaped like ADFS's FederationMetadata.xml, including its WS-Federation RoleDescriptors. */
function createAdfsMetadata({
    keyDescriptors = [
        keyDescriptor('encryption', mockIdpKeys.unknown.certificate),
        keyDescriptor('signing', mockIdpKeys.current.certificate),
        keyDescriptor('signing', mockIdpKeys.rolledOver.certificate),
    ].join(''),
    ssoServices = [
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://adfs.example.com/adfs/ls/post"/>',
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://adfs.example.com/adfs/ls/"/>',
    ].join(''),
    idpDescriptor = true,
}: Partial<{keyDescriptors: string; ssoServices: string; idpDescriptor: boolean}> = {}): string {
    return [
        '<?xml version="1.0" encoding="utf-8"?>',
        `<EntityDescriptor ID="_metadata" entityID="${mockSaml.idpEntityId}" xmlns="${metadataNamespace}">`,
        '<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">',
        keyDescriptor('signing', mockIdpKeys.unknown.certificate),
        '</RoleDescriptor>',
        '<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">',
        keyDescriptor('signing', mockIdpKeys.unknown.certificate),
        '</SPSSODescriptor>',
        idpDescriptor
            ? `<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keyDescriptors}${ssoServices}</IDPSSODescriptor>`
            : '',
        '</EntityDescriptor>',
    ].join('');
}

describe(parseIdpMetadata.name, () => {
    it('parses ADFS metadata', () => {
        const parsed = parseIdpMetadata(createAdfsMetadata());

        assert.strictEquals(parsed.entityId, mockSaml.idpEntityId);
        assert.strictEquals(parsed.ssoUrl, 'https://adfs.example.com/adfs/ls/');
        assert.deepEquals(parsed.signingCertificates, [
            normalizePem(mockIdpKeys.current.certificate),
            normalizePem(mockIdpKeys.rolledOver.certificate),
        ]);
    });

    it('produces settings that verify a real response', async () => {
        const parsed = parseIdpMetadata(createAdfsMetadata());

        const result = await verifySamlResponse({
            idp: parsed,
            spEntityId: mockSaml.spEntityId,
            acsUrl: mockSaml.acsUrl,
            samlResponse: createMockSamlResponse({
                signingKey: mockIdpKeys.rolledOver,
            }),
            replayStore: createMockReplayStore(),
        });

        assert.isTrue(result.success);
    });

    it('treats a KeyDescriptor without a use as a signing key and removes duplicates', () => {
        const parsed = parseIdpMetadata(
            createAdfsMetadata({
                keyDescriptors: [
                    keyDescriptor(undefined, mockIdpKeys.current.certificate),
                    keyDescriptor('signing', mockIdpKeys.current.certificate),
                ].join(''),
            }),
        );

        assert.deepEquals(parsed.signingCertificates, [
            normalizePem(mockIdpKeys.current.certificate),
        ]);
    });

    it('falls back to the HTTP-POST binding', () => {
        const parsed = parseIdpMetadata(
            createAdfsMetadata({
                ssoServices:
                    '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://adfs.example.com/adfs/ls/post"/>',
            }),
        );

        assert.strictEquals(parsed.ssoUrl, 'https://adfs.example.com/adfs/ls/post');
    });

    it('rejects invalid metadata', () => {
        assert.throws(() => parseIdpMetadata('not xml'));
        assert.throws(
            () => {
                return parseIdpMetadata(
                    '<!DOCTYPE x [<!ENTITY a "a">]><EntityDescriptor entityID="x" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>',
                );
            },
            {
                matchMessage: 'DOCTYPE',
            },
        );
        assert.throws(() => parseIdpMetadata('<EntitiesDescriptor/>'), {
            matchMessage: 'EntityDescriptor',
        });
        assert.throws(() => parseIdpMetadata(`<EntityDescriptor xmlns="${metadataNamespace}"/>`), {
            matchMessage: 'entityID',
        });
        assert.throws(
            () => {
                return parseIdpMetadata(
                    createAdfsMetadata({
                        idpDescriptor: false,
                    }),
                );
            },
            {
                matchMessage: 'IDPSSODescriptor',
            },
        );
        assert.throws(
            () => {
                return parseIdpMetadata(
                    createAdfsMetadata({
                        keyDescriptors: '',
                    }),
                );
            },
            {
                matchMessage: 'no signing certificates',
            },
        );
        assert.throws(
            () => {
                return parseIdpMetadata(
                    createAdfsMetadata({
                        ssoServices: '',
                    }),
                );
            },
            {
                matchMessage: 'SingleSignOnService',
            },
        );
        assert.throws(
            () => {
                return parseIdpMetadata(
                    createAdfsMetadata({
                        keyDescriptors: keyDescriptor('signing', 'not*base64'),
                    }),
                );
            },
            {
                matchMessage: 'base64',
            },
        );
    });
});

describe(generateSpMetadata.name, () => {
    it('generates SP metadata that an IdP can import', () => {
        const xml = generateSpMetadata({
            entityId: mockSaml.spEntityId,
            acsUrl: mockSaml.acsUrl,
        });
        const root = assertWrap.isDefined(
            new DOMParser().parseFromString(xml, MIME_TYPE.XML_TEXT).documentElement,
        );
        const getOnlyElement = (localName: string) => {
            return assertWrap.isDefined(
                root.getElementsByTagNameNS(metadataNamespace, localName)[0],
            );
        };
        const spDescriptor = getOnlyElement('SPSSODescriptor');
        const acs = getOnlyElement('AssertionConsumerService');
        const nameIdFormat = getOnlyElement('NameIDFormat');

        assert.strictEquals(root.localName, 'EntityDescriptor');
        assert.strictEquals(root.getAttribute('entityID'), mockSaml.spEntityId);
        assert.strictEquals(spDescriptor.getAttribute('WantAssertionsSigned'), 'true');
        assert.strictEquals(spDescriptor.getAttribute('AuthnRequestsSigned'), 'false');
        assert.strictEquals(acs.getAttribute('Location'), mockSaml.acsUrl);
        assert.strictEquals(
            acs.getAttribute('Binding'),
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        );
        assert.strictEquals(
            nameIdFormat.textContent,
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        );
    });

    it('uses a custom NameID format', () => {
        const xml = generateSpMetadata({
            entityId: mockSaml.spEntityId,
            acsUrl: mockSaml.acsUrl,
            nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        });

        assert.isTrue(xml.includes('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'));
    });

    it('is not accepted by parseIdpMetadata', () => {
        /** SP metadata has no IDPSSODescriptor, so it must never be accepted as IdP metadata. */
        assert.throws(
            () => {
                return parseIdpMetadata(
                    generateSpMetadata({
                        entityId: mockSaml.spEntityId,
                        acsUrl: mockSaml.acsUrl,
                    }),
                );
            },
            {
                matchMessage: 'IDPSSODescriptor',
            },
        );
    });
});
