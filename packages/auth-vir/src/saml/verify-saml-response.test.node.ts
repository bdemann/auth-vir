// cspell:words msis nameid samlp xmldsig
/* eslint-disable unicorn/prefer-dom-node-append, unicorn/prefer-dom-node-remove, unicorn/prefer-modern-dom-apis -- xmldom does not implement the modern DOM methods these rules suggest. */
import {assert, assertWrap} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {
    DOMParser,
    type Element,
    MIME_TYPE,
    type Document as XmlDocument,
    XMLSerializer,
} from '@xmldom/xmldom';
import {calculateRelativeDate, type FullDate, getNowInIsoString, type UtcTimezone} from 'date-vir';
import {
    createMockReplayStore,
    createMockSamlResponse,
    createMockSamlResponseXml,
    encodeSamlResponse,
    fromNow,
    mockIdpKeys,
    mockSaml,
} from './saml.mock.js';
import {
    defaultSamlClockSkew,
    SamlVerifyError,
    SamlVerifyFailureReason,
    verifySamlResponse,
    type VerifySamlResponseParams,
    type VerifySamlResponseResult,
} from './verify-saml-response.js';

const assertionNamespace = 'urn:oasis:names:tc:SAML:2.0:assertion';
const protocolNamespace = 'urn:oasis:names:tc:SAML:2.0:protocol';

function verify(
    samlResponse: string,
    overrides: Partial<VerifySamlResponseParams> = {},
): Promise<VerifySamlResponseResult> {
    return verifySamlResponse({
        idp: {
            entityId: mockSaml.idpEntityId,
            signingCertificates: [mockIdpKeys.current.certificate],
        },
        spEntityId: mockSaml.spEntityId,
        acsUrl: mockSaml.acsUrl,
        samlResponse,
        replayStore: createMockReplayStore(),
        ...overrides,
    });
}

async function assertRejected(
    samlResponse: string,
    reason: SamlVerifyFailureReason,
    overrides: Partial<VerifySamlResponseParams> = {},
) {
    const result = await verify(samlResponse, overrides);

    assert.isFalse(result.success, `Expected rejection with '${reason}' but it was accepted.`);
    assert.strictEquals(result.reason, reason, result.detail);
}

function modifyXml(
    xml: string,
    modify: (response: Element, document: XmlDocument) => void,
): string {
    const document = new DOMParser().parseFromString(xml, MIME_TYPE.XML_TEXT);
    modify(assertWrap.isDefined(document.documentElement), document);
    return new XMLSerializer().serializeToString(document);
}

function getFirst({
    parent,
    namespace,
    localName,
}: Readonly<{
    parent: Element;
    namespace: string;
    localName: string;
}>): Element {
    return assertWrap.isDefined(parent.getElementsByTagNameNS(namespace, localName)[0]);
}

function replaceNameId(assertion: Element, nameId: string) {
    getFirst({
        parent: assertion,
        namespace: assertionNamespace,
        localName: 'NameID',
    }).textContent = nameId;
}

describe(verifySamlResponse.name, () => {
    it('accepts a valid IdP-initiated response', async () => {
        const replayStore = createMockReplayStore();
        const notOnOrAfter = fromNow({
            minutes: 4,
        });
        const result = await verify(
            createMockSamlResponse({
                assertionId: '_valid-assertion',
                notOnOrAfter,
            }),
            {
                replayStore,
            },
        );

        assert.isTrue(result.success);
        assert.deepEquals(result.profile, {
            nameId: mockSaml.nameId,
            nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            assertionId: '_valid-assertion',
            notOnOrAfter,
            sessionIndex: '_valid-assertion',
            attributes: {
                role: ['admin'],
            },
        });
        assert.isTrue(replayStore.usedAssertionIds.has('_valid-assertion'));
    });

    it('accepts a response where both the response and assertion are signed', async () => {
        const result = await verify(
            createMockSamlResponse({
                signedElements: 'both',
            }),
        );

        assert.isTrue(result.success);
    });

    it('returns multi-valued attributes as arrays', async () => {
        const result = await verify(
            createMockSamlResponse({
                attributes: {
                    facility: [
                        'facility-a',
                        'facility-b',
                        'facility-c',
                    ],
                    role: ['nurse'],
                    empty: [],
                },
            }),
        );

        assert.isTrue(result.success);
        assert.deepEquals(result.profile.attributes, {
            facility: [
                'facility-a',
                'facility-b',
                'facility-c',
            ],
            role: ['nurse'],
            empty: [],
        });
    });

    it('does not let attribute names reach the object prototype', async () => {
        const result = await verify(
            createMockSamlResponse({
                attributes: {
                    ['__proto__']: ['polluted'],
                },
            }),
        );

        assert.isTrue(result.success);
        assert.deepEquals(Object.getOwnPropertyNames(result.profile.attributes), ['__proto__']);
        assert.strictEquals(Object.getPrototypeOf(result.profile.attributes), Object.prototype);
    });

    it('reads the full NameID when a comment is injected into it', async () => {
        /**
         * Comments are not signed, so an IdP user named `user@example.com.evil.com` could insert
         * one to make naive parsers read only `user@example.com`.
         */
        const xml = createMockSamlResponseXml({
            nameId: 'user@example.com.evil.com',
        }).replace('user@example.com.evil.com', 'user@example.com<!---->.evil.com');

        const result = await verify(encodeSamlResponse(xml));

        assert.isTrue(result.success);
        assert.strictEquals(result.profile.nameId, 'user@example.com.evil.com');
    });

    describe('signatures', () => {
        it('rejects tampered attribute text', async () => {
            const xml = createMockSamlResponseXml({
                attributes: {
                    role: ['nurse'],
                },
            });

            await assertRejected(
                encodeSamlResponse(xml.replace('>nurse<', '>admin<')),
                SamlVerifyFailureReason.InvalidSignature,
            );
        });

        it('rejects a tampered NameID', async () => {
            const xml = createMockSamlResponseXml();

            await assertRejected(
                encodeSamlResponse(xml.replace(mockSaml.nameId, 'ceo@example.com')),
                SamlVerifyFailureReason.InvalidSignature,
            );
        });

        it('still accepts a response after an unmodified DOM round trip', async () => {
            /**
             * Control for the wrapping tests: they must fail because of the attack, not the round
             * trip.
             */
            const result = await verify(
                encodeSamlResponse(modifyXml(createMockSamlResponseXml(), () => {})),
            );

            assert.isTrue(result.success);
        });

        it('rejects signature wrapping: signed assertion moved inside an unsigned one', async () => {
            const xml = modifyXml(createMockSamlResponseXml(), (response, document) => {
                const signedAssertion = getFirst({
                    parent: response,
                    namespace: assertionNamespace,
                    localName: 'Assertion',
                });
                const evilAssertion = signedAssertion.cloneNode(true) as Element;
                evilAssertion.setAttribute('ID', '_evil');
                replaceNameId(evilAssertion, 'ceo@example.com');

                /** Keep the original signature in the evil assertion, and hide the original. */
                const advice = document.createElementNS(assertionNamespace, 'saml:Advice');
                advice.appendChild(signedAssertion);
                evilAssertion.appendChild(advice);
                response.appendChild(evilAssertion);
            });

            await assertRejected(encodeSamlResponse(xml), SamlVerifyFailureReason.InvalidSignature);
        });

        it('rejects signature wrapping: unsigned assertion added next to the signed one', async () => {
            const xml = modifyXml(createMockSamlResponseXml(), (response) => {
                const signedAssertion = getFirst({
                    parent: response,
                    namespace: assertionNamespace,
                    localName: 'Assertion',
                });
                const evilAssertion = signedAssertion.cloneNode(true) as Element;
                evilAssertion.setAttribute('ID', '_evil');
                replaceNameId(evilAssertion, 'ceo@example.com');
                evilAssertion.removeChild(
                    getFirst({
                        parent: evilAssertion,
                        namespace: 'http://www.w3.org/2000/09/xmldsig#',
                        localName: 'Signature',
                    }),
                );

                response.insertBefore(evilAssertion, signedAssertion);
            });

            await assertRejected(encodeSamlResponse(xml), SamlVerifyFailureReason.InvalidSignature);
        });

        it('rejects signature wrapping: evil assertion reuses the signed ID', async () => {
            const xml = modifyXml(createMockSamlResponseXml(), (response, document) => {
                const signedAssertion = getFirst({
                    parent: response,
                    namespace: assertionNamespace,
                    localName: 'Assertion',
                });
                const evilAssertion = signedAssertion.cloneNode(true) as Element;
                replaceNameId(evilAssertion, 'ceo@example.com');

                /** Move the original assertion into the (unsigned) Response Extensions. */
                const extensions = document.createElementNS(protocolNamespace, 'samlp:Extensions');
                response.replaceChild(evilAssertion, signedAssertion);
                extensions.appendChild(signedAssertion);
                response.insertBefore(
                    extensions,
                    getFirst({
                        parent: response,
                        namespace: protocolNamespace,
                        localName: 'Status',
                    }),
                );
            });

            await assertRejected(encodeSamlResponse(xml), SamlVerifyFailureReason.InvalidSignature);
        });

        it('rejects a response signed by an unknown certificate', async () => {
            await assertRejected(
                createMockSamlResponse({
                    signingKey: mockIdpKeys.unknown,
                }),
                SamlVerifyFailureReason.InvalidSignature,
            );
        });

        it('accepts either certificate during a rollover', async () => {
            const idp = {
                entityId: mockSaml.idpEntityId,
                signingCertificates: [
                    mockIdpKeys.current.certificate,
                    mockIdpKeys.rolledOver.certificate,
                ],
            };

            const fromCurrent = await verify(createMockSamlResponse(), {
                idp,
            });
            const fromRolledOver = await verify(
                createMockSamlResponse({
                    signingKey: mockIdpKeys.rolledOver,
                }),
                {
                    idp,
                },
            );

            assert.isTrue(fromCurrent.success);
            assert.isTrue(fromRolledOver.success);
        });

        it('rejects a response where only the outer Response is signed', async () => {
            await assertRejected(
                createMockSamlResponse({
                    signedElements: 'response',
                }),
                SamlVerifyFailureReason.InvalidSignature,
            );
        });

        it('rejects an unsigned response', async () => {
            await assertRejected(
                createMockSamlResponse({
                    signedElements: 'none',
                }),
                SamlVerifyFailureReason.InvalidSignature,
            );
        });

        it('rejects a SHA-1 signature', async () => {
            const result = await verify(
                createMockSamlResponse({
                    hashAlgorithm: 'sha1',
                }),
            );

            assert.isFalse(result.success);
            assert.strictEquals(result.reason, SamlVerifyFailureReason.InvalidSignature);
            assert.isTrue(result.detail.includes('SHA-1'), result.detail);
        });

        it('rejects a SHA-1 signature whose algorithm is written as a character reference', async () => {
            /** Canonicalization expands the reference, so the signature itself still verifies. */
            const xml = createMockSamlResponseXml({
                hashAlgorithm: 'sha1',
            }).replace('xmldsig#rsa-sha1', 'xmldsig&#x23;rsa-sha1');
            assert.isTrue(xml.includes('xmldsig&#x23;rsa-sha1'));

            const result = await verify(encodeSamlResponse(xml));

            assert.isFalse(result.success);
            assert.strictEquals(result.reason, SamlVerifyFailureReason.InvalidSignature);
            assert.isTrue(result.detail.includes('SHA-1'), result.detail);
        });
    });

    describe('conditions', () => {
        it('rejects the wrong audience', async () => {
            await assertRejected(
                createMockSamlResponse({
                    audiences: ['https://other-app.example.com'],
                }),
                SamlVerifyFailureReason.WrongAudience,
            );
        });

        it('accepts an AudienceRestriction that lists our audience among others', async () => {
            const result = await verify(
                createMockSamlResponse({
                    audiences: [
                        'https://other-app.example.com',
                        mockSaml.spEntityId,
                    ],
                }),
            );

            assert.isTrue(result.success);
        });

        it('rejects the wrong issuer', async () => {
            await assertRejected(
                createMockSamlResponse({
                    issuer: 'http://evil.example.com/adfs/services/trust',
                }),
                SamlVerifyFailureReason.WrongIssuer,
            );
        });

        it('rejects the wrong recipient', async () => {
            await assertRejected(
                createMockSamlResponse({
                    recipient: 'https://app.example.com/sso/saml/acs/other-org',
                }),
                SamlVerifyFailureReason.WrongRecipient,
            );
        });

        it('rejects an expired response', async () => {
            await assertRejected(
                createMockSamlResponse({
                    notBefore: fromNow({
                        minutes: -20,
                    }),
                    notOnOrAfter: fromNow({
                        minutes: -10,
                    }),
                }),
                SamlVerifyFailureReason.Expired,
            );
        });

        it('rejects expired Conditions when the subject confirmation is still valid', async () => {
            await assertRejected(
                createMockSamlResponse({
                    notBefore: fromNow({
                        minutes: -20,
                    }),
                    notOnOrAfter: fromNow({
                        minutes: -10,
                    }),
                    subjectNotOnOrAfter: fromNow({
                        minutes: 4,
                    }),
                }),
                SamlVerifyFailureReason.Expired,
            );
        });

        it('rejects an expired subject confirmation when Conditions are still valid', async () => {
            await assertRejected(
                createMockSamlResponse({
                    subjectNotOnOrAfter: fromNow({
                        minutes: -10,
                    }),
                }),
                SamlVerifyFailureReason.Expired,
            );
        });

        it('allows a response that expired within the clock skew', async () => {
            const result = await verify(
                createMockSamlResponse({
                    notOnOrAfter: fromNow({
                        seconds: -30,
                    }),
                }),
            );

            assert.isTrue(result.success);
        });

        it('caps the clock skew', async () => {
            await assertRejected(
                createMockSamlResponse({
                    notBefore: fromNow({
                        minutes: -20,
                    }),
                    notOnOrAfter: fromNow({
                        minutes: -10,
                    }),
                }),
                SamlVerifyFailureReason.Expired,
                {
                    clockSkew: {
                        hours: 1,
                    },
                },
            );
        });

        it('rejects a time that is not in UTC', async () => {
            const result = await verify(
                createMockSamlResponse({
                    conditionsNotOnOrAfterText: '2099-01-01T00:00:00',
                }),
            );

            assert.isFalse(result.success);
            assert.strictEquals(result.reason, SamlVerifyFailureReason.Malformed);
            assert.isTrue(result.detail.includes('Expected a UTC time'), result.detail);
        });

        it('rejects a response that is not yet valid', async () => {
            await assertRejected(
                createMockSamlResponse({
                    notBefore: fromNow({
                        minutes: 10,
                    }),
                }),
                SamlVerifyFailureReason.NotYetValid,
            );
        });
    });

    describe('replay protection', () => {
        it('rejects a replayed assertion ID', async () => {
            const replayStore = createMockReplayStore();
            const samlResponse = createMockSamlResponse();

            const first = await verify(samlResponse, {
                replayStore,
            });
            assert.isTrue(first.success);

            await assertRejected(samlResponse, SamlVerifyFailureReason.Replayed, {
                replayStore,
            });
        });

        it('does not record assertion IDs from rejected messages', async () => {
            const replayStore = createMockReplayStore();

            await assertRejected(
                createMockSamlResponse({
                    assertionId: '_shared-id',
                    signingKey: mockIdpKeys.unknown,
                }),
                SamlVerifyFailureReason.InvalidSignature,
                {
                    replayStore,
                },
            );
            await assertRejected(
                createMockSamlResponse({
                    assertionId: '_shared-id',
                    audiences: ['wrong'],
                }),
                SamlVerifyFailureReason.WrongAudience,
                {
                    replayStore,
                },
            );

            assert.strictEquals(replayStore.usedAssertionIds.size, 0);
            assert.isTrue(
                (
                    await verify(
                        createMockSamlResponse({
                            assertionId: '_shared-id',
                        }),
                        {
                            replayStore,
                        },
                    )
                ).success,
            );
        });

        it('passes the assertion expiry plus the clock skew to the store', async () => {
            const notOnOrAfter = fromNow({
                minutes: 3,
            });
            const calls: {assertionId: string; expiresAt: FullDate<UtcTimezone>}[] = [];

            await verify(
                createMockSamlResponse({
                    assertionId: '_expiry',
                    notOnOrAfter,
                }),
                {
                    replayStore: {
                        markAssertionUsed(params) {
                            calls.push(params);
                            return Promise.resolve(true);
                        },
                    },
                },
            );

            assert.deepEquals(calls, [
                {
                    assertionId: '_expiry',
                    expiresAt: calculateRelativeDate(notOnOrAfter, defaultSamlClockSkew),
                },
            ]);
        });
    });

    describe('malformed input', () => {
        it('rejects input that is not XML', async () => {
            await assertRejected(
                Buffer.from('not xml at all').toString('base64'),
                SamlVerifyFailureReason.Malformed,
            );
        });

        it('rejects a response with a DOCTYPE', async () => {
            const result = await verify(
                encodeSamlResponse(`<!DOCTYPE samlp:Response>${createMockSamlResponseXml()}`),
            );

            assert.isFalse(result.success);
            assert.strictEquals(result.reason, SamlVerifyFailureReason.Malformed);
            assert.isTrue(result.detail.includes('DOCTYPE'), result.detail);
        });

        it('reports an IdP error status', async () => {
            const xml = [
                `<samlp:Response xmlns:samlp="${protocolNamespace}" ID="_error" Version="2.0" IssueInstant="${getNowInIsoString()}">`,
                '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>',
                '<samlp:StatusMessage>MSIS7012: An error occurred</samlp:StatusMessage></samlp:Status>',
                '</samlp:Response>',
            ].join('');

            await assertRejected(encodeSamlResponse(xml), SamlVerifyFailureReason.IdpStatusError);
        });

        it('throws on invalid params', async () => {
            await assert.throws(
                () => {
                    return verify(createMockSamlResponse(), {
                        idp: {
                            entityId: 'x',
                            signingCertificates: [],
                        },
                    });
                },
                {
                    matchConstructor: SamlVerifyError,
                    matchMessage: 'certificate',
                },
            );
            await assert.throws(
                () => {
                    return verify(createMockSamlResponse(), {
                        idp: {
                            entityId: '',
                            signingCertificates: [mockIdpKeys.current.certificate],
                        },
                    });
                },
                {
                    matchMessage: 'An IdP entity ID is required.',
                },
            );
            await assert.throws(
                () => {
                    return verify(createMockSamlResponse(), {
                        spEntityId: '',
                    });
                },
                {
                    matchMessage: 'An SP entity ID is required.',
                },
            );
            await assert.throws(
                () => {
                    return verify(createMockSamlResponse(), {
                        acsUrl: '',
                    });
                },
                {
                    matchMessage: 'An ACS URL is required.',
                },
            );
            await assert.throws(
                () => {
                    return verify(createMockSamlResponse(), {
                        clockSkew: {
                            minutes: -1,
                        },
                    });
                },
                {
                    matchMessage: 'SAML clock skew cannot be negative.',
                },
            );
        });

        it('lets replay store errors propagate', async () => {
            await assert.throws(
                () => {
                    return verify(createMockSamlResponse(), {
                        replayStore: {
                            markAssertionUsed() {
                                throw new Error('database is down');
                            },
                        },
                    });
                },
                {
                    matchMessage: 'database is down',
                },
            );
        });
    });
});
