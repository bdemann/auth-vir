// cspell:words dsig
import {DOMParser, type Element, MIME_TYPE, type Node} from '@xmldom/xmldom';

/**
 * XML namespaces used by SAML 2.0 messages and metadata.
 *
 * @category Internal
 */
export enum SamlNamespace {
    Assertion = 'urn:oasis:names:tc:SAML:2.0:assertion',
    Protocol = 'urn:oasis:names:tc:SAML:2.0:protocol',
    Metadata = 'urn:oasis:names:tc:SAML:2.0:metadata',
    XmlDsig = 'http://www.w3.org/2000/09/xmldsig#',
}

const elementNodeType = 1;

/**
 * Parse an XML string strictly: any parser warning or error is thrown instead of being silently
 * recovered from. Documents with a DOCTYPE are rejected because SAML never needs one and they are
 * the entry point for entity expansion attacks.
 *
 * @category Internal
 */
export function parseStrictXml(xml: string): Element {
    if (/<!DOCTYPE/i.test(xml)) {
        throw new Error('XML with a DOCTYPE is not allowed.');
    }

    const document = new DOMParser({
        onError(level, message) {
            throw new Error(`Invalid XML (${level}): ${message}`);
        },
    }).parseFromString(xml, MIME_TYPE.XML_TEXT);

    if (!document.documentElement) {
        throw new Error('XML has no root element.');
    }

    return document.documentElement;
}

/**
 * Checks if the given element has the given namespace and local name.
 *
 * @category Internal
 */
export function isXmlElement(
    node: Readonly<Node> | null | undefined,
    namespace: SamlNamespace,
    localName: string,
): node is Element {
    return (
        node?.nodeType === elementNodeType &&
        (node as Element).namespaceURI === namespace &&
        (node as Element).localName === localName
    );
}

/**
 * All direct children of `parent` with the given namespace and local name.
 *
 * @category Internal
 */
export function getChildElements(
    parent: Readonly<Element>,
    namespace: SamlNamespace,
    localName: string,
): Element[] {
    return Array.from(parent.childNodes).filter((child): child is Element => {
        return isXmlElement(child, namespace, localName);
    });
}

/**
 * The single direct child of `parent` with the given namespace and local name. Returns `undefined`
 * when there is none and throws when there is more than one, since duplicates of single-valued SAML
 * elements are a sign of tampering.
 *
 * @category Internal
 */
export function getOnlyChildElement(
    parent: Readonly<Element>,
    namespace: SamlNamespace,
    localName: string,
): Element | undefined {
    const children = getChildElements(parent, namespace, localName);

    if (children.length > 1) {
        throw new Error(
            `Expected at most one '${localName}' element but found ${children.length}.`,
        );
    }

    return children[0];
}

/**
 * The text of an element with comments removed. (Comments are not part of the signed content, so
 * reading only the first text node would allow comment-truncation attacks.)
 *
 * @category Internal
 */
export function getElementText(element: Readonly<Element>): string {
    return (element.textContent || '').trim();
}

/**
 * Reads an attribute, treating a missing or empty attribute as `undefined`.
 *
 * @category Internal
 */
export function getAttribute(element: Readonly<Element>, name: string): string | undefined {
    return element.getAttribute(name) || undefined;
}
