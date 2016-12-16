# -*- coding: utf-8 -*-
#
# X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP
# 
# ASN.1 source from
# https://tools.ietf.org/html/rfc6960
#
from pyasn1.type import (univ, namedtype, tag, namedval, useful)
from pyasn1_modules import rfc2459


class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0)
    )


class CertID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('issuerNameHash', univ.OctetString()),
        namedtype.NamedType('issuerKeyHash', univ.OctetString()),
        namedtype.NamedType('serialNumber', rfc2459.CertificateSerialNumber()))


class Request(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('reqCert', CertID()),
        namedtype.OptionalNamedType(
            'singleRequestExtensions',
            rfc2459.Extensions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple,
                                    0))))


class TBSRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType(
            'version', Version(0).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                                    0))),
        namedtype.OptionalNamedType(
            'requestorName',
            rfc2459.GeneralName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple,
                                    1)
            )),
        namedtype.NamedType('requestList',
                            univ.SequenceOf(componentType=Request())),
        namedtype.OptionalNamedType(
            'requestExtensions',
            rfc2459.Extensions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple,
                                    2)
            ))
    )


class Certs(univ.SequenceOf):
    componentType = rfc2459.Certificate()


class Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signatureAlgorithm',
                            rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('signature', univ.BitString()),
        namedtype.NamedType(
            'certs', Certs().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        )
    )


class OCSPRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsRequest', TBSRequest()),
        namedtype.OptionalNamedType(
            'optionalSignature', Signature().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                                    0)))
    )


# OCSP Response
class OCSPResponseStatus(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('successful', 0),
        ('malformedRequest', 1),
        ('internalError', 2),
        ('tryLater', 3),
        # ('not-used', 4),
        ('sigRequired', 5),
        ('unauthorized', 6)
    )


class ResponseBytes(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('responseType', univ.ObjectIdentifier()),
        namedtype.NamedType('response', univ.OctetString())
    )


class OCSPResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('responseStatus', OCSPResponseStatus()),
        namedtype.OptionalNamedType('responseBytes', ResponseBytes().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ))
    )


KeyHash = univ.OctetString
UnknownInfo = univ.Null


class RevokedInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('revocationTime', useful.GeneralizedTime()),
        namedtype.OptionalNamedType(
            'revocationReason',
            rfc2459.CRLReason().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple,
                                    0)
            ))
    )


class CertStatus(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('good', univ.Null().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.NamedType('revoked', RevokedInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
        namedtype.NamedType('unknown', UnknownInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ))
    )


class SingleResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certID', CertID()),
        namedtype.NamedType('certStatus', CertStatus()),
        namedtype.NamedType('thisUpdate', useful.GeneralizedTime()),
        namedtype.OptionalNamedType(
            'nextUpdate',
            useful.GeneralizedTime().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple,
                                    0)
            )),
        namedtype.OptionalNamedType(
            'singleExtensions',
            rfc2459.Extensions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple,
                                    2)
            ))
    )


class ResponderID(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('byName', rfc2459.Name().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('byKey', KeyHash().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    )


class ResponseData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', Version(0).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('responderID', ResponderID()),
        namedtype.NamedType('producedAt', useful.GeneralizedTime()),
        namedtype.NamedType('responses',
                            univ.SequenceOf(componentType=SingleResponse())),
        namedtype.OptionalNamedType(
            'responseExtensions',
            rfc2459.Extensions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext,
                                    tag.tagFormatSimple,
                                    1)
            ))
    )


class BasicOCSPResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsResponseData', ResponseData()),
        namedtype.NamedType('signatureAlgorithm',
                            rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('signature', univ.BitString()),
        namedtype.OptionalNamedType('certs', Certs().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ))
    )

