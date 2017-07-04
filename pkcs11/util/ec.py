"""
Key handling utilities for EC keys (ANSI X.62/RFC3279).
"""

from asn1crypto.keys import (
    ECDomainParameters,
    ECPrivateKey,
    NamedCurve,
    PublicKeyInfo,
)

from ..constants import Attribute, ObjectClass
from ..mechanisms import KeyType


def encode_named_curve_parameters(oid):
    """
    Return DER-encoded ANSI X.62 EC parameters for a named curve.

    Curve names are given by object identifier and can be found in
    :mod:`pyasn1_modules.rfc3279`.

    :param str curve: named curve
    :rtype: bytes
    """
    return ECDomainParameters(
        name='named',
        value=NamedCurve.unmap(oid),
    ).dump()


def decode_ec_public_key(der):
    """
    Decode a DER-encoded EC public key as stored by OpenSSL into a dictionary
    of attributes able to be passed to :meth:`pkcs11.Session.create_object`.

    :param bytes der: DER-encoded key
    :rtype: dict(Attribute,*)
    """
    asn1 = PublicKeyInfo.load(der)

    assert asn1.algorithm == 'ec', \
        "Wrong algorithm, not an EC key!"

    return {
        Attribute.KEY_TYPE: KeyType.EC,
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.EC_PARAMS: asn1['algorithm']['parameters'].dump(),
        Attribute.EC_POINT: asn1['public_key'],
    }


def decode_ec_private_key(der):
    """
    Decode a DER-encoded EC private key as stored by OpenSSL into a dictionary
    of attributes able to be passed to :meth:`pkcs11.Session.create_object`.

    :param bytes der: DER-encoded key
    :rtype: dict(Attribute,*)
    """

    asn1 = ECPrivateKey.load(der)

    return {
        Attribute.KEY_TYPE: KeyType.EC,
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.EC_PARAMS: asn1['parameters'].dump(),
        Attribute.VALUE: asn1['private_key'],
    }


def encode_ec_public_key(key):
    """
    Encode a DER-encoded EC public key as stored by OpenSSL.

    :param PublicKey key: RSA public key
    :rtype: bytes
    """

    return PublicKeyInfo({
        'algorithm': {
            'algorithm': 'ec',
            'parameters': ECDomainParameters.load(key[Attribute.EC_PARAMS]),
        },
        'public_key': key[Attribute.EC_POINT],
    }).dump()
