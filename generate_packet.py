import os
import socket
import struct
import zlib
from functools import partial

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_SOFTWARE_ATTRIBUTE = 0x8022
STUN_FINGERPRINT_ATTRIBUTE = 0x8028
QUIC_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
DEFAULT_SNI = "zoom.us"


def _padding_size(length: int) -> int:
    """Return the byte count needed to align a STUN value to four bytes."""
    return (4 - length % 4) % 4


def _encode_stun_attribute(attribute_type: int, value: bytes) -> bytes:
    """Encode a STUN attribute with its type, length, value, and padding."""
    padding = b"\x00" * _padding_size(len(value))
    return struct.pack(">HH", attribute_type, len(value)) + value + padding


def build_stun_packet(software: str) -> bytes:
    """Build a STUN binding request containing the supplied software identity."""
    transaction_id = os.urandom(12)
    attributes = _encode_stun_attribute(
        STUN_SOFTWARE_ATTRIBUTE,
        software.encode("utf-8"),
    )
    fingerprint_length = len(attributes) + 8
    fingerprint_header = struct.pack(
        ">HHI",
        STUN_BINDING_REQUEST,
        fingerprint_length,
        STUN_MAGIC_COOKIE,
    ) + transaction_id
    checksum = zlib.crc32(fingerprint_header + attributes) & 0xFFFFFFFF
    fingerprint = checksum ^ 0x5354554E
    attributes += _encode_stun_attribute(
        STUN_FINGERPRINT_ATTRIBUTE,
        struct.pack(">I", fingerprint),
    )
    header = struct.pack(
        ">HHI",
        STUN_BINDING_REQUEST,
        len(attributes),
        STUN_MAGIC_COOKIE,
    ) + transaction_id
    return header + attributes


def generate_stun_i1(
    software: str = "Zoom 5.16.10 (26186)",
) -> str:
    """Generate an I1 directive containing a STUN binding request packet."""
    packet = build_stun_packet(software)
    return f"I1 = <b 0x{packet.hex()}>"


def validate_stun_packet(packet: bytes) -> None:
    """Validate a STUN binding request and print its decoded protocol fields."""
    assert len(packet) >= 20, "Packet too short"
    message_type, message_length, magic_cookie = struct.unpack(">HHI", packet[:8])
    transaction_id = packet[8:20]

    assert message_type == STUN_BINDING_REQUEST, (
        f"Wrong message type: {message_type:#06x}"
    )
    assert magic_cookie == STUN_MAGIC_COOKIE, (
        f"Wrong magic cookie: {magic_cookie:#010x}"
    )
    assert packet[0] & 0xC0 == 0x00, "Top 2 bits must be 00"
    assert message_length == len(packet) - 20, "Length field mismatch"

    print("STUN Binding Request - VALID")
    print(f"Message Type: 0x{message_type:04X}")
    print(f"Message Length: {message_length} bytes")
    print(f"Magic Cookie: 0x{magic_cookie:08X}")
    print(f"Transaction ID: {transaction_id.hex().upper()}")
    print(f"Total Size: {len(packet)} bytes")

    offset = 20
    while offset < len(packet):
        attribute_type, attribute_length = struct.unpack(
            ">HH",
            packet[offset:offset + 4],
        )
        value_start = offset + 4
        value = packet[value_start:value_start + attribute_length]
        if attribute_type == STUN_SOFTWARE_ATTRIBUTE:
            print(f"SOFTWARE: {value.decode(errors='replace')}")
        elif attribute_type == STUN_FINGERPRINT_ATTRIBUTE:
            fingerprint = struct.unpack(">I", value)[0]
            print(f"FINGERPRINT: 0x{fingerprint:08X}")
        offset += 4 + attribute_length + _padding_size(attribute_length)


def _expand_hkdf_label(
    secret: bytes,
    label: str,
    context: bytes,
    length: int,
) -> bytes:
    """Expand TLS 1.3 key material using an HKDF label and context."""
    full_label = b"tls13 " + label.encode()
    hkdf_label = (
        struct.pack(">H", length)
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return HKDFExpand(
        algorithm=SHA256(),
        length=length,
        info=hkdf_label,
        backend=default_backend(),
    ).derive(secret)


def _derive_quic_keys(destination_id: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive the client key, IV, and header key for a QUIC Initial packet."""
    digest = HMAC(QUIC_INITIAL_SALT, SHA256(), backend=default_backend())
    digest.update(destination_id)
    initial_secret = digest.finalize()
    client_secret = _expand_hkdf_label(initial_secret, "client in", b"", 32)
    key = _expand_hkdf_label(client_secret, "quic key", b"", 16)
    iv = _expand_hkdf_label(client_secret, "quic iv", b"", 12)
    header_key = _expand_hkdf_label(client_secret, "quic hp", b"", 16)
    return key, iv, header_key


def _read_quic_varint(data: bytes | bytearray, offset: int) -> tuple[int, int]:
    """Decode a QUIC variable-length integer at an offset and return its size."""
    first_byte = data[offset]
    prefix = first_byte >> 6
    if prefix == 0:
        return first_byte & 0x3F, 1
    if prefix == 1:
        return struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF, 2
    if prefix == 2:
        return struct.unpack(">I", data[offset:offset + 4])[0] & 0x3FFFFFFF, 4
    return struct.unpack(">Q", data[offset:offset + 8])[0] & 0x3FFFFFFFFFFFFFFF, 8


def _encode_quic_varint(value: int) -> bytes:
    """Encode an integer using the QUIC variable-length integer format."""
    if value <= 0x3F:
        return bytes([value])
    if value <= 0x3FFF:
        return struct.pack(">H", value | 0x4000)
    if value <= 0x3FFFFFFF:
        return struct.pack(">I", value | 0x80000000)
    return struct.pack(">Q", value | 0xC000000000000000)


def capture_quic_packet(sni: str = DEFAULT_SNI) -> bytes:
    """Generate QUIC Initial packet for a request to the supplied domain."""
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        server_name=sni,
    )
    connection = QuicConnection(configuration=configuration)
    ip_address = socket.gethostbyname(sni)
    connection.connect((ip_address, 443), now=0.0)

    for data, _address in connection.datagrams_to_send(now=0.0):
        if data[0] & 0xF0 == 0xC0:
            return data
    raise RuntimeError("QUIC did not produce an initial packet")


def generate_obfuscated_quic_i1(initial_packet: bytes) -> bytes:
    """Rebuild a QUIC Initial packet with obfuscation intended to hinder DPI detection."""
    initial_packet = bytearray(initial_packet)

    destination_id_length = initial_packet[5]
    destination_id = bytes(initial_packet[6:6 + destination_id_length])
    source_id_offset = 6 + destination_id_length
    source_id_length = initial_packet[source_id_offset]
    token_length_offset = source_id_offset + 1 + source_id_length
    token_length, token_length_size = _read_quic_varint(
        initial_packet,
        token_length_offset,
    )
    token_offset = token_length_offset + token_length_size
    payload_length_offset = token_offset + token_length
    payload_length, payload_length_size = _read_quic_varint(
        initial_packet,
        payload_length_offset,
    )
    packet_number_offset = payload_length_offset + payload_length_size
    key, iv, header_key = _derive_quic_keys(destination_id)
    sample_offset = packet_number_offset + 4
    sample = bytes(initial_packet[sample_offset:sample_offset + 16])
    cipher = Cipher(
        algorithms.AES(header_key),
        modes.ECB(),
        backend=default_backend(),
    )
    mask = cipher.encryptor().update(sample)
    first_byte = initial_packet[0] ^ (mask[0] & 0x0F)
    packet_number_length = (first_byte & 0x03) + 1
    packet_number = bytearray(
        initial_packet[
            packet_number_offset:packet_number_offset + packet_number_length
        ]
    )
    for index in range(packet_number_length):
        packet_number[index] ^= mask[index + 1]

    encrypted_length = payload_length - packet_number_length
    encrypted_start = packet_number_offset + packet_number_length
    ciphertext = bytes(
        initial_packet[encrypted_start:encrypted_start + encrypted_length]
    )
    header = bytearray(initial_packet[:packet_number_offset])
    header[0] = first_byte
    authenticated_data = bytes(header) + bytes(packet_number)
    nonce = bytearray(iv)
    for index in range(packet_number_length):
        nonce[-packet_number_length + index] ^= packet_number[index]

    plaintext = AESGCM(key).decrypt(bytes(nonce), ciphertext, authenticated_data)
    target_length = 1200 - len(authenticated_data) - 16
    padding_length = target_length - len(plaintext)
    if padding_length > 0:
        plaintext += b"\x00" * padding_length

    new_payload_length = len(plaintext) + packet_number_length + 16
    encoded_length = _encode_quic_varint(new_payload_length)
    new_header = bytearray(header[:payload_length_offset]) + encoded_length
    new_authenticated_data = bytes(new_header) + bytes(packet_number)
    new_ciphertext = AESGCM(key).encrypt(
        bytes(nonce),
        plaintext,
        new_authenticated_data,
    )
    new_sample = new_ciphertext[
        4 - packet_number_length:20 - packet_number_length
    ]
    new_mask = cipher.encryptor().update(new_sample)
    masked_first_byte = new_header[0] ^ (new_mask[0] & 0x0F)
    masked_packet_number = bytearray(packet_number)
    for index in range(packet_number_length):
        masked_packet_number[index] ^= new_mask[index + 1]

    final_packet = (
        bytes([masked_first_byte])
        + bytes(new_header[1:])
        + bytes(masked_packet_number)
        + new_ciphertext
    )
    return final_packet


def get_quic_i1(obfuscated: bool = True, sni: str = DEFAULT_SNI) -> str:
    """Generate a captured or obfuscated QUIC I1 for a domain."""
    packet = capture_quic_packet(sni)
    if obfuscated:
        packet = generate_obfuscated_quic_i1(packet)
    return f"I1 = <b 0x{packet.hex()}>"


I1_GENERATORS = {
    "stun": generate_stun_i1,
    "quic-captured": partial(get_quic_i1, obfuscated=False),
    "quic-obfuscated": partial(get_quic_i1, obfuscated=True),
}
