#/*
# * Rapid Analysis QEMU System Emulator
# *
# * Copyright (c) 2020 Cromulence LLC
# *
# * Distribution Statement A
# *
# * Approved for Public Release, Distribution Unlimited
# *
# * Authors:
# *  Adam Critchley
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

import abc
import sys
import struct
import socket
import binascii
from pyqemu.netdefs import *

def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    idx = 0
    csum = 0
    hdr_size = len(pkt)
    while idx < hdr_size:
        csum += (pkt[idx] << 8) + pkt[idx+1]
        idx += 2
    while csum >> 16:
        csum = (csum & 0xFFFF) + ((csum & 0xFFFF0000) >> 16)
    return (~csum & 0xFFFF)

def in4_chksum(proto, u, p):
    """
    As Specified in RFC 2460 - 8.1 Upper-Layer Checksums

    Performs IPv4 Upper Layer checksum computation. Provided parameters are:
    - 'proto' : value of upper layer protocol
    - 'u'  : IP upper layer instance
    - 'p'  : the payload of the upper layer provided as a string
    """
    if not isinstance(u, IP):
        raise TypeError("No IP underlayer to compute checksum. Leaving null.")
    psdhdr = struct.pack("!4s4sHH",
                         socket.inet_pton(socket.AF_INET, str(u.src)),
                         socket.inet_pton(socket.AF_INET, str(u.dst)),
                         proto,
                         len(p))
    return checksum(psdhdr + p)

def ip2str(ip):
    return b"".join(chr(int(x, 10)) for x in str(ip).split('.'))

def str2ip(s):
    if isinstance(s, str):
        return ("%d." * 4)[:-1] % tuple(map(ord, s))
    return ("%d." * 4)[:-1] % tuple(s)

def ip62str(ip):
    return socket.inet_pton(socket.AF_INET6, ip)

def str2ip6(s):
    return socket.inet_ntop(socket.AF_INET6, s)

def mac2str(mac):
    return b"".join(chr(int(x, 16)) for x in str(mac).split(':'))

def str2mac(s):
    if isinstance(s, str):
        return ("%02x:" * 6)[:-1] % tuple(map(ord, s))
    return ("%02x:" * 6)[:-1] % tuple(s)

# def uuid2str(uuid):
#     return b"".join(chr(int(x, 16)) for x in ''.join(str(uuid).split('-')))

# def str2uuid(s):
#     if isinstance(s, str):
#         return ("%d" * 4)[:-1] % tuple(map(ord, s))
    
#     return ("%d" * 4)[:-1] % tuple(s)

class FieldStorage(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def grow_bytes(self, fv, size, fill):
        raise NotImplementedError("grow() needs to be implemented")

    @abc.abstractmethod
    def shrink_bytes(self, fv, size):
        raise NotImplementedError("shrink() needs to be implemented")

    @abc.abstractmethod
    def replace_bytes(self, fv, barray):
        raise NotImplementedError("replace_bytes() needs to be implemented")

    @abc.abstractmethod
    def get_bytes(self, fv):
        raise NotImplementedError("get_bytes() needs to be implemented")

    @abc.abstractmethod
    def size_bytes(self):
        raise NotImplementedError("size_bytes() needs to be implemented")

class FieldValue(object):
    def __init__(self, offset, size, storage):
        if not isinstance(storage, FieldStorage):
            raise TypeError("Storage provided is not FieldStorage")
        self.offset = offset
        self.size = size
        self.storage = storage

    def get_size(self):
        return self.size

    def get_offset(self):
        return self.offset

    def adjust_offset(self, a):
        self.offset += a

    def shrink_size(self, size):
        self.size -= size

    def grow_size(self, size):
        self.size += size

    def __call__(self, v):
        if isinstance(v, FieldValue):
            v = bytes(v)
        elif not isinstance(v, (bytearray, bytes)):
            raise TypeError
        # Dynamically change the packet size when necessary, this shouldn't happen that often.
        new_size = len(v)
        if new_size < self.size:
            self.storage.shrink_bytes(self, self.size - new_size)
            self.size = new_size
        elif new_size > self.size:
            self.storage.grow_bytes(self, new_size - self.size)
            self.size = new_size
        # Put the new data in the packet
        self.storage.replace_bytes(self, v)

    def __bytes__(self):
        return self.storage.get_bytes(self)

class Field(object):
    def __init__(self, name, default, fmt="H"):
        self.name = name
        self.default = default
        if fmt:
            if fmt[0] in "@=<>!":
                self.fmt = fmt
            else:
                self.fmt = "!" + fmt
        else:
            self.fmt = None
        self.field_value = None
        self.packet = None
        self.size = 0

    def get_name(self):
        return self.name

    def contains_field(self, fv):
        return (self.field_value == fv)

    def get_offset(self):
        return self.field_value.get_offset()

    def adjust_offset(self, fv, a):
        self.field_value.adjust_offset(a)

    def get_usedsize(self):
        return self.size

    def get_defaultsize(self):
        if self.fmt:
            return struct.calcsize(self.fmt)
        elif isinstance(self.default, (bytearray, bytes, str)):
            return len(self.default)
        return 0

    def reset(self):
        if self.default is not None:
            self(self.default)

    def is_shrinking(self, fv, size):
        self.size -= size

    def is_growing(self, fv, size):
        self.size += size

    def register(self, offset, packet):
        # Keep the packet around for subtype use
        self.packet = packet
        # packet.bit_offset = bit offset from last complete byte
        # Was this the bit group we left off on?
        if packet.bit_offset != 0:
            # Reset the byte alignment (adds implicit padding to last bit group)
            packet.bit_offset = 0
            offset += 1
        if self.field_value is None:
            # Get a default size to use for pre-allocation
            field_size = self.get_defaultsize()
            # Assign a set of bytes from the packet to this field
            self.field_value = FieldValue(offset, field_size, packet)
            # Attempt to pre-allocate space for this field
            packet.grow_bytes(self.field_value, field_size)
            # This is a new field so set it to the default value
            self.reset()
        else:
            # Make a new field with offset and packet registration
            self.size = 0
            old_field = self.field_value
            field_size = old_field.get_size()
            self.field_value = FieldValue(offset, field_size, packet)
            # Pre-alloc space for the field
            packet.grow_bytes(self.field_value, field_size)
            # Copy the field data to the new field
            self.field_value(old_field)
        return self.size

    def resize(self, value):
        # By default, an object's capacity cannot be changed
        pass

    def realloc(self, value):
        # By default, an object's allocation cannot be changed
        pass

    def __call__(self, value):
        if isinstance(value, Field):
            value = value.raw()
            self.field_value(value)
        elif self.fmt:
            if isinstance(value, list):
                self.field_value(struct.pack(self.fmt, *value))
            else:
                self.field_value(struct.pack(self.fmt, value))
        else:
            self.field_value(value)

    def __getitem__(self, key):
        if self.fmt:
            return struct.unpack(self.fmt, bytes(self.field_value))[key]
        return self.field_value[key]

    def __bytes__(self):
        return bytes(self.field_value)
    
    def __mul__(self, t):
        return [Field.make_default(self.__class__) for _ in range(0, t)]
    
    def __eq__(self, v):
        if isinstance(v, str):
            return str(self) == v
        elif isinstance(v, int):
            return int(self) == v
        return self.raw() == v

    def __ne__(self, v):
        if isinstance(v, str):
            return str(self) != v
        elif isinstance(v, int):
            return int(self) != v
        return self.raw() != v

    def raw(self):
        return bytes(self.field_value)
    
    @staticmethod
    def make_default(klass):
        try:
            return klass()
        except:
            try:
                return klass(None, None)
            except:
                return None

class UUIDField(Field):
    def __init__(self, name, default=None):
        super(UUIDField, self).__init__(name, default, "16s")

    def __str__(self):
        return str2uuid(self[0])

    def __call__(self, value):
        super(UUIDField, self).__call__(uuid2str(value))

class IPField(Field):
    def __init__(self, name, default=None):
        super(IPField, self).__init__(name, default, "4s")

    def __str__(self):
        return str2ip(self[0])

    def __call__(self, value):
        super(IPField, self).__call__(ip2str(value))

class IP6Field(Field):
    def __init__(self, name, default=None):
        super(IP6Field, self).__init__(name, default, "16s")

    def __str__(self):
        return str2ip6(self[0])

    def __call__(self, value):
        super(IP6Field, self).__call__(ip62str(value))

class DestIPField(IPField):
    def __init__(self, name, default="255.255.255.255"):
        super(DestIPField, self).__init__(name, default)

class SourceIPField(IPField):
    def __init__(self, name, default="0.0.0.0"):
        super(SourceIPField, self).__init__(name, default)

class DestIP6Field(IP6Field):
    def __init__(self, name, default="::"):
        super(DestIP6Field, self).__init__(name, default)

class SourceIP6Field(IP6Field):
    def __init__(self, name, default="::1"):
        super(SourceIP6Field, self).__init__(name, default)

class MACField(Field):
    def __init__(self, name, default=None):
        super(MACField, self).__init__(name, default, "6s")

    def __str__(self):
        return str2mac(self[0])

    def __call__(self, value):
        super(MACField, self).__call__(mac2str(value))

class DestMACField(MACField):
    def __init__(self, name):
        super(DestMACField, self).__init__(name, "ff:ff:ff:ff:ff:ff")

class SourceMACField(MACField):
    def __init__(self, name):
        super(SourceMACField, self).__init__(name, "00:00:00:00:00:00")

class StrField(Field):
    def __init__(self, name, default):
        super(StrField, self).__init__(name, default, None)

    def resize(self, value):
        if value > self.size:
            grow_size = value - self.size
            self.field_value.grow_size(grow_size)
            self.packet.grow_bytes(self.field_value, grow_size)
        elif value < self.size:
            shrink_size = self.size - value
            self.field_value.shrink_size(shrink_size)
            self.packet.shrink_bytes(self.field_value, shrink_size)
    
    realloc = resize

    def __str__(self):
        return super(StrField, self).__bytes__()

    def __len__(self):
        return self.get_usedsize()

    def __call__(self, value):
        super(StrField, self).__call__(bytes(value))

class XStrField(StrField):
    def __init__(self, name, default):
        super(XStrField, self).__init__(name, default)

    def __str__(self):
        return binascii.hexlify(super(XStrField, self).__str__())

class StrFixedLenField(Field):
    def __init__(self, name, default, size):
        if default is not None and len(default) != size:
            raise ValueError("StrFixedLenField needs a default value with an expected length")
        super(StrFixedLenField, self).__init__(name, default, "%ds"%(size))

    def __str__(self):
        return str(bytes(self[0]))

    def __len__(self):
        return self.get_usedsize()

    def __call__(self, value):
        if len(value) != self.get_defaultsize():
            raise ValueError("StrFixedLenField needs a value with an expected length")
        super(StrFixedLenField, self).__call__(value)

class ByteField(Field):
    def __init__(self, name, default):
        super(ByteField, self).__init__(name, default, "B")

    def __str__(self):
        return chr(self[0])

    def __call__(self, value):
        super(ByteField, self).__call__(ord(value))

class OctetField(Field):
    def __init__(self, name, default):
        super(OctetField, self).__init__(name, default, "B")

    def __int__(self):
        return self[0]

    def __str__(self):
        return str(int(self))

    def __call__(self, value):
        super(OctetField, self).__call__(value)

class XOctetField(Field):
    def __init__(self, name, default):
        super(XOctetField, self).__init__(name, default)

    def __str__(self):
        return hex(int(self))

class ShortField(Field):
    def __init__(self, name, default):
        super(ShortField, self).__init__(name, default, "H")

    def __int__(self):
        return self[0]

    def __str__(self):
        return str(self[0])

class XShortField(ShortField):
    def __init__(self, name, default):
        super(XShortField, self).__init__(name, default)

    def __str__(self):
        return hex(int(self))

class IntField(Field):
    def __init__(self, name, default):
        super(IntField, self).__init__(name, default, "I")

    def __int__(self):
        return self[0]

    def __str__(self):
        return str(self[0])

class SignedIntField(Field):
    def __init__(self, name, default):
        super(SignedIntField, self).__init__(name, default, "i")

    def __int__(self):
        return self[0]

    def __str__(self):
        return str(self[0])

class XIntField(Field):
    def __init__(self, name, default):
        super(XIntField, self).__init__(name, default)

    def __str__(self):
        return hex(int(self))

class LongField(Field):
    def __init__(self, name, default):
        super(LongField, self).__init__(name, default, "Q")

    def __long__(self):
        return self[0]

    def __str__(self):
        return str(self[0])

class XLongFieldField(Field):
    def __init__(self, name, default):
        super(XLongFieldField, self).__init__(name, default)

    def __str__(self):
        return hex(long(self))

class SignedLongField(Field):
    def __init__(self, name, default):
        super(SignedLongField, self).__init__(name, default, "q")

    def __long__(self):
        return self[0]

    def __str__(self):
        return str(self[0])

class BitField(Field):
    def __init__(self, name, default, size):
        # Sanity check the values.
        if size == 0 or default >= (1 << size):
            raise ValueError
        self.bsize = size
        self.bmask = 0
        self.bshift = 0
        self.eshift = 0
        super(BitField, self).__init__(name, default, None)

    def adjust_offset(self, fv, a):
        # Special case for bitfields, shared offsets of bitfields must not be adjusted.
        if fv.get_offset() < self.field_value.get_offset():
            super(BitField, self).adjust_offset(fv, a)

    def register(self, offset, packet):
        def create_byte_mask(bits):
            return sum([bits[i] * (1 << i) for i in range(0, 8)])

        # If we're transferring registration, get the old value first...
        old_value = None
        if self.field_value is not None:
            old_value = int(self)
        # Now proceed with the registration
        self.packet = packet
        bit_size = packet.bit_offset + self.bsize
        byte_size = int(bit_size / 8)
        last_bits = bit_size & 7
        last_pad = (8 - last_bits) & 7
        self.bshift = last_pad
        self.eshift = packet.bit_offset
        bits = [0] * self.bshift + [1] * self.bsize + [0] * self.eshift
        self.bmask = [create_byte_mask(bits[i:i + 8]) for i in range(0, len(bits), 8)]
        # Are we starting from a new bit group or an aligned bit group?
        if packet.bit_offset == 0:
            alloc_size = int((bit_size + 7) / 8)
        else:
            alloc_size = int((bit_size + 7) / 8) - 1
        packet.bit_offset = last_bits
        # How many bytes did we span with this bit field?
        byte_span = byte_size if byte_size > 0 else 1
        # Create the backing storage
        self.field_value = FieldValue(offset, byte_span, packet)
        # Do we need to allocate more bytes?
        self.size = alloc_size
        if alloc_size > 0:
            packet.grow_bytes(self.field_value, alloc_size)
        # Is this a registration transfer?
        if old_value is None:
            # Nope, just reset to the default value
            self.reset()
        else:
            # Copy the field data to the new field
            self(old_value)
        return byte_size

    def __int__(self):
        barray = super(BitField, self).__bytes__()
        iarray = list(barray)
        value = sum([(self.bmask[i] & iarray[i]) << (i * 8) for i in range(0, len(iarray))]) >> self.bshift
        return value

    def __str__(self):
        return str(int(self))

    def __call__(self, value):
        if not isinstance(value, int):
            raise TypeError
        elif value >= (1 << self.bsize):
            raise ValueError
        barray = super(BitField, self).__bytes__()
        iarray = list(barray)
        value <<= self.bshift
        varray = []
        varray.append(value & 0xFF)
        while value:
            value >>= 8
            varray.append(value & 0xFF)
        varray += [0] * (len(iarray) - len(varray))
        vbytes = bytes([((iarray[i] & ~self.bmask[i]) | varray[i]) for i in range(0, len(iarray))])
        super(BitField, self).__call__(vbytes)

    def raw(self):
        # This raw() returns our contents as byte aligned of course...
        barray = super(BitField, self).__bytes__()
        iarray = list(barray)
        return bytes(b''.join([chr(self.bmask[i] & iarray[i]) for i in range(0, len(iarray))]))

class FlagsField(BitField):
    def __init__(self, name, default, bsize, flags):
        self.flags = flags
        super(FlagsField, self).__init__(name, default, bsize)

    def __call__(self, value):
        if isinstance(value, str):
            value = [v.strip() for v in value.split('+')]

        if isinstance(value, list):
            y = 0
            for i in value:
                y |= 1 << self.flags.index(i)
            value = y
        elif not isinstance(value, int):
            raise TypeError
        super(FlagsField, self).__call__(value)

    def __int__(self):
        return super(FlagsField, self).__int__()

    def __str__(self):
        value = ""
        y = int(self)
        for i in self.flags:
            if y & (1 << self.flags.index(i)):
                value += i + "+"
        if value:
            value = value [:-1]
        return value

class EnumField(Field):
    def __init__(self, name, default, enums, fmt="H"):
        self.enums = enums
        super(EnumField, self).__init__(name, default, fmt)

    def __call__(self, value):
        if isinstance(value, str):
            try:
                value = next(k for k, v in self.enums.items() if v == value)
            except StopIteration:
                raise ValueError("Unable to set field %s to value %s" % (self.name, value))
        super(EnumField, self).__call__(value)

    def __int__(self):
        return self[0]

    def __str__(self):
        v = int(self)
        try:
            return self.enums[v]
        except KeyError:
            return str(v)

class OctetEnumField(EnumField):
    def __init__(self, name, default, enums):
        super(OctetEnumField, self).__init__(name, default, enums, "B")

    def __call__(self, value):
        super(OctetEnumField, self).__call__(value)

    def __int__(self):
        return self[0]

class XOctetEnumField(OctetEnumField):
    def __init__(self, name, default, enums):
        super(XOctetEnumField, self).__init__(name, default, enums)

    def __str__(self):
        return hex(int(self))

class ShortEnumField(EnumField):
    def __init__(self, name, default, enums):
        super(ShortEnumField, self).__init__(name, default, enums, "H")

class XShortEnumField(ShortEnumField):
    def __init__(self, name, default, enums):
        super(XShortEnumField, self).__init__(name, default, enums)

    def __str__(self):
        return hex(int(self))

class IntEnumField(EnumField):
    def __init__(self, name, default, enums):
        super(IntEnumField, self).__init__(name, default, enums, "I")

class XIntEnumField(IntEnumField):
    def __init__(self, name, default, enums):
        super(XIntEnumField, self).__init__(name, default, enums)

    def __str__(self):
        return hex(int(self))

class BitEnumField(BitField):
    def __init__(self, name, default, size, enums):
        self.enums = enums
        super(BitEnumField, self).__init__(name, default, size)

    def __call__(self, value):
        if isinstance(value, str):
            try:
                value = next(k for k, v in self.enums.items() if v == value)
            except StopIteration:
                raise ValueError
        elif not isinstance(value, int):
            raise TypeError
        elif value not in self.enums.keys():
            raise ValueError
        super(BitEnumField, self).__call__(value)

    def __str__(self):
        v = int(self)
        try:
            return self.enums[v]
        except KeyError:
            return str(v)

class FieldListField(Field):
    def __init__(self, name, default=[], field_klass=Field):
        self.klass = field_klass
        self.end_offset = 0
        self.fields = []
        super(FieldListField, self).__init__(name, default, None)

    def contains_field(self, fv):
        if super(FieldListField, self).contains_field(fv):
            return True
        for f in self.fields:
            if f.contains_field(fv):
                return True
        return False

    def adjust_offset(self, fv, a):
        super(FieldListField, self).adjust_offset(fv, a)
        for f in self.fields:
            f.adjust_offset(fv, a)

    def get_defaultsize(self):
        total = 0
        for f in self.fields:
            total += f.get_defaultsize()
        return total

    def is_shrinking(self, fv, size):
        pos = fv.get_offset()
        super(FieldListField, self).is_shrinking(fv, size)
        # Are we shrinking ourselves?
        if super(FieldListField, self).contains_field(fv):
            self.field_value.shrink_size(size)
        for f in self.fields:
            if f.contains_field(fv):
                f.is_shrinking(fv, size)
            elif f.get_offset() >= pos:
                f.adjust_offset(fv, -size)

    def is_growing(self, fv, size):
        pos = fv.get_offset()
        super(FieldListField, self).is_growing(fv, size)
        # Are we growing ourselves?
        if super(FieldListField, self).contains_field(fv):
            self.field_value.grow_size(size)
        for f in self.fields:
            if f.contains_field(fv):
                f.is_growing(fv, size)
            elif f.get_offset() >= pos:
                f.adjust_offset(fv, size)

    def realloc(self, value):
        offset = self.field_value.get_offset()

        # Remove the old fields
        del self.fields
        self.fields = []

        # Now we can safely remove the space for the old fields.
        self.packet.shrink_bytes(self.field_value, self.size)

        # Create and register the new fields
        try:
            default_size = Field.make_default(self.klass).get_defaultsize()
        except:
            raise NotImplementedError("Class %s does not have a standard constructor and does not support realloc()"%self.klass)

        if default_size > 0:
            num_fields = value // default_size
            for _ in range(0, num_fields):
                f = Field.make_default(self.klass)
                self.fields.append(f)
                offset += f.register(offset, self.packet)
            self.end_offset = offset
        else:
            raise NotImplementedError("Class %s has a dynamic size and does not support realloc()"%self.klass)

    def resize(self, value):
        offset = self.field_value.get_offset()

        # Remove the old fields
        del self.fields
        self.fields = []

        # Now we can safely remove the space for the old fields.
        self.packet.shrink_bytes(self.field_value, self.size)

        # Create and register the new fields
        for _ in range(0, value):
            f = Field.make_default(self.klass)
            if f is None:
                raise NotImplementedError("Class %s does not have a standard constructor and does not support resize()"%self.klass)

            self.fields.append(f)
            offset += f.register(offset, self.packet)
        self.end_offset = offset

    def register(self, offset, packet):
        super(FieldListField, self).register(offset, packet)
        eoffset = offset
        # Register all the fields as well
        for f in self.fields:
            size = f.register(eoffset, packet)
            eoffset += size
        return (eoffset - offset)

    def __call__(self, value):
        if isinstance(value, (FieldListField, list)):
            offset = self.field_value.get_offset()
            # Remove the old fields
            del self.fields
            self.fields = []
            # Now we can safely remove the space for the old fields.
            self.packet.shrink_bytes(self.field_value, self.size)
            # Create and register the new fields
            for v in value:
                if isinstance(v, self.klass):
                    f = v
                elif isinstance(v, dict):
                    f = self.klass(None, **v)
                else:
                    f = self.klass(None, v)

                self.fields.append(f)
                offset += f.register(offset, self.packet)
            self.end_offset = offset
        else:
            # Don't know how to handle it...
            raise TypeError("FieldListField needs to be a list of field types, dicts, or values")
    
    def append(self, value):
        if isinstance(value, (self.klass, dict)):
            value = [value]
        elif not isinstance(value, list):
            raise TypeError("FieldListField needs to be a list of field types, dicts, or values")
        offset = self.end_offset
        for v in value:
            if isinstance(v, self.klass):
                f = v
            elif isinstance(v, dict):
                f = self.klass(None, **v)
            else:
                f = self.klass(None, v)
            self.fields.append(f)
            offset += f.register(offset, self.packet)
        self.end_offset = offset

    def __getitem__(self, key):
        if isinstance(key, str):
            for f in self.fields:
                if f.get_name() == key:
                    return f
            raise KeyError
        return self.fields[key]

    def __len__(self):
        return len(self.fields)

    def __str__(self):
        s = '['
        for f in self.fields:
            s += str(f) + ', '
        if len(s) > 1:
            s = s[:-2]
        s += ']'
        return s

    def __iter__(self):
        return iter(self.fields) 

class FieldStructField(Field):

    def __init__(self, name, fields, **kwargs):
        self.definition = fields
        # We'll add the fields as they're registered.
        self.fields = []
        super(FieldStructField, self).__init__(name, kwargs, None)

    def reset(self):
        for f in self.fields:
            f.reset()
        super(FieldStructField, self).reset()

    def contains_field(self, fv):
        if super(FieldStructField, self).contains_field(fv):
            return True
        for f in self.fields:
            if f.contains_field(fv):
                return True
        return False

    def adjust_offset(self, fv, a):
        super(FieldStructField, self).adjust_offset(fv, a)
        for f in self.fields:
            f.adjust_offset(fv, a)

    def get_defaultsize(self):
        total = 0
        for f in self.fields:
            total += f.get_defaultsize()
        return total

    def is_shrinking(self, fv, size):
        pos = fv.get_offset()
        super(FieldStructField, self).is_shrinking(fv, size)
        # Are we shrinking ourselves?
        if super(FieldStructField, self).contains_field(fv):
            self.field_value.shrink_size(size)
        for f in self.fields:
            if f.contains_field(fv):
                f.is_shrinking(fv, size)
            elif f.get_offset() >= pos:
                f.adjust_offset(fv, -size)

    def is_growing(self, fv, size):
        pos = fv.get_offset()
        super(FieldStructField, self).is_growing(fv, size)
        # Are we growing ourselves?
        if super(FieldStructField, self).contains_field(fv):
            self.field_value.grow_size(size)
        for f in self.fields:
            if f.contains_field(fv):
                f.is_growing(fv, size)
            elif f.get_offset() >= pos:
                f.adjust_offset(fv, size)

    def register(self, offset, packet):
        # If we're transferring registration, get the old value first...
        old_value = None
        if self.field_value is not None:
            old_value = self.raw()
        super(FieldStructField, self).register(offset, packet)
        eoffset = offset
        del self.fields
        self.fields = []
        for f in self.definition:
            self.fields.append(f)
            size = f.register(eoffset, packet)
            eoffset += size
        # Is this a registration transfer?
        if old_value is None:
            # Nope, just reset to the default value
            self.reset()
        else:
            # Copy the field data to the new field
            self(old_value)
        return (eoffset - offset)

    def __call__(self, value):
        if isinstance(value, list):
            for fv in value:
                if not isinstance(fv, Field):
                    raise TypeError("FieldStructField needs the list contents to all be of type Field")
                try:
                    self[fv.get_name()](fv)
                except KeyError:
                    pass
        elif isinstance(value, tuple):
            for i, v in enumerate(value):
                self.fields[i](v)
        elif isinstance(value, dict):
            for k, v in value.items():
                for f in self.fields:
                    if f.get_name() == k:
                        f(v)
        else:
            super(FieldStructField, self).__call__(value)

    def __getitem__(self, key):
        for f in self.fields:
            if f.get_name() == key:
                return f
        raise KeyError
    
    def __len__(self):
        return len(self.fields)

    def __str__(self):
        s = '('
        for f in self.fields:
            if f.name:
                s += f.name + "="
            s += str(f) + ', '
        if len(s) > 1:
            s = s[:-2]
        s += ')'
        return s

class FieldLenField(Field):

    def __init__(self, name, default, fmt="H",
                length_of=None, count_of=None, size_of=None,
                adjust=lambda pkt, x: x, deadjust=lambda pkt, x: x):
        super(FieldLenField, self).__init__(name, default, fmt)
        if length_of is not None and count_of is None and size_of is None:
            self.get_value = len
            self.field_obj = length_of
            self.debuild_size = self.field_obj.resize
        elif count_of is not None and length_of is None and size_of is None:
            self.get_value = int
            self.field_obj = count_of
            self.debuild_size = self.field_obj.realloc
        elif size_of is not None and length_of is None and count_of is None:
            self.get_value = Field.get_usedsize
            self.field_obj = size_of
            self.debuild_size = self.field_obj.realloc
        else:
            raise ValueError("Cannot specify multiple length_of, count_of, or size_of for FieldLenField")
        self.adjust = adjust
        self.deadjust = deadjust

    def register(self, offset, packet):
        packet.build_hook(self)
        packet.debuild_hook(self)
        return super(FieldLenField, self).register(offset, packet)

    def build(self):
        self(self.adjust(self.packet, self.get_value(self.field_obj)))

    def debuild(self, raw_payload):
        self.debuild_size(int(self))

    def __int__(self):
        return self.deadjust(self.packet, self[0])

    def __str__(self):
        return str(self[0])

    def __call__(self, value):
        super(FieldLenField, self).__call__(value)

class StrNullField(StrField):

    def __init__(self, name, default):
        if default is not None:
            default = default + b"\x00"
        super(StrNullField, self).__init__(name, default)

    def register(self, offset, packet):
        packet.debuild_hook(self)
        return super(StrNullField, self).register(offset, packet)

    def debuild(self, raw_payload):
        pkt_offset = self.get_offset()
        idx = raw_payload[pkt_offset:].find(b"\x00")
        if idx >= 0:
            self.resize(idx+1)

    def __str__(self):
        s = super(StrNullField, self).__str__()
        idx = s.find(b"\x00")
        if idx >= 0:
            s = s[:idx]
        return s

    def __call__(self, value):
        super(StrNullField, self).__call__(value + b"\x00")

def ReType(base_klass, **newkwargs):
    def new_init(self, **kwargs):
        newkwargs.update(kwargs)
        super(self.__class__, self).__init__(**newkwargs)

    return type('', tuple([base_klass]), {
        "__init__": new_init
        })

class Packet(FieldStorage):
    all_packets = []
    payload_guess = []

    def __init__(self, _pkt=b"", _klass=None, _underlayer = None, _fields=None, **kwargs):
        Packet.all_packets.append(_klass)
        self.payload = None
        self.underlayer = _underlayer
        self.fields = []
        self.packet_data = b''
        self.bit_offset = 0
        self.build_list = []
        self.debuild_list = []

        if _klass:
            self.klass = _klass
        else:
            self.klass = Packet

        # Setup the fields
        foffset = 0
        for f in _fields:
            if isinstance(f, Field):
                # Add the registered field to our packet
                self.fields.append(f)
                # Returns the number of bytes to advance the field registration
                foffset += f.register(foffset, self)
            else:
                raise TypeError
        # Now assign values, this depends on all the fields being setup
        if _pkt:
            self.dissect(_pkt)
        else:
            for f in _fields:
                if f.name in kwargs.keys():
                    f(kwargs[f.name])

    def get_follow_criteria(self, **kwargs):
        return kwargs

    def unfollow(self):
        self.klass.payload_guess[:] = []

    def follow(self, upper):
        self.klass.payload_guess.append((upper, self[upper].get_follow_criteria()))

    def dissect(self, raw_packet):
        # Assign the packet data for the base fields
        baselen = len(self.packet_data)
        self.packet_data = bytearray(raw_packet[:baselen])

        self.add_optional_fields(raw_packet)

        # Assign the packet data for the new fields
        newlen = len(self.packet_data)
        self.packet_data[:newlen] = bytearray(raw_packet[:newlen])

        # Get the remaining data
        remaining_data = bytes(raw_packet[newlen:])
        if len(remaining_data) > 0:
            klass = self.guess_payload_class(remaining_data)
            if klass:
                self.add_payload(klass(remaining_data))

    def get_extra_payload(self, raw_payload):
        return raw_payload[len(self.packet_data):]

    def add_optional_fields(self, raw_payload):
        # Have the variable sized fields update
        self.debuild(raw_payload)

    def debuild(self, raw_payload):
        for fo in self.debuild_list:
            fo.debuild(raw_payload)

    def build(self):
        if self.payload is not None:
            self.payload.build()
        for fo in self.build_list:
            fo.build()

    def build_hook(self, build_obj):
        if not hasattr(build_obj, "build"):
            raise AttributeError("Missing build attribute for build_hook")
        self.build_list.append(build_obj)

    def debuild_hook(self, debuild_obj):
        if not hasattr(debuild_obj, "debuild"):
            raise AttributeError("Missing debuild attribute for debuild_hook")
        self.debuild_list.append(debuild_obj)

    def replace_bytes(self, field, bstr):
        pos = field.get_offset()
        self.packet_data[pos:pos+len(bstr)] = bstr

    def get_bytes(self, field):
        pos = field.get_offset()
        size = field.get_size()
        return bytes(self.packet_data[pos:pos+size])

    def shrink_bytes(self, field, size):
        pos = field.get_offset()
        # Shrink the offset of all fields that come after this offset
        for f in self.fields:
            if f.contains_field(field):
                f.is_shrinking(field, size)
            elif f.get_offset() >= pos:
                f.adjust_offset(field, -size)

        self.packet_data = bytearray(self.packet_data[:pos] + self.packet_data[pos+size:])

    def grow_bytes(self, field, size, fill=b'\0'):
        pos = field.get_offset()
        self.packet_data = bytearray(self.packet_data[:pos] + bytearray(fill * size) + self.packet_data[pos:])

        # Grow the offset of all fields that come after this offset.
        # Note: even ones with the same offset, i.e. when a field size is zero.
        for f in self.fields:
            if f.contains_field(field):
                f.is_growing(field, size)
            elif f.get_offset() >= pos:
                f.adjust_offset(field, size)

    def size_bytes(self):
        return len(self.packet_data)

    def __getattr__(self, name):
        for f in object.__getattribute__(self, "fields"):
            if f.name == name:
                return f
        if self.payload is not None:
            return self.payload.__getattr__(name)

    def __setattr__(self, name, value):
        try:
            for f in self.fields:
                if f.name == name:
                    f(value)
                    return None
        except AttributeError:
            pass
        return object.__setattr__(self, name, value)

    def __bytes__(self):
        self.build()
        if self.payload is not None:
            return bytes(self.packet_data) + bytes(self.payload)
        return bytes(self.packet_data)

    def __len__(self):
        return len(self.packet_data)

    def __copy__(self):
        p = self.klass(_pkt=self.packet_data)
        if self.payload is not None:
            p = p / self.payload.copy()
        return p

    def __contains__(self, klass):
        try:
            return self[klass] is not None
        except IndexError:
            return False

    def __getitem__(self, klass):
        if klass.__name__ == self.klass.__name__:
            return self
        elif self.payload is not None:
            return self.payload[klass]
        raise IndexError("Layer [%s] not found" % klass.__name__)

    def show(self, out=sys.stdout, indent=1):
        self.build()
        s = "%s %s %s \n" % ( "###[",
                              self.klass.__name__,
                              "]###")
        for f in self.fields:
            s += "%s%s = %s\n" % ("  " * indent, f.name, str(f))
        if self.payload is not None:
            s += self.payload.show(out=None,indent=indent+1)

        if out is None:
            return s
        print(s, file=out)

    def raw(self):
        return bytes(self.packet_data)

    def add_payload(self, payload):
        if payload is None:
            return
        elif self.payload is not None:
            self.payload.add_payload(payload)
        else:
            if isinstance(payload, (bytes, bytearray)):
                self.payload = Raw(payload)
            elif isinstance(payload, Packet):
                self.payload = payload
            else:
                raise TypeError("payload must be either 'Packet' or 'bytes', not [%s]" % repr(payload))
            payload.add_underlayer(self)

    def remove_payload(self):
        self.payload.remove_underlayer()
        self.payload = None

    def add_underlayer(self, underlayer):
        self.underlayer = underlayer

    def remove_underlayer(self):
        self.underlayer = None

    def guess_payload_class(self, payload):
        for klass, fval in self.klass.payload_guess:
            try:
                if all(v == getattr(self, k) for k, v in fval.items()):
                    return klass
            except AttributeError:
                pass
        return Raw

    def append_payload(self, packet):
        rebase_offset = len(self.packet_data)
        # Add the field data to our packet
        self.packet_data += packet.packet_data
        for f in packet.fields:
                # Register the copied field with the updated offset
                rebase_offset += f.register(rebase_offset, self)
                self.fields.append(f)

    def merge_payloads(self):
        pass

    def __div__(self, other):
        if isinstance(other, Packet):
            self.add_payload(other)
            return self
        elif isinstance(other, (bytes, str)):
            return self / Raw(other)
        else:
            return other.__rdiv__(self)
    __truediv__ = __div__

    def __rdiv__(self, other):
        if isinstance(other, (bytes, str)):
            return Raw(other) / self
        else:
            raise TypeError
    __rtruediv__ = __rdiv__

class Raw(Packet):
    def __init__(self, _pkt=b""):
        super(Raw, self).__init__(
            _klass = self.__class__,
            _fields = [
                XStrField("raw", _pkt)
            ])

    def guess_payload_class(self, payload):
        return None

class Qemu(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(Qemu, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                IntField("length", None)
            ],
            **kwargs)

    def build(self):
        super(Qemu, self).build()
        total_len = 0
        if self.payload is not None:
            total_len = len(bytes(self.payload))
        self.length = total_len
    
    def guess_payload_class(self, payload):
        return Ethernet

class Ethernet(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(Ethernet, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                DestMACField("dst"),
                SourceMACField("src"),
                XShortEnumField("type", 0x9000, ETHER_TYPES)
            ],
            **kwargs)

    def build(self):
        super(Ethernet, self).build()
        if self.payload is None:
            return

        if isinstance(self.payload, IP):
            self.type = '802_3'
        elif isinstance(self.payload, ARP):
            self.type = 'ARP'
        elif isinstance(self.payload, RARP):
            self.type = 'RARP'
        elif isinstance(self.payload, IPv6):
            self.type = '802_3v6'

    def guess_payload_class(self, payload):
        stype = ETHER_TYPES[int(self.type)]
        if stype == '802_3':
            return IP
        elif stype == 'ARP':
            return ARP
        elif stype == 'RARP':
            return RARP
        elif stype == '802_3v6':
            return IPv6
        return super(Ethernet, self).guess_payload_class(payload)

class IPOption(FieldStructField):
    def __init__(self, name, option_num=None, copy_flag=0, optclass=0, option_fields=[], **kwargs):
        super(IPOption, self).__init__(
            name = name,
            fields = [BitField("copy_flag", copy_flag, 1),
                   BitEnumField("optclass", optclass, 2, {0: "control", 2: "debug"}),
                   BitEnumField("option", option_num, 5, IPOPTION_NAMES)] +
                   option_fields,
                   **kwargs)

class IPOption_EOL(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_EOL, self).__init__(
            name = "IP Option End of Options List",
            option_num = 0,
            **kwargs)

class IPOption_NOP(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_NOP, self).__init__(
            name = "IP Option No Operation",
            option_num = 1,
            **kwargs)

class IPOption_Security(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_Security, self).__init__(
            name = "IP Option Security",
            option_num = 2,
            copy_flag = 1,
            option_fields = [OctetField("length", 11),
                   ShortField("security", 0),
                   ShortField("compartment", 0),
                   ShortField("handling_restrictions", 0),
                   StrFixedLenField("transmission_control_code", "xxx", 3),
                   ],
            **kwargs)

class IPOption_RR_Base(IPOption):
    def __init__(self, name, option_num, copy_flag=0, **kwargs):
        self.pointer = OctetField("pointer", 4)
        self.routers = FieldListField("routers", [], IPField)
        super(IPOption_RR, self).__init__(
            name = name,
            option_num = option_num,
            option_fields = [FieldLenField("length", None, fmt="B",
                                 length_of=self.routers, adjust=lambda pkt, l:l + 3),  # noqa: E501
                   self.pointer,  # 4 is first IP
                   self.routers
                   ],
            **kwargs)

    def get_current_router(self):
        return self.routers[int(self.pointer) // 4 - 1]

class IPOption_RR(IPOption_RR_Base):
    def __init__(self, name, option_num, **kwargs):
        super(IPOption_RR, self).__init__(
            name = "IP Option Record Route",
            option_num = 7,
            **kwargs)

class IPOption_LSRR(IPOption_RR_Base):
    def __init__(self, **kwargs):
        super(IPOption_LSRR, self).__init__(
            name = "IP Option Loose Source and Record Route",
            copy_flags = 1,
            option_num = 3,
            **kwargs)

class IPOption_SSRR(IPOption_RR_Base):
    def __init__(self, **kwargs):
        super(IPOption_SSRR, self).__init__(
            name = "IP Option Strict Source and Record Route",
            copy_flags = 1,
            option_num = 9,
            **kwargs)

class IPOption_Stream_Id(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_Stream_Id, self).__init__(
            name = "IP Option Stream ID",
            copy_flag = 1,
            option_num = 8,
            option_fields = [OctetField("length", 4),
                   ShortField("security", 0)
                   ],
            **kwargs)

class IPOption_MTU_Probe(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_MTU_Probe, self).__init__(
            name = "IP Option MTU Probe",
            option_num = 11,
            option_fields = [OctetField("length", 4),
                   ShortField("mtu", 0)
                   ],
            **kwargs)

class IPOption_MTU_Reply(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_MTU_Reply, self).__init__(
            name = "IP Option MTU Reply",
            option_num = 12,
            option_fields = [OctetField("length", 4),
                   ShortField("mtu", 0)
                   ],
            **kwargs)

class IPOption_Traceroute(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_Traceroute, self).__init__(
            name = "IP Option Traceroute",
            option_num = 18,
            option_fields = [OctetField("length", 12),
                   ShortField("id", 0),
                   ShortField("outbound_hops", 0),
                   ShortField("return_hops", 0),
                   IPField("originator_ip", "0.0.0.0")
                   ],
            **kwargs)

class IPOption_Address_Extension(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_Address_Extension, self).__init__(
            name = "IP Option Address Extension",
            option_num = 19,
            copy_flag = 1,
            option_fields = [OctetField("length", 10),
                   IPField("src_ext", "0.0.0.0"),
                   IPField("dst_ext", "0.0.0.0")
                   ],
            **kwargs)

class IPOption_Router_Alert(IPOption):
    def __init__(self, **kwargs):
        super(IPOption_Router_Alert, self).__init__(
            name = "IP Option Router Alert",
            option_num = 20,
            copy_flag = 1,
            option_fields = [OctetField("length", 4),
                   ShortEnumField("alert", 0, {0: "router_shall_examine_packet"})
                   ],
            **kwargs)

class IPOption_SDBM(IPOption):
    def __init__(self, **kwargs):
        self.addresses = FieldListField("addresses", [], IPField)
        super(IPOption_SDBM, self).__init__(
            name = "IP Option Selective Directed Broadcast Mode",
            option_num = 21,
            copy_flag = 1,
            option_fields = [FieldLenField("length", None, fmt="B",
                                 length_of=self.addresses, adjust=lambda pkt, l:l + 2),  # noqa: E501
                   self.addresses
                   ],
            **kwargs)

IPOPTION_TYPES = {IPOPTION_NAMES[0]: IPOption_EOL,
                IPOPTION_NAMES[1]: IPOption_NOP,
                IPOPTION_NAMES[2]: IPOption_Security,
                IPOPTION_NAMES[3]: IPOption_LSRR,
                IPOPTION_NAMES[4]: "timestamp",
                IPOPTION_NAMES[5]: "extended_security",
                IPOPTION_NAMES[6]: "commercial_security",
                IPOPTION_NAMES[7]: IPOption_RR,
                IPOPTION_NAMES[8]: IPOption_Stream_Id,
                IPOPTION_NAMES[9]: IPOption_SSRR,
                IPOPTION_NAMES[10]: "experimental_measurement",
                IPOPTION_NAMES[11]: IPOption_MTU_Probe,
                IPOPTION_NAMES[12]: IPOption_MTU_Reply,
                IPOPTION_NAMES[13]: "flow_control",
                IPOPTION_NAMES[14]: "access_control",
                IPOPTION_NAMES[15]: "encode",
                IPOPTION_NAMES[16]: "imi_traffic_descriptor",
                IPOPTION_NAMES[17]: "extended_IP",
                IPOPTION_NAMES[18]: IPOption_Traceroute,
                IPOPTION_NAMES[19]: IPOption_Address_Extension,
                IPOPTION_NAMES[20]: IPOption_Router_Alert,
                IPOPTION_NAMES[21]: IPOption_SDBM,
                IPOPTION_NAMES[23]: "dynamic_packet_state",
                IPOPTION_NAMES[24]: "upstream_multicast_packet",
                IPOPTION_NAMES[25]: "quick_start",
                IPOPTION_NAMES[30]: "rfc4727_experiment",
                IPOPTION_NAMES[31]: "unknown"
                }

class IP(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        ip_options = None
        try:
            ip_options = kwargs["options"]
        except KeyError:
            pass
        if ip_options:
            new_opts = []
            for opt in ip_options:
                if isinstance(opt, IPOption):
                    new_opts.append(opt)
                else:
                    if isinstance(opt, tuple):
                        opt_id = IPOPTION_TYPES[opt[0]]
                        opt_dict = opt[1]
                        if not isinstance(opt_dict, dict):
                            raise TypeError("Provide a dict with values for IPOptions")
                        if isinstance(opt_id, str):
                            opt_dict.update({"name":opt_id,"option_num":IPOPTION_NUMBERS[opt_id]})
                            opt_class = IPOption
                        elif isinstance(opt_id, type):
                            opt_class = opt_id
                        else:
                            raise TypeError("Invalid type for option")
                    elif isinstance(opt, str):
                        opt_id = IPOPTION_TYPES[opt]
                        if isinstance(opt_id, str):
                            opt_dict = {"name":opt,"option_num":IPOPTION_NUMBERS[opt]}
                            opt_class = IPOption
                        elif isinstance(opt_id, type):
                            opt_dict = {}
                            opt_class = opt_id
                        else:
                            raise TypeError("Invalid type for option")
                    new_opts.append(opt_class(**opt_dict))
            kwargs["options"] = new_opts
        super(IP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                BitField("version", 4, 4),
                BitField("ihl", None, 4),
                BitField("dscp", None, 6),
                BitField("ecn", None, 2),
                ShortField("len", None),
                ShortField("id", 1),
                FlagsField("flags", 0, 3, ["MF", "DF", "evil"]),
                BitField("frag", 0, 13),
                OctetField("ttl", 128),
                OctetEnumField("proto", 0, IP_PROTOS),
                XShortField("chksum", None),
                SourceIPField("src", "127.0.0.1"),
                DestIPField("dst", "127.0.0.1"),
                FieldListField("options", [], IPOption)
            ],
            **kwargs)

    def build(self):
        super(IP, self).build()
        # Be careful not to cause infinite recursion by accidentally
        # calling your own build function. :)
        # Set the protocol
        if self.payload is not None:
            if isinstance(self.payload, TCP):
                self.proto = "tcp"
            elif isinstance(self.payload, UDP):
                self.proto = "udp"
        # Calculate the checksum
        self.chksum = 0
        plen = len(self.packet_data)
        self.options.append( IPOption_EOL() * ((-plen) % 4))
        # Get the new length
        total_len = len(self.packet_data)
        self.ihl = total_len // 4
        if self.payload is not None:
            total_len += len(bytes(self.payload))
        self.len = total_len
        self.chksum = checksum(self.packet_data)

    def add_optional_fields(self, raw_payload):
        opts_len = int(self.ihl) * 4 - 20
        if opts_len <= 0:
            return

        end_data = len(self.packet_data)
        options_data = raw_payload[end_data:end_data+opts_len]
        options_fields = []

        while options_data:
            opt = Packet(options_data, _fields=[IPOption("peek")])
            try:
                opt_num = int(opt.peek["option"])
                opt_id = IPOPTION_TYPES[IPOPTION_NAMES[opt_num]]

                if isinstance(opt_id, str):
                    opt_dict = {"name":opt, "option_num":opt_num}
                    opt_class = IPOption
                elif isinstance(opt_id, type):
                    opt_dict = {}
                    opt_class = opt_id
                else:
                    raise TypeError("Invalid type for option")
            except KeyError:
                opt_dict = {"name":"Unknown IP Option", "option_num":opt_num}
                opt_class = IPOption

            new_option = opt_class(**opt_dict)
            options_fields.append(new_option)

            # Parse this field to get the next set of options data
            opt_pkt = Packet(options_data, _fields=[new_option])
            try:
                # Get the remaining options data
                options_data = opt_pkt[Raw].raw()
            except IndexError:
                break

        if options_fields:
            self.options = options_fields

    def guess_payload_class(self, payload):
        stype = IP_PROTOS[int(self.proto)]
        if stype == 'tcp':
            return TCP
        elif stype == 'udp':
            return UDP
        return super(IP, self).guess_payload_class(payload)

class ARP(Packet):

    def __init__(self, _pkt=b"", **kwargs):
        hwsrc = SourceMACField("hwsrc")
        protosrc = SourceIPField("psrc")
        hwdst = DestMACField("hwdst")
        protodst = IPField("pdst", "0.0.0.0")
        super(ARP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                XShortEnumField("hwtype", 1, HWADDR_TYPES),
                XShortEnumField("ptype", 0x0800, ETHER_TYPES),
                FieldLenField("hwlen", None, fmt="B", size_of=hwsrc),
                FieldLenField("plen", None, fmt="B", size_of=protosrc),
                ShortEnumField("op", 1, {
                    1: "who-has",
                    2: "is-at",
                    3: "RARP-req",
                    4: "RARP-rep",
                    5: "Dyn-RARP-req",
                    6: "Dyn-RAR-rep",
                    7: "Dyn-RARP-err",
                    8: "InARP-req",
                    9: "InARP-rep"
                }),
                hwsrc,
                protosrc,
                hwdst,
                protodst
            ],
            **kwargs)

class IPv6(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(IPv6, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                BitField("version", 6, 4),
                BitField("tc", 0, 8),
                BitField("fl", 0, 20),
                ShortField("plen", None),
                OctetEnumField("nh", "No Next Header", IPV6_NEXT_HEADER),
                OctetField("hlim", 64),
                SourceIP6Field("src", "::1"),
                DestIP6Field("dst", "::1")
            ],
            **kwargs)

    def build(self):
        super(IPv6, self).build()
        self.plen = len(self.packet_data)

TCPOPTION_TYPES = {
    TCPOPTION_NAMES[0]: "EOL",
    TCPOPTION_NAMES[1]: "NOP",
    TCPOPTION_NAMES[2]: ReType(ShortField, name="MSS", default=65495),
    TCPOPTION_NAMES[3]: ReType(OctetField, name="WScale", default=7),
    TCPOPTION_NAMES[4]: "SAckOK",
    #TCPOPTION_NAMES[5]: ("SAck", "!"),
    TCPOPTION_NAMES[8]: ReType(FieldStructField, name="Timestamp", fields=[IntField("value", 1809071049), IntField("echo_reply", 0)]),
    TCPOPTION_NAMES[14]: ReType(FieldStructField, name="AltChkSum", fields=[OctetField("a", 0), ShortField("b", 0)]),
    TCPOPTION_NAMES[15]: "AltChkSumOpt",
    #TCPOPTION_NAMES[25]: ReType(ShortField, name="Mood", default=0),("Mood", "!p"),
    TCPOPTION_NAMES[28]: ReType(ShortField, name="UTO", default=0),
    #TCPOPTION_NAMES[34]: ReType(FieldStructField, name="TCP Fast Open", fields=[IntField(name="cookie1", 1809071049), IntField(name="cookie2", 0)]),
}

class TCPOption(FieldStructField):
    def __init__(self, kind=0, **kwargs):
        try:
            if isinstance(kind, str):
                name = kind
            else:
                name = TCPOPTION_NAMES[kind]
            contents_type = TCPOPTION_TYPES[name]
        except KeyError:
            name = "Kind=" + str(kind)
            contents_type = None

        self.kind_field = OctetEnumField("kind", kind, TCPOPTION_NAMES)
        fields = [self.kind_field]
        # EOL and NOP don't have lengths
        if name not in ("EOL", "NOP"):
            fields.append(FieldLenField("oplength", None, size_of=self, fmt="B"))
        self.contents_field = None
        if isinstance(contents_type, type):
            self.contents_field = contents_type(**kwargs)
            fields.append(self.contents_field)
        super(TCPOption, self).__init__(
            name = name,
            fields = fields)
    
    def __int__(self):
        return int(self.kind_field)

    def __str__(self):
        s = self.name
        if self.contents_field is not None:
            s += "=" + str(self.contents_field)
        return s

class TCP(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        # Build the fields from the kwargs
        option_fields = []
        super(TCP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                ShortEnumField("sport", 20, TCP_SERVICES),
                ShortEnumField("dport", 80, TCP_SERVICES),
                IntField("seq", 0),
                IntField("ack", 0),
                BitField("dataofs", None, 4),
                BitField("reserved", 0, 3),
                FlagsField("flags", 0x2, 9, "FSRPAUECN"),
                ShortField("window", 8192),
                XShortField("chksum", None),
                ShortField("urgptr", 0),
                FieldListField("options", [], TCPOption)
            ],
            **kwargs)

    def guess_payload_class(self, payload):
        try:
            sport = TCP_SERVICES[int(self.sport)]
        except KeyError:
            sport = None
        try:
            dport = TCP_SERVICES[int(self.dport)]
        except KeyError:
            dport = None

        if dport == 'http' or sport == 'http':
            return HTTP
        return super(TCP, self).guess_payload_class(payload)

    def add_optional_fields(self, raw_payload):
        opts_len = int(self.dataofs) * 4 - 20
        if opts_len <= 0:
            return

        options_fields = []
        end_data = len(self.packet_data)
        options_data = raw_payload[end_data:end_data+opts_len]
        while options_data:
            opt = Packet(options_data, _fields=[OctetField("peek", None)])
            try:
                opt_kind = int(opt.peek)
                opt_type = TCPOPTION_TYPES[TCPOPTION_NAMES[opt_kind]]
            except KeyError:
                opt_type = "unknown"

            # The default should not be set since we're using the
            # underlying value from the packet_data contents.
            new_option = TCPOption(kind=opt_kind)
            options_fields.append(new_option)

            # Parse this field to get the next set of options data
            # add_optional_fields() the base packet class will
            # expand new_option for us. Hence why it's shared
            # between options_field and opt_pkt.
            opt_pkt = Packet(options_data, _fields=[new_option])
            try:
                # Get the remaining options data
                options_data = opt_pkt[Raw].raw()
            except IndexError:
                break

        if options_fields:
            self.options = options_fields

class HTTP(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        # Build the fields from the kwargs
        option_fields = []
        super(HTTP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                StrField("content", "")
            ],
            **kwargs)

    def add_optional_fields(self, raw_payload):
        self.content = self.get_extra_payload(raw_payload)

class UDP(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(UDP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                ShortEnumField("sport", 53, UDP_SERVICES),
                ShortEnumField("dport", 53, UDP_SERVICES),
                ShortField("len", None),
                XShortField("chksum", None),
            ],
            **kwargs)

    def build(self):
        super(UDP, self).build()
        # Be careful not to cause infinite recursion by accidentally
        # calling your own build function. :)
        self.chksum = 0
        if self.payload is not None:
            p = self.packet_data + str(self.payload)
        else:
            p = self.packet_data
        self.len = len(p)
        if isinstance(self.underlayer, IP):
            ck = in4_chksum(socket.IPPROTO_UDP, self.underlayer, p)
            # According to RFC768 if the result checksum is 0, it should be set to 0xFFFF  # noqa: E501
            if ck == 0:
                ck = 0xFFFF
            self.chksum = ck
        elif isinstance(self.underlayer, IPv6):
            ck = 0# scapy.layers.inet6.in6_chksum(socket.IPPROTO_UDP, self.underlayer, p)  # noqa: E501
            # According to RFC2460 if the result checksum is 0, it should be set to 0xFFFF  # noqa: E501
            if ck == 0:
                ck = 0xFFFF
            self.chksum = ck

    def guess_payload_class(self, payload):
        try:
            sport = UDP_SERVICES[int(self.sport)]
        except KeyError:
            sport = None
        try:
            dport = UDP_SERVICES[int(self.dport)]
        except KeyError:
            dport = None

        if sport in ('bootps', 'bootpc') and dport in ('bootps', 'bootpc'):
            return BOOTP
        elif dport == 'tftp':
            return TFTP
        return super(UDP, self).guess_payload_class(payload)

class TFTP(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                ShortEnumField("opcode", 1, TFTP_OPERATIONS)
            ],
            **kwargs)

    def build(self):
        super(TFTP, self).build()
        if self.payload is not None:
            if isinstance(self.payload, TFTP_RRQ):
                self.opcode = "RRQ"
            elif isinstance(self.payload, TFTP_WRQ):
                self.opcode = "WRQ"
            elif isinstance(self.payload, TFTP_DATA):
                self.opcode = "DATA"
            elif isinstance(self.payload, TFTP_ACK):
                self.opcode = "ACK"
            elif isinstance(self.payload, TFTP_OACK):
                self.opcode = "OACK"
            elif isinstance(self.payload, TFTP_ERROR):
                self.opcode = "ERROR"
            elif isinstance(self.payload, Raw):
                self.opcode = 0
            else:
                raise TypeError("Expected payload of type relating to TFTP, got "+str(self.payload.klass))

    def get_follow_criteria(self):
        return super(TFTP, self).get_follow_criteria(sport=int(self.underlayer.sport))

    def guess_payload_class(self, payload):
        opcode = str(self.opcode)
        if opcode == "RRQ":
            return TFTP_RRQ
        elif opcode == "WRQ":
            return TFTP_WRQ
        elif opcode == "DATA":
            return TFTP_DATA
        elif opcode == "ACK":
            return TFTP_ACK
        elif opcode == "OACK":
            return TFTP_OACK
        elif opcode == "ERROR":
            return TFTP_ERROR
        return super(TFTP, self).guess_payload_class(payload)

class TFTP_RRQ(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP_RRQ, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                StrNullField("filename", ""),
                StrNullField("mode", "octet")
            ],
            **kwargs)

    def guess_payload_class(self, payload):
        return TFTP_Options

class TFTP_WRQ(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP_WRQ, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                StrNullField("filename", ""),
                StrNullField("mode", "octet")
            ],
            **kwargs)

    def guess_payload_class(self, payload):
        return TFTP_Options

class TFTP_DATA(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP_DATA, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                ShortField("block", 0),
                XStrField("data", None)
            ],
            **kwargs)

    def add_optional_fields(self, raw_payload):
        self.data = self.get_extra_payload(raw_payload)

class TFTP_ACK(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP_ACK, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                ShortField("block", 0)
            ],
            **kwargs)

class TFTP_ERROR(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP_ERROR, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                ShortEnumField("errorcode", 0, TFTP_ERROR_CODES),
                StrNullField("errormsg", "")
            ],
            **kwargs)

class TFTP_OACK(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP_OACK, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
            ],
            **kwargs)

    def guess_payload_class(self, payload):
        return TFTP_Options

class TFTP_Option(FieldStructField):
    def __init__(self, **kwargs):
        super(TFTP_Option, self).__init__(
            name = None,
            fields = [
                StrNullField("oname", None),
                StrNullField("value", None)
            ],
            **kwargs)

class TFTP_Options(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(TFTP_Options, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                FieldListField(name="options", default=[], field_klass=TFTP_Option)
            ],
            **kwargs)

    def add_optional_fields(self, raw_payload):
        options_fields = []

        options_data = self.get_extra_payload(raw_payload)
        while options_data:
            new_option = TFTP_Option()

            # Parse this field to get the next set of options data
            # add_optional_fields() the base packet class will
            # expand new_option for us. Hence why it's shared
            # between options_fields and opt_pkt.
            opt_pkt = Packet(options_data, _fields=[new_option])

            options_fields.append(new_option)

            try:
                # Get the remaining options data
                options_data = opt_pkt[Raw].raw()
            except IndexError:
                break

        if options_fields:
            self.options = options_fields

class BOOTP(Packet):
    DHCPMAGIC = b"c\x82Sc"

    def __init__(self, _pkt=b"", **kwargs):
        # Build the fields from the kwargs
        option_fields = []
        super(BOOTP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetEnumField("op", 1, {1: "BOOTREQUEST", 2: "BOOTREPLY"}),
                OctetField("htype", 1),
                OctetField("hlen", 6),
                OctetField("hops", 0),
                IntField("xid", 0),
                ShortField("secs", 0),
                FlagsField("flags", 0, 16, "???????????????B"),
                IPField("ciaddr", "0.0.0.0"),
                IPField("yiaddr", "0.0.0.0"),
                IPField("siaddr", "0.0.0.0"),
                IPField("giaddr", "0.0.0.0"),
                MACField("chaddr", "0:0:0:0:0:0"),
                Field("chpad", b"", "10s"),
                Field("sname", b"", "64s"),
                Field("file", b"", "128s"),
                StrFixedLenField("magic", None, len(BOOTP.DHCPMAGIC))
            ],
            **kwargs)
    
    def build(self):
        self.magic = BOOTP.DHCPMAGIC

    def guess_payload_class(self, payload):
        if str(self.magic) == BOOTP.DHCPMAGIC:
            return DHCP
        return super(BOOTP, self).guess_payload_class(payload)

class DHCPOptionList(FieldListField):
    def __init__(self, name, default=[]):
        super(DHCPOptionList, self).__init__(name, default, DHCPOption)

    def __str__(self):
        s = '['
        for f in self.fields:
            s += f.get_name()
            fstr = str(f)
            if fstr:
                s += "=" + str(f)
            s += ' '
        if len(s) > 1:
            s = s[:-1]
        s += ']'
        return s

class DHCPOption(FieldStructField):
    def __init__(self, opcode=0, **kwargs):
        try:
            if isinstance(opcode, str):
                name = opcode
            else:
                name = DHCPOPTION_NAMES[opcode]
            contents_type = DHCPOPTION_TYPES[name]
        except KeyError:
            name = "unknown"
            contents_type = None

        self.opcode_field = OctetEnumField("opcode", opcode, DHCPOPTION_NAMES)
        fields = [self.opcode_field]
        if isinstance(contents_type, type):
            self.contents_field = contents_type(**kwargs)
        else:
            self.contents_field = None
        if self.contents_field is not None:
            fields += [
                   FieldLenField("oplength", None, size_of=self.contents_field, fmt="B"),
                   self.contents_field
            ]
        super(DHCPOption, self).__init__(
            name = name,
            fields = fields)
    
    def __int__(self):
        return int(self.opcode_field)

    def __str__(self):
        if self.contents_field is not None:
            return str(self.contents_field)
        return ""

class DHCPHardwareAddressField(FieldStructField):
    def __init__(self, name="client_id", hwtype=1, client_id="00:00:00:00:00:00", **kwargs):
        super(DHCPHardwareAddressField, self).__init__(
            name = name,
            fields = [OctetEnumField(name="hwtype", default=hwtype, enums=HWADDR_TYPES),
                    MACField(name="client_id", default=client_id)],
                   **kwargs)

class DHCPClientNetworkField(FieldStructField):
    def __init__(self, name="client-network", netint=1, major=0, minor=0, **kwargs):
        super(DHCPClientNetworkField, self).__init__(
            name = name,
            fields = [OctetField(name="netint", default=netint),
                    OctetField(name="major", default=major),
                    OctetField(name="minor", default=minor)],
                   **kwargs)

DHCPOPTION_TYPES = {
    DHCPOPTION_NAMES[0]: "pad",
    DHCPOPTION_NAMES[1]: ReType(IPField, name="subnet_mask", default="0.0.0.0"),
    DHCPOPTION_NAMES[2]: "time_zone",
    DHCPOPTION_NAMES[3]: ReType(IPField, name="router", default="0.0.0.0"),
    DHCPOPTION_NAMES[4]: ReType(IPField, name="time_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[5]: ReType(IPField, name="IEN_name_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[6]: ReType(IPField, name="name_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[7]: ReType(IPField, name="log_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[8]: ReType(IPField, name="cookie_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[9]: ReType(IPField, name="lpr_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[10]: ReType(IPField, name="impress-servers", default="0.0.0.0"),
    DHCPOPTION_NAMES[11]: ReType(IPField, name="resource-location-servers", default="0.0.0.0"),
    DHCPOPTION_NAMES[12]: "hostname",
    DHCPOPTION_NAMES[13]: ReType(ShortField, name="boot-size", default=1000),
    DHCPOPTION_NAMES[14]: "dump_path",
    DHCPOPTION_NAMES[15]: "domain",
    DHCPOPTION_NAMES[16]: ReType(IPField, name="swap-server", default="0.0.0.0"),
    DHCPOPTION_NAMES[17]: "root_disk_path",
    DHCPOPTION_NAMES[18]: "extensions-path",
    DHCPOPTION_NAMES[19]: ReType(OctetField, name="ip-forwarding", default=0),
    DHCPOPTION_NAMES[20]: ReType(OctetField, name="non-local-source-routing", default=0),
    DHCPOPTION_NAMES[21]: ReType(IPField, name="policy-filter", default="0.0.0.0"),
    DHCPOPTION_NAMES[22]: "max_dgram_reass_size",
    DHCPOPTION_NAMES[23]: "default_ttl",
    DHCPOPTION_NAMES[24]: "pmtu_timeout",
    DHCPOPTION_NAMES[25]: ReType(ShortField, name="path-mtu-plateau-table", default=1000),
    DHCPOPTION_NAMES[26]: ReType(ShortField, name="interface-mtu", default=50),
    DHCPOPTION_NAMES[27]: ReType(OctetField, name="all-subnets-local", default=0),
    DHCPOPTION_NAMES[28]: ReType(IPField, name="broadcast_address", default="0.0.0.0"),
    DHCPOPTION_NAMES[29]: ReType(OctetField, name="perform-mask-discovery", default=0),
    DHCPOPTION_NAMES[30]: ReType(OctetField, name="mask-supplier", default=0),
    DHCPOPTION_NAMES[31]: ReType(OctetField, name="router-discovery", default=0),
    DHCPOPTION_NAMES[32]: ReType(IPField, name="router-solicitation-address", default="0.0.0.0"),
    DHCPOPTION_NAMES[33]: ReType(IPField, name="static-routes", default="0.0.0.0"),
    DHCPOPTION_NAMES[34]: ReType(OctetField, name="trailer-encapsulation", default=0),
    DHCPOPTION_NAMES[35]: "arp_cache_timeout",
    DHCPOPTION_NAMES[36]: "ether_or_dot3",
    DHCPOPTION_NAMES[37]: "tcp_ttl",
    DHCPOPTION_NAMES[38]: "tcp_keepalive_interval",
    DHCPOPTION_NAMES[39]: "tcp_keepalive_garbage",
    DHCPOPTION_NAMES[40]: "NIS_domain",
    DHCPOPTION_NAMES[41]: ReType(IPField, name="NIS_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[42]: ReType(IPField, name="NTP_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[43]: "vendor_specific",
    DHCPOPTION_NAMES[44]: ReType(IPField, name="NetBIOS_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[45]: ReType(IPField, name="NetBIOS_dist_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[46]: ReType(OctetField, name="static-routes", default=100),
    DHCPOPTION_NAMES[47]: "netbios-scope",
    DHCPOPTION_NAMES[48]: ReType(IPField, name="font-servers", default="0.0.0.0"),
    DHCPOPTION_NAMES[49]: ReType(IPField, name="x-display-manager", default="0.0.0.0"),
    DHCPOPTION_NAMES[50]: ReType(IPField, name="requested_addr", default="0.0.0.0"),
    DHCPOPTION_NAMES[51]: ReType(IntField, name="lease_time", default=43200),
    DHCPOPTION_NAMES[52]: ReType(OctetField, name="dhcp-option-overload", default=100),
    DHCPOPTION_NAMES[53]: ReType(OctetEnumField, name="message-type", default=0, enums=DHCP_MSG_TYPES),
    DHCPOPTION_NAMES[54]: ReType(IPField, name="server_id", default="0.0.0.0"),
    DHCPOPTION_NAMES[55]: ReType(FieldListField, name="param_req_list", default=[], field_klass=OctetField),
    DHCPOPTION_NAMES[56]: "error_message",
    DHCPOPTION_NAMES[57]: ReType(ShortField, name="max_dhcp_size", default=1500),
    DHCPOPTION_NAMES[58]: ReType(IntField, name="renewal_time", default=21600),
    DHCPOPTION_NAMES[59]: ReType(IntField, name="rebinding_time", default=37800),
    DHCPOPTION_NAMES[60]: ReType(StrField, name="vendor_class_id", default=None),
    DHCPOPTION_NAMES[61]: DHCPHardwareAddressField,
    DHCPOPTION_NAMES[62]: "nwip-domain-name",
    DHCPOPTION_NAMES[64]: "NISplus_domain",
    DHCPOPTION_NAMES[65]: ReType(IPField, name="NISplus_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[67]: ReType(StrField, name="boot-file-name", default=None),
    DHCPOPTION_NAMES[68]: ReType(IPField, name="mobile-ip-home-agent", default="0.0.0.0"),
    DHCPOPTION_NAMES[69]: ReType(IPField, name="SMTP_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[70]: ReType(IPField, name="POP3_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[71]: ReType(IPField, name="NNTP_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[72]: ReType(IPField, name="WWW_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[73]: ReType(IPField, name="Finger_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[74]: ReType(IPField, name="IRC_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[75]: ReType(IPField, name="StreetTalk_server", default="0.0.0.0"),
    DHCPOPTION_NAMES[76]: "StreetTalk_Dir_Assistance",
    DHCPOPTION_NAMES[77]: ReType(StrField, name="user-class", default=None),
    DHCPOPTION_NAMES[81]: "client_FQDN",
    DHCPOPTION_NAMES[82]: "relay_agent_Information",
    DHCPOPTION_NAMES[91]: ReType(IntField, name="client-last-transaction-time", default=1000),
    DHCPOPTION_NAMES[92]: ReType(IPField, name="associated-ip", default="0.0.0.0"),
    DHCPOPTION_NAMES[93]: ReType(ShortEnumField, name="client-arch", default=0, enums=DHCP_CLIENT_ARCH_TYPES),
    DHCPOPTION_NAMES[94]: DHCPClientNetworkField,
    DHCPOPTION_NAMES[97]: ReType(XStrField, name="client-uuid", default=None),
    DHCPOPTION_NAMES[118]: ReType(IPField, name="subnet-selection", default="0.0.0.0"),
    DHCPOPTION_NAMES[175]: ReType(XStrField, name="etherboot", default=None),
    DHCPOPTION_NAMES[255]: "end"
}

class DHCP(Packet):
    def __init__(self, _pkt=b"", **kwargs):

        dhcp_options = None
        try:
            dhcp_options = kwargs["options"]
        except KeyError:
            pass
        if dhcp_options:
            new_opts = []
            for opt in dhcp_options:
                if isinstance(opt, DHCPOption):
                    new_opts.append(opt)
                else:
                    opt_dict = {}
                    if isinstance(opt, tuple):
                        if len(opt) > 2:
                            opt_dict["opcode"] = opt[0]
                            opt_dict["default"] = list(opt[1:])
                        elif len(opt) == 2:
                            opt_dict["opcode"] = opt[0]
                            opt_dict["default"] = opt[1]
                        elif len(opt) == 1:
                            opt_dict["opcode"] = opt[0]
                    elif isinstance(opt, str):
                        opt_dict["opcode"] = opt

                    new_opts.append(DHCPOption(**opt_dict))
            kwargs["options"] = new_opts

        super(DHCP, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                DHCPOptionList("options")
            ],
            **kwargs)

    def add_optional_fields(self, raw_payload):
        options_fields = []

        # Parse options until the packet data ends
        options_data = self.get_extra_payload(raw_payload)
        while options_data:
            opt = Packet(options_data, _fields=[OctetField("peek", None)])
            try:
                opt_num = int(opt.peek)
                opt_type = DHCPOPTION_TYPES[DHCPOPTION_NAMES[opt_num]]
            except KeyError:
                opt_type = "unknown"

            # The default should not be set since we're using the
            # underlying value from the packet_data contents.
            new_option = DHCPOption(opcode=opt_num, default=None)
            options_fields.append(new_option)

            # Parse this field to get the next set of options data
            # add_optional_fields() the base packet class will
            # expand new_option for us. Hence why it's shared
            # between options_field and opt_pkt.
            opt_pkt = Packet(options_data, _fields=[new_option])
            try:
                # Get the remaining options data
                options_data = opt_pkt[Raw].raw()
            except IndexError:
                break

        if options_fields:
            self.options = options_fields
