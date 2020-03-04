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

import os
import abc
import sys
import struct
import binascii

ERROR_TEXT_LENGTH = 24
NAME_LENGTH = 15
INSN_LABEL_LENGTH = 24
INDEX_LABEL_LENGTH = 32

JOB_FLAG_TYPES = [
    "continue",
    "force_save",
    "no_execute",
    "reserved1",
    "reserved2",
    "reserved3",
    "reserved4",
    "reserved5"
]

COMMS_MESSAGE_TYPES = {
    11: "MSG_REQUEST_CONFIG",
    12: "MSG_REQUEST_RST",
    13: "MSG_REQUEST_JOB_ADD",
    14: "MSG_REQUEST_JOB_PURGE",
    15: "MSG_REQUEST_JOB_REPORT",
    16: "MSG_REQUEST_QUIT",
    20: "MSG_RESPONSE_CONFIG",
    21: "MSG_RESPONSE_REPORT",
    22: "MSG_RESPONSE_RST"
}

JOB_REPORT_ITEMS = [
    "report_processor",
    "report_register",
    "report_virtual_memory",
    "report_physical_memory",
    "report_all_physical_memory",
    "report_all_virtual_memory",
    "report_error",
    "report_exception"
]

JOB_REPORT_TYPES = {
    1: JOB_REPORT_ITEMS[0],
    2: JOB_REPORT_ITEMS[1],
    4: JOB_REPORT_ITEMS[2],
    8: JOB_REPORT_ITEMS[3],
    16: JOB_REPORT_ITEMS[4],
    32: JOB_REPORT_ITEMS[5],
    64: JOB_REPORT_ITEMS[6],
    128: JOB_REPORT_ITEMS[7]
}

JOB_REPORT_IDS = {v: k for k, v in JOB_REPORT_TYPES.items()}

CONFIG_VALID_ITEMS = [
    "report_mask",
    "timeout_mask",
    "reserved1",
    "reserved2",
    "reserved3",
    "reserved4",
    "reserved5",
    "reserved6"
]

PURGE_ACTION_TYPES = {
    61: "purge_drop_results",
    62: "purge_send_results"
}

QUIT_ACTION_TYPES = {
    71: "quit_clean",
    72: "quit_now",
    73: "quit_kill"
}

JOB_ADD_TYPES = {
    31: "job_add_register",
    32: "job_add_memory",
    33: "job_add_exit_insn_count",
    34: "job_add_exit_insn_range",
    35: "job_add_exit_exception",
    36: "job_add_timeout",
    37: "job_add_stream"
}

MEMORY_TYPES = {
    1: "memory_virtual",
    2: "memory_physical"
}

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
                self.fmt = "@" + fmt
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
        return str(super(StrField, self).__bytes__())

    def __len__(self):
        return self.get_usedsize()

    def __call__(self, value):
        #print("Setting to "+value)
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

    def __int__(self):
        return self[0]

    def __str__(self):
        return str(self[0])

class XLongField(LongField):
    def __init__(self, name, default):
        super(XLongField, self).__init__(name, default)

    def __str__(self):
        return hex(int(self))

class SignedLongField(Field):
    def __init__(self, name, default):
        super(SignedLongField, self).__init__(name, default, "q")

    def __int__(self):
        return self[0]

    def __str__(self):
        return str(self[0])

class SHA1Field(Field):
    def __init__(self, name, default):
        super(SHA1Field, self).__init__(name, default, "5I")

    def __str__(self):
        return ''.join(["{:08x}".format(i) for i in self])

    def __call__(self, value):
        if not isinstance(value, str) or len(value) != 40:
            raise ValueError('%s must be a str of size 40.' % value)

        bhash = [int(value[i:i+8], 16) for i in range(0, 40, 8)]

        super(SHA1Field, self).__call__(bhash)

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
        # print("Call Setting ",self.get_name()," to ",str(value))
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
                        # print("FSF Setting ",f.get_name()," to ",str(v))
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
            # print("name is ", f.name)
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
        # print("Value is "+str(bytes(self.field_obj)))
        # print("Size is "+str(self.get_value(self.field_obj)))
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
                    # print("Setting ",f.name," to ", kwargs[f.name])
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

class CommsMessage(Packet):
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsMessage, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetEnumField("msg_id", None, COMMS_MESSAGE_TYPES),
                OctetField("version", 1),
                OctetField("has_next_message", 0),
                OctetField("reserved1", None),
                IntField("reserved2", None),
                LongField("size", 0)
            ],
            **kwargs)

    @staticmethod
    def sizeof_comms_message():
        if hasattr(CommsMessage, '_m_sizeof_comms_message'):
            return CommsMessage._m_sizeof_comms_message

        CommsMessage._m_sizeof_comms_message = len(CommsMessage().raw())
        return CommsMessage._m_sizeof_comms_message

    def build(self):
        super(CommsMessage, self).build()
        if self.payload is None:
            return

        if isinstance(self.payload, CommsRequestConfigMsg):
            self.msg_id = CommsRequestConfigMsg.TYPE_ID
        elif isinstance(self.payload, CommsRequestRapidSaveTreeMsg):
            self.msg_id = CommsRequestRapidSaveTreeMsg.TYPE_ID
        elif isinstance(self.payload, CommsRequestJobAddMsg):
            self.msg_id = CommsRequestJobAddMsg.TYPE_ID
        elif isinstance(self.payload, CommsRequestJobPurgeMsg):
            self.msg_id = CommsRequestJobPurgeMsg.TYPE_ID
        elif isinstance(self.payload, CommsRequestJobReportMsg):
            self.msg_id = CommsRequestJobReportMsg.TYPE_ID
        elif isinstance(self.payload, CommsRequestQuitMsg):
            self.msg_id = CommsRequestQuitMsg.TYPE_ID
        elif isinstance(self.payload, CommsResponseConfigMsg):
            self.msg_id = CommsResponseConfigMsg.TYPE_ID
        elif isinstance(self.payload, CommsResponseJobReportMsg):
            self.msg_id = CommsResponseJobReportMsg.TYPE_ID
        elif isinstance(self.payload, CommsResponseRapidSaveTreeMsg):
            self.msg_id = CommsResponseRapidSaveTreeMsg.TYPE_ID

        total_len = CommsMessage.sizeof_comms_message()
        if self.payload is not None:
            total_len += len(bytes(self.payload))
        self.size = total_len

    def guess_payload_class(self, payload):
        myid = int(self.msg_id)
        if myid == CommsRequestConfigMsg.TYPE_ID:
            return CommsRequestConfigMsg
        elif myid == CommsRequestRapidSaveTreeMsg.TYPE_ID:
            return CommsRequestRapidSaveTreeMsg
        elif myid == CommsRequestJobAddMsg.TYPE_ID:
            return CommsRequestJobAddMsg
        elif myid == CommsRequestJobPurgeMsg.TYPE_ID:
            return CommsRequestJobPurgeMsg
        elif myid == CommsRequestJobReportMsg.TYPE_ID:
            return CommsRequestJobReportMsg
        elif myid == CommsRequestQuitMsg.TYPE_ID:
            return CommsRequestQuitMsg
        elif myid == CommsResponseConfigMsg.TYPE_ID:
            return CommsResponseConfigMsg
        elif myid == CommsResponseJobReportMsg.TYPE_ID:
            return CommsResponseJobReportMsg
        elif myid == CommsResponseRapidSaveTreeMsg.TYPE_ID:
            return CommsResponseRapidSaveTreeMsg

        return Raw

class CommsRequestConfigMsg(Packet):
    TYPE_ID = 11
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsRequestConfigMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                FlagsField("report_mask", None, 8, JOB_REPORT_ITEMS),
                ShortField("reserved1", None),
                IntField("reserved2", None),
                FlagsField("valid_settings", None, 8, CONFIG_VALID_ITEMS),
                LongField("timeout", None)
            ],
            **kwargs)

class CommsRequestJobReportMsg(Packet):
    TYPE_ID = 15
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsRequestJobReportMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                FlagsField("report_mask", None, 8, JOB_REPORT_ITEMS),
                ShortField("reserved1", None),
                SignedIntField("job_id", None),
                SHA1Field("job_hash", None)
            ],
            **kwargs)


class CommsRequestRapidSaveTreeMsg(Packet):
    TYPE_ID = 12
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsRequestRapidSaveTreeMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                SignedIntField("job_id", None)
            ],
            **kwargs)


class CommsRequestJobPurgeMsg(Packet):
    TYPE_ID = 14
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsRequestJobPurgeMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                OctetEnumField("action", None, PURGE_ACTION_TYPES),
            ],
            **kwargs)

class CommsRequestQuitMsg(Packet):
    TYPE_ID = 16
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsRequestQuitMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetEnumField("how", None, QUIT_ACTION_TYPES),
            ],
            **kwargs)


class CommsResponseConfigMsg(Packet):
    TYPE_ID = 20
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsResponseConfigMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                FlagsField("report_mask", None, 8, JOB_REPORT_ITEMS),
                ShortField("reserved1", None),
                IntField("reserved2", None),
                LongField("timeout", None)
            ],
            **kwargs)

class CommsRequestJobAddMsg(Packet):
    TYPE_ID = 13
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsRequestJobAddMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                FlagsField("flags", 0, 8, JOB_FLAG_TYPES),
                ShortField("reserved1", None),
                SignedIntField("job_id", None),
                SHA1Field("base_hash", None),
                FieldListField("entries", [], JobAddEntry)
            ],
            **kwargs)

    def add_optional_fields(self, raw_payload):
        end_data = len(self.packet_data)
        options_data = raw_payload[end_data:]
        job_entry_fields = []

        while options_data:
            opt = Packet(options_data, _fields=[JobAddEntry("peek")])

            opt_num = int(opt.peek["entry_type"])
            job_entry = JobAddEntry.get_job_entry(opt_num)
            job_entry_fields.append(job_entry)

            # Parse this field to get the next set of options data
            opt_pkt = Packet(options_data, _fields=[job_entry])
            try:
                # Get the remaining options data
                options_data = opt_pkt[Raw].raw()
            except IndexError:
                break

        if job_entry_fields:
            self.entries = job_entry_fields

class JobAddEntry(FieldStructField):
    def __init__(self, name, job_fields=[], **kwargs):
        super(JobAddEntry, self).__init__(
            name = name,
            fields = [OctetEnumField("entry_type", None, JOB_ADD_TYPES)] +
                   job_fields,
                   **kwargs)

    @staticmethod
    def get_job_entry(etype):
        if etype == CommsRequestJobAddExitInsnCountConstraint.TYPE_ID:
            return CommsRequestJobAddExitInsnCountConstraint()
        elif etype == CommsRequestJobAddTimeoutSetup.TYPE_ID:
            return CommsRequestJobAddTimeoutSetup()
        elif etype == CommsRequestJobAddRegisterSetup.TYPE_ID:
            return CommsRequestJobAddRegisterSetup()
        elif etype == CommsRequestJobAddStreamSetup.TYPE_ID:
            return CommsRequestJobAddStreamSetup()
        elif etype == CommsRequestJobAddExitExceptionConstraint.TYPE_ID:
            return CommsRequestJobAddExitExceptionConstraint()
        elif etype == CommsRequestJobAddMemorySetup.TYPE_ID:
            return CommsRequestJobAddMemorySetup()
        elif etype == CommsRequestJobAddExitInsnRangeConstraint.TYPE_ID:
            return CommsRequestJobAddExitInsnRangeConstraint()
        return None

class CommsRequestJobAddExitInsnCountConstraint(JobAddEntry):
    TYPE_ID = 33
    def __init__(self, **kwargs):
        super(CommsRequestJobAddExitInsnCountConstraint, self).__init__(
            name = CommsRequestJobAddExitInsnCountConstraint.__name__,
            entry_type = CommsRequestJobAddExitInsnCountConstraint.TYPE_ID,
            job_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("reserved3", None),
                LongField("insn_limit", 0)
            ],
            **kwargs)

class CommsRequestJobAddTimeoutSetup(JobAddEntry):
    TYPE_ID = 36
    def __init__(self, **kwargs):
        super(CommsRequestJobAddTimeoutSetup, self).__init__(
            name = CommsRequestJobAddTimeoutSetup.__name__,
            entry_type = CommsRequestJobAddTimeoutSetup.TYPE_ID,
            job_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("reserved3", None),
                LongField("timeout", 0)
            ],
            **kwargs)

class CommsRequestJobAddRegisterSetup(JobAddEntry):
    TYPE_ID = 31
    def __init__(self, **kwargs):
        register_value = StrField("value", None)
        super(CommsRequestJobAddRegisterSetup, self).__init__(
            name = CommsRequestJobAddRegisterSetup.__name__,
            entry_type = CommsRequestJobAddRegisterSetup.TYPE_ID,
            job_fields = [
                OctetField("id", None),
                FieldLenField("size", None, fmt="B", size_of=register_value),
                StrFixedLenField("name", None, NAME_LENGTH),
                register_value
            ],
            **kwargs)

class CommsRequestJobAddStreamSetup(JobAddEntry):
    TYPE_ID = 37
    def __init__(self, **kwargs):
        stream_value = StrField("value", None)
        super(CommsRequestJobAddStreamSetup, self).__init__(
            name = CommsRequestJobAddStreamSetup.__name__,
            entry_type = CommsRequestJobAddStreamSetup.TYPE_ID,
            job_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("fileno", None),
                FieldLenField("size", None, fmt="I", size_of=stream_value),
                ShortField("reserved3", None),
                OctetField("reserved4", None),
                stream_value
            ],
            **kwargs)

class CommsRequestJobAddExitExceptionConstraint(JobAddEntry):
    TYPE_ID = 35
    def __init__(self, **kwargs):
        super(CommsRequestJobAddExitExceptionConstraint, self).__init__(
            name = CommsRequestJobAddExitExceptionConstraint.__name__,
            entry_type = CommsRequestJobAddExitExceptionConstraint.TYPE_ID,
            job_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("reserved3", None),
                LongField("mask", None)
            ],
            **kwargs)

class CommsRequestJobAddMemorySetup(JobAddEntry):
    TYPE_ID = 32
    def __init__(self, **kwargs):
        memory_value = StrField("value", None)
        super(CommsRequestJobAddMemorySetup, self).__init__(
            name = CommsRequestJobAddMemorySetup.__name__,
            entry_type = CommsRequestJobAddMemorySetup.TYPE_ID,
            job_fields = [
                OctetEnumField("flags", None, MEMORY_TYPES),
                ShortField("reserved1", None),
                FieldLenField("size", None, fmt="I", size_of=memory_value),
                LongField("offset", None),
                IntField("reserved2", None),
                ShortField("reserved3", None),
                OctetField("reserved4", None),
                memory_value
            ],
            **kwargs)

class CommsRequestJobAddExitInsnRangeConstraint(JobAddEntry):
    TYPE_ID = 34
    def __init__(self, **kwargs):
        super(CommsRequestJobAddExitInsnRangeConstraint, self).__init__(
            name = CommsRequestJobAddExitInsnRangeConstraint.__name__,
            entry_type = CommsRequestJobAddExitInsnRangeConstraint.TYPE_ID,
            job_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("block_size", None),
                LongField("offset", None)
            ],
            **kwargs)

class JobReportList(FieldListField):
    def __init__(self, name, default=[]):
        super(JobReportList, self).__init__(name, default, JobReportEntry)

    def __str__(self):
        s = '[\n'
        for f in self.fields:
            fstr = str(f)
            if fstr:
                s += str(f)
            s += '\n'
        if len(s) > 1:
            s = s[:-1]
        s += ']'
        return s

class CommsResponseJobReportMsg(Packet):
    TYPE_ID = 21
    def __init__(self, _pkt=b"", **kwargs):
        super(CommsResponseJobReportMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                OctetField("reserved1", 0),
                ShortField("reserved2", None),
                SignedIntField("job_id", None),
                IntField("num_insns", None),
                SHA1Field("job_hash", None),
                JobReportList("entries", [])
            ],
            **kwargs)

    def add_optional_fields(self, raw_payload):
        end_data = len(self.packet_data)
        options_data = raw_payload[end_data:]
        report_entry_fields = []

        while options_data:
            opt = Packet(options_data, _fields=[JobReportEntry("peek")])

            opt_num = int(opt.peek["entry_type"])
            report_entry = JobReportEntry.get_report_entry(opt_num)
            report_entry_fields.append(report_entry)

            # Parse this field to get the next set of options data
            opt_pkt = Packet(options_data, _fields=[report_entry])
            try:
                # Get the remaining options data
                options_data = opt_pkt[Raw].raw()
            except IndexError:
                break

        if report_entry_fields:
            self.entries = report_entry_fields

class JobReportEntry(FieldStructField):
    JOB_REPORT_HEADERS = {
        "report_processor": "Processor> ",
        "report_register": "Register> ",
        "report_virtual_memory": "VirtMemory> ",
        "report_physical_memory": "PhysMemory> ",
        "report_all_physical_memory": "PhysMemory> ",
        "report_all_virtual_memory": "VirtMemory> ",
        "report_error": "Error> ",
        "report_exception": "Exception> "
    }
    def __init__(self, name, report_fields=[], **kwargs):
        super(JobReportEntry, self).__init__(
            name = name,
            fields = [OctetEnumField("entry_type", None, JOB_REPORT_TYPES)] +
                   report_fields,
                   **kwargs)

    def __str__(self):
        s = '('
        for f in self.fields:
            if f.name.startswith("reserved"):
                continue
            elif f.name == "entry_type":
                s += JobReportEntry.JOB_REPORT_HEADERS[str(f)]
            else:
                contents = str(f)
                if len(contents) > 32:
                    s += f.name + ': ' + contents[:32] + '..., '
                else:
                    s += f.name + ': ' + contents + ', '
        if len(s) > 1:
            s = s[:-2]
        s += ')'
        return s

    @staticmethod
    def get_report_entry(etype):
        if etype == CommsResponseJobReportRegisterEntry.TYPE_ID:
            return CommsResponseJobReportRegisterEntry()
        elif etype == CommsResponseJobReportProcessorEntry.TYPE_ID:
            return CommsResponseJobReportProcessorEntry()
        elif etype == CommsResponseJobReportAllPhysicalMemoryEntry.TYPE_ID:
            return CommsResponseJobReportAllPhysicalMemoryEntry()
        elif etype == CommsResponseJobReportAllVirtualMemoryEntry.TYPE_ID:
            return CommsResponseJobReportAllVirtualMemoryEntry()
        elif etype == CommsResponseJobReportPhysicalMemoryEntry.TYPE_ID:
            return CommsResponseJobReportPhysicalMemoryEntry()
        elif etype == CommsResponseJobReportVirtualMemoryEntry.TYPE_ID:
            return CommsResponseJobReportVirtualMemoryEntry()
        elif etype == CommsResponseJobReportExceptionEntry.TYPE_ID:
            return CommsResponseJobReportExceptionEntry()
        elif etype == CommsResponseJobReportErrorEntry.TYPE_ID:
            return CommsResponseJobReportErrorEntry()
        return None

class CommsResponseJobReportRegisterEntry(JobReportEntry):
    TYPE_ID = 2
    def __init__(self, **kwargs):
        register_value = XStrField("value", None)
        super(CommsResponseJobReportRegisterEntry, self).__init__(
            name = CommsResponseJobReportRegisterEntry.__name__,
            entry_type = CommsResponseJobReportRegisterEntry.TYPE_ID,
            report_fields = [
                OctetField("id", None),
                FieldLenField("size", None, fmt="B", size_of=register_value),
                OctetField("reserved1", None),
                IntField("reserved2", None),
                StrFixedLenField("name", None, NAME_LENGTH),
                register_value
            ],
            **kwargs)

class CommsResponseJobReportProcessorEntry(JobReportEntry):
    TYPE_ID = 1
    def __init__(self, **kwargs):
        super(CommsResponseJobReportProcessorEntry, self).__init__(
            name = CommsResponseJobReportProcessorEntry.__name__,
            entry_type = CommsResponseJobReportProcessorEntry.TYPE_ID,
            report_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("reserved3", None),
                IntField("reserved4", None),
                StrFixedLenField("name", None, NAME_LENGTH),
                OctetField("cpu_id", None),
            ],
            **kwargs)

class CommsResponseJobReportMemoryEntry(JobReportEntry):
    def __init__(self, **kwargs):
        memory_value = XStrField("value", None)
        super(CommsResponseJobReportMemoryEntry, self).__init__(
            report_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                FieldLenField("size", None, fmt="I", size_of=memory_value),
                LongField("offset", None),
                IntField("reserved3", None),
                ShortField("reserved4", None),
                OctetField("reserved5", None),
                memory_value,
            ],
            **kwargs)

class CommsResponseJobReportAllPhysicalMemoryEntry(CommsResponseJobReportMemoryEntry):
    TYPE_ID = 16
    def __init__(self, **kwargs):
        super(CommsResponseJobReportAllPhysicalMemoryEntry, self).__init__(
            name = CommsResponseJobReportAllPhysicalMemoryEntry.__name__,
            entry_type = CommsResponseJobReportAllPhysicalMemoryEntry.TYPE_ID
        )

class CommsResponseJobReportAllVirtualMemoryEntry(CommsResponseJobReportMemoryEntry):
    TYPE_ID = 32
    def __init__(self, **kwargs):
        super(CommsResponseJobReportAllVirtualMemoryEntry, self).__init__(
            name = CommsResponseJobReportAllVirtualMemoryEntry.__name__,
            entry_type = CommsResponseJobReportAllVirtualMemoryEntry.TYPE_ID
        )

class CommsResponseJobReportVirtualMemoryEntry(CommsResponseJobReportMemoryEntry):
    TYPE_ID = 4
    def __init__(self, **kwargs):
        super(CommsResponseJobReportVirtualMemoryEntry, self).__init__(
            name = CommsResponseJobReportVirtualMemoryEntry.__name__,
            entry_type = CommsResponseJobReportVirtualMemoryEntry.TYPE_ID
        )

class CommsResponseJobReportPhysicalMemoryEntry(CommsResponseJobReportMemoryEntry):
    TYPE_ID = 8
    def __init__(self, **kwargs):
        super(CommsResponseJobReportPhysicalMemoryEntry, self).__init__(
            name = CommsResponseJobReportPhysicalMemoryEntry.__name__,
            entry_type = CommsResponseJobReportPhysicalMemoryEntry.TYPE_ID
        )

class CommsResponseJobReportExceptionEntry(JobReportEntry):
    TYPE_ID = 128
    def __init__(self, **kwargs):
        super(CommsResponseJobReportExceptionEntry, self).__init__(
            name = CommsResponseJobReportExceptionEntry.__name__,
            entry_type = CommsResponseJobReportExceptionEntry.TYPE_ID,
            report_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("reserved3", None),
                XLongField("exception_mask", None),
            ],
            **kwargs)        

class CommsResponseJobReportErrorEntry(JobReportEntry):
    TYPE_ID = 64
    def __init__(self, **kwargs):
        super(CommsResponseJobReportErrorEntry, self).__init__(
            name = CommsResponseJobReportErrorEntry.__name__,
            entry_type = CommsResponseJobReportErrorEntry.TYPE_ID,
            report_fields = [
                OctetField("reserved1", None),
                ShortField("reserved2", None),
                IntField("error_id", None),
                StrFixedLenField("error_text", None, ERROR_TEXT_LENGTH),
                LongField("error_loc", None),
            ],
            **kwargs)

class CommsResponseRapidSaveTreeMsg(Packet):
    TYPE_ID = 22
    def __init__(self, _pkt=b"", **kwargs):
        tree_insns = FieldListField("tree_insns", [], RSTInstructionEntry)
        super(CommsResponseRapidSaveTreeMsg, self).__init__(
            _pkt = _pkt,
            _klass = self.__class__,
            _fields = [
                OctetField("queue", 1),
                OctetField("reserved1", 0),
                ShortField("reserved2", None),
                SignedIntField("job_id", None),
                FieldLenField("num_insns", None, fmt="Q", length_of=tree_insns),
                tree_insns
            ],
            **kwargs)

class RSTInstructionEntry(FieldStructField):
    def __init__(self, **kwargs):
        tree_nodes = FieldListField("tree_nodes", [], RSTNodeEntry)
        super(RSTInstructionEntry, self).__init__(
            name = RSTInstructionEntry.__name__,
            fields = [
                StrFixedLenField("label", None, INSN_LABEL_LENGTH),
                FieldLenField("num_nodes", None, fmt="Q", length_of=tree_nodes),
                tree_nodes
            ],
            **kwargs)

class RSTNodeEntry(FieldStructField):
    def __init__(self, **kwargs):
        tree_indices = FieldListField("tree_nodes", [], RSTNodeIndexEntry)
        super(RSTNodeEntry, self).__init__(
            name = RSTNodeEntry.__name__,
            fields = [
                IntField("index_offset", None),
                IntField("state_offset", None),
                SignedIntField("job_id", None),
                FieldLenField("num_indices", None, fmt="I", length_of=tree_indices),
                SignedLongField("timestamp", None),
                LongField("instruction_number", None),
                LongField("cpu_exception_index", None),
                tree_indices,
                RSTNodeStateEntry()
            ],
            **kwargs)

class RSTNodeIndexEntry(FieldStructField):
    def __init__(self, **kwargs):
        super(RSTNodeIndexEntry, self).__init__(
            name = RSTNodeIndexEntry.__name__,
            fields = [
                StrFixedLenField("label", None, INDEX_LABEL_LENGTH),
                IntField("instance_id", None),
                IntField("section_id", None),
                LongField("offset", None)
            ],
            **kwargs)

class RSTNodeStateEntry(FieldStructField):
    def __init__(self, **kwargs):
        state_value = StrField("state", None)
        super(RSTNodeStateEntry, self).__init__(
            name = RSTNodeStateEntry.__name__,
            fields = [
                FieldLenField("size", None, fmt="I", size_of=state_value),
                ShortField("reserved1", None),
                OctetField("reserved2", None),
                state_value
            ],
            **kwargs)