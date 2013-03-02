from argparse import ArgumentParser
from sys import exit
import decimal

"""
Author:      Kyle Stevenson
Date:        February 6th 2012
Description: Used to take apart Java class files and parse the bytecode.
             Not sure if this will be used to compile said bytecode back into
             Java source or not but it will be a fun project none the less.
"""


class ConstantItem:
    name = None
    value = None
    tag_id = 0

    def read_data(self):
        raise "implement"

    def get_value(self):
        return self.value


class ConstantItemUTF8String(ConstantItem):
    def __init__(self):
        self.name = 'UTF8 String'
        self.tag_id = 1

    def read_data(self, reader):
        self.value = reader.read(reader.read_short())

    def get_value(self):
        w = ''

        for b in self.value:
            w += b

        return w


class ConstantItemInteger(ConstantItem):
    def __init__(self):
        self.name = 'Integer'
        self.tag_id = 3

    def read_data(self, reader):
        self.value = reader.read_int()


class ConstantItemFloat(ConstantItem):
    def __init__(self):
        self.name = 'Float'
        self.tag_id = 4

    def read_data(self, reader):
        d = reader.read_int()
        e = (d >> 23) & 0xff
        m = (d & 0x7fffff) << 1 if e == 0 else (d & 0x7fffff) | 0x800000
        self.value = float((1 if d >> 31 == 0 else -1) * m *
                           (2 ** (((d >> 23) & 0xff) - 150)))


class ConstantItemLong(ConstantItem):
    def __init__(self):
        self.name = 'Long'
        self.tag_id = 5

    def read_data(self, reader):
        self.value = reader.read_long()


class ConstantItemDouble(ConstantItem):
    def __init__(self):
        self.name = 'Double'
        self.tag_id = 6

    def read_data(self, reader):
        d = reader.read_long()
        e = int((d >> 52) & 0x7ffL)
        mask_d = d & 0xfffffffffffffL
        o_mask = 0x10000000000000L

        return Decimal((1 if d >> 63 == 0 else -1) * e *
                       mask_d << 1 if e == 0 else mask_d | o_mask)


class ConstantItemClassReference(ConstantItem):
    def __init__(self):
        self.name = 'ClassReference'
        self.tag_id = 7

    def read_data(self, reader):
        self.value = {'type': reader.read_short()}


class ConstantItemStringReference(ConstantItem):
    def __init__(self):
        self.name = 'StringReference'
        self.tag_id = 8

    def read_data(self, reader):
        self.value = {'type': reader.read_short()}


class ConstantItemFieldReference(ConstantItem):
    def __init__(self):
        self.name = 'FieldReference'
        self.tag_id = 9

    def read_data(self, reader):
        self.value = {'name': reader.read_short(), 'type': reader.read_short()}


class ConstantItemMethodReference(ConstantItem):
    def __init__(self):
        self.name = 'MethodReference'
        self.tag_id = 10

    def read_data(self, reader):
        self.value = {'name': reader.read_short(), 'type': reader.read_short()}


class ConstantItemInterfaceMethodReference(ConstantItem):
    def __init__(self):
        self.name = 'InterfaceMethodReference'
        self.tag_id = 11

    def read_data(self, reader):
        self.value = {'name': reader.read_short(), 'type': reader.read_short()}


class ConstantItemNameTypeDescriptor(ConstantItem):
    def __init__(self):
        self.name = 'NameTypeDescriptor'
        self.tag_id = 12

    def read_data(self, reader):
        self.value = {'name': reader.read_short(), 'type': reader.read_short()}


class ConstantPool:
    size = 0
    pool = None
    constant_types = {1: 'UTF8 String', 3: 'Integer', 4: 'Float', 5: 'Long',
                      6: 'Double', 7: 'ClassReference', 8: 'StringReference',
                      9: 'FieldReference', 10: 'MethodReference',
                      11: 'InterfaceMethodReference', 12: 'NameTypeDescriptor'}

    def __init__(self, size):
        self.size = size
        self.pool = []

    def add(self, item):
        self.pool.append(item)

    def get(self, index):
        return self.pool[index]

    def get_value(self, index):
        item = self.pool[index]

        if item.tag_id == 7:
            return self.index[item.value['type']].get_value()
        elif item.tag_id == 12:
            return {'name': self.get(item.value['name']).get_value(),
                    'type': self.get(item.value['type']).get_value()}
        else:
            return self.pool[index].get_value()


class Field:
    access_flags = 0
    name_index = 0
    name = None
    descriptor_index = 0
    descriptor = None
    attributes_count = 0
    attributes = []
    flags = {
        'public': 0x0001,
        'private': 0x0002,
        'protected': 0x0004,
        'static': 0x0008,
        'final': 0x0010,
        'volatile': 0x0040,
        'transient': 0x0080
    }

    def get_modifiers_list(self):
        af = self.access_flags
        return [f for f in self.flags if (af & self.flags[f]) != 0]

    def has_access_modifier(self, modifier):
        return (self.flags[modifier] & self.access_flags) != 0


class Attribute:
    attribute_name_index = 0
    attribute_length = 0


class AttributeConstantValue(Attribute):
    constantvalue_index = 0


class AttributeSynthetic(Attribute):
    """"""


class AttributeDeprepricated(Attribute):
    """"""


class JavaClass:
    constant_pool = None
    access_flags = 0
    superclass_name = ''
    class_name = ''
    fields = []
    version = {'major': 0, 'minor': 0}
    flags = {'public': 0x0001, 'private': 0x0002, 'protected': 0x0004,
             'static': 0x0008, 'final': 0x0010, 'volatile': 0x0040,
             'transient': 0x0080}

    def get_jdk_major_version(self):
        return self.version['major']

    def set_jdk_major_version(self, version):
        self.version['major'] = version

    def get_jdk_minor_version(self):
        return self.version['minor']

    def set_jdk_minor_version(self, version):
        self.version['minor'] = version

    def get_superclass_name(self):
        return self.superclass_name

    def set_superclass_name(self, name):
        self.superclass_name = name

    def get_class_name(self):
        return self.class_name

    def set_class_name(self, name):
        self.class_name = name

    def set_access_flags(self, flags):
        self.access_flags = flags

    def has_access_modifier(self, modifier):
        return (access_flags & self.flags[modifier]) != 0

    def add_field(self, field):
        self.fields.append(field)

    def get_constant_pool(self):
        return self.constant_pool

    def set_constant_pool(self, pool):
        self.constant_pool = pool


class ClassParser:
    jdk_versions = {
        51: 'JDK 7',
        50: 'JDK 6',
        49: 'JDK 5',
        48: 'JDK 1.4',
        47: 'JDK 1.3',
        46: 'JDK 1.2',
        45: 'JDK 1.1'
    }

    def __init__(self, file):
        self.file = file
        self.reader = Reader()

    def parse_class(self):
        clazz = JavaClass()
        self.reader.load_class(self.file)

        if self.reader.read_int() != 0xCAFEBABE:
            raise Exception('Not a valid Java class file')

        clazz.set_jdk_minor_version(self.reader.read_short())
        clazz.set_jdk_major_version(self.reader.read_short())

        print 'SDK Version:', self.jdk_versions[clazz.get_jdk_major_version()]

        pool = self.read_constant_pool(clazz)
        clazz.set_constant_pool(pool)

        for i in range(1, pool.size):
            item = pool.get(i)

            if item is None:
                continue

            print (i, item.name, item.get_value())

        access_flags = pool.get(self.reader.read_short()).get_value()
        clazz.set_access_flags(access_flags)

        class_name = pool.get_value(self.reader.read_short())
        clazz.set_class_name(class_name)

        superclass_name = pool.get_value(self.reader.read_short())
        clazz.set_superclass_name(superclass_name)

        self.read_interface_table(clazz)

        self.read_fields(clazz, pool)

        print self.reader.pos

    def read_constant_pool(self, clazz):
        pool = ConstantPool(self.reader.read_short())
        pool.add(None)

        # Parse Constant Pool
        for i in range(1, pool.size):
            item = None
            tag = self.reader.read_byte()

            if tag == 1:
                item = ConstantItemUTF8String()
            elif tag == 3:
                item = ConstantItemInteger()
            elif tag == 4:
                item = ConstantItemFloat()
            elif tag == 5:
                item = ConstantItemLong()
            elif tag == 6:
                item = ConstantItemDouble()
            elif tag == 7:
                item = ConstantItemClassReference()
            elif tag == 8:
                item = ConstantItemStringReference()
            elif tag == 9:
                item = ConstantItemFieldReference()
            elif tag == 10:
                item = ConstantItemMethodReference()
            elif tag == 11:
                item = ConstantItemInterfaceMethodReference()
            elif tag == 12:
                item = ConstantItemNameTypeDescriptor()

            if not item is None:
                item.read_data(self.reader)
                pool.add(item)

                if tag in (5, 6):
                    pool.add(None)
            else:
                print 'Tag %s not found for cp index %s' % (tag, i)
                self.reader.pos -= 1
                break

        return pool

    def read_interface_table(self, clazz):
        size = self.reader.read_short()

        for i in range(size):
            self.reader.read_byte()

        return None

    def read_fields(self, clazz, pool):
        size = self.reader.read_short()

        for i in range(size):
            field = Field()
            field.access_flags = self.reader.read_short()
            field.name_index = self.reader.read_short()
            field.name = pool.get(field.name_index).get_value()
            field.descriptor_index = self.reader.read_short()
            field.descriptor = pool.get(field.descriptor_index).get_value()
            field.attributes_count = self.reader.read_short()

            for j in range(field.attributes_count):
                name_index = self.reader.read_short()
                attribute_length = self.reader.read_short()

                if pool.get(name_index).get_value() == 'ConstantValue':
                    attr = AttributeConstantValue()
                    attr.constantvalue_index = self.reader.read_short()
                else:
                    print pool.get(name_index).get_value()
                    attr = Attribute()

                attr.name_index = name_index
                attr.attribute_length = attribute_length
                self.reader.read(attr.attribute_length)

                field.attributes.append(attr)

            clazz.add_field(clazz)


class Reader:
    pos = -1
    buff = None
    pool = None

    def read_byte(self):
        self.pos += 1
        return ord(self.buff[self.pos])

    def read_short(self):
        return (self.read_byte() << 8) + self.read_byte()

    def read_int(self):
        return (self.read_short() << 16) + self.read_short()

    def read_long(self):
        return (self.read_int() << 32) + self.read_int()

    def read_hex(self, n):
        return hex(n)[2:]

    def read(self, length):
        b = []

        for i in range(length):
            self.pos += 1
            b.append(self.buff[self.pos])

        return b

    def load_class(self, file):
        with open(file, 'rb') as f:
            self.buff = f.read()


def main(args):
    if args.classfile is None:
        return 'ERROR: Please pass in a classfile to parse via --classfile'

    parser = ClassParser(args.classfile)
    parser.parse_class()

if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-c', '--classfile')
    args = arg_parser.parse_args()
    exit(main(args))
