from argparse import ArgumentParser
from sys import exit

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
        self.value = reader.read_int()


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
        self.value = reader.read_long()


class ConstantItemClassReference(ConstantItem):
    def __init__(self):
        self.name = 'ClassReference'
        self.tag_id = 7

    def read_data(self, reader):
        self.value = reader.read_short()


class ConstantItemStringReference(ConstantItem):
    def __init__(self):
        self.name = 'StringReference'
        self.tag_id = 8

    def read_data(self, reader):
        self.value = reader.read_short()


class ConstantItemFieldReference(ConstantItem):
    def __init__(self):
        self.name = 'FieldReference'
        self.tag_id = 9

    def read_data(self, reader):
        self.value = reader.read_int()


class ConstantItemMethodReference(ConstantItem):
    def __init__(self):
        self.name = 'MethodReference'
        self.tag_id = 10

    def read_data(self, reader):
        self.value = reader.read_int()


class ConstantItemInterfaceMethodReference(ConstantItem):
    def __init__(self):
        self.name = 'InterfaceMethodReference'
        self.tag_id = 11

    def read_data(self, reader):
        self.value = reader.read_int()


class ConstantItemNameTypeDescriptor(ConstantItem):
    def __init__(self):
        self.name = 'NameTypeDescriptor'
        self.tag_id = 12

    def read_data(self, reader):
        self.value = reader.read_int()


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


class Field:
    access_flags = 0
    name_index = 0
    descriptor_index = 0
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

    def has_access_modifier(self, modifier):
        return (self.flags[modifier] & access_flags) != 0


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

        self.access_flags = self.reader.read_short()

        access_flags = self.reader.read_short()
        clazz.set_access_flags(access_flags)

        class_name = pool.get(self.reader.read_short()).get_value()
        clazz.set_class_name(class_name)

        superclass_name = pool.get(self.reader.read_short()).get_value()
        clazz.set_superclass_name(superclass_name)

        self.read_interface_table(clazz)

        for i in range(pool.size):
            item = pool.get(i)
            print (i, item.name, item.get_value())

        #self.read_fields(clazz, pool)

        print self.reader.pos

    def read_constant_pool(self, clazz):
        pool = ConstantPool(self.reader.read_short())

        # Parse Constant Pool
        for i in range(pool.size - 1):
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

        return pool

    def read_interface_table(self, clazz):
        size = self.reader.read_byte()
        #size = self.reader.read_short()

        for i in range(size):
            self.reader.read_byte()

        return None

    def read_fields(self, clazz, pool):
        size = self.reader.read_short()

        for i in range(size):
            print i
            field = Field()
            field.access_flags = self.reader.read_short()
            field.name_index = self.reader.read_short()
            field.descriptor_index = self.reader.read_short()
            field.attributes_count = self.reader.read_short()

            for j in range(field.attributes_count):
                name_index = self.reader.read_short()
                attribute_length = self.reader.read_short()

                print pool.get(attr.name_index).get_value()

                if pool.get(attr.name_index) == 'ConstantValue':
                    attr = AttributeConstantValue()
                    attr.constantvalue_index = self.reader.read_short()

                attr.name_index = name_index
                attr.attribute_length = attribute_length
                self.reader.read(self.attribute_length)

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
