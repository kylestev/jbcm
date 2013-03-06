from argparse import ArgumentParser
from sys import exit
import decimal
import re
from reader import Reader
from attributes import (Parsable, Attribute)
from constant_pool import ConstantPool

"""
Author:      Kyle Stevenson
Date:        February 6th 2012
Description: Used to take apart Java class files and parse the bytecode.
             Not sure if this will be used to compile said bytecode back into
             Java source or not but it will be a fun project none the less.
"""

RE_SIG = (r'\((?:\[*(B|C|D|F|I|J|S|Z|(?:L[a-zA-Z]+(?:/[a-zA-Z/<>]*)))+;?)*\)'
          '\[*(B|C|D|F|I|J|S|V|Z|(?:L[a-zA-Z]+(?:/[a-zA-Z/<>]*)));?')

CLASS_FLAGS = {'public': 0x01, 'private': 0x02, 'protected': 0x04,
               'static': 0x08, 'final': 0x10, 'volatile': 0x40,
               'transient': 0x80}

FIELD_FLAGS = {'public': 0x01, 'private': 0x02, 'protected': 0x04,
               'static': 0x08, 'final': 0x10, 'volatile': 0x40,
               'transient': 0x80}

METHOD_FLAGS = {'public': 0x01, 'private': 0x02, 'protected': 0x04,
                'static': 0x08, 'final': 0x10, 'synchronized': 0x20,
                'native': 0x0100, 'abstract': 0x0400, 'strict': 0x0800}


class Bytecode:
    op_codes = {
        'AALOAD': 0x32, 'AASTORE': 0x53, 'ACONST_NULL': 0x01, 'ALOAD': 0x19,
        'ALOAD_0': 0x2a, 'ALOAD_1': 0x2b, 'ALOAD_2': 0x2c, 'ALOAD_3': 0x2d,
        'ANEWARRAY': 0xbd, 'ARETURN': 0xb0, 'ARRAYLENGTH': 0xbe,
        'ASTORE': 0x3a, 'ASTORE_0': 0x4b, 'ASTORE_1': 0x4c, 'ASTORE_2': 0x4d,
        'ASTORE_3': 0x4e, 'ATHROW': 0xbf, 'BALOAD': 0x33, 'BASTORE': 0x54,
        'BIPUSH': 0x10, 'BREAKPOINT': 0xca, 'CALOAD': 0x34, 'CASTORE': 0x55,
        'CHECKCAST': 0xc0, 'D2F': 0x90, 'D2I': 0x8e, 'D2L': 0x8f, 'DADD': 0x63,
        'DALOAD': 0x31, 'DASTORE': 0x52, 'DCMPG': 0x98, 'DCMPL': 0x97,
        'DCONST_0': 0x0e, 'DCONST_1': 0x0f, 'DDIV': 0x6f, 'DLOAD': 0x18,
        'DLOAD_0': 0x26, 'DLOAD_1': 0x27, 'DLOAD_2': 0x28, 'DLOAD_3': 0x29,
        'DMUL': 0x6b, 'DNEG': 0x77, 'DREM': 0x73, 'DRETURN': 0xaf,
        'DSTORE': 0x39, 'DSTORE_0': 0x47, 'DSTORE_1': 0x48, 'DSTORE_2': 0x49,
        'DSTORE_3': 0x4a, 'DSUB': 0x67, 'DUP': 0x59, 'DUP2': 0x5c,
        'DUP2_X1': 0x5d, 'DUP2_X2': 0x5e, 'DUP_X1': 0x5a, 'DUP_X2': 0x5b,
        'F2D': 0x8d, 'F2I': 0x8b, 'F2L': 0x8c, 'FADD': 0x62, 'FALOAD': 0x30,
        'FASTORE': 0x51, 'FCMPG': 0x96, 'FCMPL': 0x95, 'FCONST_0': 0x0b,
        'FCONST_1': 0x0c, 'FCONST_2': 0x0d, 'FDIV': 0x6e, 'FLOAD': 0x17,
        'FLOAD_0': 0x22, 'FLOAD_1': 0x23, 'FLOAD_2': 0x24, 'FLOAD_3': 0x25,
        'FMUL': 0x6a, 'FNEG': 0x76, 'FREM': 0x72, 'FRETURN': 0xae,
        'FSTORE': 0x38, 'FSTORE_0': 0x43, 'FSTORE_1': 0x44, 'FSTORE_2': 0x45,
        'FSTORE_3': 0x46, 'FSUB': 0x66, 'GETFIELD': 0xb4, 'GETSTATIC': 0xb2,
        'GOTO': 0xa7, 'GOTO_W': 0xc8, 'I2B': 0x91, 'I2C': 0x92, 'I2D': 0x87,
        'I2F': 0x86, 'I2L': 0x85, 'I2S': 0x93, 'IADD': 0x60, 'IALOAD': 0x2e,
        'IAND': 0x7e, 'IASTORE': 0x4f, 'ICONST_0': 0x03, 'ICONST_1': 0x04,
        'ICONST_2': 0x05, 'ICONST_3': 0x06, 'ICONST_4': 0x07, 'ICONST_5': 0x08,
        'ICONST_M1': 0x02, 'IDIV': 0x6c, 'IF_ACMPEQ': 0xa5, 'IF_ACMPNE': 0xa6,
        'IF_ICMPEQ': 0x9f, 'IF_ICMPGE': 0xa2, 'IF_ICMPGT': 0xa3,
        'IF_ICMPLE': 0xa4, 'IF_ICMPLT': 0xa1, 'IF_ICMPNE': 0xa0, 'IFEQ': 0x99,
        'IFGE': 0x9c, 'IFGT': 0x9d, 'IFLE': 0x9e, 'IFLT': 0x9b, 'IFNE': 0x9a,
        'IFNONNULL': 0xc7, 'IFNULL': 0xc6, 'IINC': 0x84, 'ILOAD': 0x15,
        'ILOAD_0': 0x1a, 'ILOAD_1': 0x1b, 'ILOAD_2': 0x1c, 'ILOAD_3': 0x1d,
        'IMPDEP1': 0xfe, 'IMPDEP2': 0xff, 'IMUL': 0x68, 'INEG': 0x74,
        'INSTANCEOF': 0xc1, 'INVOKEDYNAMIC': 0xba, 'INVOKEINTERFACE': 0xb9,
        'INVOKESPECIAL': 0xb7, 'INVOKESTATIC': 0xb8, 'INVOKEVIRTUAL': 0xb6,
        'IOR': 0x80, 'IREM': 0x70, 'IRETURN': 0xac, 'ISHL': 0x78, 'ISHR': 0x7a,
        'ISTORE': 0x36, 'ISTORE_0': 0x3b, 'ISTORE_1': 0x3c, 'ISTORE_2': 0x3d,
        'ISTORE_3': 0x3e, 'ISUB': 0x64, 'IUSHR': 0x7c, 'IXOR': 0x82,
        'JSR': 0xa8, 'JSR_W': 0xc9, 'L2D': 0x8a, 'L2F': 0x89, 'L2I': 0x88,
        'LADD': 0x61, 'LALOAD': 0x2f, 'LAND': 0x7f, 'LASTORE': 0x50,
        'LCMP': 0x94, 'LCONST_0': 0x09, 'LCONST_1': 0x0a, 'LDC': 0x12,
        'LDC2_W': 0x14, 'LDC_W': 0x13, 'LDIV': 0x6d, 'LLOAD': 0x16,
        'LLOAD_0': 0x1e, 'LLOAD_1': 0x1f, 'LLOAD_2': 0x20, 'LLOAD_3': 0x21,
        'LMUL': 0x69, 'LNEG': 0x75, 'LOOKUPSWITCH': 0xab, 'LOR': 0x81,
        'LREM': 0x71, 'LRETURN': 0xad, 'LSHL': 0x79, 'LSHR': 0x7b,
        'LSTORE': 0x37, 'LSTORE_0': 0x3f, 'LSTORE_1': 0x40, 'LSTORE_2': 0x41,
        'LSTORE_3': 0x42, 'LSUB': 0x65, 'LUSHR': 0x7d, 'LXOR': 0x83,
        'MONITORENTER': 0xc2, 'MONITOREXIT': 0xc3, 'MULTIANEWARRAY': 0xc5,
        'NEW': 0xbb, 'NEWARRAY': 0xbc, 'NOP': 0x00, 'POP': 0x57, 'POP2': 0x58,
        'PUTFIELD': 0xb5, 'PUTSTATIC': 0xb3, 'RET': 0xa9, 'RETURN': 0xb1,
        'SALOAD': 0x35, 'SASTORE': 0x56, 'SIPUSH': 0x11, 'SWAP': 0x5f,
        'TABLESWITCH': 0xaa, 'WIDE': 0xc4
    }

    def get_op_name(op):
        for k in op_codes:
            if op == op_codes[k]:
                return op
        else:
            return ''

    def get_op_code(name):
        return op_codes[name]


class JavaClassMember(Parsable):
    access_flags = 0
    name_index = 0
    name = None
    descriptor_index = 0
    descriptor = None
    attributes_count = 0
    attributes = []

    def get_modifiers_list(self):
        af = self.access_flags
        return [f for f in self.flags if (af & self.flags[f]) != 0]

    def has_modifier(self, modifier):
        return (self.flags[modifier] & self.access_flags) != 0

    def parse(self, reader, pool):
        self.access_flags = reader.read_short()
        self.name_index = reader.read_short()
        self.name = pool.get_value(self.name_index)
        self.descriptor_index = reader.read_short()
        self.descriptor = pool.get_value(self.descriptor_index)

        for attr in Attribute.parse_attributes(reader, pool):
            self.attributes.append(attr)

    def __str__(self):
        return self.name


class Field(JavaClassMember):
    flags = FIELD_FLAGS


class Method(JavaClassMember):
    flags = METHOD_FLAGS


class JavaClass:
    constant_pool = None
    access_flags = 0
    superclass_name = ''
    class_name = ''
    fields = []
    methods = []
    version = {'major': 0, 'minor': 0}
    flags = CLASS_FLAGS

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

    def has_modifier(self, modifier):
        return (access_flags & self.flags[modifier]) != 0

    def add_field(self, field):
        self.fields.append(field)

    def get_constant_pool(self):
        return self.constant_pool

    def set_constant_pool(self, pool):
        self.constant_pool = pool

    def get_fields(self):
        return self.fields

    def find_fields(self, *args, **kwargs):
        found = []

        for k, v in kwargs.items():
            if k[:3] == 'is_':
                if not k[3:] in FIELD_FLAGS.keys():
                    continue

                for f in self.fields:
                    if f.has_modifier(k[3:]) == kwargs[k]:
                        found.append(f)
            elif k == 'name':
                for f in self.fields:
                    if f.name == kwargs[k]:
                        found.append(f)
                        break
            elif k in ['descriptor', 'type']:
                for f in self.fields:
                    if f.descriptor == kwargs[k]:
                        found.append(f)

        return found

    def get_methods(self):
        return self.methods


class ClassParser:
    def __init__(self, file):
        self.file = file
        self.reader = Reader()

    def parse_class(self):
        clazz = JavaClass()
        self.reader.load_class(self.file)

        if self.reader.read_int() != 0xCAFEBABE:
            raise Exception('Not a valid Java class file')

        clazz.version['minor'] = self.reader.read_short()
        clazz.version['major'] = self.reader.read_short()

        pool = self.parse_constant_pool(clazz)
        clazz.pool = pool
        clazz.access_flags = pool.get_value(self.reader.read_short())
        clazz.class_name = pool.get_value(self.reader.read_short())
        clazz.superclass_name = pool.get_value(self.reader.read_short())
        clazz.interfaces = self.parse_interface_table(clazz)
        clazz.fields = self.parse_fields(clazz, pool)
        clazz.methods = self.parse_methods(clazz, pool)
        clazz.attributes = Attribute.parse_attributes(self.reader, pool)

        return clazz

    def parse_constant_pool(self, clazz):
        pool = ConstantPool(self.reader.read_short())
        pool.parse(self.reader)

        return pool

    def parse_interface_table(self, clazz):
        size = self.reader.read_short()

        for i in range(size):
            self.reader.read_byte()

        return None

    def parse_fields(self, clazz, pool):
        fields = []
        size = self.reader.read_short()

        for i in range(size):
            field = Field()
            field.parse(self.reader, pool)
            fields.append(field)

        return fields

    def parse_methods(self, clazz, pool):
        methods = []
        size = self.reader.read_short()

        for i in range(size):
            m = Method()
            m.parse(self.reader, pool)
            methods.append(m)

        return methods


def main(args):
    if args.classfile is None:
        return 'ERROR: Please pass in a classfile to parse via --classfile'

    parser = ClassParser(args.classfile)
    clazz = parser.parse_class()

    for f in clazz.find_fields(is_static=True, type='I'):
        print f

if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-c', '--classfile')
    args = arg_parser.parse_args()
    exit(main(args))
