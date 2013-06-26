from reader import Reader


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
            return self.pool[item.value['type']].get_value()
        elif item.tag_id == 12:
            return {'name': self.get(item.value['name']).get_value(),
                    'type': self.get(item.value['type']).get_value()}
        else:
            return self.pool[index].get_value()

    def print_pool(self):
        for i in xrange(1, self.size):
            item = self.get(i)

            if item is None:
                continue

            print (i, item.name, self.get_value(i))

    def parse(self, reader, pool=None):
        self.pool.append(None)

        for i in range(1, self.size):
            item = None
            tag = reader.read_byte()

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
                item.read_data(reader)
                self.pool.append(item)

                if tag in (5, 6):
                    self.pool.append(None)
            else:
                reader.pos -= 1
                break
