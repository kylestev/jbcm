from reader import Reader


class Parsable:
    def parse(self, reader, pool=None):
        """"""


class Table:
    table_length = 0
    table = []

    def parse_table(self, reader, pool):
        table_length = reader.read_short()

        for i in range(table_length):
            self.table.append(self.parse_entry(reader, pool))

    def parse_entry(self, reader, pool):
        return None


class Attribute(Parsable):
    name_index = 0
    attribute_length = 0
    name = None

    @staticmethod
    def parse_attributes(reader, pool):
        attrs = []
        size = reader.read_short()

        for i in range(size):
            name_index = reader.read_short()
            details = {'index': name_index, 'name': pool.get_value(name_index),
                       'length': reader.read_int()}

            if details['name'] == 'ConstantValue':
                attr = AttributeConstantValue()
            elif details['name'] == 'Code':
                attr = AttributeCode()
            elif details['name'] == 'Exceptions':
                attr = AttributeException()
            elif details['name'] == 'InnerClasses':
                attr = TableInnerClasses()
            elif details['name'] == 'Synthetic':
                attr = AttributeSynthetic()
            elif details['name'] == 'SourceFile':
                attr = AttributeSourceFile()
            elif details['name'] == 'LineNumberTable':
                attr = TableLineNumberTable()
            elif details['name'] == 'LocalVariableTable':
                attr = TableLocalVariableTable()
            elif details['name'] == 'Deprecated':
                attr = AttributeDeprecated()
            elif details['name'] == 'Signature':
                attr = AttributeSignature()
            else:
                attr = Attribute()

            attr.set_attributes(details)
            attr.parse(reader, pool)

            attrs.append(attr)

        return attrs

    def parse(self, reader, pool):
        reader.read(self.attribute_length)

    def set_attributes(self, name):
        self.name_index = name['index']
        self.name = name['name']
        self.attribute_length = name['length']


class TabledAttribute(Attribute, Table):
    def parse(self, reader, pool):
        self.parse_table(reader, pool)


class AttributeConstantValue(Attribute):
    constantvalue_index = 0


class AttributeSynthetic(Attribute):
    """"""


class AttributeDeprecated(Attribute):
    """"""


class AttributeException(TabledAttribute):
    def parse_entry(self, reader, pool):
        index = reader.read_short()
        return (index, pool.get_value(index))


class TableLocalVariableTable(TabledAttribute):
    def parse_entry(self, reader, pool):
        return {'start_pc': reader.read_short(), 'length': reader.read_short(),
                'name_index': reader.read_short(),
                'index': reader.read_short(),
                'descriptor_index': reader.read_short()}


class TableLineNumberTable(TabledAttribute):
    def parse_entry(self, reader, pool):
        return {'start_pc': reader.read_short(),
                'line_number': reader.read_short()}


class AttributeSignature(Attribute):
    signature_index = 0

    def parse(self, reader, pool):
        signature_index = reader.read_short()


class AttributeSourceFile(Attribute):
    source_file_index = 0

    def parse(self, reader, pool):
        source_file_index = reader.read_short()


class TableInnerClasses(TabledAttribute):
    def parse_entry(self, reader, pool):
        return {'inner_class_info_index': reader.read_short(),
                'outer_class_info_index': reader.read_short(),
                'inner_name_index': reader.read_short(),
                'inner_class_access_flags': reader.read_short()}


class AttributeCode(Attribute):
    max_stack = 0
    max_locals = 0
    code_length = 0
    code = []
    exception_table_length = 0
    exception_table = []
    attributes_count = 0
    attributes = []
