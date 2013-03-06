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

    def read(self, length):
        b = []

        for i in range(length):
            self.pos += 1
            b.append(self.buff[self.pos])

        return b

    def load_class(self, file):
        with open(file, 'rb') as f:
            self.buff = f.read()
