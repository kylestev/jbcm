class Reader:
    pos = -1
    buff = None
    pool = None

    def read_byte(self):
        """
        Reads a single byte from the buffer
        """

        self.pos += 1
        return ord(self.buff[self.pos])

    def read_short(self):
        """
        Reads a short, or two bytes, from the buffer
        """

        return (self.read_byte() << 8) + self.read_byte()

    def read_int(self):
        """
        Reads an integer, or four bytes, from the buffer
        """

        return (self.read_short() << 16) + self.read_short()

    def read_long(self):
        return (self.read_int() << 32) + self.read_int()

    def read(self, length):
        """
        Reads a chunk with the specified length and returns it
        @param length the size of the chunk to read in
        """
        
        b = []

        for i in range(length):
            self.pos += 1
            b.append(self.buff[self.pos])

        return b

    def load_class(self, file):
        """
        Convenience method for setting the buffer of this instance to a file's
        contents
        @param file the file to read in
        """

        with open(file, 'rb') as f:
            self.buff = f.read()
